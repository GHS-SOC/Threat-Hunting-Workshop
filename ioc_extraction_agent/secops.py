"""Read-only Google SecOps (Chronicle) lookups over its MCP server.

The transport investigationAgent uses: a Google service-account key
(`SECOPS_CREDENTIALS_FILE`), or Application Default Credentials when none is set,
a token refreshed as needed, JSON-RPC `tools/call` against the tenant's MCP endpoint.
Only `get_ioc_match`, `search_entity` and `udm_search` are reachable -- an
allowlist enforced here, since the server also offers case updates, feed and
parser changes and SOAR actions.

Per report:
- `get_ioc_match` once over the feed window: what the tenant's own threat-intel
  feeds matched.
- `search_entity` per searchable IOC: whether SOAR knows the value at all (it
  answers `{}` for an unknown one).
- `udm_search` per huntable IOC, escalating: the last `HUNT_FIRST_DAYS` (7) first,
  then -- only if that found nothing -- back to `HUNT_DAYS` (30), never further: the
  hunt. Events found mean the IOC appeared in the tenant's own telemetry -- the
  question "did this touch us?" -- with the hosts involved, first/last seen and
  where it was logged.
Every IOC also gets its UDM query, so an analyst can pivot by hand.

A failed lookup is `None` -- not determined -- never `False`.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import re
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx

from .schemas import IOC, EventSightings, HuntSummary, PatternSearch, SecOpsCheck, SecOpsSighting

logger = logging.getLogger(__name__)

LOOKBACK_DAYS = 7
MAX_LOOKUPS = 60  # search_entity calls per report; measured ~35 s for 53 with 4 workers
WORKERS = 4
# The hunt: udm_search over the tenant's event logs, per IOC. The last week first;
# only an IOC with no sighting there is searched further back, to 30 days and no
# further (udm_search itself warns that more than ~a month may not complete).
# SECOPS_HUNT_DAYS lowers the limit; 0 turns the hunt off. ~2-5 s per call (ghslab).
HUNT_FIRST_DAYS = 7
HUNT_DAYS = 30
MAX_HUNT_DAYS = 30
HUNT_MAX_EVENTS = 50     # per call: enough for counts, hosts and first/last seen
MAX_HUNTS = 40           # IOCs searched per report
MAX_ASSETS = 10          # hosts listed per IOC
MAX_URLS = 5             # requested URLs listed per sighting
MAX_PATTERNS = 10        # redacted-URL patterns searched per report
READ_ONLY_TOOLS = frozenset({"search_entity", "get_ioc_match", "udm_search"})
SEARCHABLE_TYPES = frozenset({"ipv4", "ipv6", "domain", "url", "md5", "sha1", "sha256",
                              "email", "file_name"})
HUNTABLE_TYPES = SEARCHABLE_TYPES | {"registry_key", "cve"}
TENANT_VARS = ("SECOPS_MCP_URL", "SECOPS_PROJECT_ID", "SECOPS_CUSTOMER_ID", "SECOPS_REGION")
# Path to a Google service-account key (JSON). `~` and $VARS are expanded; a relative
# path is taken from the project root (the folder holding run.py), whatever the cwd.
# Empty: Application Default Credentials (`gcloud auth application-default login`,
# or GOOGLE_APPLICATION_CREDENTIALS).
CREDENTIALS_VAR = "SECOPS_CREDENTIALS_FILE"
PROJECT_ROOT = Path(__file__).resolve().parent.parent
_SCOPES = ["https://www.googleapis.com/auth/cloud-platform"]
_AUTH_HINT = re.compile(r"\b401\b|\b403\b|unauthenticated|permission|credential|invalid_grant|"
                        r"RefreshError|DefaultCredentialsError", re.I)
# An error that already tells the user what to do about their credentials.
_HINTED = re.compile(r"gcloud|SECOPS_CREDENTIALS_FILE")


class SecOpsError(RuntimeError):
    """A SecOps call with no usable answer. `fatal`: every later call would fail the
    same way (no credential, rejected identity, unreachable server), so stop."""

    def __init__(self, message: str, fatal: bool = False):
        super().__init__(message)
        self.fatal = fatal


class SecOpsClient:
    """One Chronicle tenant reached over its MCP server, read-only."""

    def __init__(self, mcp_url: str, project_id: str, customer_id: str, region: str,
                 credentials: Any = None, transport: httpx.BaseTransport | None = None,
                 credentials_file: str | None = None):
        self.mcp_url = mcp_url
        self.project_id = project_id
        self.tenant = {"projectId": project_id, "customerId": customer_id, "region": region}
        self._credentials = credentials
        self._credentials_file = credentials_file or None
        self._lock = threading.Lock()
        self._transport = transport

    def _load_credentials(self) -> Any:
        """The service-account key at `credentials_file` if one is set; ADC otherwise."""
        import google.auth

        if self._credentials_file:
            return _credentials_from_file(self._credentials_file)
        credentials, _ = google.auth.default(scopes=_SCOPES)
        return credentials

    def _token(self) -> str:
        import google.auth.transport.requests

        with self._lock:
            if self._credentials is None:
                self._credentials = self._load_credentials()
            if not self._credentials.valid:
                self._credentials.refresh(google.auth.transport.requests.Request())
            return self._credentials.token

    def _credential_hint(self, detail: str) -> str:
        if self._credentials_file:
            return (f" Check that {CREDENTIALS_VAR} points at a readable service-account key "
                    f"(resolved to {resolve_credentials_path(self._credentials_file)}).")
        return "" if "gcloud" in detail else " Run `gcloud auth application-default login`."

    def call_tool(self, name: str, arguments: dict[str, Any]) -> Any:
        """Call one allowlisted MCP tool; return its decoded payload."""
        if name not in READ_ONLY_TOOLS:
            raise SecOpsError(f"'{name}' is not an allowed read-only SecOps tool")
        try:
            token = self._token()
        except Exception as exc:  # noqa: BLE001 - any credential failure means the same thing
            detail = f"{type(exc).__name__}: {exc}"
            hint = self._credential_hint(detail)
            raise SecOpsError(f"Google credentials unavailable ({detail}).{hint}", fatal=True) from None
        payload = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                   "params": {"name": name, "arguments": {**self.tenant, **arguments}}}
        try:
            with httpx.Client(timeout=60.0, transport=self._transport) as client:
                response = client.post(self.mcp_url, json=payload, headers={
                    "Authorization": f"Bearer {token}",
                    "accept": "application/json, text/event-stream",
                    "x-goog-user-project": self.project_id,
                })
        except httpx.HTTPError as exc:
            raise SecOpsError(f"SecOps MCP server unreachable: {type(exc).__name__}: {exc}",
                              fatal=isinstance(exc, httpx.ConnectError)) from None
        if response.status_code != 200:
            raise SecOpsError(f"SecOps MCP server returned HTTP {response.status_code}: "
                              f"{response.text[:300]}", fatal=response.status_code in (401, 403, 404))
        body = _decode_jsonrpc(response.text)
        if body is None:
            raise SecOpsError(f"could not parse the SecOps MCP response: {response.text[:300]}")
        if "error" in body:
            raise SecOpsError(f"SecOps MCP error: {body['error']}")
        result = body.get("result") or {}
        text = "\n".join(block.get("text") or "" for block in result.get("content") or []
                         if isinstance(block, dict) and block.get("type") == "text")
        if result.get("isError"):
            raise SecOpsError(f"{name} was refused by SecOps: {text[:500]}")
        if isinstance(result.get("structuredContent"), (dict, list)):
            return result["structuredContent"]
        try:
            return json.loads(text) if text.strip() else {}
        except ValueError:
            return text


def resolve_credentials_path(value: str) -> Path:
    """`SECOPS_CREDENTIALS_FILE` as written in .env, made absolute: `~` and `$VAR` /
    `%VAR%` expanded, a relative path anchored at the project root rather than the
    shell's current directory."""
    expanded = os.path.expandvars(os.path.expanduser(value.strip().strip("'\"")))
    path = Path(expanded)
    return path if path.is_absolute() else PROJECT_ROOT / path


def _credentials_from_file(path: str) -> Any:
    """A scoped credential from a service-account key file, or a workload-identity /
    authorized-user config (anything `google.auth` can load from a dict)."""
    import google.auth

    with open(resolve_credentials_path(path), encoding="utf-8") as handle:
        info = json.load(handle)
    if info.get("type") == "service_account":
        from google.oauth2 import service_account

        return service_account.Credentials.from_service_account_info(info, scopes=_SCOPES)
    credentials, _ = google.auth.load_credentials_from_dict(info, scopes=_SCOPES)
    return credentials


def _decode_jsonrpc(text: str) -> dict[str, Any] | None:
    """A JSON-RPC body sent as plain JSON or as a server-sent event stream."""
    for candidate in [text] + [line[5:] for line in text.splitlines() if line.startswith("data:")]:
        try:
            return json.loads(candidate)
        except ValueError:
            continue
    return None


_default: tuple[SecOpsClient | None, str] | None = None


def default_client() -> tuple[SecOpsClient | None, str]:
    """The tenant from the SECOPS_* variables, built once; (None, why) if not configured."""
    global _default
    if _default is None:
        values = [os.environ.get(name, "").strip() for name in TENANT_VARS]
        missing = [name for name, value in zip(TENANT_VARS, values) if not value]
        credentials_file = os.environ.get(CREDENTIALS_VAR, "").strip() or None
        _default = ((None, f"{', '.join(missing)} not set in ioc_extraction_agent/.env")
                    if missing else (SecOpsClient(*values, credentials_file=credentials_file), ""))
    return _default


# --------------------------------------------------------------------------
# UDM queries
# --------------------------------------------------------------------------


def _quoted(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


_RX_SPECIAL = re.compile(r"([\\.^$|?*+()\[\]{}/])")
# Publishers redact offensive or sensitive parts of a URL (`/REDACTED OFFENSIVE`).
REDACTION = re.compile(r"[\w-]*redacted[\w-]*", re.IGNORECASE)
_DEFAULT_PORTS = {"http": 80, "https": 443}
_ANY_SEGMENT = r"[^\/?#]*"


def _rx(text: str) -> str:
    """`text` as a literal inside a UDM `/regex/` (RE2), `/` included."""
    return _RX_SPECIAL.sub(r"\\\1", text)


def url_regexes(value: str) -> tuple[str, str, str] | None:
    """(absolute-URL regex, path-only regex, host) for a URL; None if it has no usable host.

    Logs spell one URL many ways, so the regex accepts: `http`, `https` or no scheme;
    the default port written or not; a trailing slash; and a query or fragment added
    when the IOC has none. A path segment holding a redaction marker becomes a
    wildcard, and when it is the last one, so does everything after it: the URL
    `http://1.2.3.4/REDACTED` searches for any path on 1.2.3.4.
    """
    parts = urlsplit(value)
    host = parts.hostname
    if not host or REDACTION.search(host):
        return None
    scheme = parts.scheme.lower()
    try:
        port = parts.port
    except ValueError:
        port = None
    if port is None:
        port_rx = "(?::(?:80|443))?"
    elif port == _DEFAULT_PORTS.get(scheme):
        port_rx = f"(?::{port})?"
    else:
        port_rx = f":{port}"

    segments = parts.path.rstrip("/").split("/")
    redacted = [i for i, segment in enumerate(segments) if REDACTION.search(segment)]
    path_rx = r"\/".join(_ANY_SEGMENT.join(_rx(piece) for piece in REDACTION.split(segment))
                         for segment in segments)
    if redacted and redacted[-1] == len(segments) - 1:
        tail = r"(?:[\/?#].*)?$"                      # the rest of the URL was withheld
    elif parts.query and not redacted:
        tail = r"\/?\?" + _rx(parts.query) + "(?:#.*)?$"
    else:
        tail = r"\/?(?:[?#].*)?$"
    schemes = "https?" if scheme in _DEFAULT_PORTS else _rx(scheme)
    host_rx = rf"\[{_rx(host)}\]" if ":" in host else _rx(host)
    return (f"^(?:{schemes}:\\/\\/)?{host_rx}{port_rx}{path_rx}{tail}", f"^{path_rx}{tail}", host)


def _url_query(value: str) -> str | None:
    """Full URLs (proxy, EDR) by regex, or a path logged apart from its server (web
    server logs) on that server's address or name."""
    built = url_regexes(value)
    if built is None:
        return None
    absolute, relative, host = built
    try:
        ipaddress.ip_address(host)
        server = f"target.ip = {_quoted(host)}"
    except ValueError:
        server = f"target.hostname = {_quoted(host.lower())} nocase"
    return f"target.url = /{absolute}/ nocase or ({server} and target.url = /{relative}/ nocase)"


def redaction_pattern(value: str) -> str:
    """A redacted URL as people read the pattern: `http://1.2.3.4/*`."""
    parts = urlsplit(value)
    segments = parts.path.split("/")
    for index, segment in enumerate(segments):
        if REDACTION.search(segment):
            segments[index] = REDACTION.sub("*", segment)
            if index == len(segments) - 1 or not "".join(segments[index + 1:]):
                segments = segments[: index + 1]
            break
    return f"{parts.scheme}://{parts.netloc}{'/'.join(segments)}"


def udm_query(ioc_type: str, value: str) -> str | None:
    """A UDM search for the events that would mention this IOC, or None.

    UDM `=` on strings is case-sensitive -- measured on the ghslab tenant,
    `principal.hostname = "win10target..."` finds nothing that `... nocase` finds --
    so every string comparison is `nocase`. DNS question names may carry the root
    dot (`evil.com.`), so domains match both spellings.
    """
    if ioc_type in ("ipv4", "ipv6"):
        v = _quoted(value)
        return f"principal.ip = {v} or target.ip = {v} or src.ip = {v}"
    if ioc_type == "domain":
        v, rooted = _quoted(value.lower()), _quoted(value.lower() + ".")
        return (f"principal.hostname = {v} nocase or target.hostname = {v} nocase "
                f"or network.dns.questions.name = {v} nocase "
                f"or network.dns.questions.name = {rooted} nocase")
    if ioc_type == "url":
        return _url_query(value)
    if ioc_type in ("md5", "sha1", "sha256"):
        v = _quoted(value.lower())
        return (f"target.file.{ioc_type} = {v} nocase "
                f"or principal.process.file.{ioc_type} = {v} nocase")
    if ioc_type == "email":
        v = _quoted(value.lower())
        return (f"network.email.from = {v} nocase or network.email.to = {v} nocase "
                f"or principal.user.email_addresses = {v} nocase")
    if ioc_type == "file_name":
        pattern = f"/{_rx(value)}/"
        return (f"target.file.full_path = {pattern} nocase "
                f"or target.process.file.full_path = {pattern} nocase")
    if ioc_type == "registry_key":
        return f"target.registry.registry_key = {_quoted(value)} nocase"
    if ioc_type == "cve":
        return f"extensions.vulns.vulnerabilities.cve_id = {_quoted(value)}"
    return None


# --------------------------------------------------------------------------
# The check
# --------------------------------------------------------------------------


def _rows(payload: Any, key: str) -> list[str] | None:
    """payload[key] as lower-cased JSON strings to search; None if unreadable."""
    if not isinstance(payload, dict):
        return None
    return [json.dumps(row, default=str).lower() for row in payload.get(key) or []]


def _searchable(ioc: IOC) -> bool:
    if ioc.type in ("ipv4", "ipv6"):
        return ipaddress.ip_address(ioc.value).is_global
    return ioc.type in SEARCHABLE_TYPES


def _huntable(ioc: IOC) -> bool:
    """Worth a UDM search: a private address would match the tenant's own network."""
    if ioc.type in ("ipv4", "ipv6"):
        return ipaddress.ip_address(ioc.value).is_global
    return ioc.type in HUNTABLE_TYPES and ioc.secops is not None and bool(ioc.secops.udm_query)


# --------------------------------------------------------------------------
# The hunt: udm_search over the tenant's event logs
# --------------------------------------------------------------------------


def configured_hunt_days() -> int:
    """The hunt look-back in days: SECOPS_HUNT_DAYS, else HUNT_DAYS, at most
    MAX_HUNT_DAYS; 0 turns it off."""
    raw = os.environ.get("SECOPS_HUNT_DAYS", "").strip()
    try:
        days = int(raw) if raw else HUNT_DAYS
    except ValueError:
        logger.warning("[secops] SECOPS_HUNT_DAYS=%r is not a number; using %d", raw, HUNT_DAYS)
        days = HUNT_DAYS
    return max(0, min(days, MAX_HUNT_DAYS))


def _iso(moment: datetime) -> str:
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def hunt_stages(end: datetime, days: int,
                first_days: int = HUNT_FIRST_DAYS) -> list[tuple[str, str, int]]:
    """The hunt's escalation, newest first: (start, end, days covered once it ran).

    The last `first_days`; then the rest of `days`, run only for an IOC the first
    stage found nothing for, and without searching the first week again.
    """
    if days <= first_days:
        return [(_iso(end - timedelta(days=days)), _iso(end), days)]
    week = end - timedelta(days=first_days)
    return [(_iso(week), _iso(end), first_days),
            (_iso(end - timedelta(days=days)), _iso(week), days)]


def _hunt(client: SecOpsClient, query: str, stages: list[tuple[str, str, int]],
          stop: threading.Event) -> tuple[list[dict[str, Any]], bool, list[str], int]:
    """(UDM events, more available, errors, days searched) for one IOC's or pattern's
    UDM query.

    A stage runs only while nothing has been found: a sighting in the last week
    ends the search there.
    """
    events: list[dict[str, Any]] = []
    more, errors, searched = False, [], 0
    for start, end, covered in stages:
        if events:
            break
        if stop.is_set():
            errors.append("skipped: an earlier event search was refused")
            break
        try:
            payload = client.call_tool("udm_search", {
                "query": query, "startTime": start, "endTime": end,
                "maxEvents": HUNT_MAX_EVENTS})
        except SecOpsError as exc:
            message = str(exc)[:300]
            # A refused identity fails every search the same way: stop the hunt.
            if exc.fatal or _AUTH_HINT.search(message):
                stop.set()
            errors.append(message)
            continue
        if not isinstance(payload, dict):
            errors.append("udm_search answered with something other than JSON")
            continue
        found = [event["udm"] for event in payload.get("events") or []
                 if isinstance(event, dict) and isinstance(event.get("udm"), dict)]
        events.extend(found)
        searched = covered
        # A full page is truncated even when the API says otherwise (measured: 50 of
        # 50 events, all from the last 7 hours of a 7-day window, moreDataAvailable false).
        more = more or bool(payload.get("moreDataAvailable")) or len(found) >= HUNT_MAX_EVENTS
    return events, more, errors, searched


def _first(*values: Any) -> str | None:
    for value in values:
        if isinstance(value, list):
            value = value[0] if value else None
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _assets(events: list[dict[str, Any]], ioc_value: str) -> list[str]:
    """The machines in `events`, other than the IOC itself: a hostname per side of
    each event (principal, target, src), or its address when no name is logged."""
    found: dict[str, None] = {}
    needle = ioc_value.lower()
    for event in events:
        for side in ("principal", "target", "src"):
            noun = event.get(side)
            if not isinstance(noun, dict):
                continue
            asset = noun.get("asset") if isinstance(noun.get("asset"), dict) else {}
            name = _first(noun.get("hostname"), asset.get("hostname"),
                          noun.get("ip"), asset.get("ip"))
            if name and name.lower() not in needle and needle not in name.lower():
                found.setdefault(name, None)
            if len(found) >= MAX_ASSETS:
                return list(found)
    return list(found)


def summarise_events(events: list[dict[str, Any]], more: bool, ioc_value: str) -> EventSightings:
    times = sorted(t for t in ((e.get("metadata") or {}).get("eventTimestamp") for e in events)
                   if isinstance(t, str))
    distinct = lambda key: list(dict.fromkeys(  # noqa: E731
        v for v in ((e.get("metadata") or {}).get(key) for e in events) if isinstance(v, str)))[:5]
    urls = list(dict.fromkeys(url[:300] for url in ((e.get("target") or {}).get("url") for e in events)
                              if isinstance(url, str) and url.strip()))[:MAX_URLS]
    return EventSightings(count=len(events), more_available=more,
                          first_seen=times[0] if times else None,
                          last_seen=times[-1] if times else None,
                          assets=_assets(events, ioc_value), urls=urls,
                          event_types=distinct("eventType"), log_types=distinct("logType"))


def _entity_lookup(client: SecOpsClient, ioc: IOC) -> tuple[bool | None, str | None]:
    """(entity_match, error) for one IOC."""
    try:
        rows = _rows(client.call_tool("search_entity", {"indicator": ioc.value, "pageSize": 10}),
                     "entities")
    except SecOpsError as exc:
        return None, str(exc)[:300]
    if rows is None:
        return None, "search_entity answered with something other than JSON"
    return any(ioc.value.lower() in row for row in rows), None


def _collect(jobs: list[Any], on_crash: Any) -> list[Any]:
    """Each job's result; a job that raised becomes `on_crash(message)` (the check never raises)."""
    results = []
    for job in jobs:
        try:
            results.append(job.result())
        except Exception as exc:  # noqa: BLE001
            logger.warning("[secops] lookup crashed: %s: %s", type(exc).__name__, exc)
            results.append(on_crash(f"{type(exc).__name__}: {exc}"[:300]))
    return results


def check_iocs(iocs: list[IOC], *, client: SecOpsClient | None, unavailable: str = "",
               patterns: list[PatternSearch] | None = None,
               lookback_days: int = LOOKBACK_DAYS, max_lookups: int = MAX_LOOKUPS,
               hunt_lookback: int | None = None, max_hunts: int = MAX_HUNTS,
               now: datetime | None = None) -> SecOpsCheck:
    """Set `ioc.secops` on every IOC, search the event logs for every redacted-URL
    pattern, and return the check summary. Never raises.

    `hunt_lookback` is how far back the event-log search may go, in days (None:
    SECOPS_HUNT_DAYS, else HUNT_DAYS; at most MAX_HUNT_DAYS; 0: no search). The last
    HUNT_FIRST_DAYS are searched first, and further back only without a sighting.
    """
    patterns = patterns or []
    for ioc in iocs:
        ioc.secops = SecOpsSighting(checked=False, udm_query=udm_query(ioc.type, ioc.value))
    for pattern in patterns:
        pattern.udm_query = udm_query("url", pattern.source)
        if pattern.udm_query is None:
            pattern.note = "the host itself was withheld; nothing specific enough to search"
    if client is None:
        for item in [ioc.secops for ioc in iocs] + patterns:
            item.note = item.note or "SecOps check not configured"
        return SecOpsCheck(status="not_configured", error=unavailable or None)
    if not iocs and not patterns:
        return SecOpsCheck(status="skipped")

    end = now or datetime.now(timezone.utc)
    window = (_iso(end - timedelta(days=lookback_days)), _iso(end))
    days = (configured_hunt_days() if hunt_lookback is None
            else max(0, min(hunt_lookback, MAX_HUNT_DAYS)))
    stages = hunt_stages(end, days) if days else []

    feed_error = None
    try:
        feed = _rows(client.call_tool("get_ioc_match",
                                      {"startTime": window[0], "endTime": window[1]}), "matches")
        if feed is None:
            feed_error = "get_ioc_match answered with something other than JSON"
    except SecOpsError as exc:
        feed, feed_error = None, str(exc)[:300]
        if exc.fatal:
            logger.warning("[secops] stopping the check: %s", feed_error)
            for item in [ioc.secops for ioc in iocs] + patterns:
                item.note = "not checked: SecOps unavailable (see secops_check.error)"
            if _AUTH_HINT.search(feed_error) and not _HINTED.search(feed_error):
                feed_error += " Check the Google credentials and the tenant's IAM grant."
            return SecOpsCheck(status="failed", window_start=window[0], window_end=window[1],
                               error=feed_error)

    searchable = [ioc for ioc in iocs if _searchable(ioc)]
    huntable = [ioc for ioc in iocs if _huntable(ioc)] if stages else []
    searchable_patterns = [p for p in patterns if p.udm_query][:MAX_PATTERNS] if stages else []
    stop = threading.Event()
    crashed = lambda message: ([], False, [message], 0)  # noqa: E731
    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        entity_jobs = [pool.submit(_entity_lookup, client, ioc) for ioc in searchable[:max_lookups]]
        hunt_jobs = [pool.submit(_hunt, client, ioc.secops.udm_query, stages, stop)
                     for ioc in huntable[:max_hunts]]
        pattern_jobs = [pool.submit(_hunt, client, p.udm_query, stages, stop)
                        for p in searchable_patterns]
        results = _collect(entity_jobs, lambda message: (None, message))
        hunts = _collect(hunt_jobs, crashed)
        pattern_hunts = _collect(pattern_jobs, crashed)
    lookups = {id(ioc): result for ioc, result in zip(searchable, results)}
    hunted = {id(ioc): result for ioc, result in zip(huntable, hunts)}
    for pattern, (events, more, errors, searched) in zip(searchable_patterns, pattern_hunts):
        pattern.searched_days = searched or None
        if events:
            pattern.seen_in_environment = True
            pattern.events = summarise_events(events, more, pattern.source)
        elif not errors:
            pattern.seen_in_environment = False
        if errors:
            pattern.note = f"event search {'incomplete' if events else 'failed'}: {errors[0]}"
    for pattern in patterns:
        if pattern.udm_query and pattern not in searchable_patterns:
            pattern.note = ("event search turned off (SECOPS_HUNT_DAYS=0)" if not stages
                            else f"event search skipped: budget of {MAX_PATTERNS} patterns reached")

    for ioc in iocs:
        sighting, notes = ioc.secops, []
        if ioc.type in SEARCHABLE_TYPES:
            if feed is not None:
                sighting.ioc_match = any(ioc.value.lower() in row for row in feed)
            else:
                notes.append(f"feed match not determined: {feed_error}")
        if id(ioc) in lookups:
            sighting.entity_match, error = lookups[id(ioc)]
            if error:
                notes.append(f"entity lookup failed: {error}")
        elif _searchable(ioc):
            notes.append(f"entity lookup skipped: budget of {max_lookups} lookups reached")
        elif ioc.type in ("ipv4", "ipv6"):
            notes.append("non-public address; not looked up")
        elif ioc.type not in HUNTABLE_TYPES:
            notes.append(f"{ioc.type} values are not looked up in SecOps")

        if id(ioc) in hunted:
            events, more, errors, searched = hunted[id(ioc)]
            sighting.searched_days = searched or None
            if events:
                sighting.seen_in_environment = True
                sighting.events = summarise_events(events, more, ioc.value)
                if ioc.type == "cve":
                    notes.append("the events are vulnerability findings: hosts exposed to the "
                                 "CVE, not proof of compromise")
            elif not errors:
                sighting.seen_in_environment = False
            if errors:
                notes.append(f"event search {'incomplete' if events else 'failed'}: {errors[0]}")
        elif _huntable(ioc):
            notes.append(f"event search skipped: budget of {max_hunts} IOCs reached" if stages
                         else "event search turned off (SECOPS_HUNT_DAYS=0)")
        sighting.checked = any(value is not None for value in (
            sighting.ioc_match, sighting.entity_match, sighting.seen_in_environment))
        sighting.note = "; ".join(notes) or None

    hunt = _hunt_summary(iocs, stages, hunts, over_budget=len(huntable) > max_hunts,
                         patterns=searchable_patterns, pattern_hunts=pattern_hunts)
    failures = (feed_error is not None) + sum(1 for _, error in results if error)
    answered = ((feed_error is None) + sum(1 for _, error in results if not error)
                + sum(1 for events, _, errors, _ in hunts + pattern_hunts if events or not errors))
    checked = sum(ioc.secops.checked for ioc in iocs)
    matched = sum(bool(ioc.secops.ioc_match or ioc.secops.entity_match) for ioc in iocs)
    if answered == 0:
        status, error = "failed", feed_error or "every SecOps lookup failed"
        if _AUTH_HINT.search(error) and not _HINTED.search(error):
            error += " Check the Google credentials and the tenant's IAM grant."
    elif (failures or len(searchable) > max_lookups
          or (hunt.status in ("partial", "failed"))):
        status = "partial"
        error = feed_error or (f"event search: {hunt.error}" if hunt.error else None)
    else:
        status, error = "completed", None
    logger.info("[secops] %s: %d checked, %d matched, %d call(s) failed; hunt %s: %d searched, "
                "%d seen in the event logs", status, checked, matched, failures, hunt.status,
                hunt.searched, hunt.seen)
    return SecOpsCheck(status=status, window_start=window[0], window_end=window[1],
                       checked=checked, matched=matched, hunt=hunt, error=error)


def _hunt_summary(iocs: list[IOC], stages: list[tuple[str, str, int]],
                  hunts: list[tuple[list, bool, list[str], int]], over_budget: bool,
                  patterns: list[PatternSearch] = (),
                  pattern_hunts: list[tuple[list, bool, list[str], int]] = ()) -> HuntSummary:
    if not stages:
        return HuntSummary(status="skipped")
    seen = [ioc for ioc in iocs if ioc.secops.seen_in_environment]
    seen_patterns = [p for p in patterns if p.seen_in_environment]
    sightings = [i.secops.events for i in seen] + [p.events for p in seen_patterns]
    assets = list(dict.fromkeys(a for events in sightings for a in events.assets))[:25]
    every = list(hunts) + list(pattern_hunts)
    first_errors = [errs[0] for _, _, errs, _ in every if errs]
    undetermined = sum(1 for events, _, errs, _ in every if errs and not events)
    if not every:
        status = "skipped"
    elif undetermined == len(every):
        status = "failed"
    elif first_errors or over_budget:
        status = "partial"
    else:
        status = "completed"
    error = first_errors[0] if first_errors else None
    if error and _AUTH_HINT.search(error) and not _HINTED.search(error):
        error += " Check the tenant's IAM grant for UDM search."
    return HuntSummary(status=status, window_start=stages[-1][0], window_end=stages[0][1],
                       first_window_start=stages[0][0], searched=len(hunts), seen=len(seen),
                       seen_iocs=[i.value for i in seen], patterns_searched=len(pattern_hunts),
                       seen_patterns=[p.pattern for p in seen_patterns], assets=assets,
                       error=error)
