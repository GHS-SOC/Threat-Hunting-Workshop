"""The report as Markdown, for people: the agent's reply in chat (`adk web`, `adk run`)
and `run.py --format markdown`.

Rendered by code from the validated report dict -- the model never writes it -- and
the JSON itself stays in session state (`ioc_report`) with every field. Two rules
keep it safe to read in a chat window:

- Indicators are defanged (`hxxp://evil[.]com`) and set in code spans, so nothing
  turns an attacker URL into a clickable link.
- Text that came from the page or the model (titles, reasons, errors) is escaped,
  so a hostile page cannot inject links, images or HTML into the report.
"""

from __future__ import annotations

import re
from collections import Counter
from datetime import datetime
from typing import Any
from urllib.parse import urlsplit

_MD_SPECIAL = re.compile(r"([\\`*_\[\]()<>#!|~])")
# Renderers auto-link `http://...` and `www....` even in plain text: defang them there too.
_TEXT_SCHEME = re.compile(r"\b(h)tt(ps?)://", re.IGNORECASE)
_TEXT_WWW = re.compile(r"\bwww\.", re.IGNORECASE)
_MAX_EXCLUDED = 25
_TYPE_LABELS = {"ipv4": "IPv4", "ipv6": "IPv6", "md5": "MD5", "sha1": "SHA1", "sha256": "SHA256",
                "url": "URL", "cve": "CVE", "domain": "domain", "email": "email",
                "file_name": "file name", "registry_key": "registry key", "mutex": "mutex"}


# --------------------------------------------------------------------------
# Safe pieces
# --------------------------------------------------------------------------


def defang(ioc_type: str, value: str) -> str:
    """The value as analysts write it in reports: unusable as a link."""
    if ioc_type == "url":
        parts = urlsplit(value)
        scheme = {"http": "hxxp", "https": "hxxps", "ftp": "fxp"}.get(parts.scheme.lower(),
                                                                       parts.scheme)
        rest = value[len(parts.scheme) + 3 + len(parts.netloc):]
        return f"{scheme}://{parts.netloc.replace('.', '[.]')}{rest}"
    if ioc_type in ("domain", "ipv4"):
        return value.replace(".", "[.]")
    if ioc_type == "email":
        local, _, host = value.rpartition("@")
        return f"{local}[@]{host.replace('.', '[.]')}"
    if ioc_type == "ipv6":
        return value.replace(":", "[:]")
    return value


def _text(value: Any, limit: int | None = None) -> str:
    """Untrusted text, one line, Markdown-escaped, with no auto-linkable address."""
    text = " ".join(str(value or "").split())
    if limit and len(text) > limit:
        text = text[: limit - 1] + "…"
    text = _MD_SPECIAL.sub(r"\\\1", text)
    # After escaping: every "(" from the page is "\(" by now, so "[.]" cannot form a link.
    return _TEXT_WWW.sub("www[.]", _TEXT_SCHEME.sub(r"\1xx\2://", text))


def _code(value: str, table: bool = False) -> str:
    text = " ".join(str(value).split())
    if table:
        text = text.replace("|", "\\|")
    return f"`` {text} ``" if "`" in text else f"`{text}`"


def _ioc(ioc: dict[str, Any], table: bool = False) -> str:
    return _code(defang(ioc["type"], ioc["value"]), table)


def _when(timestamp: str | None, date_only: bool = False) -> str:
    if not timestamp:
        return "?"
    try:
        moment = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError:
        return _text(timestamp)
    return moment.strftime("%Y-%m-%d" if date_only else "%Y-%m-%d %H:%M UTC")


def _plural(count: int, word: str) -> str:
    return f"{count} {word}{'' if count == 1 else 's'}"


# --------------------------------------------------------------------------
# Sections
# --------------------------------------------------------------------------


def _environment(report: dict[str, Any]) -> list[str]:
    """The headline: was any of this seen in the tenant's event logs?"""
    check = report.get("secops_check") or {}
    hunt = check.get("hunt") or {}
    status = check.get("status")
    if status in (None, "skipped") and not hunt:
        return ["> **SecOps was not checked** for this report."]
    if status == "not_configured":
        return [f"> **SecOps is not configured**, so the environment was not searched. "
                f"{_text(check.get('error'))}".rstrip()]
    if status == "failed" and not hunt:
        return [f"> **The SecOps check failed:** {_text(check.get('error'), 300)}",
                ">", "> Whether these indicators were seen is **not determined**."]
    if hunt.get("status") == "skipped":
        return ["> **The event-log search was turned off** (`SECOPS_HUNT_DAYS=0`); only the "
                "feed and entity lookups ran."]
    if hunt.get("status") == "failed":
        return [f"> **The event-log search failed:** {_text(hunt.get('error'), 300)}",
                ">", "> Whether these indicators were seen is **not determined**."]

    searched, seen = hunt.get("searched", 0), hunt.get("seen", 0)
    patterns, seen_patterns = hunt.get("patterns_searched", 0), len(hunt.get("seen_patterns") or [])
    window = (f"{_when(hunt.get('window_start'), True)} → {_when(hunt.get('window_end'), True)}")
    if seen or seen_patterns:
        found = [f"{seen} of {searched} indicators"] if seen else []
        if seen_patterns:
            found.append(f"{seen_patterns} of {patterns} redacted-URL "
                         f"{'pattern' if patterns == 1 else 'patterns'}")
        hosts = ", ".join(_code(a) for a in hunt.get("assets") or []) or "none logged"
        lines = [f"> 🚨 **{' and '.join(found)} {'was' if seen + seen_patterns == 1 else 'were'} "
                 "seen in your environment.**",
                 f"> Hosts involved: {hosts}. Details below."]
    else:
        also = (f" and {_plural(patterns, 'redacted-URL pattern')}" if patterns else "")
        lines = [f"> ✅ **No sightings.** None of the {searched} indicators{also} searched appear "
                 f"in your SecOps event logs ({window}: the last 7 days, extended to 30 days when "
                 "nothing was found)."]
    if hunt.get("status") == "partial":
        lines += [">", f"> ⚠️ Some searches failed, so the result is incomplete: "
                       f"{_text(hunt.get('error'), 300)}"]
    return lines


def _summary(report: dict[str, Any]) -> list[str]:
    iocs = report.get("iocs") or []
    check = report.get("secops_check") or {}
    hunt = check.get("hunt") or {}
    by_type = Counter(_TYPE_LABELS.get(i["type"], i["type"]) for i in iocs)
    rows = [("Indicators", f"{len(iocs)}" + (" — " + ", ".join(f"{n} {t}" for t, n in by_type.items())
                                             if by_type else ""))]
    if hunt and hunt.get("status") != "skipped":
        rows.append(("Seen in your event logs",
                     f"{hunt.get('seen', 0)} of {hunt.get('searched', 0)} searched · "
                     f"{_when(hunt.get('window_start'), True)} → {_when(hunt.get('window_end'), True)}"))
        if hunt.get("patterns_searched"):
            rows.append(("Redacted-URL patterns seen",
                         f"{len(hunt.get('seen_patterns') or [])} of {hunt['patterns_searched']} searched"))
    if check.get("status") not in (None, "skipped", "not_configured"):
        sightings = [i.get("secops") or {} for i in iocs]
        rows.append(("Threat-intel feed matches (7 days)", str(sum(bool(s.get("ioc_match")) for s in sightings))))
        rows.append(("Known to SecOps (SOAR entity)", str(sum(bool(s.get("entity_match")) for s in sightings))))
    rows.append(("SecOps check", _text(check.get("status") or "not run")))
    return ["| Check | Result |", "|---|---|"] + [f"| {k} | {v} |" for k, v in rows]


def _sighting_lines(title: str, sighting: dict[str, Any]) -> list[str]:
    events = sighting.get("events") or {}
    count = events.get("count", 0)
    more = " (more exist)" if events.get("more_available") else ""
    hosts = ", ".join(_code(a) for a in events.get("assets") or []) or "none logged"
    logged = ", ".join(_text(t) for t in events.get("log_types") or []) or "?"
    kinds = ", ".join(_text(t) for t in events.get("event_types") or [])
    lines = [title,
             f"- **Events:** {count}{more} · first {_when(events.get('first_seen'))} · "
             f"last {_when(events.get('last_seen'))} · within the last "
             f"{sighting.get('searched_days') or '?'} days",
             f"- **Hosts:** {hosts}",
             f"- **Logged by:** {logged}" + (f" · {kinds}" if kinds else "")]
    if events.get("urls"):
        lines.append("- **URLs requested:** "
                     + ", ".join(_code(defang("url", u)) for u in events["urls"]))
    if sighting.get("note"):
        lines.append(f"- **Note:** {_text(sighting['note'], 300)}")
    if sighting.get("udm_query"):
        lines.append(f"- **Pivot:** {_code(sighting['udm_query'])}")
    return lines + [""]


def _seen_details(iocs: list[dict[str, Any]], patterns: list[dict[str, Any]]) -> list[str]:
    seen = [i for i in iocs if (i.get("secops") or {}).get("seen_in_environment")]
    seen_patterns = [p for p in patterns if p.get("seen_in_environment")]
    if not seen and not seen_patterns:
        return []
    lines = ["", "### 🚨 Seen in your environment", ""]
    for ioc in seen:
        lines += _sighting_lines(f"#### {_ioc(ioc)} · {_TYPE_LABELS.get(ioc['type'], ioc['type'])}",
                                 ioc["secops"])
    for pattern in seen_patterns:
        lines += _sighting_lines(f"#### {_code(defang('url', pattern['pattern']))} · redacted-URL "
                                 "pattern", pattern)
    return lines


def _patterns(patterns: list[dict[str, Any]]) -> list[str]:
    if not patterns:
        return []
    lines = ["", f"### Pattern searches ({len(patterns)})", "",
             "The publisher withheld part of these URLs, so they are not indicators; the "
             "withheld part (`*`) was searched as a wildcard.", "",
             "| Pattern searched | On the page | Your environment |", "|---|---|---|"]
    for pattern in patterns:
        seen = pattern.get("seen_in_environment")
        if seen:
            where = f"🚨 **seen** · {_plural((pattern.get('events') or {}).get('count', 0), 'event')}"
        elif seen is False:
            where = f"not seen · {pattern.get('searched_days') or '?'} d"
        elif "failed" in (pattern.get("note") or ""):
            where = "⚠️ not determined"
        else:
            where = _text(pattern.get("note"), 60) or "not searched"
        page = _code(defang("url", pattern["source"]), table=True)
        lines.append(f"| {_code(defang('url', pattern['pattern']), table=True)} | {page} | {where} |")
    return lines


def _environment_cell(ioc: dict[str, Any]) -> str:
    sighting = ioc.get("secops")
    if not sighting:
        return "—"
    seen = sighting.get("seen_in_environment")
    if seen:
        return f"🚨 **seen** · {_plural((sighting.get('events') or {}).get('count', 0), 'event')}"
    if seen is False:
        return f"not seen · {sighting.get('searched_days') or '?'} d"
    note = sighting.get("note") or ""
    if "event search failed" in note:
        return "⚠️ not determined"
    if "turned off" in note or "budget" in note:
        return "not searched"
    if "not configured" in note:
        return "—"
    return "not searched"


def _secops_cell(ioc: dict[str, Any]) -> str:
    sighting = ioc.get("secops") or {}
    labels = []
    if sighting.get("ioc_match"):
        labels.append("**feed match**")
    if sighting.get("entity_match"):
        labels.append("known entity")
    note = sighting.get("note") or ""
    if "non-public" in note:
        labels.append("private address")
    elif "failed" in note:
        labels.append("⚠️ lookup failed")
    return ", ".join(labels) or "—"


_ACCEPTED = "accepted as extracted, at the suggested confidence"


def _why(ioc: dict[str, Any]) -> str:
    """The model's reason; without one (seen live: every keep sent without a reason),
    the page's own sentence, quoted, with the indicator itself elided."""
    reason = ioc.get("reason")
    if reason and reason != _ACCEPTED:
        return _text(reason, 90)
    context = " ".join((ioc.get("context") or "").split())
    for spelling in {ioc.get("raw_value"), ioc["value"]} - {None}:
        context = context.replace(spelling, "…")
    if not context.strip(" .…|"):
        return "—"
    # A list item: its context is the list's heading, "Indicators of Compromise | …".
    label, separator, rest = context.partition(" | ")
    if separator and rest.strip(" .") == "…":
        return f"listed under “{_text(label, 70)}”"
    # A long sentence: keep the part around the indicator, which says what it is.
    at = context.find("…")
    if len(context) > 90 and at > 60:
        start = context.find(" ", at - 55) + 1  # on a word boundary
        context = "…" + context[start if 0 < start < at else at - 55:]
    return f"“{_text(context, 90)}”"


def _indicators(iocs: list[dict[str, Any]]) -> list[str]:
    if not iocs:
        return ["", "### Indicators", "", "No indicators of compromise were found on the page."]
    lines = ["", f"### Indicators ({len(iocs)})", "",
             "| Type | Indicator | Confidence | Your environment | SecOps | Why |",
             "|---|---|---|---|---|---|"]
    for ioc in iocs:
        lines.append(f"| {_TYPE_LABELS.get(ioc['type'], ioc['type'])} | {_ioc(ioc, table=True)} | "
                     f"{ioc['confidence']} | {_environment_cell(ioc)} | {_secops_cell(ioc)} | "
                     f"{_why(ioc)} |")
    return lines


def _excluded(excluded: list[dict[str, Any]]) -> list[str]:
    if not excluded:
        return []
    lines = ["", f"### Excluded ({len(excluded)})", ""]
    for item in excluded[:_MAX_EXCLUDED]:
        lines.append(f"- {_ioc(item)} ({_TYPE_LABELS.get(item['type'], item['type'])}) — "
                     f"{_text(item.get('reason'), 140)}")
    if len(excluded) > _MAX_EXCLUDED:
        lines.append(f"- … and {len(excluded) - _MAX_EXCLUDED} more (see the JSON)")
    return lines


def _queries(iocs: list[dict[str, Any]], patterns: list[dict[str, Any]]) -> list[str]:
    rows = [(i["value"], (i.get("secops") or {}).get("udm_query")) for i in iocs]
    rows += [(f"pattern {p['pattern']}", p.get("udm_query")) for p in patterns]
    rows = [(value, query) for value, query in rows if query]
    if not rows:
        return []
    # A code block: not rendered, never linked, and ready to paste into SecOps.
    return ["", "### UDM queries for pivoting", "", "```text"] + [
        f"# {value.replace(chr(10), ' ')}\n{query.replace(chr(10), ' ')}" for value, query in rows
    ] + ["```"]


# --------------------------------------------------------------------------
# The report
# --------------------------------------------------------------------------


def render_markdown(report: dict[str, Any]) -> str:
    """The validated report (`IOCReport.model_dump(mode="json")`) as Markdown."""
    title = _text(report.get("page_title"), 140) or "IOC report"
    source = _code(report.get("source_url") or "")
    if report.get("extraction_status") == "failed":
        return "\n".join([
            "## IOC report: extraction failed", "",
            f"**Source:** {source}", "",
            f"**Error:** {_text(report.get('error'), 400)}", "",
            "No indicators were extracted, and SecOps was not checked.",
        ])

    iocs = report.get("iocs") or []
    patterns = report.get("pattern_searches") or []
    lines = [f"## {title}", "",
             f"**Source:** {source} · **Extraction:** {_text(report.get('extraction_status'))} · "
             f"**Generated:** {_when(report.get('generated_at'))}", "",
             "### Environment check", ""]
    lines += _environment(report)
    lines += [""] + _summary(report)
    lines += _seen_details(iocs, patterns)
    lines += _indicators(iocs)
    lines += _patterns(patterns)
    lines += _excluded(report.get("excluded") or [])
    if report.get("warnings"):
        lines += ["", "### Warnings", ""] + [f"- {_text(w, 300)}" for w in report["warnings"]]
    lines += _queries(iocs, patterns)
    lines += ["", "---",
              "_Indicators are defanged. The full JSON report (usable values, page context, "
              "every SecOps field) is in the session state under `ioc_report`._"]
    return "\n".join(lines)
