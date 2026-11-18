"""Pydantic models: the report the agent returns (`IOCReport`), validated before it
is emitted, and the model's review input (`CandidateDecision`, `AdditionalIOC`),
which ADK turns into the tool's JSON schema.

`is_valid_ioc_value` is the one definition of "well-formed for this type", shared
by the extractor, the review step and the report validator.
"""

from __future__ import annotations

import ipaddress
import re
from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, Field, field_validator, model_validator

IOCType = Literal["ipv4", "ipv6", "domain", "url", "md5", "sha1", "sha256", "email",
                  "file_name", "cve", "mutex", "registry_key"]
Confidence = Literal["high", "medium", "low"]

_HEX = {"md5": 32, "sha1": 40, "sha256": 64}
_DOMAIN_RE = re.compile(
    r"^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}$", re.I
)
_EMAIL_RE = re.compile(r"^[a-z0-9][a-z0-9._%+-]{0,63}@[a-z0-9.-]+\.[a-z]{2,24}$", re.I)
_URL_RE = re.compile(r"^(?:https?|ftp)://[^\s/?#]+[^\s]*$", re.I)
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$")
_REGISTRY_RE = re.compile(
    r"^(?:HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT|HKEY_USERS|"
    r"HKEY_CURRENT_CONFIG|HKLM|HKCU|HKCR|HKU|HKCC):?\\.+",
    re.I,
)
_FILE_NAME_RE = re.compile(r"^[^\\/:*?\"<>|\r\n]{1,255}\.[a-z0-9]{1,8}$", re.I)


def is_valid_ioc_value(ioc_type: str, value: str) -> bool:
    """True when `value` is well-formed for `ioc_type`. Format only, not reputation."""
    if not value or value != value.strip() or len(value) > 2048:
        return False
    if ioc_type in _HEX:
        return len(value) == _HEX[ioc_type] and all(c in "0123456789abcdefABCDEF" for c in value)
    if ioc_type in ("ipv4", "ipv6"):
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            return False
        return address.version == (4 if ioc_type == "ipv4" else 6)
    if ioc_type == "domain":
        return bool(_DOMAIN_RE.match(value))
    if ioc_type == "email":
        return bool(_EMAIL_RE.match(value))
    if ioc_type == "url":
        return bool(_URL_RE.match(value))
    if ioc_type == "cve":
        return bool(_CVE_RE.match(value))
    if ioc_type == "registry_key":
        return bool(_REGISTRY_RE.match(value))
    if ioc_type == "file_name":
        return bool(_FILE_NAME_RE.match(value))
    if ioc_type == "mutex":
        return 3 <= len(value) <= 260 and not any(c.isspace() for c in value)
    return False


def dedupe_key(ioc_type: str, value: str) -> tuple[str, str]:
    """Identity of an IOC for de-duplication.

    Mutex names are case-sensitive on Windows, so they are compared exactly;
    everything else here is case-insensitive in practice.
    """
    return (ioc_type, value if ioc_type == "mutex" else value.lower())


# --------------------------------------------------------------------------
# Output
# --------------------------------------------------------------------------


class EventSightings(BaseModel):
    """What a UDM search of the tenant's event logs found for one IOC."""

    count: int = Field(ge=0, description="Events returned; a lower bound when more_available.")
    more_available: bool = Field(
        default=False, description="SecOps holds more events than were sampled; count, first_seen "
                                   "and last_seen describe the sample.")
    first_seen: str | None = None
    last_seen: str | None = None
    assets: list[str] = Field(
        default_factory=list,
        description="Hosts (or addresses, when no hostname is logged) in those events, other than "
                    "the IOC itself: the machines to investigate.")
    urls: list[str] = Field(default_factory=list,
                            description="URLs in those events (target.url): what was requested.")
    event_types: list[str] = Field(default_factory=list)
    log_types: list[str] = Field(default_factory=list, description="Where it was seen (DNS, proxy, EDR...).")


class SecOpsSighting(BaseModel):
    """What Google SecOps knows about one IOC, from the read-only check.

    `None` in a match field means "not determined" -- the call failed, was not
    made, or its answer could not be read. It never means "not seen".
    """

    checked: bool
    seen_in_environment: bool | None = Field(
        default=None,
        description="Found in the tenant's event logs by a UDM search over the hunt window "
                    "(udm_search). None: not searched, or the search failed.",
    )
    ioc_match: bool | None = Field(
        default=None,
        description="Matched by the tenant's own threat-intel feeds (get_ioc_match) in the window.",
    )
    entity_match: bool | None = Field(
        default=None,
        description="Known to SecOps as an entity (search_entity).",
    )
    searched_days: int | None = Field(
        default=None,
        description="Days of event logs searched for this IOC: 7 when the last week already "
                    "had a sighting, otherwise up to 30.")
    events: EventSightings | None = Field(
        default=None, description="The events the UDM search found, when it found any.")
    udm_query: str | None = Field(
        default=None, description="A UDM search to pivot into the raw events yourself."
    )
    note: str | None = None


class IOC(BaseModel):
    type: IOCType
    value: str = Field(min_length=1, description="Refanged value, original case kept.")
    context: str = Field(description="The sentence on the page where the value was found.")
    confidence: Confidence
    raw_value: str | None = Field(
        default=None,
        description="The value as written on the page, when that differs (defanged or normalised).",
    )
    reason: str | None = None
    secops: SecOpsSighting | None = None

    @model_validator(mode="after")
    def _value_matches_type(self) -> IOC:
        if not is_valid_ioc_value(self.type, self.value):
            raise ValueError(f"{self.value!r} is not a valid {self.type}")
        return self


class PatternSearch(BaseModel):
    """A URL the publisher partly redacted (`/REDACTED OFFENSIVE`): not an IOC, since its
    real value was withheld, but searched with the withheld part as a wildcard -- a
    sighting shows the URL that was really requested."""

    pattern: str = Field(description="The URL with the withheld part as `*`.")
    source: str = Field(description="The URL as extracted from the page.")
    raw_value: str | None = Field(default=None, description="The page's own spelling.")
    context: str = ""
    udm_query: str | None = None
    seen_in_environment: bool | None = None
    searched_days: int | None = None
    events: EventSightings | None = None
    note: str | None = None


class ExcludedCandidate(BaseModel):
    """A value that looked like an IOC and was left out, and why -- kept for audit."""

    type: IOCType
    value: str
    reason: str


class HuntSummary(BaseModel):
    """The UDM search of the tenant's event logs, across all IOCs."""

    status: Literal["completed", "partial", "failed", "skipped"]
    window_start: str | None = Field(
        default=None, description="The furthest back any IOC was searched (at most 30 days).")
    window_end: str | None = None
    first_window_start: str | None = Field(
        default=None, description="Start of the first search, the last 7 days; an IOC was "
                                  "searched further back only when that found nothing.")
    searched: int = Field(default=0, description="IOCs searched.")
    seen: int = Field(default=0, description="IOCs found in the event logs.")
    seen_iocs: list[str] = Field(default_factory=list, description="The values that were found.")
    patterns_searched: int = Field(default=0, description="Redacted-URL patterns searched.")
    seen_patterns: list[str] = Field(default_factory=list,
                                     description="The redacted-URL patterns that were found.")
    assets: list[str] = Field(default_factory=list,
                              description="Every host involved in those events: the triage list.")
    error: str | None = None


class SecOpsCheck(BaseModel):
    status: Literal["completed", "partial", "failed", "not_configured", "skipped"]
    window_start: str | None = None
    window_end: str | None = None
    checked: int = 0
    matched: int = 0
    hunt: HuntSummary | None = None
    error: str | None = None


class IOCReport(BaseModel):
    """The agent's answer. Field order is the order the JSON is printed in."""

    source_url: str
    extraction_status: Literal["success", "partial", "failed"]
    total_iocs: int = Field(ge=0)
    iocs: list[IOC] = Field(default_factory=list)
    excluded: list[ExcludedCandidate] = Field(default_factory=list)
    pattern_searches: list[PatternSearch] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    secops_check: SecOpsCheck | None = None
    error: str | None = None
    final_url: str | None = None
    page_title: str | None = None
    generated_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    )

    @model_validator(mode="after")
    def _consistent(self) -> IOCReport:
        if self.total_iocs != len(self.iocs):
            raise ValueError(f"total_iocs is {self.total_iocs} but {len(self.iocs)} IOCs are listed")
        seen: set[tuple[str, str]] = set()
        for ioc in self.iocs:
            key = dedupe_key(ioc.type, ioc.value)
            if key in seen:
                raise ValueError(f"duplicate IOC {ioc.type} {ioc.value!r}")
            seen.add(key)
        if self.extraction_status == "failed" and not self.error:
            raise ValueError("a failed extraction must say why in `error`")
        return self


# --------------------------------------------------------------------------
# Input: the model's review, as submit_ioc_report receives it
# --------------------------------------------------------------------------


class CandidateDecision(BaseModel):
    """The model's verdict on one candidate returned by extract_iocs."""

    id: str = Field(description="The candidate id from extract_iocs, e.g. 'c7'.")
    is_ioc: bool = Field(description="True to keep it as an IOC, false to exclude it.")
    confidence: Confidence | None = Field(
        default=None,
        description="How sure you are that it is a real IOC; omit to keep the suggested one.",
    )
    type: IOCType | None = Field(
        default=None, description="Only to correct a wrong type; omit to keep the extracted one."
    )
    reason: str = Field(default="", description="A few words on why. Required when is_ioc is false.")

    @field_validator("confidence", "type", mode="before")
    @classmethod
    def _lower(cls, value):
        # Models write "High" as readily as "high"; neither is worth a rejection.
        return value.strip().lower() if isinstance(value, str) else value

    @field_validator("reason", mode="before")
    @classmethod
    def _short(cls, value) -> str:
        return (value or "").strip()[:200]


class AdditionalIOC(BaseModel):
    """An IOC the extractor missed. Its value must appear verbatim on the page."""

    type: IOCType
    value: str = Field(description="Copied exactly as it appears on the page.")
    confidence: Confidence
    reason: str = Field(default="", description="A few words on why it is an IOC.")

    @field_validator("confidence", "type", mode="before")
    @classmethod
    def _lower(cls, value):
        return value.strip().lower() if isinstance(value, str) else value

    @field_validator("value", "reason", mode="before")
    @classmethod
    def _strip(cls, value) -> str:
        return (value or "").strip()
