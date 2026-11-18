"""The review step (`submit_ioc_report`) and the callback that makes the validated
report the agent's answer.

The model decides by candidate *id*; values and contexts come from the
extractor's record in session state, and anything the model adds is accepted
only if it is found on the page. `emit_final_report` then answers the next model
call with the report's JSON, so the model never writes (or alters) the JSON.
"""

from __future__ import annotations

import json
import logging
import os
import re
from typing import Any

from google.adk.models import LlmResponse
from google.adk.tools import ToolContext
from google.genai import types
from pydantic import ValidationError

from .. import secops, state
from ..schemas import (
    IOC,
    AdditionalIOC,
    CandidateDecision,
    ExcludedCandidate,
    IOCReport,
    PatternSearch,
    SecOpsCheck,
    dedupe_key,
    is_valid_ioc_value,
)
from .ioc_extractor import locate, refang
from .report_markdown import render_markdown

logger = logging.getLogger(__name__)

_MAX_REASON = 200
# Skipping SecOps is the user's decision, not the model's: seen live, the model sent
# check_secops=false to "Extract the IOCs from <url>" and the hunt silently did not run.
_SKIP_SECOPS = re.compile(
    r"\b(?:don'?t|do\s+not|without|skip|no|never)\b(?!\s+(?:forget|fail|miss))[^.?!\n]{0,40}?"
    r"\b(?:secops|chronicle|siem|check(?:s|ing)?|look(?:ing)?\s+(?:them\s+|it\s+)?up|lookups?|"
    r"hunt(?:s|ing)?|search(?:es|ing)?)\b",
    re.IGNORECASE,
)
_URL_TOKEN = re.compile(r"\S*://\S*")


def user_asked_to_skip_secops(content: Any) -> bool:
    """Whether the user's own message asks not to check SecOps. URLs are removed
    first, so a path like /no-more-checks/ cannot read as a request."""
    text = " ".join(getattr(part, "text", None) or ""
                    for part in getattr(content, "parts", None) or [])
    return bool(_SKIP_SECOPS.search(_URL_TOKEN.sub(" ", refang(text)[0])))


def _store(context: Any, report: IOCReport) -> dict[str, Any]:
    payload = report.model_dump(mode="json", exclude_none=True)
    state.put(context, state.REPORT, {"report": payload})
    return payload


def record_failure(tool_context: Any, source_url: str, error: str) -> None:
    """Record a failed extraction as this turn's report, so the answer is still JSON."""
    _store(tool_context, IOCReport(
        source_url=source_url,
        extraction_status="failed",
        total_iocs=0,
        error=error,
        secops_check=SecOpsCheck(status="skipped"),
    ))


def submit_ioc_report(
    decisions: list[CandidateDecision],
    tool_context: ToolContext,
    additions: list[AdditionalIOC] | None = None,
    check_secops: bool = True,
) -> dict[str, Any]:
    """Submit your review of the candidates and produce the final IOC report.

    Call this once, after extract_iocs. The report is built from your decisions,
    validated, checked against Google SecOps (read-only: threat-intel feed
    matches, entity lookups, and a UDM search of the tenant's event logs for
    each IOC), and returned to the user as JSON exactly as built -- you do not
    write the report yourself.

    Args:
        decisions: Your verdicts, by candidate id from extract_iocs: whether
            it is an IOC, your confidence, an optional corrected type, and a
            short reason. Required for every candidate that has hints; for the
            others, only to exclude one or change its confidence or type. A
            candidate without hints that you leave out is accepted at its
            suggested_confidence; one with hints that you leave out is excluded.
        additions: IOCs the extractor missed, typically mutexes, registry keys
            or file names. Each value must be copied exactly from the page; a
            value that is not on the page is rejected.
        check_secops: Look the IOCs up in Google SecOps and search its event
            logs for them. Leave it true; false only if the user's message asks
            not to check SecOps (the system verifies that against the message).

    Returns:
        A short receipt: `status`, `total_iocs`, `secops_check`. On failure,
        `error`.
    """
    page = state.current(tool_context, state.PAGE)
    extracted = state.current(tool_context, state.CANDIDATES)
    if page is None:
        return {"error": "No page has been fetched for this request. Call fetch_url first.",
                "error_type": "no_page"}
    if extracted is None:
        return {"error": "Call extract_iocs before submitting a report.",
                "error_type": "no_candidates"}
    if state.current(tool_context, state.REPORT) is not None:
        return {"error": "The report for this request has already been submitted.",
                "error_type": "already_submitted"}

    decisions, problems = _coerce(decisions, CandidateDecision, "decision")
    additions, more = _coerce(additions or [], AdditionalIOC, "addition")
    report = build_report(page, extracted, decisions, additions, warnings=problems + more)
    allowed = tool_context.state.get(state.SECOPS_CHECK, True) is not False
    user_skip = user_asked_to_skip_secops(getattr(tool_context, "user_content", None))
    if not check_secops and not user_skip and allowed:
        logger.warning("[report] the model asked to skip SecOps; the user did not -- checking")
        report.warnings.append("the model asked to skip the SecOps check, but the user's message "
                               "did not ask for that; the check ran")
    if allowed and not user_skip:
        client, unavailable = secops.default_client()
        report.secops_check = secops.check_iocs(report.iocs, client=client, unavailable=unavailable,
                                                patterns=report.pattern_searches)
    else:
        for ioc in report.iocs:
            ioc.secops = None
        for pattern in report.pattern_searches:
            pattern.udm_query = secops.udm_query("url", pattern.source)
        report.secops_check = SecOpsCheck(status="skipped")
    report = IOCReport.model_validate(report.model_dump())

    payload = _store(tool_context, report)
    hunt = report.secops_check.hunt
    logger.info("[report] %s: %d IOCs, %d excluded, SecOps %s, seen in the event logs: %s",
                report.extraction_status, report.total_iocs, len(report.excluded),
                report.secops_check.status, hunt.seen if hunt else "not searched")
    receipt = {"status": "report_ready", "total_iocs": payload["total_iocs"],
               "secops_check": payload["secops_check"]["status"]}
    if hunt is not None:
        receipt["seen_in_environment"] = hunt.seen
    return receipt


def _coerce(items: list[Any], model: type, label: str) -> tuple[list[Any], list[str]]:
    """Validate each item on its own: one malformed entry costs that entry only.

    ADK converts a tool argument to Pydantic models only when every item in the
    list validates, and not at all for an optional list; otherwise the tool
    receives raw dicts. So the conversion is done here, item by item.
    """
    valid, problems = [], []
    for number, item in enumerate(items or [], start=1):
        if isinstance(item, model):
            valid.append(item)
            continue
        try:
            valid.append(model.model_validate(item))
        except ValidationError as exc:
            first = exc.errors()[0]
            where = ".".join(str(part) for part in first["loc"]) or "value"
            got = repr(first.get("input"))[:60] if "input" in first else "missing"
            problems.append(f"{label} {number} ignored: {where} {got} -- {first['msg'][:70]}")
    return valid, problems


def build_report(page: dict[str, Any], extracted: dict[str, Any],
                 decisions: list[CandidateDecision],
                 additions: list[AdditionalIOC],
                 warnings: list[str] | None = None) -> IOCReport:
    """Turn the extractor's candidates and the model's review into a report."""
    candidates = {c["id"]: c for c in extracted["candidates"]}
    by_id: dict[str, CandidateDecision] = {}
    warnings = list(warnings or [])
    for decision in decisions:
        if decision.id not in candidates:
            warnings.append(f"review referred to unknown candidate id {decision.id!r}; ignored")
        elif decision.id in by_id:
            warnings.append(f"candidate {decision.id} was reviewed twice; the first decision was used")
        else:
            by_id[decision.id] = decision

    iocs: list[IOC] = []
    excluded: list[ExcludedCandidate] = []
    seen: set[tuple[str, str]] = set()

    def keep(ioc: IOC) -> None:
        key = dedupe_key(ioc.type, ioc.value)
        if key not in seen:
            seen.add(key)
            iocs.append(ioc)

    for candidate in extracted["candidates"]:
        decision = by_id.get(candidate["id"])
        ioc_type = candidate["type"]
        if decision is None:
            # Not mentioned: accepted unless the extractor flagged it, since a
            # flagged candidate is one the model was required to decide.
            if candidate["hints"]:
                excluded.append(ExcludedCandidate(
                    type=ioc_type, value=candidate["value"],
                    reason="not reviewed; flagged: " + "; ".join(candidate["hints"]),
                ))
                continue
            keep(_ioc(candidate, ioc_type, candidate["confidence"],
                      "accepted as extracted, at the suggested confidence"))
            continue
        if not decision.is_ioc:
            excluded.append(ExcludedCandidate(
                type=ioc_type, value=candidate["value"],
                reason=decision.reason or "judged not to be an IOC",
            ))
            continue
        if decision.type and decision.type != ioc_type:
            if is_valid_ioc_value(decision.type, candidate["value"]):
                ioc_type = decision.type
            else:
                warnings.append(f"{candidate['id']}: {candidate['value']!r} is not a valid "
                                f"{decision.type}; kept as {ioc_type}")
        keep(_ioc(candidate, ioc_type, decision.confidence or candidate["confidence"],
                  decision.reason or None))

    # Additions are for values the extractor missed. One it found was decided in the
    # review: seen live, the model excluded 130.0.0.0 (a user-agent version) and
    # re-added it as an IOC in the same call -- the decision on the candidate stands.
    reviewed = {dedupe_key(c["type"], c["value"]) for c in extracted["candidates"]}
    reviewed |= {dedupe_key(p["type"], p["value"]) for p in extracted["placeholders"]}
    for addition in additions:
        # Copied from the page, an addition may be defanged (hxxp://a[.]b): refang it,
        # and drop it quietly when it only repeats an IOC already kept.
        refanged = refang(addition.value)[0]
        if refanged != addition.value and is_valid_ioc_value(addition.type, refanged):
            addition = addition.model_copy(update={"value": refanged})
        key = dedupe_key(addition.type, addition.value)
        if key in seen:
            continue
        if key in reviewed:
            warnings.append(f"addition {addition.value[:80]!r} ({addition.type}) repeats a candidate "
                            "the review already decided; that decision stands")
            continue
        if not is_valid_ioc_value(addition.type, addition.value):
            excluded.append(ExcludedCandidate(
                type=addition.type, value=addition.value[:200],
                reason=f"proposed by the model but not a valid {addition.type}",
            ))
            continue
        found = locate(page["text"], addition.type, addition.value)
        if found is None:
            excluded.append(ExcludedCandidate(
                type=addition.type, value=addition.value[:200],
                reason="proposed by the model but not found on the page",
            ))
            continue
        context, raw = found
        keep(IOC(type=addition.type, value=addition.value, context=context,
                 confidence=addition.confidence, raw_value=raw,
                 reason=(addition.reason or "added by the model")[:_MAX_REASON]))

    for placeholder in extracted["placeholders"]:
        excluded.append(ExcludedCandidate(type=placeholder["type"], value=placeholder["value"],
                                          reason=placeholder["placeholder"]))
    iocs, excluded, patterns = _redacted_urls(extracted, iocs, excluded)

    partial = False
    if page.get("truncated"):
        partial = True
        warnings.append("the page was larger than the retrieval limit; only the first part "
                        "was analysed")
    if extracted.get("truncated"):
        partial = True
        total = sum(extracted["counts"].values())
        warnings.append(f"{total} candidates were found but only the first "
                        f"{len(extracted['candidates'])} were reviewed")
    if page.get("injection_indicators"):
        warnings.append("the page contains instruction-like text, treated as data: "
                        + "; ".join(f'"{s[:60]}"' for s in page["injection_indicators"]))

    return IOCReport(
        source_url=page["source_url"],
        final_url=page["final_url"] if page["final_url"] != page["source_url"] else None,
        page_title=page.get("title") or None,
        extraction_status="partial" if partial else "success",
        total_iocs=len(iocs),
        iocs=iocs,
        excluded=excluded,
        pattern_searches=patterns,
        warnings=warnings,
    )


_PATTERN_REASON = ("the publisher redacted part of this URL; the withheld part is searched as "
                   "a wildcard (see pattern_searches)")


def _redacted_urls(extracted: dict[str, Any], iocs: list[IOC], excluded: list[ExcludedCandidate],
                   ) -> tuple[list[IOC], list[ExcludedCandidate], list[PatternSearch]]:
    """Redacted URLs out of the IOCs and into pattern searches, whatever the model decided.

    `http://1.2.3.4/REDACTED` is not the attacker's URL -- its real value was withheld
    -- so it is never an IOC; but the part that is known is still worth a search.
    """
    found: dict[str, PatternSearch] = {}
    sources = ([(c["value"], c.get("raw_value"), c["context"]) for c in extracted["candidates"]
                if c["type"] == "url"]
               + [(i.value, i.raw_value, i.context) for i in iocs if i.type == "url"])
    for value, raw, context in sources:
        if secops.REDACTION.search(value):
            found.setdefault(value.lower(), PatternSearch(
                pattern=secops.redaction_pattern(value), source=value, raw_value=raw,
                context=context))
    if not found:
        return iocs, excluded, []
    iocs = [i for i in iocs if not (i.type == "url" and i.value.lower() in found)]
    excluded = [e for e in excluded if not (e.type == "url" and e.value.lower() in found)]
    excluded += [ExcludedCandidate(type="url", value=p.source, reason=_PATTERN_REASON)
                 for p in found.values()]
    return iocs, excluded, list(found.values())


def _ioc(candidate: dict[str, Any], ioc_type: str, confidence: str, reason: str | None) -> IOC:
    return IOC(
        type=ioc_type,
        value=candidate["value"],
        context=candidate["context"],
        confidence=confidence,
        raw_value=candidate.get("raw_value"),
        reason=reason[:_MAX_REASON] if reason else None,
    )


def report_format() -> str:
    """How the reply shows the report: `markdown` (default, for people) or `json`
    (IOC_REPORT_FORMAT=json, for a program reading the agent's answer)."""
    return "json" if os.environ.get("IOC_REPORT_FORMAT", "").strip().lower() == "json" else "markdown"


def emit_final_report(callback_context: Any, llm_request: Any) -> LlmResponse | None:
    """Before-model callback: once this turn has a report, it IS the answer.

    Returning a response here skips the model call, so the user receives the
    validated report rendered by code -- Markdown, or the JSON byte for byte --
    and the turn ends without another model call. The JSON is always in state.
    """
    entry = state.current(callback_context, state.REPORT)
    if entry is None:
        return None
    report = entry["report"]
    text = (json.dumps(report, indent=2, ensure_ascii=False) if report_format() == "json"
            else render_markdown(report))
    return LlmResponse(content=types.Content(role="model", parts=[types.Part(text=text)]))
