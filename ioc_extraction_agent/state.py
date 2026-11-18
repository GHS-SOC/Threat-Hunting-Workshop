"""Session-state keys the tools share, stamped with the invocation (user turn) that
wrote them, so a later turn never picks up an earlier page or report."""

from __future__ import annotations

from typing import Any

PAGE = "temp:ioc_page"              # the fetched page; `temp:` is never persisted
CANDIDATES = "temp:ioc_candidates"  # what extract_iocs found
REPORT = "ioc_report"               # the finished, validated report (persisted)
SECOPS_CHECK = "ioc_secops_check"   # False in a session's state skips the SecOps check


def put(context: Any, key: str, value: dict[str, Any]) -> None:
    context.state[key] = {"invocation_id": context.invocation_id, **value}


def current(context: Any, key: str) -> dict[str, Any] | None:
    """The entry under `key` if THIS invocation wrote it, else None."""
    entry = context.state.get(key)
    if isinstance(entry, dict) and entry.get("invocation_id") == context.invocation_id:
        return entry
    return None
