"""Run the IOC extraction agent once from the command line and print its JSON report.

    python run.py https://example.com/threat-report
    python run.py https://example.com/threat-report --no-secops
    python run.py https://example.com/threat-report --hunt-days 7
    python run.py https://example.com/threat-report --format markdown
    python run.py https://example.com/threat-report --verbose

The same agent `adk web` serves, run through ADK's in-memory runner. The report
is read from session state, where it was stored after validation, so what is
printed is the validated report even if the reply text were ever altered.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import json
import logging
import os
import sys

from google.adk.runners import InMemoryRunner
from google.genai import types

from ioc_extraction_agent import state
from ioc_extraction_agent.agent import root_agent
from ioc_extraction_agent.tools.report_markdown import render_markdown

APP_NAME = "ioc_extraction_agent"


async def extract(url: str, check_secops: bool) -> dict | None:
    runner = InMemoryRunner(agent=root_agent, app_name=APP_NAME)
    session = await runner.session_service.create_session(
        app_name=APP_NAME, user_id="cli", state={state.SECOPS_CHECK: check_secops}
    )
    message = types.Content(role="user", parts=[types.Part(text=f"Extract the IOCs from {url}")])
    reply = ""
    async for event in runner.run_async(user_id="cli", session_id=session.id, new_message=message):
        if event.is_final_response() and event.content and event.content.parts:
            reply = "".join(part.text or "" for part in event.content.parts)

    session = await runner.session_service.get_session(
        app_name=APP_NAME, user_id="cli", session_id=session.id
    )
    stored = session.state.get(state.REPORT) if session else None
    if stored:
        return stored["report"]
    # No report means the agent answered in prose (no URL, an off-topic request).
    print(reply or "The agent returned no report.", file=sys.stderr)
    return None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("url", help="http(s) URL of the page to analyse")
    parser.add_argument("--no-secops", action="store_true", help="skip the Google SecOps check")
    parser.add_argument("--hunt-days", type=int, metavar="N",
                        help="how far back to search the SecOps event logs for each IOC: the "
                             "last 7 days first, further back only if nothing was found "
                             "(default: SECOPS_HUNT_DAYS, else 30; at most 30; 0 skips it)")
    parser.add_argument("--format", choices=("json", "markdown"), default="json",
                        help="json (default; for > report.json or | jq) or a readable Markdown "
                             "report, as the agent replies in adk web")
    parser.add_argument("--verbose", action="store_true", help="log tool activity to stderr")
    args = parser.parse_args()
    if args.hunt_days is not None:
        if args.hunt_days < 0:
            parser.error("--hunt-days must be 0 or more")
        os.environ["SECOPS_HUNT_DAYS"] = str(args.hunt_days)

    logging.basicConfig(level=logging.INFO if args.verbose else logging.WARNING,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
                        datefmt="%H:%M:%S", stream=sys.stderr)
    # LiteLLM prints banners and its own log lines to stdout. Keep stdout for the
    # JSON alone, so `run.py <url> > report.json` and `| jq` work.
    with contextlib.redirect_stdout(sys.stderr):
        report = asyncio.run(extract(args.url, check_secops=not args.no_secops))
    if report is None:
        return 2
    print(render_markdown(report) if args.format == "markdown"
          else json.dumps(report, indent=2, ensure_ascii=False))
    return 1 if report.get("extraction_status") == "failed" else 0


if __name__ == "__main__":
    sys.exit(main())
