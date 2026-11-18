# IOC extraction agent for Google SecOps (Google ADK)

Give it a URL to a threat report. It fetches the page safely, extracts the
Indicators of Compromise, has the model classify them, checks them read-only
against your Google SecOps (Chronicle) tenant -- including a UDM search of your
event logs, so each IOC says whether it was **seen in your environment** and on
which hosts -- and replies with a readable report (validated JSON underneath).

```
you> Extract the IOCs from https://arcticwolf.com/resources/blog/php2shell-critical-php-vulnerabilities-enable-unauthenticated-remote-code-execution/

## PHP2Shell: Critical PHP Vulnerabilities Enable Unauthenticated Remote Code Execution
### Environment check
> ✅ No sightings. None of the 12 indicators searched appear in your SecOps event logs ...
| Type   | Indicator                      | Confidence | Your environment | SecOps       | Why |
| domain | `thunder[.]godofthunder[.]st`  | high       | not seen · 30 d  | known entity | ... |
```

Same stack as `investigationAgent`: Google ADK 2.5, LiteLLM (`SECOPS_MODEL`), and the
SecOps MCP server authenticated with a Google service-account key.

## Setup

```bash
uv venv --python 3.11 .venv
```

```bash
uv pip install --python .venv/Scripts/python.exe -r requirements.txt
```

```bash
cp ioc_extraction_agent/.env.example ioc_extraction_agent/.env
```

In `.env`, set `SECOPS_MODEL` and its key (e.g. `OPENROUTER_API_KEY`), and the four
`SECOPS_*` tenant values for the SecOps check (leave them empty to skip it).

For Google auth, point `SECOPS_CREDENTIALS_FILE` at a service-account key (JSON)
whose account has the Chronicle API viewer role on the tenant's project. Leave the
variable empty to fall back to Application Default Credentials instead:

```bash
gcloud auth application-default login
```

### Setting `SECOPS_CREDENTIALS_FILE`

The value is a file path, written **without quotes**, exactly as your OS spells it.
Either form works:

- **Absolute path** — the key lives anywhere on the machine (recommended; keeps it
  out of the project folder entirely).
- **Relative path** — taken from the project root (the folder holding `run.py`),
  no matter which directory you start `adk web`, `adk run` or `run.py` from. The
  name `secops-sa.json` is already in `.gitignore`, so `ioc_extraction_agent/secops-sa.json`
  can never be committed by accident.

`~` expands to your home directory, and `$VAR` (or `%VAR%` on Windows) to an
environment variable.

| OS | Example `.env` line |
|---|---|
| Windows, absolute | `SECOPS_CREDENTIALS_FILE=C:\Users\khanh\keys\secops-sa.json` |
| Windows, path with spaces | `SECOPS_CREDENTIALS_FILE=D:\Claude Projects\keys\secops-sa.json` |
| Windows, forward slashes (also fine) | `SECOPS_CREDENTIALS_FILE=C:/Users/khanh/keys/secops-sa.json` |
| Windows, home directory | `SECOPS_CREDENTIALS_FILE=%USERPROFILE%\keys\secops-sa.json` |
| macOS, absolute | `SECOPS_CREDENTIALS_FILE=/Users/khanh/keys/secops-sa.json` |
| macOS / Linux, home directory | `SECOPS_CREDENTIALS_FILE=~/keys/secops-sa.json` |
| Linux, absolute | `SECOPS_CREDENTIALS_FILE=/home/khanh/keys/secops-sa.json` |
| Linux, shared system location | `SECOPS_CREDENTIALS_FILE=/etc/secops/secops-sa.json` |
| Any OS, relative to the project | `SECOPS_CREDENTIALS_FILE=ioc_extraction_agent/secops-sa.json` |

Rules of thumb:

- **Do not wrap a Windows path in double quotes.** `.env` files process escape
  sequences inside `"..."`, so `"C:\temp\new\key.json"` turns `\t` into a tab and
  `\n` into a newline and the file is not found. Unquoted, or with forward slashes,
  backslashes are kept as typed. Spaces in an unquoted path are fine.
- **Single quotes are safe** on every OS (`'C:\temp\key.json'`) but unnecessary.
- **One path per machine.** `.env` is per-machine and never committed, so each
  developer or server points at its own copy of the key; the same `.env.example`
  serves all of them.
- **Lock the file down:** `chmod 600 ~/keys/secops-sa.json` on macOS / Linux; on
  Windows keep it under your own user profile, which other users cannot read.

To check the path resolves before running a report:

```bash
.venv/Scripts/python.exe -c "import ioc_extraction_agent, os; from ioc_extraction_agent.secops import resolve_credentials_path as r; p=r(os.environ['SECOPS_CREDENTIALS_FILE']); print(p, '->', 'found' if p.is_file() else 'NOT FOUND')"
```

(On macOS / Linux use `.venv/bin/python` instead of `.venv/Scripts/python.exe`. The
command imports the agent, and LiteLLM downloads its model price table on import, so
expect it to take up to a minute or two on a slow connection; it is not stuck.)

## Run

```bash
.venv/Scripts/adk.exe web --port 8000 .
```

```bash
.venv/Scripts/adk.exe run ioc_extraction_agent
```

```bash
.venv/Scripts/python.exe run.py https://example.com/threat-report --verbose
```

`adk web` and `adk run` reply with the readable Markdown report; the JSON is in the
session state (`ioc_report`, the State tab in `adk web`). Set `IOC_REPORT_FORMAT=json`
in `.env` to reply with the JSON instead. `run.py` prints only the JSON by default, so
`> report.json` and `| jq` work; `--format markdown` prints the readable report
(`--no-secops` skips the check, `--hunt-days N` limits the event-log search; exit code 1
means the extraction failed). Prompts: `Extract the IOCs from <url>` — defanged URLs
work — or `... but don't check them in SecOps`. For `adk web` / `adk run`, set
`SECOPS_HUNT_DAYS` in `.env`.

## How it works

One ADK `LlmAgent` (`agent.py`) calls three tools in one turn:

| Tool | What it does |
|---|---|
| `fetch_url` | One SSRF-guarded GET of the URL **from the user's message** (never a link on the page). Full text goes to session state; the model gets a fenced 20k-char excerpt. |
| `extract_iocs` | Regex extraction of 12 types from the stored text: refangs while keeping the page spelling, de-duplicates, quotes the context sentence, excludes documentation placeholders, flags probable noise with hints. |
| `submit_ioc_report` | The model's review by candidate id. Code builds the Pydantic `IOCReport`, verifies any model-added value is on the page, and runs the SecOps check. |

A `before_model_callback` then returns the validated report as the reply, rendered by
code (`tools/report_markdown.py`). The model never writes the report or retypes a hash,
and a successful turn is exactly three model calls.

**Fetching** (`tools/url_fetcher.py`): http/https only, no credentials in URLs, ports
80/443/8080/8443; internal names refused before DNS; **every** resolved address must
be public (no private, loopback, link-local, CGNAT, multicast, reserved or
cloud-metadata address, including IPv4 inside IPv6). The connection is pinned to the
validated IP with the real name in Host and SNI, which defeats DNS rebinding. Redirects
are re-validated, 3 at most; 30 s overall, 5 MB cap, no environment proxies or
cookies. HTML becomes text with scripts, styles, hidden elements and site navigation
removed (`<nav>`, navigation/menu roles, and lists whose id or class names a menu, such
as WordPress mega menus that list other articles' CVEs), and instruction-like text is
flagged in `warnings`.

**Extraction** (`tools/ioc_extractor.py`): `_STEPS` runs the types in order, masking
matches as it goes, so a URL's host isn't repeated as a domain and a file name isn't
read as a domain. The cap is 200 candidates, shared round-robin across types so an IP
table can't crowd out a CVE. A value alone on its line (a list item, a table cell) gets
the nearest heading above it as its context label, walking past the other values in
the list, so every item of an "Indicators of Compromise" list says so. Values with a
redaction marker and `Product/1.2.3.4` user-agent versions are flagged with hints.

**Review contract**: the model must decide every candidate that has hints, plus any
it rejects or re-grades. Unmentioned clean candidates are accepted at the suggested
confidence. Rejections land in `excluded` with a reason.

**SecOps** (`secops.py`) makes three kinds of read-only call, 4 in parallel. They are
the only tools allowed (the server also offers case, feed, parser and rule changes),
and code enforces that.

| Call | Per | Answers |
|---|---|---|
| `get_ioc_match` | report, last 7 days | `ioc_match`: your threat-intel feeds matched the value in your data |
| `search_entity` | searchable IOC (up to 60) | `entity_match`: SOAR knows the value (it answers `{}` for unknown ones); not a verdict |
| `udm_search` | huntable IOC (up to 40): last 7 days, then back to 30 only if nothing was found | `seen_in_environment`: the IOC's `udm_query` found events in your logs |

**The hunt** is what answers "did this touch us?". Each IOC's UDM query runs first over
the **last 7 days**. Only an IOC with no sighting there is searched further back, over
days 7–30 (the first week is not searched again), and the search **stops at 30 days**.
`searched_days` on each IOC says how far it went: 7 when the last week already had a
sighting, otherwise 30. `SECOPS_HUNT_DAYS` / `--hunt-days` can lower the limit (values
above 30 are capped; 0 turns the hunt off). Up to 50 events are kept per search. A
sighting lists `events.count` (a lower bound
when `more_available`), `first_seen` / `last_seen`, the `assets` involved (hostnames,
or addresses when no name is logged, never the IOC itself), and the event and log
types. `secops_check.hunt` rolls this up: `seen_iocs` and every asset, the triage
list. Private addresses and mutexes are not searched; a CVE sighting is a
vulnerability finding (exposure, not compromise) and says so. `seen_in_environment:
false` means the search ran and found nothing in the window *for the telemetry you
ingest* -- a hash only shows up if your EDR logs hashes.

**URLs are searched by regex**, because logs spell one URL many ways. The query accepts
`http`, `https` or no scheme, the default port written or not, a trailing slash, and a
query or fragment added when the IOC has none (a non-default port like `:8000` must
match); it also finds the path logged apart from its server (web server logs) on that
server's IP or hostname. Validated on the ghslab tenant: `http://…/terraform.tfstate/`
matched the logged `https://…/terraform.tfstate` and not `….tfstate.backup`.

**Redacted URLs become pattern searches.** A URL the publisher partly withheld
(`hxxp://92.118.112[.]100/REDACTED OFFENSIVE`) is never an IOC -- code moves it out of
the IOCs whatever the model decided -- but the known part is searched with the withheld
part as a wildcard: `http://92.118.112.100/*` is any path on that host, and
`/files/REDACTED.sh` becomes `/files/*.sh`. They are listed in `pattern_searches` with
the same 7-then-30-day search, and a sighting's `events.urls` shows the URL really
requested -- what the publisher withheld. A withheld host is not searched. Every
sighting (IOC or pattern) lists up to 5 such `urls`.

Only the user can turn the check off: `--no-secops`, or saying so in the prompt. A
`check_secops: false` from the model alone is overridden and noted in `warnings` (seen
live: the model skipped it for a plain "Extract the IOCs from <url>").

`null` anywhere means *not determined*, never "clean". An expired login stops the
check after one call; a refused UDM search (IAM) stops the hunt after the searches
already in flight. Every IOC carries its `udm_query` for pivoting by hand.

Limits (timeouts, caps, look-back, lookup budget) are constants at the top of
`url_fetcher.py`, `ioc_extractor.py` and `secops.py`.

## Output

**The reply** (Markdown) puts the verdict first: whether any IOC was seen in your
environment and on which hosts, then a summary table, a section per sighting (events,
first/last seen, hosts, where it was logged, the pivot query), the indicator table, the
exclusions with reasons, warnings, and every UDM query in a block ready to paste. Two
rules keep it safe in a chat window: indicators are **defanged** (`hxxp://evil[.]com`)
and set in code, so nothing becomes a clickable attacker link; and text from the page or
the model is **escaped**, so a hostile page cannot inject links, images or HTML.

**The JSON** (session state `ioc_report`, `run.py`, or `IOC_REPORT_FORMAT=json`):

```json
{
  "source_url": "https://blog.example-security.net/lantern",
  "extraction_status": "success",
  "total_iocs": 2,
  "iocs": [
    {
      "type": "url",
      "value": "https://update-cdn.top/gate.php",
      "context": "The loader beacons to hxxps://update-cdn[.]top/gate.php every 60 seconds.",
      "confidence": "high",
      "raw_value": "hxxps://update-cdn[.]top/gate.php",
      "reason": "C2 beacon URL",
      "secops": { "checked": true, "seen_in_environment": false, "ioc_match": false,
                  "entity_match": true, "searched_days": 30,
                  "udm_query": "target.url = \"https://update-cdn.top/gate.php\" nocase" }
    },
    {
      "type": "ipv4",
      "value": "45.77.120.11",
      "context": "Command and control traffic goes to 45.77.120.11.",
      "confidence": "high",
      "reason": "C2 server",
      "secops": { "checked": true, "seen_in_environment": true, "ioc_match": true,
                  "entity_match": false, "searched_days": 7,
                  "events": { "count": 3, "more_available": false,
                              "first_seen": "2026-10-30T08:14:02.118Z",
                              "last_seen": "2026-11-02T19:40:55.020Z",
                              "assets": ["WS-042.corp.example", "10.20.4.17"],
                              "event_types": ["NETWORK_CONNECTION"],
                              "log_types": ["WINDOWS_SYSMON", "PAN_FIREWALL"] },
                  "udm_query": "principal.ip = \"45.77.120.11\" or target.ip = \"45.77.120.11\" or src.ip = \"45.77.120.11\"" }
    }
  ],
  "excluded": [
    { "type": "domain", "value": "github.com", "reason": "reference link to the write-up" },
    { "type": "ipv4", "value": "192.0.2.10", "reason": "RFC 5737 documentation address" }
  ],
  "warnings": [],
  "secops_check": { "status": "completed", "window_start": "2026-10-28T12:00:00Z",
                    "window_end": "2026-11-04T12:00:00Z", "checked": 2, "matched": 2,
                    "hunt": { "status": "completed", "window_start": "2026-10-05T12:00:00Z",
                              "window_end": "2026-11-04T12:00:00Z",
                              "first_window_start": "2026-10-28T12:00:00Z", "searched": 2, "seen": 1,
                              "seen_iocs": ["45.77.120.11"],
                              "assets": ["WS-042.corp.example", "10.20.4.17"] } },
  "page_title": "Operation Lantern",
  "generated_at": "2026-11-04T12:00:05Z"
}
```

The first four keys are the required contract; the rest are additive. A failed
fetch returns `"extraction_status": "failed"` with the reason in `error`
(e.g. `blocked_url: ... resolves to 169.254.169.254 (cloud metadata endpoint)`).
The validated dict is also in session state at `ioc_report.report`.

## Layout

```
ioc_extraction_agent/
  __init__.py          loads .env, imports agent
  agent.py             root_agent, instruction, model
  state.py             session-state keys shared by the tools
  secops.py            read-only SecOps MCP client + the check
  schemas/ioc_schema.py  Pydantic output and review models
  tools/url_fetcher.py   fetch_url
  tools/ioc_extractor.py extract_iocs
  tools/report_builder.py submit_ioc_report + emit_final_report
  tools/report_markdown.py the readable report (defanged, escaped)
run.py                 one-shot CLI
tests/                 188 offline tests (no network, model or SecOps)
```

## Tests

```bash
.venv/Scripts/python.exe -m pytest
```

Covers the SSRF guards (every blocked address class, rebinding, redirects, caps), each
IOC type and the noise rules, the review step, SecOps parsing and failure modes, and
two complete ADK turns with a scripted model.

## Verified live (2026-11-04)

With `openrouter/z-ai/glm-4.7-flash` and the ghslab tenant, on The DFIR Report's
Gentlemen ransomware alert: 66 candidates, 58–59 IOCs kept, and three model calls.
End to end the run takes about 5.5 minutes on this machine (341 s and 340 s across
two runs); that covers startup and Google token refresh, and model latency is most
of it. The SecOps check ran in about 35 seconds: the report's 11 URLs and 11 domains
are known to the tenant, with no feed matches. Some sites refuse automated clients
(cisa.gov returned 403 after a few fetches); that is reported as `http_error`, not
worked around.
