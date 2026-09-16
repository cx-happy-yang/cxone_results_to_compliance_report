# cxone-pci-report

Consolidate Checkmarx One scan results from multiple scanners — **SAST**,
**SCA**, **IaC Security (KICS)** and **API Security** — for the projects you
choose, and generate a customized **application security assessment PDF
report** that maps findings to **PCI DSS v4.0.1** requirements as
supporting evidence (English) with
[reportlab](https://www.reportlab.com/).

The report frames findings as **gap evidence** for PCI requirements, not as
a compliance certification. Requirement texts are paraphrased; PCI SSC is
the authoritative source.

## Features

- Uses [CheckmarxPythonSDK](https://github.com/checkmarx-ts/checkmarx-python-sdk) (`checkmarxpythonsdk==1.9.1`) to pull results per scanner:
  - SAST via `sast-results` (query name, CWE, PCI compliance tags, file/line)
  - SCA via the SCA risk-reports endpoint (CVE, CVSS, package, fix version)
  - IaC/KICS via `kics-results` (query name, file, expected/actual value)
  - API Security via the APISec risks endpoint (risk name, asset)
- Client-side filtering: result state/status (SAST/KICS/APISec), severity
  floor, SCA "ignored" flag, and per-project dedupe by similarity id.
  Everything excluded is counted and shown in the report.
- Rule engine maps findings to PCI DSS v4.0.1 requirements
  (6.2.1–6.2.4, 6.3.1–6.3.3, 6.4.1–6.4.3, 6.5.1–6.5.6, 11.3.1–11.3.3) using
  query-name/CWE/CVE/package patterns; CVSS ≥ 9.0 findings are escalated to
  6.5.6; unmatched findings fall back to 6.3.1. A JSON overlay file can add,
  replace or remove rules without touching code. Requirements 6.2.2
  (training), 6.4.3 (payment-page scripts), 11.3.2 (ASV scans) and 11.3.3
  (penetration testing) cannot be evidenced by scan tools and are listed in
  the report as outside tool-based evidence.
- Customizable PDF: company/logo/colors, cover page, document control,
  auto-generated table of contents, executive summary with charts and a
  per-requirement status summary (GAPS IDENTIFIED / WATCH / NO FINDINGS /
  NOT COVERED — gap indications, not a compliance verdict), methodology
  (scan inventory + filters + scope exclusions), per-requirement mapping
  with the same indicators, detailed
  findings appendix, and a tool-information page. The Checkmarx corporate
  logo is drawn at the top of every page; set `report.logo_path` to show
  your own logo centered on the cover.
- `--demo` mode generates a realistic report from bundled synthetic data —
  no API access needed. Great for testing layout changes or showing the
  format to auditors.

## Install

```powershell
python -m venv .venv
.venv\Scripts\pip install -e ".[test]"
```

Requires Python ≥ 3.14. Fonts: the report uses Microsoft YaHei when
available (Latin + CJK), otherwise Arial, otherwise reportlab's bundled
Vera — no extra font packages needed.

### Prebuilt binaries

Self-contained executables (no Python required) are attached to every
[GitHub Release](https://github.com/cx-happy-yang/cxone_results_to_compliance_report/releases):

| Platform                | Binary |
| ----------------------- | ------ |
| Windows (x64)           | `cxone-pci-report-<version>-windows-x64.exe` |
| macOS (Apple Silicon)   | `cxone-pci-report-<version>-macos-arm64` |
| Linux (x64)             | `cxone-pci-report-<version>-linux-x64` |

Platform notes for first run: Windows may show SmartScreen on the unsigned
exe (choose "More info → Run anyway"); macOS downloads need
`xattr -dr com.apple.quarantine <binary>`; on Linux `chmod +x <binary>`
first. Verify a download with `<binary> --demo --output smoke.pdf`
(offline, no API access).

To build one yourself (from the repo root):

```powershell
.venv\Scripts\pip install ".[build]"
.venv\Scripts\python build_binaries.py   # binary lands in dist\
```

Cutting a release: bump `__version__` in `cxone_pci_report/__init__.py`
(the package and `pyproject.toml` both read it from there), commit, then
tag and push — the `release` workflow builds all three binaries, checks
that the tag matches the version, and attaches them to the release:

```powershell
git tag v0.1.1
git push origin v0.1.1
```

## Authentication (delegated to the SDK)

The tool uses the standard CheckmarxPythonSDK configuration; it does not
handle credentials itself. In precedence order the SDK reads:

1. CLI option `--checkmarx_config_path` (passed through by the SDK)
2. Environment variable `checkmarx_config_path` (path to a config file)
3. `~/.Checkmarx/config.ini` with a `[CxOne]` section
4. `cxone_*` environment variables (`cxone_server`, `cxone_tenant_name`,
   `cxone_refresh_token`, …)

Example `~/.Checkmarx/config.ini`:

```ini
[CxOne]
access_control_url = https://iam.checkmarx.net
server = https://ast.checkmarx.net
tenant_name = your-tenant-name
grant_type = refresh_token
client_id = ast-app
refresh_token = your-api-key
```

(For `client_credentials` grant, configure a client with roles such as
`ast-scanner` / `ast-viewer` instead.)

## Usage

```powershell
# Real run against your tenant
.venv\Scripts\cxone-pci-report --config report_config.json --verbose

# Offline demo report from synthetic data
.venv\Scripts\cxone-pci-report --demo

# Override the output path and use a different config
.venv\Scripts\cxone-pci-report --config demo_config.example.json --demo --output out\demo.pdf

# Or as a module
.venv\Scripts\python -m cxone_pci_report --demo
```

## Configuration

See [`report_config.example.json`](report_config.example.json) for a fully
annotated example. Highlights:

- `projects`: list of objects with exactly one of `name` (resolved via the
  projects API) or `id`. Optional `display_name`, `branch`, and `scan_id`
  (override that skips latest-scan resolution).
- `filters.states` defaults to `TO_VERIFY, CONFIRMED, URGENT` (excludes
  `NOT_EXPLOITABLE`/`PROPOSED_NOT_EXPLOITABLE`); `filters.statuses` defaults
  to `NEW, RECURRENT` (excludes `FIXED`). State/status filters apply to
  SAST/KICS/APISec — the SCA endpoint does not expose CxOne triage state,
  so SCA is filtered by its "ignored" flag only (documented in the report).
- `mapping.rules_override_path`: JSON file with rule actions, e.g.:

  ```json
  [
    { "action": "add", "rule": {
        "rule_id": "custom-sql", "requirement": "6.5.6",
        "scanners": ["sast"], "match_type": "query_name_regex",
        "pattern": "SQL_Injection", "priority": 5 } },
    { "action": "replace", "rule": {
        "rule_id": "kics-iam", "requirement": "11.3.1",
        "scanners": ["kics"], "match_type": "kics_query_name_regex",
        "pattern": "IAM.*(policy|user)", "priority": 10 } },
    { "action": "remove", "rule_id": "sca-log4shell" }
  ]
  ```

  Valid `match_type`s: `query_name_regex`, `kics_query_name_regex`,
  `apisec_risk_type`, `cwe`, `cve_regex`, `package_regex`,
  `description_regex`.
- `appearance`: primary/accent/table colors plus indicator colors.

## Copilot integration (MCP server)

The package ships an MCP server exposing the report pipeline as tools that
GitHub Copilot (VS Code, Copilot CLI, github.com chat) and other MCP
clients can call — Copilot invokes the real pipeline instead of
reimplementing the PDF logic. Tools:

- `generate_pci_report` — real run from a config object (schema:
  `report_config.example.json`). Credentials are never part of the config;
  the server host's SDK configuration is used.
- `generate_demo_report` — offline demo PDF from synthetic data.
- `validate_report_config` — validate a config object without fetching.

### Step 1 — Install the MCP server

Install the `mcp` extra into the venv:

```powershell
python -m venv .venv
.venv\Scripts\pip install -e ".[mcp]"
```

The server runs with the credentials of the host it runs on, so install it
on the machine that has your CxOne SDK configuration (see
[Authentication](#authentication-delegated-to-the-sdk)).

### Step 2 — Connect your MCP client

Local use (VS Code Copilot, Copilot CLI) — stdio server; create
`.vscode/mcp.json` in the workspace:

```json
{"servers": {"cxone-pci-report": {"type": "stdio",
    "command": ".venv\\Scripts\\cxone-pci-report-mcp"}}}
```

VS Code then shows the `cxone-pci-report` server with its three tools in
the Copilot chat view; restart the chat window if it does not appear.

Remote use (Copilot Chat on github.com / cloud agent) — run the server
with the streamable-HTTP transport on a host that can reach CxOne, behind
your own auth (OAuth or token) since the endpoint writes PDFs and proxies
CxOne API calls:

```powershell
.venv\Scripts\cxone-pci-report-mcp --http --host 0.0.0.0 --port 8000
```

The org admin adds it to the org's MCP servers in Copilot Chat
(Copilot Business/Enterprise must have the MCP servers policy enabled),
pointing at the URL above (default path `/mcp`). Set `PCI_REPORT_BASE_URL`
(e.g. `https://reports.example.com/pdf`) on the server so the tools return
a download URL instead of a server-local path.

### Step 3 — Generate the PDF report from Copilot

1. **Demo first** — ask for a report from synthetic data to confirm the
   format, e.g.:

   > Generate the demo PCI report.

   Copilot calls `generate_demo_report`; the PDF lands at
   `out/demo_report.pdf` next to where the server runs (or at the URL from
   `PCI_REPORT_BASE_URL`).

2. **Validate your config** — paste your real config (same schema as
   `report_config.example.json`, minus `output` if you want the default
   path):

   > Validate this config: { ... }

   `validate_report_config` checks it without fetching anything. Note that
   `logo_path` / `rules_override_path` in the config resolve **on the
   server host**.

3. **Live run** — ask Copilot to generate the report with the same config:

   > Generate the PCI report with this config: { ... }

   Copilot calls `generate_pci_report`, which pulls your Checkmarx One
   scans and writes the PDF to the config's `output.pdf_path` on the
   server host (or to the `output` argument you give Copilot). The reply
   includes the path or download URL of the finished report.

For developers using Copilot in this repo itself, `AGENTS.md`,
`.github/copilot-instructions.md` and the `pci-report` custom agent
(`.github/agents/pci-report.md`) teach Copilot to run the CLI directly.

## Development

```powershell
.venv\Scripts\python -m pytest
```

Layout: `cxone_pci_report/sdk_client.py` is the only module that imports
CheckmarxPythonSDK; `normalize.py` turns per-scanner payloads into a common
`Finding`; `pci_map.py` is the rule engine; `report/` renders the PDF.

## Disclaimer

This tool and its output are not affiliated with or endorsed by the PCI
Security Standards Council. The report is supporting evidence for internal
review — it is not a PCI DSS compliance assessment and does not replace a
report from a Qualified Security Assessor (QSA) or Approved Scanning
Vendor (ASV).
