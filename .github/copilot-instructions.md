# Copilot instructions

This repository generates PCI DSS v4.0.1 compliance PDF reports from
Checkmarx One scan results. When someone asks you to generate, create, or
update such a report:

- Use the existing pipeline - run the CLI rather than writing new code:
  `.venv\Scripts\cxone-pci-report --config report_config.json` (real run)
  or `.venv\Scripts\cxone-pci-report --demo` (synthetic demo, no
  credentials). Success is the printed `Report written: <path>` line.
- If the `cxone-pci-report-mcp` MCP server is connected, prefer its tools
  (`generate_pci_report`, `generate_demo_report`, `validate_report_config`)
  over shelling out.
- Offer `--demo` first so the user sees the report format without needing
  API access.
- A real run needs a config matching `report_config.example.json` plus a
  working CheckmarxPythonSDK configuration (`~/.Checkmarx/config.ini` or
  `cxone_*` env vars). If a config is invalid, the CLI prints the
  validation errors - fix the config, don't bypass validation.
- Never ask for, print, or store CxOne credentials (refresh tokens, API
  keys).
- Never invent findings or change fetched data. The report is supporting
  evidence for a gap assessment, not a certification.
- `--application <name>` expands scope to all projects of an application;
  `--main-branch-only` restricts to main (protected) branch scans.
