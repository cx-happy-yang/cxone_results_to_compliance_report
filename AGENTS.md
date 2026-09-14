# AGENTS.md

This repo turns Checkmarx One scan results (SAST, SCA, IaC/KICS, API
Security) into a PCI DSS v4.0.1 compliance PDF report. Full details in
[README.md](README.md).

## Generating a report

```powershell
# Offline demo from synthetic data (no credentials) - try this first
.venv\Scripts\cxone-pci-report --demo

# Real run against a tenant
.venv\Scripts\cxone-pci-report --config report_config.json --verbose

# Include every project of a CxOne application
.venv\Scripts\cxone-pci-report --config report_config.json --application "My App"

# Restrict to main (protected) branch scans
.venv\Scripts\cxone-pci-report --config report_config.json --main-branch-only
```

- Config schema: `report_config.example.json` (fully annotated). The CLI
  rejects unknown keys and prints all validation errors - read them and
  fix the config, don't bypass validation.
- Output PDF path: config `output.pdf_path`, overridden by `--output`.
- Success is the printed `Report written: <path>` line.

## Rules

- Never print, commit, or hardcode CxOne credentials (refresh tokens, API
  keys). Authentication is delegated to CheckmarxPythonSDK: the user's
  `~/.Checkmarx/config.ini` or `cxone_*` environment variables.
- Never invent or modify findings: the report is evidence. Do not edit
  fetched data or mapping output to change a requirement's status.
- To change mapping behavior, prefer the JSON rules overlay
  (`mapping.rules_override_path`) over editing `rules.py`.

## Layout

- `cxone_pci_report/cli.py` - entry point pipeline
- `cxone_pci_report/sdk_client.py` - only module importing CheckmarxPythonSDK
- `cxone_pci_report/normalize.py` - per-scanner payloads to common `Finding`
- `cxone_pci_report/pci_map.py` - finding -> PCI requirement mapping
- `cxone_pci_report/report/` - PDF rendering (reportlab)
- `cxone_pci_report/mcp_server.py` - MCP tools for Copilot and other clients

## Tests

```powershell
.venv\Scripts\python -m pytest
```
