"""MCP server exposing the PCI report pipeline as tools for Copilot and
other MCP clients.

Local stdio server (VS Code Copilot, Claude Desktop, ...)::

    cxone-pci-report-mcp

Remote streamable-HTTP server (Copilot Chat on github.com, cloud agent)::

    cxone-pci-report-mcp --http --host 0.0.0.0 --port 8000

The tool functions are plain callables importable without the optional
``mcp`` dependency; ``create_server()`` imports MCPServer lazily so the
core package stays installable without it.
"""

import argparse
import json
import os
import tempfile
from pathlib import Path
from urllib.parse import urljoin

from .cli import ToolError, run
from .config import ConfigError, load_config
from .demo.demo_config import build_demo_config

SERVER_NAME = "cxone-pci-report"
DEMO_OUTPUT = "out/demo_report.pdf"


def _tool_error(message: str) -> Exception:
    """Return an error that reaches the MCP client with its text intact.

    mcp 2.x only forwards the text of a deliberate ``ToolError``; any other
    exception is treated as a crash and its message stays on the server.
    Falls back to ``ValueError`` so this module still works without mcp.
    """
    try:
        from mcp.server.mcpserver.exceptions import ToolError
    except ImportError:
        return ValueError(message)
    return ToolError(message)


def _load_config_from_dict(config: dict):
    """Validate a config object by round-tripping it through load_config."""
    if not isinstance(config, dict):
        raise _tool_error(
            "config must be a JSON object - see report_config.example.json "
            "for the schema."
        )
    try:
        raw = json.dumps(config)
    except (TypeError, ValueError) as exc:
        raise _tool_error(
            f"config is not JSON-serializable: {exc}"
        ) from exc
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "report_config.json"
        path.write_text(raw, encoding="utf-8")
        return load_config(path)


def _public_location(pdf_path: str) -> str:
    """Return a download URL when PCI_REPORT_BASE_URL is set, else the path."""
    base = os.environ.get("PCI_REPORT_BASE_URL")
    if base:
        return urljoin(base.rstrip("/") + "/", Path(pdf_path).name)
    return pdf_path


def _result_message(pdf_path: str, *, demo: bool, project_count: int) -> str:
    kind = "Demo" if demo else "Live"
    scope = f" ({project_count} project(s) in scope)" if project_count else ""
    return (
        f"{kind} PCI DSS v4.0.1 supporting-evidence report generated"
        f"{scope}: {_public_location(pdf_path)}"
    )


def generate_pci_report(config: dict, output: str | None = None) -> str:
    """Generate a PCI DSS v4.0.1 supporting-evidence PDF from Checkmarx One
    scan results (SAST, SCA, IaC/KICS, API Security) for the configured
    projects.

    Args:
        config: Full report configuration object (sections: report, output,
            filters, projects, mapping, appearance, api - schema in
            report_config.example.json).
        output: Optional output PDF path on the MCP server host (overrides
            config output.pdf_path).

    CxOne credentials are NOT part of the config: the server host's
    CheckmarxPythonSDK configuration is used (env vars or
    ~/.Checkmarx/config.ini). File paths in the config (logo_path,
    rules_override_path) resolve on the server host. A live run needs
    network access to the CxOne tenant.

    Returns:
        Where the report was written: a PDF path on the server host, or a
        download URL when PCI_REPORT_BASE_URL is set.
    """
    try:
        cfg = _load_config_from_dict(config)
    except (ConfigError, ValueError) as exc:
        raise _tool_error(str(exc)) from exc
    if output:
        cfg.output.pdf_path = output
    Path(cfg.output.pdf_path).parent.mkdir(parents=True, exist_ok=True)
    try:
        pdf_path = run(cfg, demo=False)
    except ToolError as exc:
        raise _tool_error(str(exc)) from exc
    return _result_message(
        pdf_path, demo=False, project_count=len(cfg.projects)
    )


def generate_demo_report(output: str | None = None) -> str:
    """Generate a demo PCI DSS v4.0.1 PDF from bundled synthetic scan data.

    No CxOne credentials or API access needed - offer this first so the
    user can see the report format before a live run.

    Args:
        output: Optional output PDF path on the MCP server host.

    Returns:
        Where the report was written: a PDF path on the server host, or a
        download URL when PCI_REPORT_BASE_URL is set.
    """
    cfg = build_demo_config(output or DEMO_OUTPUT)
    Path(cfg.output.pdf_path).parent.mkdir(parents=True, exist_ok=True)
    try:
        pdf_path = run(cfg, demo=True)
    except ToolError as exc:
        raise _tool_error(str(exc)) from exc
    return _result_message(
        pdf_path, demo=True, project_count=len(cfg.projects)
    )


def validate_report_config(config: dict) -> str:
    """Validate a PCI report configuration object without fetching anything.

    Args:
        config: Full report configuration object (schema in
            report_config.example.json).

    Returns:
        "Config is valid." or the list of validation errors.
    """
    try:
        _load_config_from_dict(config)
    except (ConfigError, ValueError) as exc:
        return f"Invalid config:\n{exc}"
    return "Config is valid."


def create_server():
    """Build the MCP server with all tools registered."""
    from mcp.server.mcpserver import MCPServer

    server = MCPServer(
        SERVER_NAME,
        instructions=(
            "You help users generate PCI DSS v4.0.1 supporting-evidence PDF "
            "reports (application security assessments, not compliance "
            "reports) from Checkmarx One scan results. Use the provided "
            "tools; never reimplement PDF generation yourself. Suggest "
            "generate_demo_report first so the user can see the report "
            "format, then validate_report_config before a live run. Never "
            "ask for or print CxOne credentials - authentication uses the "
            "server host's SDK configuration."
        ),
    )
    server.tool()(generate_pci_report)
    server.tool()(generate_demo_report)
    server.tool()(validate_report_config)
    return server


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cxone-pci-report-mcp",
        description=(
            "Serve the cxone-pci-report pipeline as MCP tools for Copilot "
            "and other MCP clients."
        ),
    )
    parser.add_argument(
        "--http",
        action="store_true",
        help=(
            "Serve streamable HTTP instead of stdio (for remote hosting "
            "behind Copilot Chat on github.com)."
        ),
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="HTTP host (with --http).",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8000,
        help="HTTP port (with --http).",
    )
    parser.add_argument(
        "--path",
        default="/mcp",
        help="HTTP endpoint path (with --http).",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    server = create_server()
    if args.http:
        server.run(
            transport="streamable-http",
            host=args.host,
            port=args.port,
            streamable_http_path=args.path,
        )
    else:
        server.run(transport="stdio")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
