"""MCP server tools: registration, config validation, demo generation."""

import asyncio

import pytest
from mcp.server.mcpserver.exceptions import ToolError as MCPToolError

from cxone_pci_report import mcp_server

VALID_CONFIG = {
    "report": {
        "title": "PCI DSS v4.0.1 Application Security Gap Assessment",
        "company_name": "ACME Retail",
        "auditor": "Security Engineering Team",
        "prepared_date": "2026-09-14",
        "assessment_period": "2026-08-01 to 2026-09-10",
    },
    "projects": [{"name": "web-shop"}],
}


def test_create_server_registers_tools():
    server = mcp_server.create_server()
    assert server.name == mcp_server.SERVER_NAME
    tools = asyncio.run(server.list_tools())
    assert {tool.name for tool in tools} == {
        "generate_pci_report",
        "generate_demo_report",
        "validate_report_config",
    }


def test_validate_config_valid():
    assert mcp_server.validate_report_config(VALID_CONFIG) == "Config is valid."


def test_validate_config_errors():
    result = mcp_server.validate_report_config({"projects": [{"id": "p1"}]})
    assert result.startswith("Invalid config:")
    assert "report.title" in result


def test_validate_config_unknown_key():
    result = mcp_server.validate_report_config({**VALID_CONFIG, "bogus": 1})
    assert "Unknown config section" in result


def test_validate_config_not_serializable():
    # Caller-side mistake: surfaces as a tool error so the model can fix it.
    with pytest.raises(MCPToolError, match="JSON-serializable"):
        mcp_server.validate_report_config({"report": object()})


def test_demo_tool_generates_pdf(tmp_path):
    out = tmp_path / "demo.pdf"
    message = mcp_server.generate_demo_report(str(out))
    assert message.startswith("Demo PCI DSS")
    assert str(out) in message

    raw = out.read_bytes()
    assert raw[:5] == b"%PDF-"


def test_live_tool_rejects_invalid_config():
    with pytest.raises(MCPToolError, match="report.title"):
        mcp_server.generate_pci_report({"projects": [{"id": "p1"}]})


def test_live_tool_rejects_non_dict():
    with pytest.raises(MCPToolError, match="JSON object"):
        mcp_server.generate_pci_report(["not", "a", "dict"])


def test_public_location(monkeypatch):
    monkeypatch.setenv(
        "PCI_REPORT_BASE_URL", "https://reports.example.com/pdf"
    )
    assert (
        mcp_server._public_location("C:/out/pci_dss_v4_0_1_report.pdf")
        == "https://reports.example.com/pdf/pci_dss_v4_0_1_report.pdf"
    )
    monkeypatch.delenv("PCI_REPORT_BASE_URL")
    assert mcp_server._public_location("C:/out/x.pdf") == "C:/out/x.pdf"
