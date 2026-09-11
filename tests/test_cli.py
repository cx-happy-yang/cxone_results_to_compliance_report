"""CLI pipeline tests with the SDK client monkeypatched (no network)."""

import httpx

from cxone_pci_report import cli
from cxone_pci_report.config import ProjectConfig, ReportConfig, ReportConfigSection
from cxone_pci_report.models import Finding, ProjectScan, Scanner, Severity


def _finding(finding_id: str) -> Finding:
    return Finding(
        finding_id=finding_id, scanner=Scanner.SAST, severity=Severity.HIGH,
        state="TO_VERIFY", status="NEW", confidence_level=None,
        project_id="p1", project_name="proj", scan_id="s1",
        similarity_id=None, title="SQL_Injection", description="",
        component=None, location=None, cwe="CWE-89", cve=None, cvss=None,
        remediation=None, found_at=None,
    )


def _config(tmp_path) -> ReportConfig:
    return ReportConfig(
        report=ReportConfigSection(
            title="t", company_name="c", auditor="a",
            prepared_date="2026-09-11", assessment_period="x",
        ),
        output=__import__("cxone_pci_report.config", fromlist=["OutputConfigSection"]).OutputConfigSection(
            pdf_path=str(tmp_path / "out.pdf")
        ),
        projects=[ProjectConfig(id="p1"), ProjectConfig(id="p2")],
    )


class FakeClient:
    """Replaces sdk_client.CxOneClient for tests."""

    def __init__(self, behaviors):
        self.behaviors = behaviors  # project_id -> result or exception

    def fetch_project_scan(self, project_cfg, cfg):
        behavior = self.behaviors[project_cfg.id]
        if isinstance(behavior, Exception):
            raise behavior
        return behavior, 0, []


def _scan(project_id: str) -> ProjectScan:
    return ProjectScan(
        project_id=project_id,
        project_name=project_id,
        display_name=project_id,
        scan_id="scan-1",
        scan_created_at="2026-09-10T00:00:00Z",
        scan_status="Completed",
        branch="master",
        engines=["sast"],
        findings=[_finding("f-1")],
    )


def test_timeout_skips_project_and_continues(tmp_path, monkeypatch):
    client = FakeClient(
        {
            "p1": _scan("p1"),
            "p2": httpx.ReadTimeout("read timed out", request=None),
        }
    )
    monkeypatch.setattr(
        "cxone_pci_report.sdk_client.CxOneClient", lambda: client
    )
    out = cli.run(_config(tmp_path), demo=False)
    assert out.endswith("out.pdf")
    assert (tmp_path / "out.pdf").exists()


def test_no_scan_found_skips_project(tmp_path, monkeypatch):
    from cxone_pci_report.sdk_client import CxOneError

    client = FakeClient(
        {
            "p1": _scan("p1"),
            "p2": CxOneError("No scan found for project 'p2'."),
        }
    )
    monkeypatch.setattr(
        "cxone_pci_report.sdk_client.CxOneClient", lambda: client
    )
    out = cli.run(_config(tmp_path), demo=False)
    assert out.endswith("out.pdf")


def test_all_projects_skipped_raises_tool_error(tmp_path, monkeypatch):
    from cxone_pci_report.sdk_client import CxOneError

    client = FakeClient(
        {"p1": CxOneError("No scan found for project 'p1'."),
         "p2": CxOneError("No scan found for project 'p2'.")}
    )
    monkeypatch.setattr(
        "cxone_pci_report.sdk_client.CxOneClient", lambda: client
    )
    import pytest

    with pytest.raises(cli.ToolError, match="no projects"):
        cli.run(_config(tmp_path), demo=False)
