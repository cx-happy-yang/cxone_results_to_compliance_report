from cxone_pci_report.aggregate import (
    GAP_INDICATOR,
    NOT_COVERED_INDICATOR,
    OK_INDICATOR,
    WATCH_INDICATOR,
    build_report_data,
    gap_indicator,
)
from cxone_pci_report.config import ReportConfig
from cxone_pci_report.models import Finding, ProjectScan, Scanner, Severity
from cxone_pci_report.pci_requirements import PCI_REQUIREMENTS


def _finding(
    *,
    scanner=Scanner.SAST,
    severity=Severity.HIGH,
    reqs=("6.5.1",),
    primary="6.5.1",
    project_id="p1",
    title="f",
    found_at="2026-08-01T00:00:00Z",
) -> Finding:
    return Finding(
        finding_id=title, scanner=scanner, severity=severity,
        state="TO_VERIFY", status="NEW", confidence_level=None,
        project_id=project_id, project_name="n", scan_id="s1",
        similarity_id=None, title=title, description="",
        component=None, location=None, cwe=None, cve=None, cvss=None,
        remediation=None, found_at=found_at,
        pci_requirements=reqs, pci_primary=primary,
    )


def _project(project_id="p1", name="proj-one", findings=None) -> ProjectScan:
    return ProjectScan(
        project_id=project_id,
        project_name=name,
        display_name=name,
        scan_id="scan-1",
        scan_created_at="2026-08-01T00:00:00Z",
        scan_status="Completed",
        branch="main",
        engines=["sast", "sca", "kics", "apisec"],
        findings=findings or [],
    )


def test_gap_indicator():
    cfg = ReportConfig()
    counts = {sev: 0 for sev in Severity}
    assert gap_indicator(counts, cfg) == OK_INDICATOR
    counts[Severity.MEDIUM] = 1
    assert gap_indicator(counts, cfg) == WATCH_INDICATOR
    counts[Severity.HIGH] = 1
    assert gap_indicator(counts, cfg) == GAP_INDICATOR
    counts[Severity.CRITICAL] = 1
    assert gap_indicator(counts, cfg) == GAP_INDICATOR


def test_severity_by_project_rows():
    p = _project(findings=[
        _finding(severity=Severity.HIGH),
        _finding(severity=Severity.LOW, title="low"),
    ])
    data = build_report_data([p], ReportConfig())
    row = data.severity_by_project[0]
    assert row["project"] == "proj-one"
    assert row["HIGH"] == 1
    assert row["LOW"] == 1
    assert row["CRITICAL"] == 0
    assert row["total"] == 2


def test_scanner_matrix():
    p = _project(findings=[
        _finding(scanner=Scanner.SAST),
        _finding(scanner=Scanner.SCA, title="sca"),
    ])
    data = build_report_data([p], ReportConfig())
    assert data.scanner_matrix[Scanner.SAST][Severity.HIGH] == 1
    assert data.scanner_matrix[Scanner.SCA][Severity.HIGH] == 1
    assert data.scanner_matrix[Scanner.KICS][Severity.HIGH] == 0


def test_requirement_stats_include_zero_rows():
    p = _project(findings=[_finding()])
    data = build_report_data([p], ReportConfig())
    assert len(data.requirement_stats) == len(PCI_REQUIREMENTS)
    stat = data.requirement_stats["6.5.1"]
    assert stat.total == 1
    assert stat.indicator == GAP_INDICATOR
    assert stat.sample_findings[0].title == "f"
    # A requirement with no findings still exists with zero counts.
    zero = data.requirement_stats["6.5.2"]
    assert zero.total == 0
    assert zero.indicator == OK_INDICATOR


def test_sample_findings_sorted_by_severity_then_date():
    p = _project(findings=[
        _finding(severity=Severity.LOW, title="low-new", found_at="2026-09-01T00:00:00Z"),
        _finding(severity=Severity.CRITICAL, title="crit", found_at="2026-01-01T00:00:00Z"),
        _finding(severity=Severity.HIGH, title="high", found_at="2026-08-01T00:00:00Z"),
    ])
    data = build_report_data([p], ReportConfig())
    samples = data.requirement_stats["6.5.1"].sample_findings
    assert [s.title for s in samples] == ["crit", "high", "low-new"]


def test_findings_with_multiple_requirements_count_in_both():
    p = _project(findings=[
        _finding(reqs=("6.5.1", "6.3.2"), primary="6.5.1"),
    ])
    data = build_report_data([p], ReportConfig())
    assert data.requirement_stats["6.5.1"].total == 1
    assert data.requirement_stats["6.3.2"].total == 1


def test_top_findings_limited_to_ten():
    findings = [
        _finding(severity=Severity.LOW, title=f"f{i}", found_at="2026-08-01T00:00:00Z")
        for i in range(15)
    ]
    data = build_report_data([_project(findings=findings)], ReportConfig())
    assert len(data.top_findings) == 10


def test_scan_table_and_totals():
    p = _project(findings=[_finding()])
    data = build_report_data([p], ReportConfig(), filtered_out={"by_state": 3})
    assert data.scan_table[0]["project"] == "proj-one"
    assert data.scan_table[0]["scan_id"] == "scan-1"
    assert data.scan_table[0]["engines"] == "sast, sca, kics, apisec"
    assert data.totals["kept"] == 1
    assert data.totals["projects"] == 1
    assert data.filtered_out["by_state"] == 3


def test_skipped_projects_passthrough():
    skipped = [{"project": "empty-proj", "reason": "No scan found"}]
    data = build_report_data(
        [_project()], ReportConfig(), skipped_projects=skipped
    )
    assert data.skipped_projects == skipped


def test_skipped_projects_default_empty():
    data = build_report_data([_project()], ReportConfig())
    assert data.skipped_projects == []


def test_not_covered_requirements():
    data = build_report_data([_project()], ReportConfig())
    stats = data.requirement_stats
    for req_id in ("6.2.2", "6.4.3", "11.3.2", "11.3.3"):
        stat = stats[req_id]
        assert stat.indicator == NOT_COVERED_INDICATOR
        assert stat.covered is False
        assert stat.total == 0
    # A covered requirement with no findings keeps the OK indicator.
    assert stats["6.3.3"].indicator == OK_INDICATOR
    assert stats["6.3.3"].covered is True
    assert data.totals["requirements"] == len(PCI_REQUIREMENTS) == 19
    assert data.totals["covered"] == 15
    assert data.totals["not_covered"] == 4
