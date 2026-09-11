"""Aggregate filtered findings into the structures the PDF report consumes."""

from dataclasses import dataclass, field

from .config import ReportConfig
from .models import Finding, ProjectScan, Scanner, Severity, severity_rank, SEVERITY_ORDER
from .pci_requirements import PCI_REQUIREMENTS

GAP_INDICATOR = "GAPS IDENTIFIED"
WATCH_INDICATOR = "WATCH"
OK_INDICATOR = "NO FINDINGS"


@dataclass
class RequirementStat:
    requirement: str
    title: str
    counts: dict[Severity, int] = field(default_factory=dict)
    total: int = 0
    indicator: str = OK_INDICATOR
    sample_findings: list[Finding] = field(default_factory=list)


@dataclass
class ReportData:
    projects: list[ProjectScan]
    severity_by_project: list[dict]
    scanner_matrix: dict[Scanner, dict[Severity, int]]
    requirement_stats: dict[str, RequirementStat]
    findings_by_requirement: dict[str, list[Finding]]
    scan_table: list[dict]
    totals: dict[str, int]
    filtered_out: dict[str, int]
    top_findings: list[Finding]
    summary_crosscheck: dict | None = None
    skipped_projects: list[dict] = field(default_factory=list)
    data_notes: list[str] = field(default_factory=list)


def _empty_counts() -> dict[Severity, int]:
    return {sev: 0 for sev in SEVERITY_ORDER}


def gap_indicator(
    counts: dict[Severity, int],
    cfg: ReportConfig,
) -> str:
    gap_sevs = {Severity(s) for s in cfg.mapping.gap_if_any}
    watch_sevs = {Severity(s) for s in cfg.mapping.watch_if_any}
    if any(counts.get(sev, 0) > 0 for sev in gap_sevs):
        return GAP_INDICATOR
    if any(counts.get(sev, 0) > 0 for sev in watch_sevs):
        return WATCH_INDICATOR
    return OK_INDICATOR


def _sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(
        findings,
        key=lambda f: (severity_rank(f.severity), f.found_at or ""),
        reverse=False,
    )


def build_report_data(
    projects: list[ProjectScan],
    cfg: ReportConfig,
    *,
    filtered_out: dict[str, int] | None = None,
    summary_crosscheck: dict | None = None,
    skipped_projects: list[dict] | None = None,
    data_notes: list[str] | None = None,
) -> ReportData:
    all_findings: list[Finding] = []
    for project in projects:
        all_findings.extend(project.findings)

    # Per-project severity table rows.
    severity_by_project: list[dict] = []
    for project in projects:
        counts = _empty_counts()
        for finding in project.findings:
            counts[finding.severity] += 1
        severity_by_project.append(
            {
                "project": project.display_name,
                **{sev.value: counts[sev] for sev in SEVERITY_ORDER},
                "total": len(project.findings),
            }
        )

    # Scanner x severity matrix.
    scanner_matrix: dict[Scanner, dict[Severity, int]] = {
        scanner: _empty_counts() for scanner in Scanner
    }
    for finding in all_findings:
        scanner_matrix[finding.scanner][finding.severity] += 1

    # Requirement stats (every requirement present, even at zero findings).
    requirement_stats: dict[str, RequirementStat] = {}
    findings_by_requirement: dict[str, list[Finding]] = {
        req.requirement: [] for req in PCI_REQUIREMENTS
    }
    for finding in all_findings:
        for req_id in finding.pci_requirements:
            findings_by_requirement.setdefault(req_id, []).append(finding)

    for req in PCI_REQUIREMENTS:
        findings = findings_by_requirement[req.requirement]
        counts = _empty_counts()
        for finding in findings:
            counts[finding.severity] += 1
        ordered = _sort_findings(findings)
        requirement_stats[req.requirement] = RequirementStat(
            requirement=req.requirement,
            title=req.title,
            counts=counts,
            total=len(findings),
            indicator=gap_indicator(counts, cfg),
            sample_findings=ordered[:3],
        )
        findings_by_requirement[req.requirement] = ordered

    # Scan inventory table.
    scan_table = [
        {
            "project": project.display_name,
            "project_id": project.project_id,
            "scan_id": project.scan_id,
            "scan_created_at": project.scan_created_at,
            "branch": project.branch,
            "engines": ", ".join(project.engines) if project.engines else "",
            "status": project.scan_status,
        }
        for project in projects
    ]

    totals = {
        "kept": len(all_findings),
        "projects": len(projects),
        "requirements": len(PCI_REQUIREMENTS),
    }
    top_findings = _sort_findings(all_findings)[:10]

    return ReportData(
        projects=projects,
        severity_by_project=severity_by_project,
        scanner_matrix=scanner_matrix,
        requirement_stats=requirement_stats,
        findings_by_requirement=findings_by_requirement,
        scan_table=scan_table,
        totals=totals,
        filtered_out=filtered_out or {},
        top_findings=top_findings,
        summary_crosscheck=summary_crosscheck,
        skipped_projects=skipped_projects or [],
        data_notes=data_notes or [],
    )
