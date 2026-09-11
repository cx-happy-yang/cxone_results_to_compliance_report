"""Client-side filtering and deduplication of normalized findings.

The API is called without state/status/severity filters so the demo, tests
and live pipelines share exactly one filtering implementation; everything
dropped is counted for transparency in the report.
"""

from dataclasses import dataclass, field

from .config import FilterConfigSection
from .models import Finding, Scanner, severity_rank, Severity

# SCA findings come from an endpoint without CxOne triage state/status,
# so state/status filters apply to SAST/KICS/APISec only.
STATEFUL_SCANNERS = (Scanner.SAST, Scanner.KICS, Scanner.APISEC)


@dataclass
class FilterResult:
    kept: list[Finding]
    filtered_out: dict[str, int] = field(default_factory=dict)


def apply_sca_ignored_filter(
    sca_raw_items: list[dict],
    *,
    include_ignored: bool = False,
) -> tuple[list[dict], int]:
    """Drop SCA vulnerabilities marked ``isIgnored`` in CxOne SCA
    risk management. Returns (kept items, number dropped)."""
    if include_ignored:
        return sca_raw_items, 0
    kept = [item for item in sca_raw_items if not item.get("isIgnored")]
    return kept, len(sca_raw_items) - len(kept)


def apply_filters(
    findings: list[Finding],
    cfg: FilterConfigSection,
) -> FilterResult:
    """Apply state/status/severity filters, then dedupe.

    Dedupe key is (scanner, similarity_id) — falling back to
    (scanner, finding_id) when no similarity id is present. With
    ``dedupe_scope="project"`` (default) the key includes the project, so
    the same finding in two projects counts in both.
    """
    states = set(cfg.states)
    statuses = set(cfg.statuses)
    min_severity = Severity(cfg.min_severity)
    min_rank = severity_rank(min_severity)

    kept: list[Finding] = []
    out: dict[str, int] = {
        "by_state": 0,
        "by_status": 0,
        "by_severity": 0,
        "deduplicated": 0,
    }

    for finding in findings:
        if finding.scanner in STATEFUL_SCANNERS:
            if finding.state not in states:
                out["by_state"] += 1
                continue
            if finding.status not in statuses:
                out["by_status"] += 1
                continue
        if severity_rank(finding.severity) > min_rank:
            out["by_severity"] += 1
            continue
        kept.append(finding)

    if cfg.dedupe_scope == "off":
        return FilterResult(kept=kept, filtered_out=out)

    seen: set[tuple] = set()
    deduped: list[Finding] = []
    for finding in kept:
        key = (
            finding.scanner,
            finding.similarity_id or finding.finding_id,
        )
        if cfg.dedupe_scope == "project":
            key = (finding.project_id, *key)
        if key in seen:
            out["deduplicated"] += 1
            continue
        seen.add(key)
        deduped.append(finding)

    return FilterResult(kept=deduped, filtered_out=out)
