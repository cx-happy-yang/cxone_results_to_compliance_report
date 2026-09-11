import pytest

from cxone_pci_report.config import FilterConfigSection
from cxone_pci_report.filter import (
    apply_filters,
    apply_sca_ignored_filter,
)
from cxone_pci_report.models import Finding, Scanner, Severity


def _finding(
    *,
    scanner=Scanner.SAST,
    severity=Severity.HIGH,
    state="TO_VERIFY",
    status="NEW",
    finding_id="id-1",
    similarity_id=None,
    project_id="proj-1",
) -> Finding:
    return Finding(
        finding_id=finding_id,
        scanner=scanner,
        severity=severity,
        state=state,
        status=status,
        confidence_level=None,
        project_id=project_id,
        project_name="p",
        scan_id="scan-1",
        similarity_id=similarity_id,
        title="t",
        description="",
        component=None,
        location=None,
        cwe=None,
        cve=None,
        cvss=None,
        remediation=None,
        found_at=None,
    )


class TestScaIgnoredFilter:
    def test_drops_ignored_by_default(self, sca_ignored, sca_log4j):
        kept, dropped = apply_sca_ignored_filter(
            [sca_ignored, sca_log4j]
        )
        assert dropped == 1
        assert kept == [sca_log4j]

    def test_keeps_ignored_when_configured(self, sca_ignored, sca_log4j):
        kept, dropped = apply_sca_ignored_filter(
            [sca_ignored, sca_log4j], include_ignored=True
        )
        assert dropped == 0
        assert len(kept) == 2


class TestApplyFilters:
    def cfg(self, **kwargs) -> FilterConfigSection:
        defaults = dict(
            states=["TO_VERIFY", "CONFIRMED", "URGENT"],
            statuses=["NEW", "RECURRENT"],
            min_severity="LOW",
            dedupe_scope="project",
            sca_include_ignored=False,
        )
        defaults.update(kwargs)
        return FilterConfigSection(**defaults)

    def test_keeps_valid_finding(self):
        result = apply_filters([_finding()], self.cfg())
        assert len(result.kept) == 1
        assert result.filtered_out == {
            "by_state": 0, "by_status": 0, "by_severity": 0, "deduplicated": 0,
        }

    def test_drops_not_exploitable(self):
        f = _finding(state="NOT_EXPLOITABLE")
        result = apply_filters([f], self.cfg())
        assert result.kept == []
        assert result.filtered_out["by_state"] == 1

    def test_drops_fixed_status(self):
        f = _finding(status="FIXED")
        result = apply_filters([f], self.cfg())
        assert result.kept == []
        assert result.filtered_out["by_status"] == 1

    def test_drops_info_severity(self):
        f = _finding(severity=Severity.INFO)
        result = apply_filters([f], self.cfg(min_severity="LOW"))
        assert result.kept == []
        assert result.filtered_out["by_severity"] == 1

    def test_keeps_critical(self):
        f = _finding(severity=Severity.CRITICAL)
        result = apply_filters([f], self.cfg(min_severity="LOW"))
        assert len(result.kept) == 1

    def test_sca_bypasses_state_status_filters(self):
        f = _finding(
            scanner=Scanner.SCA,
            state=None,
            status=None,
        )
        result = apply_filters([f], self.cfg())
        assert len(result.kept) == 1

    def test_dedupe_by_similarity_id_within_project(self):
        a = _finding(finding_id="a", similarity_id="simi-1")
        b = _finding(finding_id="b", similarity_id="simi-1")
        result = apply_filters([a, b], self.cfg())
        assert len(result.kept) == 1
        assert result.filtered_out["deduplicated"] == 1

    def test_dedupe_falls_back_to_finding_id(self):
        a = _finding(finding_id="same", similarity_id=None)
        b = _finding(finding_id="same", similarity_id=None)
        result = apply_filters([a, b], self.cfg())
        assert len(result.kept) == 1
        assert result.filtered_out["deduplicated"] == 1

    def test_dedupe_is_per_project(self):
        a = _finding(finding_id="a", similarity_id="simi-1", project_id="p1")
        b = _finding(finding_id="b", similarity_id="simi-1", project_id="p2")
        result = apply_filters([a, b], self.cfg())
        assert len(result.kept) == 2

    def test_dedupe_off(self):
        a = _finding(finding_id="same", similarity_id=None)
        b = _finding(finding_id="same", similarity_id=None)
        result = apply_filters([a, b], self.cfg(dedupe_scope="off"))
        assert len(result.kept) == 2
        assert result.filtered_out["deduplicated"] == 0
