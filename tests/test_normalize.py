import pytest

from cxone_pci_report.models import Scanner, Severity
from cxone_pci_report.normalize import (
    from_apisec,
    from_kics,
    from_sast,
    from_sca,
    normalize_severity,
    _norm_cwe,
    _parse_sca_package,
)
from tests.conftest import CTX


class TestNormalizeSeverity:
    @pytest.mark.parametrize(
        "value, expected",
        [
            ("CRITICAL", Severity.CRITICAL),
            ("HIGH", Severity.HIGH),
            ("MEDIUM", Severity.MEDIUM),
            ("LOW", Severity.LOW),
            ("INFO", Severity.INFO),
            ("High", Severity.HIGH),       # SCA title-case
            ("high", Severity.HIGH),
            ("Critical", Severity.CRITICAL),
            ("Informational", Severity.INFO),
            (None, Severity.INFO),
            ("BOGUS", Severity.INFO),
            ("", Severity.INFO),
        ],
    )
    def test_severity_mapping(self, value, expected):
        assert normalize_severity(value) is expected


class TestNormCwe:
    def test_formats(self):
        assert _norm_cwe(89) == "CWE-89"
        assert _norm_cwe("89") == "CWE-89"
        assert _norm_cwe("CWE-89") == "CWE-89"
        assert _norm_cwe("CWE 89") == "CWE-89"
        assert _norm_cwe("cwe-89") == "CWE-89"
        assert _norm_cwe(None) is None
        assert _norm_cwe("") is None


class TestParseScaPackage:
    def test_normal(self):
        assert _parse_sca_package("Yarn-commons-collections:commons-collections-3.2.1") == (
            "Yarn-commons-collections:commons-collections",
            "3.2.1",
        )

    def test_no_version(self):
        assert _parse_sca_package("plain-name") == ("plain-name", None)

    def test_empty(self):
        assert _parse_sca_package("") == (None, None)
        assert _parse_sca_package(None) == (None, None)


class TestFromSast:
    def test_full_result(self, sast_sql):
        f = from_sast(sast_sql, **CTX)
        assert f.finding_id == "r-sast-1"
        assert f.scanner is Scanner.SAST
        assert f.severity is Severity.HIGH
        assert f.state == "TO_VERIFY"
        assert f.status == "NEW"
        assert f.title == "SQL_Injection"
        assert f.cwe == "CWE-89"
        assert f.pci_tagged is True
        assert f.component == "src/api/users.py"
        assert f.location == "src/api/users.py:42"
        assert f.similarity_id == "1001"
        assert f.project_id == "proj-1"

    def test_malformed_never_raises(self, sast_malformed):
        f = from_sast(sast_malformed, **CTX)
        assert f.finding_id == "unknown"
        assert f.severity is Severity.INFO
        assert f.title == "SAST finding"
        assert f.cwe is None
        assert f.pci_tagged is False
        assert f.location is None


class TestFromSca:
    def test_full_vulnerability(self, sca_log4j):
        f = from_sca(sca_log4j, **CTX)
        assert f.scanner is Scanner.SCA
        assert f.severity is Severity.CRITICAL
        assert f.cve == "CVE-2021-44228"
        assert f.cvss == 10.0
        assert f.cwe == "CWE-502"
        assert f.component == "Maven-org.apache.logging.log4j:log4j-core"
        assert f.location == "Maven-org.apache.logging.log4j:log4j-core@2.14.1"
        assert f.title == (
            "Maven-org.apache.logging.log4j:log4j-core: CVE-2021-44228"
        )
        assert f.state is None  # SCA has no triage state here
        assert f.remediation == "Upgrade to 2.17.1."

    def test_fix_resolution_fallback(self):
        item = {
            "id": "CVE-2022-0001",
            "cveName": "CVE-2022-0001",
            "severity": "Medium",
            "packageId": "Maven-com.example:lib-1.0",
            "recommendations": None,
            "fixResolutionText": "1.1.0",
        }
        f = from_sca(item, **CTX)
        assert f.remediation == "Upgrade to version 1.1.0 or later."

    def test_malformed_never_raises(self, sca_malformed):
        f = from_sca(sca_malformed, **CTX)
        assert f.finding_id == "unknown"
        assert f.cve is None
        assert f.severity is Severity.INFO


class TestFromKics:
    def test_full_result(self, kics_open_port):
        f = from_kics(kics_open_port, **CTX)
        assert f.scanner is Scanner.KICS
        assert f.severity is Severity.MEDIUM
        assert f.title == "Security Group Allows Unrestricted Ingress"
        assert f.location == "infra/terraform/main.tf:17"
        assert f.remediation == (
            "Expected: Port 22 restricted; actual: 0.0.0.0/0 open."
        )

    def test_malformed_never_raises(self, kics_malformed):
        f = from_kics(kics_malformed, **CTX)
        assert f.finding_id == "unknown"
        assert f.severity is Severity.INFO
        assert f.title == "KICS finding"
        assert f.location is None


class TestFromApisec:
    def test_full_risk(self, apisec_bola):
        f = from_apisec(apisec_bola, **CTX)
        assert f.scanner is Scanner.APISEC
        assert f.severity is Severity.CRITICAL
        assert f.title == "Broken Object Level Authorization (BOLA)"
        assert f.state == "CONFIRMED"
        assert f.status == "RECURRENT"
        assert f.component == "/api/v1/orders/{id}"
        assert f.location == "ENDPOINT"
        assert f.similarity_id == "g-77"

    def test_malformed_never_raises(self, apisec_malformed):
        f = from_apisec(apisec_malformed, **CTX)
        assert f.finding_id == "unknown"
        assert f.severity is Severity.INFO
        assert f.title == "API Security risk"
