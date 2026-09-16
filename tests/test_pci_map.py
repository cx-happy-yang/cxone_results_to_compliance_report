import json

import pytest

from cxone_pci_report.models import Finding, Scanner, Severity
from cxone_pci_report.normalize import from_apisec, from_kics, from_sast, from_sca
from cxone_pci_report.pci_map import MappingError, load_rules, map_finding
from cxone_pci_report.rules import BUILT_IN_RULES
from tests.conftest import CTX


def _mapped(finding, rules=BUILT_IN_RULES, default="6.3.1"):
    return map_finding(finding, rules, default_requirement=default)


class TestBuiltInRules:
    def test_sast_sql_injection_primary_6_5_1(self, sast_sql):
        f = _mapped(from_sast(sast_sql, **CTX))
        assert f.pci_primary == "6.5.1"
        assert "6.5.1" in f.pci_requirements

    def test_sast_sql_cwe_match_accumulates(self, sast_sql):
        f = _mapped(from_sast(sast_sql, **CTX))
        # query-name rule and CWE-89 rule both point at 6.5.1; deduped
        assert f.pci_requirements == ("6.5.1",)

    def test_sca_log4shell_primary_6_5_6_and_6_3_2(self, sca_log4j):
        f = _mapped(from_sca(sca_log4j, **CTX))
        assert f.pci_primary == "6.5.6"
        assert set(f.pci_requirements) == {"6.5.6", "6.3.2"}
        # CWE-502 -> 6.5.6, log4shell CVE -> 6.5.6, sca-all -> 6.3.2

    def test_sca_regular_cve_primary_6_3_2(self, sca_ignored):
        item = dict(sca_ignored)
        item["isIgnored"] = False
        f = _mapped(from_sca(item, **CTX))
        assert f.pci_primary == "6.5.1"  # CWE-79 XSS rule (priority 10)
        assert "6.3.2" in f.pci_requirements

    def test_sca_cve_without_cwe_mapping_falls_to_6_3_2(self):
        item = {
            "id": "CVE-2024-99999",
            "cveName": "CVE-2024-99999",
            "severity": "Medium",
            "score": 5.0,
            "packageId": "Maven-org.example:widget-2.0",
            "cwe": None,
        }
        f = _mapped(from_sca(item, **CTX))
        assert f.pci_primary == "6.3.2"

    def test_kics_public_s3_maps_11_3_1(self):
        f = from_kics(
            type("K", (), {
                "kics_result_id": "r-1",
                "severity": "HIGH",
                "status": "NEW",
                "state": "TO_VERIFY",
                "query_name": "S3 Bucket Allows Public ACL",
                "file_name": "s3.tf",
                "line": 3,
                "expected_value": None,
                "actual_value": None,
            })(),
            **CTX,
        )
        f = _mapped(f)
        assert f.pci_primary == "11.3.1"

    def test_kics_security_group_maps_internal(self, kics_open_port):
        f = _mapped(from_kics(kics_open_port, **CTX))
        assert f.pci_primary == "11.3.1"

    def test_apisec_bola_maps_6_2_4(self, apisec_bola):
        f = _mapped(from_apisec(apisec_bola, **CTX))
        assert f.pci_primary == "6.2.4"

    def test_unmatched_falls_back_to_default(self, kics_malformed):
        f = _mapped(from_kics(kics_malformed, **CTX))
        assert f.pci_primary == "6.3.1"
        assert f.pci_requirements == ("6.3.1",)

    def test_custom_default_requirement(self, kics_malformed):
        f = _mapped(from_kics(kics_malformed, **CTX), default="11.3.1")
        assert f.pci_primary == "11.3.1"

    def test_cvss9_synthetic_rule(self):
        item = {
            "id": "CVE-2024-11111",
            "cveName": "CVE-2024-11111",
            "severity": "Critical",
            "score": 9.8,
            "packageId": "Maven-org.example:widget-2.0",
            "cwe": None,
        }
        f = _mapped(from_sca(item, **CTX))
        assert f.pci_primary == "6.5.6"  # synthetic CVSS>=9 rule, priority 5
        assert "6.3.2" in f.pci_requirements

    def test_cwe_normalization_matches(self):
        f = Finding(
            finding_id="x", scanner=Scanner.APISEC, severity=Severity.HIGH,
            state="TO_VERIFY", status="NEW", confidence_level=None,
            project_id="p", project_name="p", scan_id="s",
            similarity_id=None, title="Something", description="",
            component=None, location=None, cwe="89", cve=None, cvss=None,
            remediation=None, found_at=None,
        )
        mapped = _mapped(f)
        assert "6.5.1" in mapped.pci_requirements


class TestOverlay:
    def _write_overlay(self, tmp_path, entries):
        path = tmp_path / "overlay.json"
        path.write_text(json.dumps(entries), encoding="utf-8")
        return path

    def test_add_rule(self, tmp_path, sast_sql):
        path = self._write_overlay(tmp_path, [
            {
                "action": "add",
                "rule": {
                    "rule_id": "custom-sql",
                    "requirement": "6.5.6",
                    "scanners": ["sast"],
                    "match_type": "query_name_regex",
                    "pattern": r"SQL_Injection",
                    "priority": 5,
                },
            }
        ])
        rules = load_rules(path)
        f = _mapped(from_sast(sast_sql, **CTX), rules=rules)
        assert f.pci_primary == "6.5.6"

    def test_replace_rule(self, tmp_path, sast_sql):
        path = self._write_overlay(tmp_path, [
            {
                "action": "replace",
                "rule": {
                    "rule_id": "sast-sql-inj",
                    "requirement": "11.3.1",
                    "scanners": ["sast"],
                    "match_type": "query_name_regex",
                    "pattern": r"(?i)sql_injection",
                    "priority": 10,
                },
            }
        ])
        rules = load_rules(path)
        f = _mapped(from_sast(sast_sql, **CTX), rules=rules)
        assert f.pci_primary == "11.3.1"
        assert "6.5.1" in f.pci_requirements  # CWE-89 still matches

    def test_remove_rule(self, tmp_path, sca_log4j):
        path = self._write_overlay(tmp_path, [
            {"action": "remove", "rule_id": "sca-log4shell"}
        ])
        rules = load_rules(path)
        f = _mapped(from_sca(sca_log4j, **CTX), rules=rules)
        # Without the CVE rule, CWE-502 (6.5.6, priority 10) still wins.
        assert f.pci_primary == "6.5.6"

    def test_unknown_requirement_rejected(self, tmp_path):
        path = self._write_overlay(tmp_path, [
            {
                "rule": {
                    "rule_id": "bad",
                    "requirement": "9.9.9",
                    "scanners": None,
                    "match_type": "cwe",
                    "pattern": "CWE-1",
                }
            }
        ])
        with pytest.raises(MappingError, match="unknown requirement"):
            load_rules(path)

    def test_unknown_match_type_rejected(self, tmp_path):
        path = self._write_overlay(tmp_path, [
            {
                "rule": {
                    "rule_id": "bad",
                    "requirement": "6.3.1",
                    "scanners": None,
                    "match_type": "bogus",
                    "pattern": "x",
                }
            }
        ])
        with pytest.raises(MappingError, match="match_type"):
            load_rules(path)

    def test_replace_unknown_rule_rejected(self, tmp_path):
        path = self._write_overlay(tmp_path, [
            {
                "action": "replace",
                "rule": {
                    "rule_id": "does-not-exist",
                    "requirement": "6.3.1",
                    "scanners": None,
                    "match_type": "cwe",
                    "pattern": "CWE-1",
                },
            }
        ])
        with pytest.raises(MappingError, match="unknown rule"):
            load_rules(path)

    def test_missing_file_raises(self, tmp_path):
        with pytest.raises(MappingError, match="not found"):
            load_rules(tmp_path / "nope.json")

    def test_none_path_returns_builtins(self):
        assert load_rules(None) == BUILT_IN_RULES
