import json

import pytest

from cxone_pci_report.config import ConfigError, load_config, validate_config
from cxone_pci_report.config import ReportConfig, ProjectConfig


def _write_config(tmp_path, raw: dict):
    path = tmp_path / "cfg.json"
    path.write_text(json.dumps(raw), encoding="utf-8")
    return path


def _minimal_raw() -> dict:
    return {
        "report": {
            "title": "PCI Report",
            "company_name": "ACME",
            "auditor": "Security Team",
            "prepared_date": "2026-09-11",
            "assessment_period": "2026-08-01 to 2026-09-10",
        },
        "projects": [{"name": "web-shop"}],
    }


def test_minimal_config_loads_with_defaults(tmp_path):
    cfg = load_config(_write_config(tmp_path, _minimal_raw()))
    assert cfg.report.title == "PCI Report"
    assert cfg.output.pdf_path == "out/pci_dss_v4_0_1_report.pdf"
    assert cfg.filters.states == ["TO_VERIFY", "CONFIRMED", "URGENT"]
    assert cfg.filters.statuses == ["NEW", "RECURRENT"]
    assert cfg.filters.min_severity == "LOW"
    assert cfg.filters.dedupe_scope == "project"
    assert cfg.mapping.default_requirement == "6.3.1"
    assert cfg.mapping.max_findings_per_requirement == 100
    assert cfg.appearance.primary_color == "#1F3B73"
    assert cfg.api.page_size == 100
    assert len(cfg.projects) == 1
    assert cfg.projects[0].name == "web-shop"


def test_missing_file_raises(tmp_path):
    with pytest.raises(ConfigError):
        load_config(tmp_path / "nope.json")


def test_unknown_section_rejected(tmp_path):
    raw = _minimal_raw()
    raw["bogus_section"] = {}
    with pytest.raises(ConfigError, match="bogus_section"):
        load_config(_write_config(tmp_path, raw))


def test_unknown_key_rejected(tmp_path):
    raw = _minimal_raw()
    raw["report"]["titel"] = "typo"
    with pytest.raises(ConfigError, match="titel"):
        load_config(_write_config(tmp_path, raw))


def test_unknown_project_key_rejected(tmp_path):
    raw = _minimal_raw()
    raw["projects"][0]["displayname"] = "typo"
    with pytest.raises(ConfigError, match="displayname"):
        load_config(_write_config(tmp_path, raw))


def test_required_report_fields(tmp_path):
    for field in ("title", "company_name", "auditor", "prepared_date",
                  "assessment_period"):
        raw = _minimal_raw()
        del raw["report"][field]
        with pytest.raises(ConfigError, match=field):
            load_config(_write_config(tmp_path, raw))


def test_project_requires_exactly_one_of_name_or_id(tmp_path):
    raw = _minimal_raw()
    raw["projects"] = [{"name": "a", "id": "b"}]
    with pytest.raises(ConfigError, match="exactly one"):
        load_config(_write_config(tmp_path, raw))

    raw["projects"] = [{"branch": "main"}]
    with pytest.raises(ConfigError, match="exactly one"):
        load_config(_write_config(tmp_path, raw))


def test_no_projects_rejected(tmp_path):
    raw = _minimal_raw()
    raw["projects"] = []
    with pytest.raises(ConfigError, match="At least one"):
        load_config(_write_config(tmp_path, raw))


def test_invalid_min_severity_rejected(tmp_path):
    raw = _minimal_raw()
    raw["filters"] = {"min_severity": "EXTREME"}
    with pytest.raises(ConfigError, match="min_severity"):
        load_config(_write_config(tmp_path, raw))


def test_invalid_dedupe_scope_rejected(tmp_path):
    raw = _minimal_raw()
    raw["filters"] = {"dedupe_scope": "tenant"}
    with pytest.raises(ConfigError, match="dedupe_scope"):
        load_config(_write_config(tmp_path, raw))


def test_invalid_gap_severity_rejected(tmp_path):
    raw = _minimal_raw()
    raw["mapping"] = {"gap_if_any": ["SEVERE"]}
    with pytest.raises(ConfigError, match="gap_if_any"):
        load_config(_write_config(tmp_path, raw))


def test_validate_config_empty_projects():
    cfg = ReportConfig(projects=[])
    errors = validate_config(cfg)
    assert any("projects" in e for e in errors)
