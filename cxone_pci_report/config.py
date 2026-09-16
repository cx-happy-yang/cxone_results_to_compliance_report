"""Tool configuration: dataclasses, loading and validation."""

import json
from dataclasses import dataclass, field
from pathlib import Path

from .models import Severity

VALID_SEVERITIES = {sev.value for sev in Severity}
VALID_LANGUAGES = {"en"}
VALID_DEDUPE_SCOPES = {"project", "off"}


class ConfigError(Exception):
    pass


@dataclass
class ReportConfigSection:
    title: str = ""
    subtitle: str = (
        "Supporting Evidence for PCI DSS v4.0.1 (Requirements 6 & 11)"
    )
    company_name: str = ""
    auditor: str = ""
    prepared_date: str = ""
    assessment_period: str = ""
    confidentiality: str = "Confidential"
    logo_path: str | None = None
    language: str = "en"


@dataclass
class OutputConfigSection:
    pdf_path: str = "out/pci_dss_v4_0_1_report.pdf"


@dataclass
class FilterConfigSection:
    states: list[str] = field(
        default_factory=lambda: ["TO_VERIFY", "CONFIRMED", "URGENT"]
    )
    statuses: list[str] = field(default_factory=lambda: ["NEW", "RECURRENT"])
    min_severity: str = "LOW"
    dedupe_scope: str = "project"
    sca_include_ignored: bool = False


@dataclass
class ProjectConfig:
    name: str | None = None
    id: str | None = None
    display_name: str | None = None
    branch: str | None = None
    scan_id: str | None = None
    use_main_branch: bool = False


@dataclass
class MappingConfigSection:
    rules_override_path: str | None = None
    default_requirement: str = "6.3.1"
    gap_if_any: list[str] = field(default_factory=lambda: ["CRITICAL", "HIGH"])
    watch_if_any: list[str] = field(default_factory=lambda: ["MEDIUM"])
    max_findings_per_requirement: int = 100


@dataclass
class AppearanceConfigSection:
    primary_color: str = "#1F3B73"
    accent_color: str = "#C8102E"
    table_alt_row: str = "#F2F5FA"
    gap_color: str = "#C0392B"
    watch_color: str = "#E67E22"
    ok_color: str = "#27AE60"


@dataclass
class ApiConfigSection:
    page_size: int = 100
    include_summary: bool = False


@dataclass
class ReportConfig:
    report: ReportConfigSection = field(default_factory=ReportConfigSection)
    output: OutputConfigSection = field(default_factory=OutputConfigSection)
    filters: FilterConfigSection = field(default_factory=FilterConfigSection)
    projects: list[ProjectConfig] = field(default_factory=list)
    mapping: MappingConfigSection = field(default_factory=MappingConfigSection)
    appearance: AppearanceConfigSection = field(
        default_factory=AppearanceConfigSection
    )
    api: ApiConfigSection = field(default_factory=ApiConfigSection)


def _section_keys() -> dict[str, set[str]]:
    return {
        "report": {
            "title", "subtitle", "company_name", "auditor", "prepared_date",
            "assessment_period", "confidentiality", "logo_path", "language",
        },
        "output": {"pdf_path"},
        "filters": {
            "states", "statuses", "min_severity", "dedupe_scope",
            "sca_include_ignored",
        },
        "projects": None,  # list, handled separately
        "mapping": {
            "rules_override_path", "default_requirement", "gap_if_any",
            "watch_if_any", "max_findings_per_requirement",
        },
        "appearance": {
            "primary_color", "accent_color", "table_alt_row", "gap_color",
            "watch_color", "ok_color",
        },
        "api": {"page_size", "include_summary"},
    }


def load_config(
    path: str | Path,
    *,
    require_projects: bool = True,
) -> ReportConfig:
    """Load and validate a report config JSON file (strict on unknown keys).

    ``require_projects=False`` allows an empty ``projects`` section when the
    CLI supplies project scope from another source (``--application``).
    """
    path = Path(path)
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise ConfigError(f"Config file not found: {path}")
    except json.JSONDecodeError as exc:
        raise ConfigError(f"Invalid JSON in config file {path}: {exc}")

    if not isinstance(raw, dict):
        raise ConfigError("Config root must be a JSON object.")

    known_sections = set(_section_keys())
    unknown_sections = set(raw) - known_sections
    if unknown_sections:
        raise ConfigError(
            f"Unknown config section(s): {sorted(unknown_sections)}. "
            f"Known sections: {sorted(known_sections)}."
        )

    cfg = ReportConfig()
    errors: list[str] = []

    for section in ("report", "output", "filters", "mapping", "appearance", "api"):
        section_raw = raw.get(section, {})
        if not isinstance(section_raw, dict):
            errors.append(f"'{section}' must be an object.")
            continue
        allowed = _section_keys()[section]
        unknown = set(section_raw) - allowed
        if unknown:
            errors.append(
                f"Unknown key(s) in '{section}': {sorted(unknown)}."
            )
        for key in allowed:
            if key in section_raw:
                setattr(getattr(cfg, section), key, section_raw[key])

    projects_raw = raw.get("projects", [])
    if not isinstance(projects_raw, list):
        errors.append("'projects' must be a list.")
        projects_raw = []
    for i, proj in enumerate(projects_raw):
        if not isinstance(proj, dict):
            errors.append(f"projects[{i}] must be an object.")
            continue
        unknown = set(proj) - {
            "name", "id", "display_name", "branch", "scan_id",
            "use_main_branch",
        }
        if unknown:
            errors.append(f"Unknown key(s) in projects[{i}]: {sorted(unknown)}.")
        cfg.projects.append(
            ProjectConfig(
                name=proj.get("name"),
                id=proj.get("id"),
                display_name=proj.get("display_name"),
                branch=proj.get("branch"),
                scan_id=proj.get("scan_id"),
                use_main_branch=bool(proj.get("use_main_branch", False)),
            )
        )

    errors.extend(validate_config(cfg, require_projects=require_projects))
    if errors:
        raise ConfigError("\n".join(f"- {e}" for e in errors))
    return cfg


def validate_config(
    cfg: ReportConfig,
    *,
    require_projects: bool = True,
) -> list[str]:
    """Return a list of human-readable validation errors (empty = valid)."""
    errors: list[str] = []
    report = cfg.report
    for required, label in (
        (report.title, "report.title"),
        (report.company_name, "report.company_name"),
        (report.auditor, "report.auditor"),
        (report.prepared_date, "report.prepared_date"),
        (report.assessment_period, "report.assessment_period"),
    ):
        if not required:
            errors.append(f"{label} is required.")

    if not report.subtitle.strip():
        errors.append("report.subtitle must not be empty.")

    if report.language not in VALID_LANGUAGES:
        errors.append(
            f"report.language must be one of {sorted(VALID_LANGUAGES)} "
            f"(got {report.language!r})."
        )

    if report.logo_path and not Path(report.logo_path).is_file():
        errors.append(f"report.logo_path does not exist: {report.logo_path}")

    if not cfg.projects and require_projects:
        errors.append("At least one entry in 'projects' is required.")
    for i, proj in enumerate(cfg.projects):
        has_name = bool(proj.name)
        has_id = bool(proj.id)
        if has_name == has_id:
            errors.append(
                f"projects[{i}] must have exactly one of 'name' or 'id'."
            )

    if cfg.filters.min_severity not in VALID_SEVERITIES:
        errors.append(
            f"filters.min_severity must be one of {sorted(VALID_SEVERITIES)} "
            f"(got {cfg.filters.min_severity!r})."
        )
    if cfg.filters.dedupe_scope not in VALID_DEDUPE_SCOPES:
        errors.append(
            f"filters.dedupe_scope must be one of "
            f"{sorted(VALID_DEDUPE_SCOPES)} (got {cfg.filters.dedupe_scope!r})."
        )

    for key in ("gap_if_any", "watch_if_any"):
        for sev in getattr(cfg.mapping, key):
            if sev not in VALID_SEVERITIES:
                errors.append(
                    f"mapping.{key} contains invalid severity {sev!r}."
                )

    if cfg.mapping.max_findings_per_requirement < 1:
        errors.append("mapping.max_findings_per_requirement must be >= 1.")

    if cfg.api.page_size < 1:
        errors.append("api.page_size must be >= 1.")

    return errors
