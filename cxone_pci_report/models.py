"""Core data models shared across the pipeline."""

from dataclasses import dataclass, field
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Scanner(str, Enum):
    SAST = "sast"
    SCA = "sca"
    KICS = "kics"
    APISEC = "apisec"


SEVERITY_ORDER: tuple[Severity, ...] = (
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
)

SEVERITY_RANK = {sev: rank for rank, sev in enumerate(SEVERITY_ORDER)}


def severity_rank(severity: Severity) -> int:
    """Lower rank = more severe (0 = CRITICAL)."""
    return SEVERITY_RANK[severity]


@dataclass(frozen=True)
class Finding:
    """A normalized finding from any supported scanner."""

    finding_id: str
    scanner: Scanner
    severity: Severity
    state: str | None
    status: str | None
    confidence_level: int | None
    project_id: str
    project_name: str
    scan_id: str
    similarity_id: str | None
    title: str
    description: str
    component: str | None
    location: str | None
    cwe: str | None
    cve: str | None
    cvss: float | None
    remediation: str | None
    found_at: str | None
    pci_tagged: bool = False
    # Filled in by pci_map.map_finding (which returns a new Finding):
    pci_requirements: tuple[str, ...] = ()
    pci_primary: str | None = None


@dataclass
class ProjectScan:
    """A project resolved to one scan, plus its findings."""

    project_id: str
    project_name: str
    display_name: str
    scan_id: str
    scan_created_at: str | None
    scan_status: str | None
    branch: str | None
    engines: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
