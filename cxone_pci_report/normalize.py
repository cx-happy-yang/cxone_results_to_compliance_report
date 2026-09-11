"""Normalize per-scanner SDK payloads into the common :class:`Finding` model.

Every extractor is total: it never raises. Missing/malformed fields degrade
to safe defaults (None / empty strings) so a single bad payload cannot abort
a whole report run.
"""

import logging
import re
from typing import Any

from .models import Finding, Scanner, Severity

log = logging.getLogger(__name__)

_TITLE_CASE_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
    "informational": Severity.INFO,
}


def normalize_severity(value: Any) -> Severity:
    """Map any severity spelling to a Severity; unknown values become INFO.

    CxOne APIs are inconsistent: SAST/KICS/APISec use uppercase enums, the
    SCA endpoint uses title case ("High"). CRITICAL is accepted even though
    some docstrings omit it.
    """
    if value is None:
        return Severity.INFO
    text = str(value).strip()
    upper = text.upper()
    if upper in {sev.value for sev in Severity}:
        return Severity(upper)
    return _TITLE_CASE_MAP.get(text.lower(), Severity.INFO)


def _safe_str(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _safe_int(value: Any) -> int | None:
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def _safe_float(value: Any) -> float | None:
    try:
        return float(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def _norm_cwe(value: Any) -> str | None:
    """Normalize CWE spellings: 89, CWE-89, CWE 89 -> 'CWE-89'."""
    text = _safe_str(value)
    if not text:
        return None
    upper = text.upper().replace(" ", "")
    if upper.isdigit():
        return f"CWE-{upper}"
    if upper.startswith("CWE-") and upper[4:].isdigit():
        return upper
    if upper.startswith("CWE") and upper[3:].isdigit():
        return f"CWE-{upper[3:]}"
    return text


def _norm_cve(value: Any) -> str | None:
    text = _safe_str(value)
    if not text:
        return None
    return text if text.upper().startswith("CVE-") else None


def _first(seq: Any) -> Any:
    if isinstance(seq, (list, tuple)) and seq:
        return seq[0]
    return None


_VERSION_SUFFIX = re.compile(r"^(?P<name>.+?)-(?P<version>\d+(?:\.\d+)*.*)$")


def _parse_sca_package(package_id: str) -> tuple[str | None, str | None]:
    """Split 'Yarn-commons-collections:commons-collections-3.2.1' into
    (package name, version).

    The last colon-separated segment is '<artifact>-<version>'; the version
    is extracted with a heuristic (starts with digits). Unknown layouts
    degrade gracefully to (package_id, None).
    """
    if not package_id:
        return None, None
    if ":" in package_id:
        group, artifact_version = package_id.rsplit(":", 1)
        match = _VERSION_SUFFIX.match(artifact_version)
        if match:
            return (
                f"{group}:{match.group('name')}" or None,
                match.group("version") or None,
            )
        return (package_id or None), None
    match = _VERSION_SUFFIX.match(package_id)
    if match:
        return (match.group("name") or None), (match.group("version") or None)
    return package_id, None


def from_sast(
    result: Any,
    *,
    project_id: str,
    project_name: str,
    scan_id: str,
) -> Finding:
    """Convert a SastResult (from get_sast_results_by_scan_id)."""
    nodes = getattr(result, "nodes", None) or []
    first_node = _first(nodes)
    file_name = getattr(first_node, "file_name", None) or getattr(
        first_node, "fileName", None
    )
    line = getattr(first_node, "line", None) or getattr(
        first_node, "line_number", None
    )
    location = _safe_str(file_name)
    if location and line:
        location = f"{location}:{line}"

    compliances = getattr(result, "compliances", None) or []
    pci_tagged = any(
        "PCI" in str(c).upper()
        for c in (compliances if isinstance(compliances, (list, tuple)) else [])
    )

    return Finding(
        finding_id=_safe_str(getattr(result, "id", None)) or _safe_str(
            getattr(result, "result_hash", None)
        ) or "unknown",
        scanner=Scanner.SAST,
        severity=normalize_severity(getattr(result, "severity", None)),
        state=_safe_str(getattr(result, "state", None)),
        status=_safe_str(getattr(result, "status", None)),
        confidence_level=_safe_int(getattr(result, "confidence_level", None)),
        project_id=project_id,
        project_name=project_name,
        scan_id=scan_id,
        similarity_id=_safe_str(getattr(result, "similarity_id", None)),
        title=_safe_str(getattr(result, "query_name", None)) or "SAST finding",
        description=_safe_str(getattr(result, "description", None)) or "",
        component=_safe_str(file_name),
        location=location,
        cwe=_norm_cwe(getattr(result, "cwe_id", None)),
        cve=None,
        cvss=None,
        remediation=None,
        found_at=_safe_str(getattr(result, "first_found_at", None))
        or _safe_str(getattr(result, "found_at", None)),
        pci_tagged=pci_tagged,
    )


def from_sca(
    item: dict,
    *,
    project_id: str,
    project_name: str,
    scan_id: str,
) -> Finding:
    """Convert an SCA vulnerability dict (from ScaAPI.get_vulnerabilities_of_a_scan)."""
    cve = _norm_cve(item.get("cveName")) or _norm_cve(item.get("id"))
    package_name, package_version = _parse_sca_package(
        _safe_str(item.get("packageId")) or ""
    )
    title_parts = [p for p in (package_name, cve) if p]
    remediation = _safe_str(item.get("recommendations"))
    if not remediation:
        fix = _safe_str(item.get("fixResolutionText"))
        if fix:
            remediation = f"Upgrade to version {fix} or later."

    return Finding(
        finding_id=_safe_str(item.get("id")) or "unknown",
        scanner=Scanner.SCA,
        severity=normalize_severity(item.get("severity")),
        state=None,
        status=None,
        confidence_level=None,
        project_id=project_id,
        project_name=project_name,
        scan_id=scan_id,
        similarity_id=_safe_str(item.get("similarityId")),
        title=": ".join(title_parts) or "SCA vulnerability",
        description=_safe_str(item.get("description")) or "",
        component=package_name,
        location=f"{package_name}@{package_version}" if package_name else None,
        cwe=_norm_cwe(item.get("cwe")),
        cve=cve,
        cvss=_safe_float(item.get("score")),
        remediation=remediation,
        found_at=_safe_str(item.get("publishDate")),
    )


def from_kics(
    result: Any,
    *,
    project_id: str,
    project_name: str,
    scan_id: str,
) -> Finding:
    """Convert a KicsResult (from get_kics_results_by_scan_id)."""
    file_name = _safe_str(getattr(result, "file_name", None))
    line = _safe_int(getattr(result, "line", None))
    location = file_name
    if location and line is not None:
        location = f"{location}:{line}"

    expected = _safe_str(getattr(result, "expected_value", None))
    actual = _safe_str(getattr(result, "actual_value", None))
    remediation = None
    if expected and actual:
        remediation = f"Expected: {expected}; actual: {actual}."
    elif expected:
        remediation = f"Expected: {expected}."

    return Finding(
        finding_id=_safe_str(getattr(result, "kics_result_id", None)) or "unknown",
        scanner=Scanner.KICS,
        severity=normalize_severity(getattr(result, "severity", None)),
        state=_safe_str(getattr(result, "state", None)),
        status=_safe_str(getattr(result, "status", None)),
        confidence_level=None,
        project_id=project_id,
        project_name=project_name,
        scan_id=scan_id,
        similarity_id=_safe_str(getattr(result, "similarity_id", None)),
        title=_safe_str(getattr(result, "query_name", None)) or "KICS finding",
        description=_safe_str(getattr(result, "description", None)) or "",
        component=file_name,
        location=location,
        cwe=None,
        cve=None,
        cvss=None,
        remediation=remediation,
        found_at=_safe_str(getattr(result, "first_found_at", None))
        or _safe_str(getattr(result, "found_at", None)),
    )


def from_apisec(
    risk: Any,
    *,
    project_id: str,
    project_name: str,
    scan_id: str,
) -> Finding:
    """Convert an APISec Risk (from get_api_security_risks_by_scan_id)."""
    asset_name = _safe_str(getattr(risk, "assetName", None))
    asset_type = _safe_str(getattr(risk, "assetType", None))
    return Finding(
        finding_id=_safe_str(getattr(risk, "id", None)) or "unknown",
        scanner=Scanner.APISEC,
        severity=normalize_severity(getattr(risk, "severity", None)),
        state=_safe_str(getattr(risk, "state", None)),
        status=_safe_str(getattr(risk, "status", None)),
        confidence_level=None,
        project_id=project_id,
        project_name=project_name,
        scan_id=scan_id,
        similarity_id=_safe_str(getattr(risk, "groupId", None)),
        title=_safe_str(getattr(risk, "riskName", None)) or "API Security risk",
        description="",
        component=asset_name,
        location=asset_type,
        cwe=None,
        cve=None,
        cvss=None,
        remediation=None,
        found_at=_safe_str(getattr(risk, "firstDetectionDate", None)),
    )
