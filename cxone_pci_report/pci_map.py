"""Rule engine: map normalized findings to PCI DSS v4.0.1 requirements."""

import json
import logging
import re
from dataclasses import replace
from pathlib import Path

from .models import Finding, Scanner
from .pci_requirements import REQUIREMENT_BY_ID
from .rules import BUILT_IN_RULES, MATCH_TYPES, MappingRule

log = logging.getLogger(__name__)

CVSS_CRITICAL_RULE = MappingRule(
    "synthetic-cvss9", "6.5.6", None, "description_regex", "", priority=5
)


class MappingError(Exception):
    pass


def load_rules(overlay_path: str | Path | None) -> tuple[MappingRule, ...]:
    """Return the effective rule table: built-ins merged with a JSON overlay.

    The overlay is a list of objects, each with ``"action"``
    ("add"|"replace"|"remove", default "add") and either a full ``"rule"``
    object (add/replace) or a ``"rule_id"`` (remove).
    """
    rules_by_id: dict[str, MappingRule] = {
        rule.rule_id: rule for rule in BUILT_IN_RULES
    }
    if not overlay_path:
        return BUILT_IN_RULES

    overlay_path = Path(overlay_path)
    try:
        raw = json.loads(overlay_path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise MappingError(f"Rules overlay file not found: {overlay_path}")
    except json.JSONDecodeError as exc:
        raise MappingError(f"Invalid JSON in rules overlay {overlay_path}: {exc}")

    if not isinstance(raw, list):
        raise MappingError("Rules overlay must be a JSON list of rule actions.")

    for i, entry in enumerate(raw):
        if not isinstance(entry, dict):
            raise MappingError(f"Overlay entry {i} must be an object.")
        action = entry.get("action", "add")
        if action == "remove":
            rule_id = entry.get("rule_id")
            if not rule_id:
                raise MappingError(
                    f"Overlay entry {i}: 'remove' requires 'rule_id'."
                )
            rules_by_id.pop(rule_id, None)
            continue
        rule_dict = entry.get("rule")
        if not isinstance(rule_dict, dict):
            raise MappingError(
                f"Overlay entry {i}: '{action}' requires a 'rule' object."
            )
        rule = _rule_from_dict(rule_dict, entry_index=i)
        if action == "replace" and rule.rule_id not in rules_by_id:
            raise MappingError(
                f"Overlay entry {i}: cannot replace unknown rule "
                f"{rule.rule_id!r}."
            )
        if action not in ("add", "replace"):
            raise MappingError(
                f"Overlay entry {i}: unknown action {action!r}."
            )
        rules_by_id[rule.rule_id] = rule

    return tuple(rules_by_id.values())


def _rule_from_dict(rule_dict: dict, *, entry_index: int) -> MappingRule:
    try:
        rule = MappingRule(
            rule_id=rule_dict["rule_id"],
            requirement=rule_dict["requirement"],
            scanners=(
                tuple(Scanner(s) for s in rule_dict["scanners"])
                if rule_dict.get("scanners")
                else None
            ),
            match_type=rule_dict["match_type"],
            pattern=rule_dict["pattern"],
            priority=int(rule_dict.get("priority", 30)),
        )
    except (KeyError, ValueError, TypeError) as exc:
        raise MappingError(
            f"Overlay entry {entry_index}: invalid rule object: {exc}"
        )
    if rule.requirement not in REQUIREMENT_BY_ID:
        raise MappingError(
            f"Overlay entry {entry_index}: unknown requirement "
            f"{rule.requirement!r}."
        )
    if rule.match_type not in MATCH_TYPES:
        raise MappingError(
            f"Overlay entry {entry_index}: unknown match_type "
            f"{rule.match_type!r}. Valid: {sorted(MATCH_TYPES)}."
        )
    return rule


def _cwe_matches(pattern: str, cwe: str) -> bool:
    """Prefix-normalized CWE equality: 'CWE-89' == '89' == 'CWE 89'."""
    norm = cwe.upper().replace(" ", "")
    if norm.isdigit():
        norm = f"CWE-{norm}"
    return norm == pattern.upper()


def _match(rule: MappingRule, finding: Finding) -> bool:
    if rule.scanners is not None and finding.scanner not in rule.scanners:
        return False

    match_type, pattern = rule.match_type, rule.pattern
    if match_type == "cwe":
        return bool(finding.cwe) and _cwe_matches(pattern, finding.cwe)
    if match_type == "cve_regex":
        return bool(finding.cve) and re.search(pattern, finding.cve) is not None
    if match_type == "package_regex":
        return bool(finding.component) and (
            re.search(pattern, finding.component) is not None
        )
    if match_type == "description_regex":
        return re.search(pattern, finding.description or "") is not None
    if match_type in (
        "query_name_regex",
        "kics_query_name_regex",
        "apisec_risk_type",
    ):
        expected_scanner = {
            "query_name_regex": Scanner.SAST,
            "kics_query_name_regex": Scanner.KICS,
            "apisec_risk_type": Scanner.APISEC,
        }[match_type]
        if finding.scanner is not expected_scanner:
            return False
        return re.search(pattern, finding.title) is not None
    return False


def map_finding(
    finding: Finding,
    rules: tuple[MappingRule, ...],
    *,
    default_requirement: str = "6.3.1",
) -> Finding:
    """Attach PCI requirements to a finding; returns a new Finding.

    All matching requirements are collected; the primary is the lowest
    priority (ties: first in table order). Unmatched findings fall back to
    ``default_requirement``.
    """
    candidates: list[tuple[int, MappingRule]] = []
    if finding.cvss is not None and finding.cvss >= 9.0:
        candidates.append((CVSS_CRITICAL_RULE.priority, CVSS_CRITICAL_RULE))
    for rule in rules:
        if _match(rule, finding):
            candidates.append((rule.priority, rule))

    if candidates:
        candidates.sort(key=lambda item: item[0])
        requirements = tuple(dict.fromkeys(rule.requirement for _, rule in candidates))
        primary = candidates[0][1].requirement
    else:
        requirements = (default_requirement,)
        primary = default_requirement

    return replace(
        finding,
        pci_requirements=requirements,
        pci_primary=primary,
    )
