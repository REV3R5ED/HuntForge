"""Rule → ATT&CK technique mapping (v0.6).

The mapping is curated, one entry per built-in detection rule, and
documented with reasoning in ``docs/ATTACK.md``. Every finding the
detection engine produces carries its rule's techniques (see
``DetectionEngine.run``), so coverage is computed from findings, not
from rule metadata — a technique counts as "covered" only when a
finding actually fired.

Coverage philosophy: a mapped finding is evidence that a technique
was *used* in the case. It is never attribution of actor intent, and
a technique with no findings is a gap in *evidence*, not proof of
absence.
"""

from __future__ import annotations

from typing import Any

from huntforge.detections.rules import RULES
from huntforge.mitre.table import KNOWN_IDS


def rule_techniques() -> dict[str, list[str]]:
    """Rule ID → ATT&CK technique IDs, from the rule catalog itself."""
    return {rule.id: list(rule.mitre) for rule in RULES}


def validate_mapping() -> list[str]:
    """Check mapping completeness; returns a list of problems (empty = ok).

    - Every built-in rule must map to at least one technique.
    - Every mapped technique must exist in the curated table.
    """
    problems: list[str] = []
    for rule in RULES:
        if not rule.mitre:
            problems.append(f"rule {rule.id} has no ATT&CK mapping")
        for technique_id in rule.mitre:
            if technique_id.upper() not in KNOWN_IDS:
                problems.append(
                    f"rule {rule.id} maps to unknown technique {technique_id}"
                )
    return problems


def coverage_from_findings(
    findings: list[dict[str, Any]],
) -> dict[str, Any]:
    """Technique coverage over stored case findings.

    Each stored finding is expected to carry ``mitre`` (a list of
    technique IDs) and ``rule_id``. Unknown technique IDs are reported
    separately rather than silently dropped.
    """
    by_technique: dict[str, dict[str, Any]] = {}
    unknown: dict[str, list[str]] = {}
    for finding in findings:
        techniques = finding.get("mitre") or []
        for technique_id in techniques:
            tid = str(technique_id).upper()
            if tid not in KNOWN_IDS:
                unknown.setdefault(tid, []).append(
                    str(finding.get("finding_uid") or "?")
                )
                continue
            entry = by_technique.setdefault(
                tid, {"technique_id": tid, "finding_count": 0, "rules": {}}
            )
            entry["finding_count"] = int(entry["finding_count"]) + 1
            rules = entry["rules"]
            assert isinstance(rules, dict)
            rid = str(finding.get("rule_id") or "?")
            rules[rid] = rules.get(rid, 0) + 1
    covered = sorted(by_technique)
    return {
        "covered": [by_technique[tid] for tid in covered],
        "covered_count": len(covered),
        "unknown_technique_ids": sorted(unknown),
        "unknown_references": unknown,
    }
