"""Detection engine: run rules over a case's events.

The engine loads the case's normalized events, runs the selected
rules, and returns findings ordered by (severity rank, rule id).
It reports which rules had no applicable data so "no findings" is
distinguishable from "no telemetry".
"""

from __future__ import annotations

from typing import Any

from huntforge.detections.model import Finding, Rule, Severity
from huntforge.detections.rules import RULES, get_rule, list_rules


class DetectionEngine:
    """Runs a rule set over normalized events."""

    def __init__(self, events: list[dict[str, Any]]) -> None:
        self.events = events

    def applicable(self, rules: list[Rule]) -> dict[str, bool]:
        """Whether each rule has any of its required telemetry present."""
        present = {(e.get("source"), str(e.get("event_id"))) for e in self.events}
        return {
            rule.id: any(req in present for req in rule.required_sources)
            for rule in rules
        }

    def run(
        self,
        rules: list[Rule] | None = None,
        min_severity: Severity | None = None,
    ) -> list[Finding]:
        """Evaluate rules; findings sorted by severity (desc), then rule id."""
        selected = list(rules) if rules is not None else list(RULES)
        findings: list[Finding] = []
        for rule in selected:
            for finding in rule.evaluate(self.events, rule):
                if min_severity is not None and (
                    finding.severity.rank() < min_severity.rank()
                ):
                    continue
                # v0.6: ATT&CK mapping rides along from the rule unless the
                # finding already carries its own (e.g. Sigma conversions).
                if not finding.mitre:
                    finding.mitre = list(rule.mitre)
                findings.append(finding)
        findings.sort(key=lambda f: (-f.severity.rank(), f.rule_id))
        # Stable per-run UIDs; the CLI re-numbers when persisting.
        for index, finding in enumerate(findings, start=1):
            if not finding.finding_uid:
                finding.finding_uid = f"HF-{index:04d}"
        return findings


def select_rules(rule_ids: list[str] | None) -> list[Rule]:
    """Resolve ``--rule`` IDs to rules; None means the whole catalog."""
    if not rule_ids:
        return list_rules()
    selected: list[Rule] = []
    for rule_id in rule_ids:
        try:
            selected.append(get_rule(rule_id))
        except KeyError as exc:
            valid = ", ".join(r.id for r in list_rules())
            raise ValueError(f"{exc} (valid: {valid})") from None
    return selected


def summarize(findings: list[Finding]) -> dict[str, Any]:
    """Severity histogram for result summaries."""
    counts: dict[str, int] = {}
    for finding in findings:
        counts[finding.severity.value] = counts.get(finding.severity.value, 0) + 1
    return {"total": len(findings), "by_severity": counts}
