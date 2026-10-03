"""Sigma-subset evaluation over normalized events (v0.6).

A :class:`SigmaRule` becomes findings — one per matching event — with
the same explainable shape as built-in detections: ``why`` names the
matched selections, ``evidence`` cites the event, and the finding
keeps provenance ``huntforge.sigma`` (rule version ``0.6.0``).

Only the documented subset evaluates (see :mod:`huntforge.sigma.model`).
Anything outside it is a load-time :class:`SigmaError`, never a silent
mis-evaluation.
"""

from __future__ import annotations

import fnmatch
from typing import Any

from huntforge.detections.model import EvidenceRef, Finding, Severity
from huntforge.sigma.loader import logsource_filter, technique_ids_from_tags
from huntforge.sigma.model import (
    LEVEL_CONFIDENCE,
    LEVELS,
    SigmaError,
    SigmaRule,
)

SIGMA_PROVENANCE = "huntforge.sigma"
SIGMA_RULE_VERSION = "0.6.0"


def _match_value(pattern: str, actual: object) -> bool:
    """Case-insensitive match with ``*`` wildcards (fnmatch)."""
    if actual is None:
        return False
    return fnmatch.fnmatchcase(str(actual).lower(), pattern.lower())


def _selection_matches(
    fields: dict[str, list[str]], event: dict[str, Any]
) -> list[str]:
    """Fields that matched, or [] when the selection does not match.

    All fields must match (AND); multiple values per field are OR.
    """
    matched: list[str] = []
    for event_field, patterns in fields.items():
        actual = event.get(event_field)
        hit = next((p for p in patterns if _match_value(p, actual)), None)
        if hit is None:
            return []
        matched.append(f"{event_field} matches {hit!r}")
    return matched


class _Condition:
    """Tiny recursive-descent evaluator for the supported conditions."""

    def __init__(self, rule: SigmaRule, selection_hit: dict[str, bool]) -> None:
        self.rule = rule
        self.hit = selection_hit
        self.tokens = self._tokenize(rule.condition, rule.id)
        self.pos = 0

    @staticmethod
    def _tokenize(condition: str, rule_id: str) -> list[str]:
        if "(" in condition or ")" in condition:
            raise SigmaError(
                f"rule {rule_id}: parentheses are not supported "
                "in conditions (use 'a and b' / '1 of sel*' forms)"
            )
        return condition.split()

    def evaluate(self) -> bool:
        result = self._parse_or()
        if self.pos != len(self.tokens):
            raise SigmaError(
                f"rule {self.rule.id}: cannot parse condition "
                f"{self.rule.condition!r} near {self.tokens[self.pos]!r}"
            )
        return result

    def _peek(self) -> str | None:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def _next(self) -> str:
        token = self._peek()
        if token is None:  # pragma: no cover - guarded by callers
            raise SigmaError(f"rule {self.rule.id}: truncated condition")
        self.pos += 1
        return token

    def _parse_or(self) -> bool:
        result = self._parse_and()
        while (self._peek() or "").lower() == "or":
            self._next()
            result = self._parse_and() or result
        return result

    def _parse_and(self) -> bool:
        result = self._parse_not()
        while (self._peek() or "").lower() == "and":
            self._next()
            result = self._parse_not() and result
        return result

    def _parse_not(self) -> bool:
        if (self._peek() or "").lower() == "not":
            self._next()
            return not self._parse_not()
        return self._parse_atom()

    def _parse_atom(self) -> bool:
        token = self._next()
        lowered = token.lower()
        if lowered == "all" and (self._peek() or "").lower() == "of":
            self._next()
            pattern = self._next()
            names = self._glob(pattern)
            if not names:
                raise SigmaError(
                    f"rule {self.rule.id}: 'all of {pattern}' matches no selection"
                )
            return all(self.hit[name] for name in names)
        if token.isdigit() and (self._peek() or "").lower() == "of":
            self._next()
            pattern = self._next()
            names = self._glob(pattern)
            if not names:
                raise SigmaError(
                    f"rule {self.rule.id}: '{token} of {pattern}' matches no selection"
                )
            return sum(1 for name in names if self.hit[name]) >= int(token)
        if token not in self.hit:
            raise SigmaError(
                f"rule {self.rule.id}: condition references unknown selection {token!r}"
            )
        return self.hit[token]

    def _glob(self, pattern: str) -> list[str]:
        return [
            name
            for name in self.rule.selection_names()
            if fnmatch.fnmatchcase(name, pattern)
        ]


def _event_summary(event: dict[str, Any]) -> str:
    bits = [
        f"{event.get('source')}:{event.get('event_id')}",
        f"host={event.get('host') or '-'}",
    ]
    if event.get("process_name"):
        bits.append(f"process={event['process_name']}")
    if event.get("command_line"):
        bits.append(f"cmd={(str(event['command_line'])[:80])}")
    return " ".join(bits)


def evaluate_rule(rule: SigmaRule, events: list[dict[str, Any]]) -> list[Finding]:
    """Evaluate one Sigma rule; one finding per matching event."""
    techniques = technique_ids_from_tags(rule.tags)
    source_filter = logsource_filter(rule.logsource)
    severity = Severity(LEVELS[rule.level])
    confidence = LEVEL_CONFIDENCE[rule.level]
    findings: list[Finding] = []
    for event in events:
        if source_filter is not None:
            want_source, want_ids = source_filter
            if event.get("source") != want_source:
                continue
            if want_ids and str(event.get("event_id")) not in want_ids:
                continue
        selection_detail: dict[str, list[str]] = {}
        for name, fields in rule.detection.items():
            matched = _selection_matches(fields, event)
            selection_detail[name] = matched
        hits = {name: bool(detail) for name, detail in selection_detail.items()}
        try:
            condition_hit = _Condition(rule, hits).evaluate()
        except SigmaError:
            raise
        if not condition_hit:
            continue
        why = [
            f"selection {name!r} matched ({'; '.join(selection_detail[name])})"
            for name in sorted(hits)
            if hits[name]
        ]
        technique_bits = f" (ATT&CK: {', '.join(techniques)})" if techniques else ""
        findings.append(
            Finding(
                rule_id=rule.id,
                rule_version=SIGMA_RULE_VERSION,
                title=rule.title,
                severity=severity,
                confidence=confidence,
                confidence_reason=(
                    f"Confidence derives from the rule author's level "
                    f"({rule.level}), not from independent HuntForge "
                    f"analysis — treat it as the author's prior."
                ),
                why=why,
                what=(
                    f"Sigma rule {rule.id} {rule.title!r} matched event "
                    f"#{event.get('id')}: {_event_summary(event)}"
                    f"{technique_bits}"
                ),
                evidence=[
                    EvidenceRef(
                        event_id=int(event["id"]),
                        source=str(event.get("source") or "?"),
                        source_event_id=str(event.get("event_id") or "?"),
                        observation=(
                            f"sigma selections matched: "
                            f"{', '.join(sorted(n for n, h in hits.items() if h))}"
                        ),
                    )
                ],
                observed=[
                    f"event #{event.get('id')} ({_event_summary(event)}) "
                    f"satisfies condition {rule.condition!r}"
                ],
                inferred=[
                    "the rule author associates this pattern with "
                    f"{', '.join(techniques) if techniques else 'no ATT&CK technique'} "
                    "(analyst judgment required)"
                ],
                mitre=techniques,
                provenance=SIGMA_PROVENANCE,
            )
        )
    findings.sort(key=lambda f: f.evidence[0].event_id)
    return findings
