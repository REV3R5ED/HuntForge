"""Detection data model: severity, evidence references, findings, rules.

Every v0.5 detection is *explainable*: a finding carries the matched
conditions (``why``), a plain-language summary (``what``), a numeric
confidence *with its reasoning*, and a full evidence chain — each cited
event row plus the observation drawn from it. Observed facts and
inferences are kept in separate fields so the analyst always knows
which is which. There is no ML and no black box: the rule logic is
plain Python and is documented rule-by-rule in ``docs/DETECTIONS.md``.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    """Detection severity, ordered least to most severe.

    - ``informational``: context worth knowing, no action implied.
    - ``low``: weak or noisy indicator; usually needs corroboration.
    - ``medium``: notable technique indicator; investigate in context.
    - ``high``: strong technique indicator; prioritize investigation.
    - ``critical``: reserved for confirmed-compromise indicators.
      No v0.5 starter rule emits ``critical`` — a heuristic alone is
      never enough to declare a compromise (see docs/DETECTIONS.md).
    """

    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    def rank(self) -> int:
        return _SEVERITY_RANK[self]

    @classmethod
    def parse(cls, value: str) -> tuple[Severity, bool]:
        """Parse ``high`` or ``high+`` (``+`` means "this level and above").

        Returns ``(minimum severity, at_least)``.
        """
        text = value.strip().lower()
        at_least = text.endswith("+")
        name = text[:-1] if at_least else text
        try:
            return cls(name), at_least
        except ValueError:
            valid = ", ".join(s.value for s in cls)
            raise ValueError(
                f"unknown severity {value!r} (expected one of: {valid}, "
                "optionally suffixed with '+')"
            ) from None


_SEVERITY_RANK = {
    Severity.INFORMATIONAL: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


@dataclass
class EvidenceRef:
    """One cited event: the case event row plus what it shows.

    ``event_id`` is the row id in the case event store (the ``[#]`` in
    ``huntforge events`` output), so every finding can be re-derived.
    """

    event_id: int
    source: str
    source_event_id: str
    observation: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "source": self.source,
            "source_event_id": self.source_event_id,
            "observation": self.observation,
        }


@dataclass
class Finding:
    """One rule match, fully explained.

    ``why`` lists the matched conditions in plain language;
    ``observed`` states facts drawn from evidence; ``inferred`` states
    what those facts *suggest* (clearly labeled — the analyst decides).
    ``confidence`` is 0-100 and is meaningless without
    ``confidence_reason``.
    """

    rule_id: str
    rule_version: str
    title: str
    severity: Severity
    confidence: int
    confidence_reason: str
    why: list[str]
    what: str
    evidence: list[EvidenceRef]
    observed: list[str] = field(default_factory=list)
    inferred: list[str] = field(default_factory=list)
    finding_uid: str = ""
    # v0.6: ATT&CK technique IDs this finding evidences (e.g. ["T1059.001"]).
    # Evidence of technique *use*, never attribution of actor intent.
    mitre: list[str] = field(default_factory=list)
    # Provenance of the finding producer: "huntforge.detections" for the
    # built-in rule catalog, "huntforge.sigma" for Sigma-converted rules.
    provenance: str = "huntforge.detections"

    def __post_init__(self) -> None:
        if not self.evidence:
            raise ValueError("a finding must cite at least one event")
        if not 0 <= self.confidence <= 100:
            raise ValueError("confidence must be 0-100")
        if not self.why:
            raise ValueError("a finding must explain why it fired")

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_uid": self.finding_uid,
            "rule_id": self.rule_id,
            "rule_version": self.rule_version,
            "title": self.title,
            "severity": self.severity.value,
            "confidence": self.confidence,
            "confidence_reason": self.confidence_reason,
            "why": list(self.why),
            "what": self.what,
            "evidence": [e.to_dict() for e in self.evidence],
            "observed": list(self.observed),
            "inferred": list(self.inferred),
            "mitre": list(self.mitre),
            "provenance": self.provenance,
        }


@dataclass
class Rule:
    """A named, versioned detection rule.

    ``evaluate`` takes the case's normalized events (as stored dicts,
    see ``CaseDB.all_events``) and returns findings with complete
    evidence chains. ``required_sources`` names the (source, event_id)
    pairs the rule reads, e.g. ``[("sysmon", "1")]`` — used for the
    rule catalog and for "no applicable data" reporting.
    """

    id: str
    title: str
    description: str
    severity: Severity
    version: str
    required_sources: list[tuple[str, str]]
    logic: str
    false_positives: str
    evidence_requirements: str
    evaluate: Callable[[list[dict[str, Any]], Rule], list[Finding]]
    # v0.6: ATT&CK technique IDs this rule evidences. Mapping is curated
    # and documented in docs/ATTACK.md; the engine copies it onto findings.
    mitre: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "version": self.version,
            "required_sources": [
                {"source": s, "event_id": e} for s, e in self.required_sources
            ],
            "logic": self.logic,
            "false_positives": self.false_positives,
            "evidence_requirements": self.evidence_requirements,
            "mitre": list(self.mitre),
        }
