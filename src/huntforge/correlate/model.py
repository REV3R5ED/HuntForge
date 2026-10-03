"""Correlation data model: linkages, activity clusters, narratives.

A **linkage** is an INFERRED hypothesis that two events describe the
same underlying activity (same process, same file, persistence paired
with execution, download followed by execution). Linkages are
deterministic and explainable: each carries its basis, a confidence
with a reason, the heuristic that produced it, and its known failure
modes. Linkages are never observed facts — they are labeled INFERRED
everywhere they are rendered.

An **activity cluster** is a connected component of events joined by
linkages, plus the case findings whose evidence falls inside it, the
entities involved, and the ATT&CK techniques those findings evidence.

A **narrative** is the analyst-facing rendering of one cluster: the
observed timeline, the inferred linkages, detections, techniques, an
explicit confidence, and a "what's missing" section naming the
evidence that would be expected but was not observed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class Linkage:
    """One INFERRED hypothesis joining two events.

    ``kind`` is one of ``same-process``, ``same-file``,
    ``persistence-execution``, ``download-execution`` (see
    ``docs/CORRELATION.md`` for each heuristic and its failure modes).
    ``event_a``/``event_b`` are case event row ids. ``basis`` states
    what matched in plain language; ``confidence`` (0-100) is
    meaningless without ``confidence_reason``.
    """

    kind: str
    event_a: int
    event_b: int
    basis: str
    confidence: int
    confidence_reason: str
    heuristic: str
    failure_modes: str

    def __post_init__(self) -> None:
        if not 0 <= self.confidence <= 100:
            raise ValueError("linkage confidence must be 0-100")
        if self.event_a == self.event_b:
            raise ValueError("a linkage must join two different events")
        if not self.basis:
            raise ValueError("a linkage must state its basis")

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "event_a": self.event_a,
            "event_b": self.event_b,
            "basis": self.basis,
            "confidence": self.confidence,
            "confidence_reason": self.confidence_reason,
            "heuristic": self.heuristic,
            "failure_modes": self.failure_modes,
            "label": "INFERRED",
        }


@dataclass
class ActivityCluster:
    """Events joined by linkages, with findings, entities, techniques.

    ``event_ids`` are case event row ids (ordered by timestamp then id).
    ``findings`` are stored finding dicts (see
    ``CaseDB.list_findings``) whose evidence lands mostly inside this
    cluster. ``techniques`` are ATT&CK ids evidenced by those findings.
    ``confidence`` is the weakest linkage confidence (the chain is only
    as strong as its weakest link), with ``confidence_reason`` naming
    that linkage.
    """

    cluster_id: int
    event_ids: list[int]
    linkages: list[Linkage] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)
    entities: list[dict[str, Any]] = field(default_factory=list)
    techniques: list[dict[str, str]] = field(default_factory=list)
    confidence: int = 0
    confidence_reason: str = ""

    def max_severity_rank(self) -> int:
        from huntforge.detections.model import Severity

        rank = -1
        for finding in self.findings:
            try:
                rank = max(rank, Severity(str(finding.get("severity", ""))).rank())
            except ValueError:
                continue
        return rank

    def to_dict(self) -> dict[str, Any]:
        severities: dict[str, int] = {}
        for finding in self.findings:
            sev = str(finding.get("severity", "informational"))
            severities[sev] = severities.get(sev, 0) + 1
        return {
            "cluster_id": self.cluster_id,
            "event_ids": list(self.event_ids),
            "event_count": len(self.event_ids),
            "linkages": [link.to_dict() for link in self.linkages],
            "findings": [
                {
                    "finding_uid": f.get("finding_uid"),
                    "rule_id": f.get("rule_id"),
                    "title": f.get("title"),
                    "severity": f.get("severity"),
                    "confidence": f.get("confidence"),
                }
                for f in self.findings
            ],
            "finding_count": len(self.findings),
            "by_severity": severities,
            "entities": [dict(e) for e in self.entities],
            "techniques": [dict(t) for t in self.techniques],
            "confidence": self.confidence,
            "confidence_reason": self.confidence_reason,
            "label": "INFERRED",
        }


@dataclass
class Narrative:
    """Full analyst narrative for one activity cluster."""

    cluster_id: int
    confidence: int
    confidence_reason: str
    summary: str
    # OBSERVED: ordered timeline entries (facts, with event row ids).
    observed: list[dict[str, Any]] = field(default_factory=list)
    # INFERRED: the linkage hypotheses and what they claim.
    inferred: list[dict[str, Any]] = field(default_factory=list)
    detections: list[dict[str, Any]] = field(default_factory=list)
    techniques: list[dict[str, str]] = field(default_factory=list)
    entities: list[dict[str, Any]] = field(default_factory=list)
    whats_missing: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "cluster_id": self.cluster_id,
            "confidence": self.confidence,
            "confidence_reason": self.confidence_reason,
            "summary": self.summary,
            "observed": [dict(e) for e in self.observed],
            "inferred": [dict(e) for e in self.inferred],
            "detections": [dict(d) for d in self.detections],
            "techniques": [dict(t) for t in self.techniques],
            "entities": [dict(e) for e in self.entities],
            "whats_missing": list(self.whats_missing),
        }
