"""Case report model for HuntForge v0.8.

A **case report** assembles everything in a case — metadata, evidence,
timeline, lineage, detections, ATT&CK coverage, correlations, entities,
analyst notes, methodology, limitations, and chain of custody — into one
structured document.

Reporting philosophy (following the AegisForge v1.0 reporting model):

- OBSERVED facts and INFERRED hypotheses are labeled everywhere they
  appear. Findings, linkages, and narratives already carry the split;
  the report preserves it instead of flattening it.
- The executive summary is machine-generated from counts. It is marked
  ``generated: true`` and ``analyst_review_required: true`` — it is a
  starting point, not a conclusion.
- Analyst notes are analyst-authored free text, stored verbatim, and
  always rendered under a clearly-marked section. HuntForge never
  writes notes itself.
- "What this report does not claim" states the boundaries up front.
"""

from __future__ import annotations

from typing import Any

from huntforge import __version__ as tool_version
from huntforge import correlate as correlate_mod
from huntforge import mitre as mitre_mod
from huntforge import timeline as timeline_mod
from huntforge.core.logging import utc_now_iso
from huntforge.store.db import CaseDB
from huntforge.timeline.timeline import TimelineOptions, build_timeline

REPORT_SCHEMA_VERSION = "0.8.0"
REPORTING_VERSION = "0.8.0"

# Sections every report must contain (assembly-completeness gate).
REQUIRED_SECTIONS = (
    "meta",
    "executive_summary",
    "what_this_report_does_not_claim",
    "methodology",
    "case_overview",
    "timeline_highlights",
    "process_lineage",
    "detections",
    "attack_coverage",
    "correlations",
    "entities",
    "analyst_notes",
    "limitations",
    "chain_of_custody",
)

DOES_NOT_CLAIM = [
    "This report does not attribute activity to a named threat actor. "
    "Technique IDs describe observed behavior shapes, not intent or identity.",
    "This report does not declare the case clean. Absence of findings is "
    "absence of observed evidence, not evidence of absence — see the "
    '"what\'s missing" notes in each narrative.',
    "INFERRED linkages are deterministic hypotheses with documented "
    "failure modes, not facts. They are labeled wherever they appear.",
    "Timestamps are only as good as the source clocks; clock skew between "
    "hosts is not corrected.",
    "The executive summary is machine-generated from counts and requires "
    "analyst review before it leaves the team.",
]

LIMITATIONS = [
    "Binary .evtx is not parsed: exported Event XML/JSON only.",
    "Prefetch versions 23/26/30 only; no Amcache/Shimcache parsing.",
    "Offline registry hives only; no transaction-log replay.",
    "Timeline ordering is only as good as source clocks.",
    "Lineage PID-reuse handling is heuristic; ambiguity notes are the "
    "safety net, not a guarantee.",
    "A mapped finding is evidence of technique use, never attribution of intent.",
    "PDF export is out of scope in v0.8 (stdlib-only; no PDF writer).",
]


def _finding_to_report(finding: dict[str, Any]) -> dict[str, Any]:
    """Render one stored finding with explicit OBSERVED/INFERRED labels."""
    explanation = finding.get("explanation") or {}
    return {
        "finding_uid": finding.get("finding_uid"),
        "rule_id": finding.get("rule_id"),
        "rule_version": finding.get("rule_version"),
        "severity": finding.get("severity"),
        "title": finding.get("title"),
        "confidence": finding.get("confidence"),
        "confidence_reason": finding.get("confidence_reason", ""),
        "why": list(explanation.get("why") or []),
        "what": explanation.get("what", ""),
        "observed": {
            "label": "OBSERVED",
            "facts": list(explanation.get("observed") or []),
        },
        "inferred": {
            "label": "INFERRED",
            "hypotheses": list(explanation.get("inferred") or []),
        },
        "evidence": list(finding.get("evidence") or []),
        "mitre": list(finding.get("mitre") or []),
        "provenance": finding.get("provenance"),
        "created_at": finding.get("created_at"),
    }


def _summarize_event(event: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": event.get("id"),
        "timestamp": event.get("timestamp"),
        "source": event.get("source"),
        "event_id": event.get("event_id"),
        "host": event.get("host"),
        "user": event.get("user"),
        "process": event.get("process_name"),
        "command_line": event.get("command_line"),
        "file_path": event.get("file_path"),
        "registry_key": event.get("registry_key"),
        "dst": (
            f"{event.get('dst_ip')}:{event.get('dst_port')}"
            if event.get("dst_ip")
            else None
        ),
    }


def build_report(db: CaseDB) -> dict[str, Any]:
    """Assemble the full case report for an open case database."""
    meta = db.meta()
    case_id = meta.get("case_id", db.case_id)
    events = db.all_events()
    findings = db.list_findings()
    notes = db.list_notes()
    evidence = [
        {
            "id": int(e.id),
            "filename": e.filename,
            "size": e.size,
            "sha256": e.sha256,
            "md5": e.md5,
            "ingested_at": e.ingested_at,
            "parser": e.parser,
        }
        for e in db.list_evidence()
    ]

    # --- methodology: which parsers produced this evidence ---------------
    parsers: dict[str, str] = {}
    for event in events:
        prov = event.get("provenance") or {}
        name = str(prov.get("parser_name") or "unknown")
        version = str(prov.get("parser_version") or "?")
        parsers[name] = version
    audit_commands = [entry["command"] for entry in db.audit_log(limit=1000)]

    # --- overview ---------------------------------------------------------
    per_source: dict[str, dict[str, Any]] = {}
    for event in events:
        source = str(event.get("source") or "unknown")
        stat = per_source.setdefault(
            source, {"source": source, "events": 0, "first": None, "last": None}
        )
        stat["events"] += 1
        ts = str(event.get("timestamp") or "")
        if stat["first"] is None or ts < stat["first"]:
            stat["first"] = ts
        if stat["last"] is None or ts > stat["last"]:
            stat["last"] = ts
    untimed = sum(1 for e in events if not e.get("timestamp_original"))

    # --- timeline highlights ----------------------------------------------
    timeline = build_timeline(db, TimelineOptions(limit=10_000))
    timed = timeline.timed
    highlights = {
        "first_events": [_summarize_event(e) for e in timed[:10]],
        "last_events": [_summarize_event(e) for e in timed[-10:]] if timed else [],
        "timed_count": len(timed),
        "untimed_count": len(timeline.untimed),
        "per_source_coverage": timeline.coverage,
        "note": (
            "Untimed events are listed, never placed on the timeline. "
            "Ordering is only as good as source clocks."
        ),
    }

    # --- process lineage ---------------------------------------------------
    forest = timeline_mod.lineage_mod.build_lineage(db)
    instances = forest["instances"]
    forest_lines = timeline_mod.lineage_mod.render_forest(
        forest, list(forest["roots"])
    )[:200]
    lineage_summary = {
        "instances": forest["instance_count"],
        "roots": list(forest["roots"]),
        "pid_reuse": list(forest["reused_pids"]),
        "ambiguous_parents": sum(
            1 for inst in instances.values() if inst.ambiguous_parent
        ),
        "orphans": sum(1 for inst in instances.values() if inst.orphan),
        "forest": forest_lines,
        "note": "OBSERVED process instances. Parent links use the "
        "latest-plausible-parent heuristic; ambiguity is noted, never "
        "hidden.",
    }

    # --- detections ---------------------------------------------------------
    by_severity: dict[str, int] = {}
    for finding in findings:
        sev = str(finding.get("severity") or "unknown")
        by_severity[sev] = by_severity.get(sev, 0) + 1
    detections = {
        "count": len(findings),
        "by_severity": by_severity,
        "findings": [_finding_to_report(f) for f in findings],
    }

    # --- ATT&CK coverage ----------------------------------------------------
    table = mitre_mod.TABLE
    coverage = mitre_mod.coverage_from_findings(findings)
    covered_ids = {str(e["technique_id"]) for e in coverage["covered"]}
    attack_coverage = {
        "attack_snapshot": table.attack_snapshot,
        "covered": [
            {
                "technique_id": tid,
                "name": table.get(tid).name,
                "findings": [
                    str(f["finding_uid"])
                    for f in findings
                    if tid in [str(t).upper() for t in f.get("mitre") or []]
                ],
            }
            for tid in sorted(covered_ids)
        ],
        "gaps": [tid for tid in table.ids() if tid not in covered_ids],
        "unobservable": [t.id for t in table.techniques if not t.huntforge_sources],
        "note": "A covered technique means findings evidence that "
        "behavior shape — never attribution of intent.",
    }

    # --- correlations --------------------------------------------------------
    clusters, stats = correlate_mod.engine_mod.correlate_case(events, findings)
    narratives = [
        correlate_mod.engine_mod.build_narrative(cluster, events).to_dict()
        for cluster in clusters
    ]
    for narrative, cluster in zip(narratives, clusters, strict=True):
        narrative["label_observed"] = "OBSERVED"
        narrative["label_inferred"] = "INFERRED"
        narrative["cluster_id"] = cluster.cluster_id
    correlations = {
        "cluster_count": len(clusters),
        "linkage_kinds": stats.get("linkage_kinds", {}),
        "uncorrelated_events": stats.get("uncorrelated_events", 0),
        "clusters": narratives,
        "note": "Observed events and inferred linkages are separate "
        "sections inside each narrative.",
    }

    # --- entities -------------------------------------------------------------
    resolved = timeline_mod.entities_mod.resolve_entities(db)
    by_type: dict[str, int] = {}
    for entity in resolved:
        by_type[entity.type] = by_type.get(entity.type, 0) + 1
    entities = {
        "count": len(resolved),
        "by_type": by_type,
        "entities": [
            {
                "type": entity.type,
                "value": entity.value,
                "observed_as": sorted(entity.observed_as),
                "observations": entity.count,
                "sources": sorted(entity.sources),
                "first_seen": entity.first_seen,
                "last_seen": entity.last_seen,
            }
            for entity in resolved
        ],
    }

    # --- executive summary (generated; needs analyst review) -------------------
    top_sev = "none"
    for sev in ("critical", "high", "medium", "low", "informational"):
        if by_severity.get(sev):
            top_sev = sev
            break
    summary_text = (
        f"Case {case_id}: {len(events)} events from {len(per_source)} "
        f"source(s) across {len(evidence)} evidence file(s). "
        f"{len(findings)} detection finding(s) "
        f"(highest severity: {top_sev}); "
        f"{len(covered_ids)} ATT&CK technique(s) with findings; "
        f"{len(clusters)} correlated activity cluster(s); "
        f"{untimed} untimed event(s); "
        f"{len(notes)} analyst note(s). "
        "This summary is machine-generated from counts and requires "
        "analyst review."
    )

    report = {
        "meta": {
            "tool": "huntforge",
            "tool_version": tool_version,
            "reporting_module": f"huntforge.reporting {REPORTING_VERSION}",
            "report_schema_version": REPORT_SCHEMA_VERSION,
            "case_id": case_id,
            "case_name": meta.get("name", case_id),
            "case_created": meta.get("created", ""),
            "generated_at": utc_now_iso(),
        },
        "executive_summary": {
            "generated": True,
            "analyst_review_required": True,
            "text": summary_text,
        },
        "what_this_report_does_not_claim": list(DOES_NOT_CLAIM),
        "methodology": {
            "parsers": [
                {"name": name, "version": version}
                for name, version in sorted(parsers.items())
            ],
            "analysis_steps": sorted(set(audit_commands)),
            "note": "Only commands recorded in the case audit log are "
            "listed. Re-running those commands reproduces this report.",
        },
        "case_overview": {
            "events": len(events),
            "evidence_files": len(evidence),
            "untimed_events": untimed,
            "sources": sorted(per_source.values(), key=lambda s: str(s["source"])),
        },
        "timeline_highlights": highlights,
        "process_lineage": lineage_summary,
        "detections": detections,
        "attack_coverage": attack_coverage,
        "correlations": correlations,
        "entities": entities,
        "analyst_notes": {
            "count": len(notes),
            "notes": notes,
            "note": "Analyst-authored free text, stored verbatim. "
            "HuntForge never writes notes itself.",
        },
        "limitations": list(LIMITATIONS),
        "chain_of_custody": {
            "evidence": evidence,
            "audit": db.audit_log(limit=1000),
            "note": "Evidence files are hashed at ingest (SHA-256 + MD5) "
            "and never modified. The audit log records every CLI "
            "invocation touching this case.",
        },
    }

    missing = [s for s in REQUIRED_SECTIONS if s not in report]
    if missing:  # pragma: no cover - structural guard
        raise ValueError(f"report missing sections: {missing}")
    return report
