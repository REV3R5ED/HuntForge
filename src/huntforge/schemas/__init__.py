"""Stable JSON schemas for HuntForge v1.0.

Every JSON artifact HuntForge produces — CLI ``--json`` envelopes, JSONL
exports, batch summaries/manifests, generated reports — conforms to one
of the schemas documented here. Each schema carries a versioned ``$id``
(``huntforge/<name>@1.0``); the 1.x stability promise is: **fields are
only ever added, never removed or retyped**, and new ``$id`` versions
are minted if a breaking change is ever required.

``huntforge schema`` prints these documents so integrations can consume
them offline. ``validate()`` is the stdlib-only checker the test suite
uses to prove every command's ``--json`` output conforms.
"""

from __future__ import annotations

from typing import Any

# --- schema identifiers (stable; bump the @version on breaking change) ---
SCHEMA_ENVELOPE = "huntforge/envelope@1.0"
SCHEMA_EVENT = "huntforge/event@1.0"
SCHEMA_FINDING = "huntforge/finding@1.0"
SCHEMA_LINKAGE = "huntforge/linkage@1.0"
SCHEMA_ACTIVITY_CLUSTER = "huntforge/activity-cluster@1.0"
SCHEMA_NARRATIVE = "huntforge/narrative@1.0"
SCHEMA_REPORT = "huntforge/report@1.0"
SCHEMA_BATCH_SUMMARY = "huntforge/batch-summary@1.0"
SCHEMA_BATCH_MANIFEST = "huntforge/batch-manifest@1.0"
SCHEMA_JSONL_ENVELOPE = "huntforge/jsonl-envelope@1.0"

# Smaller record schemas referenced by the documents above.
SCHEMA_CASE = "huntforge/case@1.0"
SCHEMA_AUDIT_ENTRY = "huntforge/audit-entry@1.0"
SCHEMA_NOTE = "huntforge/note@1.0"
SCHEMA_ENTITY = "huntforge/entity@1.0"
SCHEMA_REGISTRY_VIEW = "huntforge/registry-view@1.0"
SCHEMA_RULE = "huntforge/rule@1.0"
SCHEMA_SIGMA_RULE = "huntforge/sigma-rule@1.0"
SCHEMA_TECHNIQUE = "huntforge/technique@1.0"

_ISO = {
    "type": "string",
    "description": "UTC ISO-8601 timestamp (Z-suffixed).",
}
_NULLSTR = {"type": ["string", "null"]}
_NULLINT = {"type": ["integer", "null"]}

SCHEMAS: dict[str, dict[str, Any]] = {
    "envelope": {
        "$id": SCHEMA_ENVELOPE,
        "title": "CLI result envelope",
        "description": (
            "Every huntforge command returns this envelope. Human-readable "
            "rendering, --json and --csv all derive from it. 'status' drives "
            "the exit code: ok->0, warning->1 (findings are the product), "
            "error->2."
        ),
        "type": "object",
        "required": [
            "tool",
            "version",
            "command",
            "timestamp",
            "status",
            "summary",
            "data",
            "findings",
            "events",
        ],
        "properties": {
            "tool": {"type": "string", "enum": ["huntforge"]},
            "version": {"type": "string"},
            "command": {"type": "string"},
            "timestamp": _ISO,
            "status": {"type": "string", "enum": ["ok", "warning", "error"]},
            "summary": {"type": "string"},
            "data": {"type": "object"},
            "findings": {"type": "array", "items": {"$ref": "finding"}},
            "events": {"type": "array", "items": {"$ref": "event"}},
        },
    },
    "event": {
        "$id": SCHEMA_EVENT,
        "title": "Normalized event record",
        "description": (
            "One endpoint telemetry record in HuntForge's common schema. "
            "Field presence is stable across parsers; inapplicable fields "
            "are null, never absent. 'timestamp' is UTC-normalized; "
            "'timestamp_original' preserves the source's verbatim text "
            "(null only when the source carried no recoverable time — the "
            "v0.4 'untimed' section)."
        ),
        "type": "object",
        "required": [
            "id",
            "source",
            "event_id",
            "timestamp",
            "host",
            "user",
            "process_name",
            "process_id",
            "parent_name",
            "parent_id",
            "command_line",
            "file_path",
            "registry_key",
            "src_ip",
            "src_port",
            "dst_ip",
            "dst_port",
            "hashes",
            "flags",
            "provenance",
            "raw",
            "timestamp_original",
            "evidence_id",
        ],
        "properties": {
            "id": {"type": "integer"},
            "source": {"type": "string"},
            "event_id": {"type": "string"},
            "timestamp": _NULLSTR,
            "timestamp_original": _NULLSTR,
            "host": _NULLSTR,
            "user": _NULLSTR,
            "process_name": _NULLSTR,
            "process_id": _NULLINT,
            "parent_name": _NULLSTR,
            "parent_id": _NULLINT,
            "command_line": _NULLSTR,
            "file_path": _NULLSTR,
            "registry_key": _NULLSTR,
            "src_ip": _NULLSTR,
            "src_port": _NULLINT,
            "dst_ip": _NULLSTR,
            "dst_port": _NULLINT,
            "hashes": {"type": ["object", "null"]},
            "flags": {"type": "array", "items": {"type": "string"}},
            "provenance": {"type": "object"},
            "raw": _NULLSTR,
            "evidence_id": _NULLINT,
        },
    },
    "finding": {
        "$id": SCHEMA_FINDING,
        "title": "Detection finding",
        "description": (
            "One rule match, fully explained. 'why' lists matched "
            "conditions; 'observed' states facts drawn from evidence; "
            "'inferred' states what those facts suggest (labeled — the "
            "analyst decides). 'confidence' is 0-100 and meaningless "
            "without 'confidence_reason'. 'finding_uid' (HF-0001...) is "
            "assigned when the finding is stored in a case; fresh engine "
            "output may omit it and 'created_at'."
        ),
        "type": "object",
        "required": [
            "rule_id",
            "rule_version",
            "title",
            "severity",
            "confidence",
            "confidence_reason",
            "why",
            "what",
            "evidence",
            "observed",
            "inferred",
            "mitre",
            "provenance",
        ],
        "properties": {
            "finding_uid": {"type": "string"},
            "rule_id": {"type": "string"},
            "rule_version": {"type": "string"},
            "title": {"type": "string"},
            "severity": {
                "type": "string",
                "enum": [
                    "informational",
                    "low",
                    "medium",
                    "high",
                    "critical",
                ],
            },
            "confidence": {"type": "integer"},
            "confidence_reason": {"type": "string"},
            "why": {"type": "array", "items": {"type": "string"}},
            "what": {"type": "string"},
            "evidence": {
                "type": "array",
                "items": {
                    "type": "object",
                    "required": ["event_id", "observation"],
                    "properties": {
                        "event_id": {"type": "integer"},
                        "source": {"type": "string"},
                        "source_event_id": {"type": "string"},
                        "observation": {"type": "string"},
                    },
                },
            },
            "observed": {"type": "array", "items": {"type": "string"}},
            "inferred": {"type": "array", "items": {"type": "string"}},
            "mitre": {"type": "array", "items": {"type": "string"}},
            "provenance": {"type": "string"},
            "created_at": _ISO,
        },
    },
    "linkage": {
        "$id": SCHEMA_LINKAGE,
        "title": "Correlation linkage",
        "description": (
            "One INFERRED hypothesis that two events describe the same "
            "underlying activity. Deterministic and explainable: carries "
            "its basis, a confidence with a reason, the heuristic that "
            "produced it, and known failure modes. 'label' is always "
            "'INFERRED' — linkages are never observed facts."
        ),
        "type": "object",
        "required": [
            "kind",
            "event_a",
            "event_b",
            "basis",
            "confidence",
            "confidence_reason",
            "heuristic",
            "failure_modes",
            "label",
        ],
        "properties": {
            "kind": {
                "type": "string",
                "enum": [
                    "same-process",
                    "same-file",
                    "persistence-execution",
                    "download-execution",
                ],
            },
            "event_a": {"type": "integer"},
            "event_b": {"type": "integer"},
            "basis": {"type": "string"},
            "confidence": {"type": "integer"},
            "confidence_reason": {"type": "string"},
            "heuristic": {"type": "string"},
            "failure_modes": {"type": "string"},
            "label": {"type": "string", "enum": ["INFERRED"]},
        },
    },
    "activity_cluster": {
        "$id": SCHEMA_ACTIVITY_CLUSTER,
        "title": "Activity cluster",
        "description": (
            "Events joined by linkages (a connected component), plus the "
            "case findings whose evidence falls inside it, the entities "
            "involved, and the ATT&CK techniques those findings evidence. "
            "'confidence' is the weakest linkage confidence."
        ),
        "type": "object",
        "required": [
            "cluster_id",
            "event_ids",
            "event_count",
            "linkages",
            "findings",
            "entities",
            "techniques",
            "confidence",
            "confidence_reason",
        ],
        "properties": {
            "cluster_id": {"type": "integer"},
            "event_ids": {"type": "array", "items": {"type": "integer"}},
            "event_count": {"type": "integer"},
            "linkages": {"type": "array", "items": {"$ref": "linkage"}},
            "findings": {"type": "array", "items": {"type": "object"}},
            "entities": {"type": "array", "items": {"type": "object"}},
            "techniques": {"type": "array", "items": {"type": "object"}},
            "confidence": {"type": "integer"},
            "confidence_reason": {"type": "string"},
            "label": {"type": "string"},
            "by_severity": {"type": "object"},
            "finding_count": {"type": "integer"},
        },
    },
    "narrative": {
        "$id": SCHEMA_NARRATIVE,
        "title": "Cluster narrative",
        "description": (
            "Analyst-facing rendering of one activity cluster: the "
            "observed timeline, the inferred linkages, detections, "
            "techniques, an explicit confidence, and 'whats_missing' — "
            "the evidence that would be expected but was not observed."
        ),
        "type": "object",
        "required": [
            "cluster_id",
            "summary",
            "confidence",
            "confidence_reason",
            "observed",
            "inferred",
            "detections",
            "entities",
            "techniques",
            "whats_missing",
        ],
        "properties": {
            "cluster_id": {"type": "integer"},
            "summary": {"type": "string"},
            "confidence": {"type": "integer"},
            "confidence_reason": {"type": "string"},
            "observed": {"type": "array", "items": {"type": "object"}},
            "inferred": {
                "type": "array",
                "items": {
                    "type": "object",
                    "description": (
                        "Condensed linkage for analyst reading: the "
                        "linkage's basis and heuristic are rendered into "
                        "'claim'; see the linkage schema for the full form."
                    ),
                    "required": [
                        "kind",
                        "event_a",
                        "event_b",
                        "claim",
                        "confidence",
                        "confidence_reason",
                        "failure_modes",
                        "label",
                    ],
                    "properties": {
                        "kind": {"type": "string"},
                        "event_a": {"type": "integer"},
                        "event_b": {"type": "integer"},
                        "claim": {"type": "string"},
                        "confidence": {"type": "integer"},
                        "confidence_reason": {"type": "string"},
                        "failure_modes": {"type": "string"},
                        "label": {"type": "string", "enum": ["INFERRED"]},
                    },
                },
            },
            "detections": {"type": "array", "items": {"type": "object"}},
            "entities": {"type": "array", "items": {"type": "object"}},
            "techniques": {"type": "array", "items": {"type": "object"}},
            "whats_missing": {"type": "array", "items": {"type": "string"}},
            "label_observed": {"type": "string"},
            "label_inferred": {"type": "string"},
        },
    },
    "report": {
        "$id": SCHEMA_REPORT,
        "title": "Case report document",
        "description": (
            "The generated case report (report case --format json). "
            "'executive_summary' is machine-generated and flagged for "
            "analyst review. Report findings carry observed/inferred as "
            "objects ({facts:[...], note} / {hypotheses:[...], note}) — "
            "a report-level wrapping of the finding schema's arrays."
        ),
        "type": "object",
        "required": [
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
        ],
        "properties": {
            "meta": {
                "type": "object",
                "required": [
                    "tool",
                    "tool_version",
                    "reporting_module",
                    "report_schema_version",
                    "case_id",
                    "case_name",
                    "case_created",
                    "generated_at",
                ],
                "properties": {
                    "report_schema_version": {
                        "type": "string",
                        "enum": [SCHEMA_REPORT],
                    },
                },
            },
            "executive_summary": {
                "type": "object",
                "required": [
                    "generated",
                    "analyst_review_required",
                    "text",
                ],
            },
            "what_this_report_does_not_claim": {
                "type": "array",
                "items": {"type": "string"},
            },
            "methodology": {"type": "object"},
            "case_overview": {"type": "object"},
            "timeline_highlights": {"type": "object"},
            "process_lineage": {"type": "object"},
            "detections": {"type": "object"},
            "attack_coverage": {"type": "object"},
            "correlations": {"type": "object"},
            "entities": {"type": "object"},
            "analyst_notes": {"type": "object"},
            "limitations": {"type": "array", "items": {"type": "string"}},
            "chain_of_custody": {"type": "object"},
        },
    },
    "batch_summary": {
        "$id": SCHEMA_BATCH_SUMMARY,
        "title": "Batch triage summary",
        "description": (
            "Result of 'huntforge batch': one case per evidence file. "
            "Written to <output>/batch-summary.json and returned as the "
            "command's data payload. 'cases' entries are batch_case "
            "records; re-runs skip unchanged files ('status': 'skipped')."
        ),
        "type": "object",
        "required": [
            "tool",
            "version",
            "input_dir",
            "output_dir",
            "started",
            "finished",
            "files_found",
            "cases_created",
            "cases_skipped",
            "files_failed",
            "total_events",
            "total_findings",
            "by_severity",
            "top_techniques",
            "manifest",
            "cases",
        ],
        "properties": {
            "tool": {"type": "string", "enum": ["huntforge"]},
            "version": {"type": "string"},
            "input_dir": {"type": "string"},
            "output_dir": {"type": "string"},
            "started": _ISO,
            "finished": _ISO,
            "files_found": {"type": "integer"},
            "cases_created": {"type": "integer"},
            "cases_skipped": {"type": "integer"},
            "files_failed": {"type": "array", "items": {"type": "object"}},
            "total_events": {"type": "integer"},
            "total_findings": {"type": "integer"},
            "by_severity": {"type": "object"},
            "top_techniques": {"type": "array", "items": {"type": "object"}},
            "manifest": {"type": "string"},
            "cases": {"type": "array", "items": {"type": "object"}},
        },
    },
    "batch_manifest": {
        "$id": SCHEMA_BATCH_MANIFEST,
        "title": "Batch manifest",
        "description": (
            "Resumability record at <output>/batch-manifest.json: SHA-256 "
            "of each processed input file mapped to its batch_case "
            "record. Files whose digest is present with status 'ok' are "
            "skipped on re-run."
        ),
        "type": "object",
    },
    "jsonl_envelope": {
        "$id": SCHEMA_JSONL_ENVELOPE,
        "title": "JSONL export envelope",
        "description": (
            "One line of 'huntforge export' output. Self-describing: a "
            "SIEM can parse each line without sidecar metadata. "
            "'record' is an event or finding per 'record_type'."
        ),
        "type": "object",
        "required": ["record_type", "schema", "tool", "version", "record"],
        "properties": {
            "record_type": {"type": "string", "enum": ["event", "finding"]},
            "schema": {"type": "string"},
            "tool": {"type": "string", "enum": ["huntforge"]},
            "version": {"type": "string"},
            "record": {"type": "object"},
        },
    },
    # --- smaller record schemas -------------------------------------------
    "case": {
        "$id": SCHEMA_CASE,
        "title": "Case record",
        "description": "Case metadata and evidence inventory.",
        "type": "object",
        "required": ["case_id", "name", "created", "events", "evidence"],
        "properties": {
            "case_id": {"type": "string"},
            "name": {"type": "string"},
            "created": _ISO,
            "events": {"type": "integer"},
            "evidence": {"type": "integer"},
            "evidence_files": {"type": "array", "items": {"type": "object"}},
            "schema_version": {"type": "string"},
        },
    },
    "audit_entry": {
        "$id": SCHEMA_AUDIT_ENTRY,
        "title": "Audit log entry",
        "description": "One CLI invocation recorded against a case.",
        "type": "object",
        "required": ["id", "ts", "command", "status"],
        "properties": {
            "id": {"type": "integer"},
            "ts": _ISO,
            "command": {"type": "string"},
            "args": {"type": "object"},
            "status": {"type": "string"},
            "result_count": {"type": ["integer", "null"]},
        },
    },
    "note": {
        "$id": SCHEMA_NOTE,
        "title": "Analyst note",
        "description": "Analyst-authored free text, stored verbatim.",
        "type": "object",
        "required": ["id", "author", "text", "ts"],
        "properties": {
            "id": {"type": "integer"},
            "author": {"type": "string"},
            "text": {"type": "string"},
            "ts": _ISO,
        },
    },
    "entity": {
        "$id": SCHEMA_ENTITY,
        "title": "Resolved entity",
        "description": "Cross-source normalized entity with provenance.",
        "type": "object",
        "required": [
            "type",
            "value",
            "count",
            "observed_as",
            "sources",
            "first_seen",
            "last_seen",
        ],
        "properties": {
            "type": {"type": "string"},
            "value": {"type": "string"},
            "count": {"type": "integer"},
            "observed_as": {"type": "array", "items": {"type": "string"}},
            "sources": {"type": "array", "items": {"type": "string"}},
            "first_seen": _NULLSTR,
            "last_seen": _NULLSTR,
        },
    },
    "registry_view": {
        "$id": SCHEMA_REGISTRY_VIEW,
        "title": "Registry key view",
        "description": "Offline hive key listing.",
        "type": "object",
        "required": ["path", "last_write", "subkeys", "values"],
        "properties": {
            "path": {"type": "string"},
            "last_write": _NULLSTR,
            "subkeys": {"type": "array", "items": {"type": "string"}},
            "values": {"type": "array", "items": {"type": "object"}},
        },
    },
    "rule": {
        "$id": SCHEMA_RULE,
        "title": "Detection rule catalog entry",
        "description": "One explainable detection rule's metadata.",
        "type": "object",
        "required": [
            "id",
            "title",
            "description",
            "severity",
            "version",
            "required_sources",
            "logic",
            "false_positives",
        ],
        "properties": {
            "id": {"type": "string"},
            "title": {"type": "string"},
            "description": {"type": "string"},
            "severity": {"type": "string"},
            "version": {"type": "string"},
            "required_sources": {"type": "array"},
            "logic": {"type": "string"},
            "false_positives": {"type": "string"},
            "mitre": {"type": "array", "items": {"type": "string"}},
        },
    },
    "sigma_rule": {
        "$id": SCHEMA_SIGMA_RULE,
        "title": "Sigma-subset rule record",
        "description": "A loaded Sigma-subset rule (JSON form preferred).",
        "type": "object",
        "required": ["id", "title", "detection", "condition"],
        "properties": {
            "id": {"type": "string"},
            "title": {"type": "string"},
            "description": _NULLSTR,
            "author": _NULLSTR,
            "date": _NULLSTR,
            "logsource": {"type": "object"},
            "detection": {"type": "object"},
            "condition": {"type": "string"},
            "level": _NULLSTR,
            "status": _NULLSTR,
            "tags": {"type": "array", "items": {"type": "string"}},
            "falsepositives": {"type": "array", "items": {"type": "string"}},
            "techniques": {"type": "array", "items": {"type": "string"}},
            "source_format": {"type": "string"},
            "source_path": {"type": "string"},
        },
    },
    "technique": {
        "$id": SCHEMA_TECHNIQUE,
        "title": "ATT&CK technique record",
        "description": "One curated ATT&CK technique.",
        "type": "object",
        "required": ["id", "name", "tactics"],
        "properties": {
            "id": {"type": "string"},
            "name": {"type": "string"},
            "description": _NULLSTR,
            "tactics": {"type": "array", "items": {"type": "string"}},
            "huntforge_sources": {"type": "array"},
            "observable": {"type": "boolean"},
            "detection_notes": _NULLSTR,
        },
    },
}


def names() -> list[str]:
    """Schema names in stable order."""
    return list(SCHEMAS)


def get(name: str) -> dict[str, Any]:
    """Return the schema document for ``name`` (KeyError if unknown)."""
    return SCHEMAS[name]


_TYPE_MAP: dict[str, tuple[type, ...]] = {
    "string": (str,),
    "integer": (int,),
    "number": (int, float),
    "boolean": (bool,),
    "object": (dict,),
    "array": (list,),
    "null": (type(None),),
}


def _check_type(value: Any, type_name: str) -> bool:
    # bool is a subclass of int: keep JSON's boolean/integer distinct.
    if type_name == "integer" and isinstance(value, bool):
        return False
    if type_name == "number" and isinstance(value, bool):
        return False
    return isinstance(value, _TYPE_MAP[type_name])


def validate(instance: Any, schema: dict[str, Any] | str) -> list[str]:
    """Check ``instance`` against a schema document (or schema name).

    Returns a list of human-readable errors; empty means valid. This is
    a small structural checker (stdlib-only), not a full JSON Schema
    implementation: it honors ``type`` (string or list), ``required``,
    ``properties``, ``items``, ``enum`` and ``$ref`` to a named schema.
    Unknown keywords are ignored so the documents stay readable.
    """
    if isinstance(schema, str):
        schema = SCHEMAS[schema]
    errors: list[str] = []
    _validate_into(instance, schema, "$", errors)
    return errors


def _validate_into(
    instance: Any, schema: dict[str, Any], path: str, errors: list[str]
) -> None:
    if "$ref" in schema:
        ref = schema["$ref"]
        if ref not in SCHEMAS:
            errors.append(f"{path}: unknown $ref {ref!r}")
            return
        _validate_into(instance, SCHEMAS[ref], path, errors)
        return
    expected = schema.get("type")
    if expected is not None:
        names_ = [expected] if isinstance(expected, str) else list(expected)
        if not any(_check_type(instance, name) for name in names_):
            errors.append(
                f"{path}: expected type {expected}, got {type(instance).__name__}"
            )
            return
    enum = schema.get("enum")
    if enum is not None and instance not in enum:
        errors.append(f"{path}: {instance!r} not in enum {enum}")
    if isinstance(instance, dict):
        for key in schema.get("required", []):
            if key not in instance:
                errors.append(f"{path}: missing required key {key!r}")
        props = schema.get("properties", {})
        for key, value in instance.items():
            if key in props:
                _validate_into(value, props[key], f"{path}.{key}", errors)
    if isinstance(instance, list):
        items = schema.get("items")
        if items is not None:
            for i, value in enumerate(instance):
                _validate_into(value, items, f"{path}[{i}]", errors)
