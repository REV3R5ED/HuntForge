"""HuntForge CLI: ``huntforge case ...`` / ``huntforge ingest ...`` /
``huntforge events ...`` / ``huntforge registry ...`` /
``huntforge timeline ...`` / ``huntforge lineage ...`` /
``huntforge entities ...`` / ``huntforge detect ...`` /
``huntforge rules ...`` / ``huntforge mitre ...`` / ``huntforge sigma ...`` /
``huntforge correlate ...`` / ``huntforge narrative ...`` /
``huntforge batch ...`` / ``huntforge export ...``.

Every command returns a shared result envelope, renders human-readable
text by default (``--json`` for automation), uses structured exit
codes (0 ok / 1 findings / 2 error), and writes an audit record to the
case when one is involved. Diagnostics go to stderr; stdout carries
only the requested output.

v0.5 adds explainable detections: ``detect`` runs the rule catalog
over a case's events and every finding cites its evidence; ``rules``
lists the catalog. No verdicts are final — the analyst decides.

v0.9 adds batch triage (``batch``: one case per evidence file,
resumable via manifest), JSONL export for SIEM ingestion
(``export``), and an analyst config file (``--config`` /
``~/.huntforge/config.toml``).
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from huntforge import __version__
from huntforge import batch as batch_mod
from huntforge import correlate as correlate_mod
from huntforge import mitre as mitre_mod
from huntforge import reporting as reporting_mod
from huntforge import sigma as sigma_mod
from huntforge.cases.service import CaseService
from huntforge.core import appconfig as appconfig_mod
from huntforge.core import config as config_mod
from huntforge.core import plugins as plugins_mod
from huntforge.core.appconfig import ConfigError
from huntforge.core.results import (
    EXIT_ERROR,
    EXIT_OK,
    Result,
    exit_code_for,
)
from huntforge.detections import (
    DetectionEngine,
    Severity,
    list_rules,
    select_rules,
    summarize,
)
from huntforge.events.query import EventQuery
from huntforge.ingest.service import ingest_path, load_fixture
from huntforge.parsers import SOURCE_KINDS
from huntforge.parsers.common import check_parse_size
from huntforge.parsers.registry import Hive, HiveError, KeyNotFoundError
from huntforge.store.db import CaseDB, CaseError
from huntforge.timeline import entities as entities_mod
from huntforge.timeline import lineage as lineage_mod
from huntforge.timeline import timeline as timeline_mod

plugins_mod.register(
    plugins_mod.ModuleInfo(
        name="core",
        description="Core CLI, normalized event model, case store, ingest",
        version=__version__,
        commands=[
            "case",
            "ingest",
            "events",
            "registry",
            "audit",
            "version",
            "timeline",
            "lineage",
            "entities",
            "detect",
            "rules",
            "mitre",
            "sigma",
            "correlate",
            "narrative",
            "report",
            "notes",
            "batch",
            "export",
        ],
    )
)


def _print_json(result: Result) -> None:
    print(json.dumps(result.to_dict(), indent=2, sort_keys=True))


def _human_kv(title: str, mapping: dict[str, Any]) -> None:
    print(title)
    for key, value in mapping.items():
        print(f"  {key}: {value}")


def _human_events(events: list[dict[str, Any]]) -> None:
    for event in events:
        ident = event.get("id")
        print(
            f"[{ident}] {event.get('timestamp')} {event.get('source')}:"
            f"{event.get('event_id')} host={event.get('host') or '-'} "
            f"user={event.get('user') or '-'} "
            f"process={event.get('process_name') or '-'}"
            f"({event.get('process_id') or '-'})"
        )
        for field in ("command_line", "file_path", "registry_key", "dst_ip"):
            value = event.get(field)
            if value:
                print(f"      {field}: {value}")
        flags = event.get("flags") or []
        if flags:
            print(f"      flags: {', '.join(flags)} (parser observation)")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="huntforge",
        description="Hunt the endpoint. Reconstruct the attack.",
    )
    parser.add_argument(
        "--version", action="version", version=f"huntforge {__version__}"
    )
    parser.add_argument(
        "--state-dir",
        default=None,
        help="State directory override (default: ~/.huntforge or HUNTFORGE_STATE_DIR)",
    )
    parser.add_argument(
        "--config",
        default=None,
        help="Config file (TOML); default: ~/.huntforge/config.toml if present",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit the result envelope as JSON on stdout",
    )
    sub = parser.add_subparsers(dest="command")

    case_p = sub.add_parser("case", help="Case management")
    case_sub = case_p.add_subparsers(dest="case_command", required=True)
    create_p = case_sub.add_parser("create", help="Create a case")
    create_p.add_argument("case_id", help="Case identifier (letters, digits, . _ -)")
    create_p.add_argument("--name", default=None, help="Human-friendly case name")
    show_p = case_sub.add_parser("show", help="Show a case")
    show_p.add_argument("case_id", help="Case identifier")
    case_sub.add_parser("list", help="List all cases")

    ingest_p = sub.add_parser("ingest", help="Ingest evidence into a case")
    ingest_p.add_argument("path", help="Evidence file or directory")
    ingest_p.add_argument("--case", required=True, help="Case identifier")
    ingest_p.add_argument(
        "--fixture",
        default=None,
        help="JSONL fixture of normalized events to load into the event store",
    )
    ingest_p.add_argument(
        "--no-recursive",
        action="store_true",
        help="Do not recurse into subdirectories",
    )
    ingest_p.add_argument(
        "--source",
        choices=list(SOURCE_KINDS),
        default=None,
        help=(
            "Force one telemetry source kind for every file "
            "(default: auto-detect by content)"
        ),
    )
    ingest_p.add_argument(
        "--no-parse",
        action="store_true",
        help="Register evidence only; skip telemetry parsing",
    )

    events_p = sub.add_parser("events", help="Query normalized events")
    events_p.add_argument("--case", required=True, help="Case identifier")
    events_p.add_argument(
        "--host", default=None, help="Filter by host (case-insensitive)"
    )
    events_p.add_argument(
        "--user", default=None, help="Filter by user (case-insensitive)"
    )
    events_p.add_argument("--event-id", default=None, help="Filter by event id (exact)")
    events_p.add_argument(
        "--process", default=None, help="Filter by process name (case-insensitive)"
    )
    events_p.add_argument(
        "--keyword",
        default=None,
        help=(
            "Substring search over command line, file path, registry key, process name"
        ),
    )
    events_p.add_argument(
        "--limit", type=int, default=200, help="Max events (default 200)"
    )
    events_p.add_argument("--offset", type=int, default=0, help="Result offset")

    audit_p = sub.add_parser("audit", help="Show a case's audit log")
    audit_p.add_argument("--case", required=True, help="Case identifier")
    audit_p.add_argument("--limit", type=int, default=50, help="Max rows (default 50)")

    registry_p = sub.add_parser(
        "registry", help="Read an offline registry hive (forensic copy)"
    )
    registry_p.add_argument("hive", help="Path to the hive file (e.g. NTUSER.DAT)")
    registry_p.add_argument(
        "key", help=r"Key path, e.g. Software\Microsoft\Windows\CurrentVersion\Run"
    )

    timeline_p = sub.add_parser(
        "timeline", help="Unified chronological timeline (observation only)"
    )
    timeline_p.add_argument("--case", required=True, help="Case identifier")
    timeline_p.add_argument(
        "--from", dest="from_ts", default=None, help="Start of window (ISO timestamp)"
    )
    timeline_p.add_argument(
        "--to", dest="to_ts", default=None, help="End of window (ISO timestamp)"
    )
    timeline_p.add_argument(
        "--source", default=None, help="Filter by source prefix (e.g. sysmon)"
    )
    timeline_p.add_argument(
        "--limit", type=int, default=500, help="Max timed entries (default 500)"
    )

    lineage_p = sub.add_parser(
        "lineage", help="Process lineage trees (observation only)"
    )
    lineage_p.add_argument("--case", required=True, help="Case identifier")
    lineage_p.add_argument(
        "--pid",
        type=int,
        default=None,
        help="Focus on this PID (ancestors + descendants)",
    )
    lineage_p.add_argument(
        "--image",
        default=None,
        help="Focus on processes with this image name (case-insensitive)",
    )

    entities_p = sub.add_parser(
        "entities", help="Resolved entities across sources (observation only)"
    )
    entities_p.add_argument("--case", required=True, help="Case identifier")
    entities_p.add_argument(
        "--type",
        dest="entity_type",
        default=None,
        choices=list(entities_mod.ENTITY_TYPES),
        help="Only show this entity type",
    )

    detect_p = sub.add_parser(
        "detect", help="Run explainable detection rules over a case"
    )
    detect_p.add_argument("--case", required=True, help="Case identifier")
    detect_p.add_argument(
        "--rule",
        action="append",
        default=None,
        dest="rule_ids",
        help="Run only this rule (repeatable; default: whole catalog)",
    )
    detect_p.add_argument(
        "--severity",
        default=None,
        help=(
            "Severity filter, e.g. 'high' (exactly high) or 'high+' (high and above)"
        ),
    )
    detect_p.add_argument(
        "--explain",
        action="store_true",
        help="Show full reasoning: why, evidence, confidence, observed vs inferred",
    )

    rules_p = sub.add_parser("rules", help="Detection rule catalog")
    rules_sub = rules_p.add_subparsers(dest="rules_command", required=True)
    rules_sub.add_parser("list", help="List all detection rules")

    mitre_p = sub.add_parser("mitre", help="ATT&CK technique coverage for a case")
    mitre_p.add_argument(
        "--case",
        default=None,
        help="Case identifier (coverage over its stored findings)",
    )
    mitre_sub = mitre_p.add_subparsers(dest="mitre_command")
    mitre_sub.add_parser("techniques", help="List the curated ATT&CK technique table")

    sigma_p = sub.add_parser("sigma", help="Sigma-subset rules")
    sigma_sub = sigma_p.add_subparsers(dest="sigma_command", required=True)
    sigma_sub.add_parser("list", help="List bundled sample Sigma rules")
    sigma_run_p = sigma_sub.add_parser(
        "run", help="Evaluate one Sigma rule over a case"
    )
    sigma_run_p.add_argument("--case", required=True, help="Case identifier")
    sigma_run_p.add_argument(
        "--rule",
        required=True,
        help="Rule file (.json/.yaml/.yml) or bundled sample name",
    )

    correlate_p = sub.add_parser(
        "correlate", help="Correlate a case into activity clusters"
    )
    correlate_p.add_argument("--case", required=True, help="Case identifier")

    narrative_p = sub.add_parser(
        "narrative", help="Full attack narrative for one activity cluster"
    )
    narrative_p.add_argument("--case", required=True, help="Case identifier")
    narrative_p.add_argument(
        "--cluster", required=True, type=int, help="Cluster id from 'correlate'"
    )

    report_p = sub.add_parser("report", help="Generate case reports")
    report_sub = report_p.add_subparsers(dest="report_command")
    report_case_p = report_sub.add_parser("case", help="Report on a case")
    report_case_p.add_argument("case", help="Case identifier")
    report_case_p.add_argument(
        "--output",
        required=True,
        help="Output directory for the report files (created if missing)",
    )
    report_case_p.add_argument(
        "--format",
        choices=["html", "json", "md", "all"],
        default="all",
        help="Report format (default: all)",
    )

    notes_p = sub.add_parser("notes", help="Analyst notes for a case")
    notes_p.add_argument("--case", required=True, help="Case identifier")
    notes_p.add_argument("--add", default=None, help="Add a note with this text")
    notes_p.add_argument(
        "--author",
        default=None,
        help="Note author (default: analyst_name from config, else 'analyst')",
    )
    notes_p.add_argument(
        "--list", action="store_true", help="List notes (default if --add not given)"
    )

    batch_p = sub.add_parser(
        "batch", help="Triage a directory of evidence: one case per file"
    )
    batch_p.add_argument("input_dir", help="Directory of evidence files to triage")
    batch_p.add_argument(
        "--output",
        required=True,
        help="Output directory for batch-summary.json and batch-manifest.json",
    )
    batch_p.add_argument(
        "--severity",
        default=None,
        help="Minimum finding severity (default: config default_severity, else all)",
    )

    export_p = sub.add_parser("export", help="Export case events/findings as JSONL")
    export_p.add_argument("--case", required=True, help="Case identifier")
    export_p.add_argument(
        "--what",
        choices=["events", "findings"],
        default="events",
        help="What to export (default: events)",
    )
    export_p.add_argument(
        "--format",
        choices=["jsonl"],
        default="jsonl",
        help="Export format (default: jsonl)",
    )
    export_p.add_argument(
        "--output",
        "-o",
        default=None,
        help="Output file (default: stdout; the result envelope then goes to stderr)",
    )

    return parser


def _audit(
    db_case: str,
    state_dir: Path,
    command: str,
    args: argparse.Namespace,
    result: Result,
) -> None:
    """Best-effort audit write; audit failures never fail the command."""
    try:
        fixture = result.data.get("fixture") or {}
        result_count = (
            len(result.events)
            + len(result.findings)
            + len(result.data.get("evidence", []) or [])
            + int(result.data.get("registered", 0) or 0)
            + int(fixture.get("loaded", 0) or 0)
            + int(result.data.get("parsed_events", 0) or 0)
        )
        db = CaseDB(state_dir, db_case)
        try:
            db.audit(
                command=command,
                args=vars(args),
                result_count=result_count,
                status=result.status,
            )
        finally:
            db.close()
    except Exception:
        pass  # pragma: no cover - audit is best effort


def cmd_case(args: argparse.Namespace, state_dir: Path) -> tuple[Result, str | None]:
    service = CaseService(state_dir)
    result = Result(command=f"case {args.case_command}")
    audit_case: str | None = None
    try:
        if args.case_command == "create":
            data = service.create(args.case_id, name=args.name)
            result.data = data
            result.summary = f"case {args.case_id!r} created"
            audit_case = args.case_id
        elif args.case_command == "show":
            result.data = service.show(args.case_id)
            result.summary = f"case {args.case_id!r}"
        elif args.case_command == "list":
            cases = service.list()
            result.data = {"cases": cases, "count": len(cases)}
            result.summary = f"{len(cases)} case(s)"
    except CaseError as exc:
        result.fail(str(exc))
    return result, audit_case


def cmd_ingest(args: argparse.Namespace, state_dir: Path) -> tuple[Result, str | None]:
    result = Result(command="ingest")
    service = CaseService(state_dir)
    try:
        db = service.open_db(args.case)
    except CaseError as exc:
        result.fail(str(exc))
        return result, None
    try:
        path = Path(args.path).expanduser()
        summary = ingest_path(
            db,
            path,
            recursive=not args.no_recursive,
            parse=not args.no_parse,
            source=args.source,
        )
        result.data.update(summary)
        fixture_summary: dict[str, Any] = {}
        if args.fixture:
            fixture_summary = load_fixture(db, Path(args.fixture).expanduser())
            result.data["fixture"] = fixture_summary
            if fixture_summary["loaded"] == 0 and fixture_summary["skipped"] > 0:
                result.fail(
                    f"fixture loaded 0 events, skipped "
                    f"{fixture_summary['skipped']}: see fixture.errors"
                )
        if result.status != "error":
            parsed = summary.get("parsed_events", 0)
            by_source = summary.get("parsed_by_source", {})
            source_bits = (
                ", ".join(f"{k}: {v}" for k, v in sorted(by_source.items()))
                if by_source
                else "none"
            )
            warnings = summary.get("parse_warnings", [])
            result.summary = (
                f"registered {summary['registered']} evidence file(s), "
                f"parsed {parsed} event(s) [{source_bits}]"
            )
            if fixture_summary.get("loaded"):
                result.summary += (
                    f", loaded {fixture_summary['loaded']} fixture event(s)"
                )
            if warnings:
                result.summary += f", {len(warnings)} warning(s)"
    except FileNotFoundError as exc:
        result.fail(str(exc))
    except OSError as exc:
        result.fail(f"ingest failed: {exc}")
    finally:
        db.close()
    return result, args.case


def cmd_events(args: argparse.Namespace, state_dir: Path) -> tuple[Result, str | None]:
    result = Result(command="events")
    service = CaseService(state_dir)
    try:
        db = service.open_db(args.case)
    except CaseError as exc:
        result.fail(str(exc))
        return result, None
    try:
        try:
            query = EventQuery(
                host=args.host,
                user=args.user,
                event_id=args.event_id,
                process=args.process,
                keyword=args.keyword,
                limit=args.limit,
                offset=args.offset,
            )
        except ValueError as exc:
            result.fail(f"invalid query: {exc}")
            return result, args.case
        events = query.run(db)
        result.events = events
        result.data = {"filters": query.describe(), "count": len(events)}
        if events:
            result.summary = f"{len(events)} event(s) match"
        else:
            result.summary = "no events match the given filters"
    finally:
        db.close()
    return result, args.case


def cmd_audit(args: argparse.Namespace, state_dir: Path) -> tuple[Result, str | None]:
    result = Result(command="audit")
    service = CaseService(state_dir)
    try:
        db = service.open_db(args.case)
    except CaseError as exc:
        result.fail(str(exc))
        return result, None
    try:
        rows = db.audit_log(limit=args.limit)
        result.data = {"entries": rows, "count": len(rows)}
        result.summary = f"{len(rows)} audit entr{'y' if len(rows) == 1 else 'ies'}"
    finally:
        db.close()
    return result, args.case


def cmd_registry(
    args: argparse.Namespace, state_dir: Path
) -> tuple[Result, str | None]:
    result = Result(command="registry")
    hive_path = Path(args.hive).expanduser()
    oversize = check_parse_size(hive_path)
    if oversize:
        result.fail(oversize)
        return result, None
    try:
        data = hive_path.read_bytes()
    except OSError as exc:
        result.fail(f"cannot read hive file: {exc}")
        return result, None
    try:
        view = Hive(data).list_key(args.key)
    except KeyNotFoundError as exc:
        result.fail(str(exc))
        return result, None
    except HiveError as exc:
        result.fail(f"cannot parse hive: {exc}")
        return result, None
    result.data = view.to_dict()
    result.summary = (
        f"{view.path}: {len(view.subkeys)} subkey(s), {len(view.values)} value(s)"
    )
    return result, None  # no case involved: no audit record


def cmd_timeline(
    args: argparse.Namespace, state_dir: Path
) -> tuple[Result, str | None]:
    result = Result(command="timeline")
    service = CaseService(state_dir)
    try:
        db = service.open_db(args.case)
    except CaseError as exc:
        result.fail(str(exc))
        return result, None
    try:
        try:
            options = timeline_mod.TimelineOptions(
                from_ts=args.from_ts,
                to_ts=args.to_ts,
                source=args.source,
                limit=args.limit,
            )
        except ValueError as exc:
            result.fail(f"invalid options: {exc}")
            return result, args.case
        try:
            built = timeline_mod.build_timeline(db, options)
        except ValueError as exc:
            result.fail(str(exc))
            return result, args.case
        data = built.to_dict()
        result.data = data
        timed_n = data["coverage"]["timed_count"]
        untimed_n = data["coverage"]["untimed_count"]
        result.summary = f"timeline: {timed_n} timed event(s), {untimed_n} untimed"
        if built.truncated:
            result.summary += f" (showing first {len(built.timed)})"
    finally:
        db.close()
    return result, args.case


def cmd_lineage(args: argparse.Namespace, state_dir: Path) -> tuple[Result, str | None]:
    result = Result(command="lineage")
    service = CaseService(state_dir)
    try:
        db = service.open_db(args.case)
    except CaseError as exc:
        result.fail(str(exc))
        return result, None
    try:
        forest = lineage_mod.build_lineage(db)
        instances = forest["instances"]
        if args.pid is not None and args.image:
            result.fail("use only one of --pid or --image")
            return result, args.case
        focus_keys: list[str] = []
        if args.pid is not None:
            focus_keys = [k for k, v in instances.items() if v.pid == args.pid]
            if not focus_keys:
                result.fail(f"no process instance with pid {args.pid}")
                return result, args.case
        elif args.image:
            needle = args.image.lower()
            focus_keys = [k for k, v in instances.items() if needle in v.image.lower()]
            if not focus_keys:
                result.fail(f"no process instance matching image {args.image!r}")
                return result, args.case
        if focus_keys:
            # Ancestors of every focus instance plus their descendants.
            roots: list[str] = []
            for key in focus_keys:
                chain = lineage_mod.ancestors(forest, key)
                if chain[0] not in roots:
                    roots.append(chain[0])
            shown: set[str] = set()
            for key in focus_keys:
                shown.update(lineage_mod.descendants(forest, key))
                shown.update(lineage_mod.ancestors(forest, key))
            result.data = {
                "focus": [
                    lineage_mod.instance_to_dict(instances[k]) for k in focus_keys
                ],
                "shown_instances": sorted(shown),
                "trees": lineage_mod.render_forest(forest, roots),
            }
            result.summary = (
                f"lineage: {len(focus_keys)} matching instance(s), {len(shown)} shown"
            )
        else:
            result.data = {
                "roots": forest["roots"],
                "instance_count": forest["instance_count"],
                "reused_pids": forest["reused_pids"],
                "trees": lineage_mod.render_forest(forest, forest["roots"]),
            }
            summary = f"lineage: {forest['instance_count']} process instance(s)"
            if forest["reused_pids"]:
                summary += f", pid reuse: {', '.join(forest['reused_pids'])}"
            result.summary = summary
    finally:
        db.close()
    return result, args.case


def cmd_entities(
    args: argparse.Namespace, state_dir: Path
) -> tuple[Result, str | None]:
    result = Result(command="entities")
    service = CaseService(state_dir)
    try:
        db = service.open_db(args.case)
    except CaseError as exc:
        result.fail(str(exc))
        return result, None
    try:
        resolved = entities_mod.resolve_entities(db)
        if args.entity_type:
            resolved = [e for e in resolved if e.type == args.entity_type]
        result.data = {
            "entities": [e.to_dict() for e in resolved],
            "count": len(resolved),
            "entity_type": args.entity_type,
        }
        result.summary = f"{len(resolved)} entit{'y' if len(resolved) == 1 else 'ies'}"
        if args.entity_type:
            result.summary += f" of type {args.entity_type}"
    finally:
        db.close()
    return result, args.case


def cmd_detect(args: argparse.Namespace, state_dir: Path) -> tuple[Result, str | None]:
    result = Result(command="detect")
    service = CaseService(state_dir)
    try:
        db = service.open_db(args.case)
    except CaseError as exc:
        result.fail(str(exc))
        return result, None
    try:
        try:
            rules = select_rules(args.rule_ids)
        except ValueError as exc:
            result.fail(str(exc))
            return result, args.case
        min_severity: Severity | None = None
        exact: Severity | None = None
        cfg = getattr(args, "app_config", None)
        severity_arg = args.severity or (
            cfg.default_severity if cfg is not None else None
        )
        if severity_arg:
            try:
                level, at_least = Severity.parse(severity_arg)
            except ValueError as exc:
                result.fail(str(exc))
                return result, args.case
            if at_least:
                min_severity = level
            else:
                min_severity = level
                exact = level
        engine = DetectionEngine(db.all_events())
        applicable = engine.applicable(rules)
        findings = engine.run(rules=rules, min_severity=min_severity)
        if exact is not None:
            findings = [f for f in findings if f.severity == exact]
        # Persist findings to the case; the DB assigns case-scoped UIDs.
        stored: list[dict[str, Any]] = []
        for finding in findings:
            data = finding.to_dict()
            data["finding_uid"] = db.add_finding(data)
            stored.append(data)
        result.findings = stored
        stats = summarize(findings)
        result.data = {
            "count": len(findings),
            "by_severity": stats["by_severity"],
            "rules_run": [r.id for r in rules],
            "rules_without_data": sorted(
                rid for rid, ok in applicable.items() if not ok
            ),
            "severity_filter": args.severity,
        }
        if findings:
            bits = ", ".join(
                f"{n} {sev}" for sev, n in sorted(stats["by_severity"].items())
            )
            result.summary = f"{len(findings)} finding(s): {bits}"
            # Findings are the product, not an error: exit 1 (EXIT_FINDINGS).
            result.status = "warning"
        else:
            result.summary = "no findings"
            if applicable and not all(applicable.values()):
                missing = ", ".join(
                    rid for rid, ok in sorted(applicable.items()) if not ok
                )
                result.summary += f" (no telemetry for: {missing})"
    finally:
        db.close()
    return result, args.case


def cmd_rules(args: argparse.Namespace, state_dir: Path) -> tuple[Result, str | None]:
    del state_dir  # catalog needs no case
    result = Result(command="rules list")
    catalog = [rule.to_dict() for rule in list_rules()]
    result.data = {"rules": catalog, "count": len(catalog)}
    result.summary = f"{len(catalog)} rule(s)"
    return result, None


def cmd_mitre(args: argparse.Namespace, state_dir: Path) -> tuple[Result, str | None]:
    table = mitre_mod.TABLE
    if args.mitre_command == "techniques":
        result = Result(command="mitre techniques")
        result.data = table.to_dict()
        result.summary = (
            f"{len(table.techniques)} technique(s) "
            f"({table.attack_snapshot}; curated subset)"
        )
        return result, None
    # Coverage mode: needs a case.
    if not args.case:
        result = Result(command="mitre")
        result.fail("provide --case for coverage, or 'mitre techniques'")
        return result, None
    result = Result(command="mitre")
    service = CaseService(state_dir)
    try:
        db = service.open_db(args.case)
    except CaseError as exc:
        result.fail(str(exc))
        return result, None
    try:
        stored = db.list_findings()
        coverage = mitre_mod.coverage_from_findings(stored)
        covered_ids = {entry["technique_id"] for entry in coverage["covered"]}
        # Enrich covered entries with technique metadata.
        for entry in coverage["covered"]:
            technique = table.get(entry["technique_id"])
            entry["name"] = technique.name
            entry["tactics"] = list(technique.tactics)
            # Which stored findings (UIDs) evidence this technique.
            entry["findings"] = [
                str(f["finding_uid"])
                for f in stored
                if entry["technique_id"] in [str(t).upper() for t in f["mitre"]]
            ]
        gaps = [tid for tid in table.ids() if tid not in covered_ids]
        unobservable = [t.id for t in table.techniques if not t.huntforge_sources]
        result.data = {
            "case": args.case,
            "attack_snapshot": table.attack_snapshot,
            "data_version": table.data_version,
            "stored_findings": len(stored),
            "technique_count": len(table.techniques),
            **coverage,
            "gaps": gaps,
            "unobservable": unobservable,
        }
        result.summary = (
            f"technique coverage: {coverage['covered_count']} of "
            f"{len(table.techniques)} techniques have findings "
            f"({len(stored)} stored finding(s))"
        )
        if not stored:
            result.summary += " — run 'huntforge detect' first"
    finally:
        db.close()
    return result, args.case


def cmd_sigma(args: argparse.Namespace, state_dir: Path) -> tuple[Result, str | None]:
    if args.sigma_command == "list":
        result = Result(command="sigma list")
        samples = sigma_mod.list_samples()
        result.data = {"rules": samples, "count": len(samples)}
        result.summary = f"{len(samples)} bundled sample rule(s)"
        return result, None
    # sigma run
    result = Result(command="sigma run")
    service = CaseService(state_dir)
    try:
        db = service.open_db(args.case)
    except CaseError as exc:
        result.fail(str(exc))
        return result, None
    try:
        try:
            rule = sigma_mod.load_rule_file(args.rule)
        except sigma_mod.SigmaError as exc:
            result.fail(str(exc))
            return result, args.case
        findings = sigma_mod.evaluate_rule(rule, db.all_events())
        stored: list[dict[str, Any]] = []
        for finding in findings:
            data = finding.to_dict()
            data["finding_uid"] = db.add_finding(data)
            stored.append(data)
        result.findings = stored
        result.data = {
            "rule_id": rule.id,
            "rule_title": rule.title,
            "count": len(findings),
            "techniques": finding.mitre if findings else [],
        }
        if findings:
            result.summary = f"{len(findings)} finding(s) from sigma rule {rule.id}"
            result.status = "warning"  # findings are the product: exit 1
        else:
            result.summary = f"sigma rule {rule.id}: no matches"
    finally:
        db.close()
    return result, args.case


def cmd_correlate(
    args: argparse.Namespace, state_dir: Path
) -> tuple[Result, str | None]:
    result = Result(command="correlate")
    service = CaseService(state_dir)
    try:
        db = service.open_db(args.case)
    except CaseError as exc:
        result.fail(str(exc))
        return result, None
    try:
        events = db.all_events()
        findings = db.list_findings()
        clusters, stats = correlate_mod.engine_mod.correlate_case(events, findings)
        result.data = {
            "case": args.case,
            "clusters": [c.to_dict() for c in clusters],
            **stats,
        }
        n = len(clusters)
        result.summary = (
            f"{n} activity cluster(s) from {len(events)} event(s), "
            f"{stats['linkage_count']} linkage(s)"
        )
        if n == 0:
            result.summary += " — no correlated activity"
    finally:
        db.close()
    return result, args.case


def cmd_narrative(
    args: argparse.Namespace, state_dir: Path
) -> tuple[Result, str | None]:
    result = Result(command="narrative")
    service = CaseService(state_dir)
    try:
        db = service.open_db(args.case)
    except CaseError as exc:
        result.fail(str(exc))
        return result, None
    try:
        events = db.all_events()
        findings = db.list_findings()
        clusters, _stats = correlate_mod.engine_mod.correlate_case(events, findings)
        if args.cluster < 0 or args.cluster >= len(clusters):
            result.fail(
                f"no cluster {args.cluster} "
                f"({len(clusters)} cluster(s); see 'huntforge correlate')"
            )
            return result, args.case
        narrative = correlate_mod.engine_mod.build_narrative(
            clusters[args.cluster], events
        )
        result.data = narrative.to_dict()
        result.summary = (
            f"cluster {args.cluster}: {narrative.summary} "
            f"(confidence {narrative.confidence})"
        )
    finally:
        db.close()
    return result, args.case


def cmd_report(args: argparse.Namespace, state_dir: Path) -> tuple[Result, str | None]:
    result = Result(command="report case")
    if args.report_command != "case":
        result.fail("usage: huntforge report case CASE-ID --output DIR")
        return result, None
    service = CaseService(state_dir)
    try:
        db = service.open_db(args.case)
    except CaseError as exc:
        result.fail(str(exc))
        return result, None
    try:
        output_dir = Path(args.output).expanduser()
        formats = (
            ("html", "json", "md", "csv") if args.format == "all" else (args.format,)
        )
        try:
            manifest = reporting_mod.report_mod.generate(db, output_dir, formats)
        except ValueError as exc:
            result.fail(str(exc))
            return result, args.case
        result.data = manifest
        result.summary = (
            f"report for {args.case}: {len(manifest['files'])} file(s) in {output_dir}"
        )
    finally:
        db.close()
    return result, args.case


def cmd_notes(args: argparse.Namespace, state_dir: Path) -> tuple[Result, str | None]:
    result = Result(command="notes")
    service = CaseService(state_dir)
    try:
        db = service.open_db(args.case)
    except CaseError as exc:
        result.fail(str(exc))
        return result, None
    try:
        added: dict[str, Any] | None = None
        if args.add is not None:
            try:
                cfg = getattr(args, "app_config", None)
                author = (
                    args.author
                    or (cfg.analyst_name if cfg is not None else None)
                    or "analyst"
                )
                added = reporting_mod.notes_mod.add_note(db, args.add, author=author)
            except CaseError as exc:
                result.fail(str(exc))
                return result, args.case
        show = bool(args.list) or args.add is None
        notes = reporting_mod.notes_mod.list_notes(db) if show else []
        result.data = {
            "case": args.case,
            "added": added,
            "notes": notes,
            "count": len(notes),
        }
        if added is not None and show:
            result.summary = f"note #{added['id']} added; {len(notes)} note(s)"
        elif added is not None:
            result.summary = f"note #{added['id']} added"
        else:
            result.summary = f"{len(notes)} note(s)"
    finally:
        db.close()
    return result, args.case


def cmd_batch(args: argparse.Namespace, state_dir: Path) -> tuple[Result, str | None]:
    result = Result(command="batch")
    cfg = getattr(args, "app_config", None)
    severity_arg = args.severity or (cfg.default_severity if cfg is not None else None)
    min_severity: Severity | None = None
    if severity_arg:
        try:
            level, _ = Severity.parse(severity_arg)
        except ValueError as exc:
            result.fail(str(exc))
            return result, None
        min_severity = level
    runner = batch_mod.BatchRunner(state_dir, min_severity=min_severity)
    try:
        summary = runner.run(args.input_dir, args.output)
    except (ValueError, OSError) as exc:
        result.fail(str(exc))
        return result, None
    if summary["files_found"] == 0:
        result.fail(f"no evidence files found in {args.input_dir}")
        return result, None
    failed = summary["files_failed"]
    result.data = summary
    if failed and summary["cases_created"] == 0:
        result.fail(f"no cases created; {len(failed)} file(s) failed")
        return result, None
    bits = ", ".join(f"{n} {sev}" for sev, n in sorted(summary["by_severity"].items()))
    result.summary = (
        f"{summary['cases_created']} case(s) from {summary['files_found']} file(s), "
        f"{summary['total_events']} event(s), "
        f"{summary['total_findings']} finding(s)"
        + (f": {bits}" if bits else "")
        + (
            f"; {summary['cases_skipped']} skipped (manifest)"
            if summary["cases_skipped"]
            else ""
        )
        + (f"; {len(failed)} file(s) failed" if failed else "")
    )
    if failed or summary["total_findings"]:
        result.status = "warning"
    # Batch touches many cases; each processed case gets its own audit
    # record inside the runner. No single-case audit applies here.
    return result, None


def cmd_export(args: argparse.Namespace, state_dir: Path) -> tuple[Result, str | None]:
    result = Result(command="export")
    service = CaseService(state_dir)
    try:
        db = service.open_db(args.case)
    except CaseError as exc:
        result.fail(str(exc))
        return result, None
    try:
        count = 0
        output = args.output
        try:
            if output:
                out_path = Path(output).expanduser()
                out_path.parent.mkdir(parents=True, exist_ok=True)
                with out_path.open("w", encoding="utf-8") as fh:
                    count = batch_mod.export_what(db, args.what, fh)
                digest = batch_mod.file_sha256(out_path)
                result.data = {
                    "case": args.case,
                    "what": args.what,
                    "format": args.format,
                    "output": str(out_path),
                    "lines": count,
                    "sha256": digest,
                }
            else:
                # No --output: the JSONL goes to stdout; the envelope moves
                # to stderr (or is an error in --json mode, where stdout is
                # reserved for the envelope).
                if args.json:
                    result.fail("use --output with --json (stdout carries the data)")
                    return result, args.case
                count = batch_mod.export_what(db, args.what, sys.stdout)
                result.data = {
                    "case": args.case,
                    "what": args.what,
                    "format": args.format,
                    "output": "stdout",
                    "lines": count,
                }
                print(
                    f"exported {count} {args.what} line(s) as JSONL",
                    file=sys.stderr,
                )
        except (OSError, ValueError) as exc:
            result.fail(str(exc))
            return result, args.case
        result.summary = f"exported {count} {args.what} record(s) as {args.format}"
    finally:
        db.close()
    return result, args.case


def _human_detect(
    data: dict[str, Any], findings: list[dict[str, Any]], explain: bool
) -> None:
    if not findings:
        print("  no findings")
        missing = data.get("rules_without_data") or []
        if missing:
            print(f"  rules without telemetry: {', '.join(missing)}")
        return
    for finding in findings:
        sev = str(finding.get("severity", "?")).upper()
        print(
            f"  [{finding.get('finding_uid')}] {sev} "
            f"{finding.get('rule_id')} — {finding.get('title')} "
            f"(confidence {finding.get('confidence')})"
        )
        for reason in finding.get("why") or []:
            print(f"    why: {reason}")
        for ref in finding.get("evidence") or []:
            print(
                f"    evidence: event #{ref.get('event_id')} "
                f"({ref.get('source')}:{ref.get('source_event_id')}) — "
                f"{ref.get('observation')}"
            )
        if explain:
            print(f"    what: {finding.get('what')}")
            print(f"    confidence: {finding.get('confidence_reason')}")
            for fact in finding.get("observed") or []:
                print(f"    observed: {fact}")
            for guess in finding.get("inferred") or []:
                print(f"    inferred (analyst decides): {guess}")
    missing = data.get("rules_without_data") or []
    if missing:
        print(f"  rules without telemetry: {', '.join(missing)}")


def _human_report(data: dict[str, Any]) -> None:
    for path in data.get("files") or []:
        print(f"  wrote {path}")
    meta = data.get("meta") or {}
    print(f"  report schema {meta.get('report_schema_version')}")
    print("  executive summary is generated — analyst review required")


def _human_notes(data: dict[str, Any]) -> None:
    added = data.get("added")
    if added:
        print(f"  added note #{added['id']}: {added['text']}")
    notes = data.get("notes") or []
    if notes:
        for note in notes:
            print(f"  [#{note['id']}] {note['ts']} ({note['author']}): {note['text']}")
    elif added is None:
        print("  no notes")


def _human_rules(data: dict[str, Any]) -> None:
    for rule in data.get("rules") or []:
        print(f"  {rule['id']} [{rule['severity']}] — {rule['title']}")
        print(f"    {rule['description']}")
        techniques = rule.get("mitre") or []
        if techniques:
            print(f"    ATT&CK: {', '.join(techniques)}")


def _human_batch(data: dict[str, Any]) -> None:
    print(f"  input: {data.get('input_dir')}")
    print(f"  output: {data.get('output_dir')}")
    print(
        f"  files: {data.get('files_found')} found, "
        f"{data.get('cases_created')} case(s) created, "
        f"{data.get('cases_skipped')} skipped"
    )
    print(
        f"  events: {data.get('total_events')}, findings: {data.get('total_findings')}"
    )
    by_sev = data.get("by_severity") or {}
    if by_sev:
        print(
            "  by severity: "
            + ", ".join(f"{n} {sev}" for sev, n in sorted(by_sev.items()))
        )
    top = data.get("top_techniques") or []
    if top:
        print("  top techniques:")
        for entry in top[:5]:
            print(
                f"    {entry['technique_id']} {entry['name']} "
                f"({entry['finding_count']} finding(s))"
            )
    failed = data.get("files_failed") or []
    if failed:
        print(f"  failed: {len(failed)} file(s)")
        for item in failed[:5]:
            print(f"    - {item['file']}: {item['error']}")
    print(f"  summary: {data.get('output_dir')}/{batch_mod.SUMMARY_NAME}")
    print(f"  manifest: {data.get('manifest')}")


def _human_export(data: dict[str, Any]) -> None:
    print(f"  case: {data.get('case')}")
    print(f"  what: {data.get('what')} ({data.get('format')})")
    print(f"  lines: {data.get('lines')}")
    print(f"  output: {data.get('output')}")
    if data.get("sha256"):
        print(f"  sha256: {data['sha256']}")


def _human_mitre(data: dict[str, Any]) -> None:
    if "techniques" in data and "covered" not in data:
        # `mitre techniques` listing.
        for technique in data["techniques"]:
            tactics = "/".join(technique["tactics"])
            sources = technique.get("huntforge_sources") or []
            if sources:
                via = ", ".join(f"{s['source']}:{s['event_id']}" for s in sources)
                print(f"  {technique['id']} {technique['name']} [{tactics}]")
                print(f"    observable via: {via}")
            else:
                print(f"  {technique['id']} {technique['name']} [{tactics}]")
                print("    not observable with current parsers (coverage gap)")
        return
    # Coverage view.
    for entry in data.get("covered") or []:
        tactics = "/".join(entry.get("tactics") or [])
        print(f"  {entry['technique_id']} {entry['name']} [{tactics}]")
        for rule_id, count in sorted((entry.get("rules") or {}).items()):
            print(f"    {rule_id} x{count}")
        findings = entry.get("findings") or []
        if findings:
            print(f"    findings: {', '.join(findings)}")
    gaps = data.get("gaps") or []
    if gaps:
        print(f"  gaps (no findings in this case): {', '.join(gaps)}")
    unobservable = data.get("unobservable") or []
    if unobservable:
        print(f"  not observable with current parsers: {', '.join(unobservable)}")
    unknown = data.get("unknown_technique_ids") or []
    if unknown:
        print(f"  unknown technique references: {', '.join(unknown)}")
    if not data.get("stored_findings"):
        print("  hint: run 'huntforge detect --case ID' to record findings")


def _human_sigma(data: dict[str, Any], findings: list[dict[str, Any]]) -> None:
    rules = data.get("rules")
    if rules is not None:
        for rule in rules:
            if "error" in rule:
                print(f"  {rule.get('file')}: ERROR — {rule['error']}")
                continue
            techniques = rule.get("techniques") or []
            tech = f" ({', '.join(techniques)})" if techniques else ""
            print(
                f"  {rule['id']} [{rule['level']}] {rule['title']}{tech} "
                f"— {Path(rule.get('source_path') or '').name}"
            )
        return
    # `sigma run`: same shape as detect.
    _human_detect(data, findings, explain=False)


def _human_correlate(data: dict[str, Any]) -> None:
    clusters = data.get("clusters") or []
    if not clusters:
        print("  no activity clusters — no linkages between events")
        return
    for cluster in clusters:
        sev = ", ".join(
            f"{n} {name}" for name, n in sorted(cluster.get("by_severity", {}).items())
        )
        sev = f", findings: {sev}" if sev else ", no findings"
        techs = ", ".join(t["id"] for t in cluster.get("techniques") or [])
        techs = f" [{techs}]" if techs else ""
        print(
            f"  [{cluster['cluster_id']}] confidence {cluster['confidence']} "
            f"— {cluster['event_count']} event(s){sev}{techs}"
        )
        for link in cluster.get("linkages") or []:
            print(
                f"      {link['kind']}: #{link['event_a']} <-> #{link['event_b']} "
                f"(INFERRED, conf {link['confidence']})"
            )
    kinds = data.get("linkages_by_kind") or {}
    if kinds:
        bits = ", ".join(f"{k}: {n}" for k, n in sorted(kinds.items()))
        print(f"  linkages: {bits}")
    print(f"  uncorrelated events: {data.get('uncorrelated_event_count', 0)}")
    print("  note: linkages are INFERRED hypotheses; events are OBSERVED facts")


def _human_narrative(data: dict[str, Any]) -> None:
    print(f"  {data['summary']}")
    print(f"  confidence {data['confidence']}: {data['confidence_reason']}")
    observed = data.get("observed") or []
    print(f"  OBSERVED ({len(observed)} events):")
    for entry in observed:
        ts = entry.get("timestamp") or "(untimed)"
        print(f"    {ts} [#{entry['id']}] {entry['summary']}")
    inferred = data.get("inferred") or []
    print(f"  INFERRED linkages ({len(inferred)}):")
    for link in inferred:
        print(f"    [{link['kind']}] {link['claim']}")
        print(f"        confidence {link['confidence']}: {link['confidence_reason']}")
    detections = data.get("detections") or []
    print(f"  detections ({len(detections)}):")
    for det in detections:
        print(
            f"    [{det.get('finding_uid')}] {det.get('severity')} "
            f"{det.get('title')} (conf {det.get('confidence')})"
        )
    techniques = data.get("techniques") or []
    if techniques:
        print("  techniques:")
        for tech in techniques:
            name = f" {tech['name']}" if tech.get("name") else ""
            print(f"    {tech['id']}{name}")
    entities = data.get("entities") or []
    if entities:
        print(f"  entities ({len(entities)}):")
        for entity in entities[:12]:
            print(
                f"    {entity['type']}: {entity['value']} "
                f"({entity['count']} observation(s))"
            )
        if len(entities) > 12:
            print(f"    … and {len(entities) - 12} more")
    missing = data.get("whats_missing") or []
    print(f"  what's missing ({len(missing)}):")
    for item in missing:
        print(f"    - {item}")


def _human_registry(data: dict[str, Any]) -> None:
    print(f"  path: {data.get('path')}")
    print(f"  last_write: {data.get('last_write') or '-'}")
    subkeys = data.get("subkeys") or []
    print(f"  subkeys ({len(subkeys)}):")
    for subkey in subkeys:
        print(f"    {subkey}")
    values = data.get("values") or []
    print(f"  values ({len(values)}):")
    for value in values:
        val_data = value.get("data")
        if isinstance(val_data, list):
            val_data = " | ".join(val_data)
        name = value.get("name") or "(default)"
        print(f"    {name} [{value.get('type_name')}] = {val_data}")


def _human_timeline(data: dict[str, Any]) -> None:
    coverage = data.get("coverage") or {}
    sources = coverage.get("sources") or {}
    if sources:
        bits = ", ".join(
            f"{name}: {info['events']}" for name, info in sorted(sources.items())
        )
        print(f"  sources: {bits}")
    time_filter = coverage.get("time_filter") or {}
    if time_filter.get("from") or time_filter.get("to"):
        start = time_filter.get("from") or "…"
        end = time_filter.get("to") or "…"
        print(f"  window: {start} .. {end}")
    timed = data.get("timed") or []
    print(f"  timed ({len(timed)}):")
    for entry in timed:
        print(f"    {entry['timestamp']} [{entry['id']}] {entry['summary']}")
    if data.get("truncated"):
        print("    … truncated (raise --limit)")
    untimed = data.get("untimed") or []
    if untimed:
        print(f"  untimed ({len(untimed)} — no original timestamp, never placed):")
        for entry in untimed:
            print(
                f"    [#{entry['id']}] {entry['source']}:{entry['event_id']}"
                f" — {entry['summary']}"
            )
    note = coverage.get("note")
    if note:
        print(f"  note: {note}")


def _human_lineage(data: dict[str, Any]) -> None:
    if data.get("reused_pids"):
        print(f"  pid reuse observed: {', '.join(data['reused_pids'])}")
    trees = data.get("trees") or []
    for line in trees:
        print(f"  {line}" if line else "")


def _human_entities(data: dict[str, Any]) -> None:
    entities = data.get("entities") or []
    current_type = ""
    for entity in entities:
        if entity["type"] != current_type:
            current_type = entity["type"]
            print(f"  {current_type}:")
        variants = ""
        if (
            len(entity["observed_as"]) > 1
            or entity["observed_as"][0] != entity["value"]
        ):
            variants = f" (seen as: {', '.join(entity['observed_as'])})"
        print(
            f"    {entity['value']}{variants} — {entity['count']} observation(s) "
            f"[{', '.join(entity['sources'])}]"
        )


def render(
    result: Result, as_json: bool, args: argparse.Namespace | None = None
) -> None:
    if as_json:
        _print_json(result)
        return
    if result.status == "error":
        print(f"error: {result.summary}", file=sys.stderr)
        return
    if (
        result.command == "export"
        and result.data
        and result.data.get("output") == "stdout"
    ):
        # JSONL owns stdout here; the one-line summary already went to stderr.
        return
    print(result.summary or "ok")
    if result.command == "registry" and result.data:
        _human_registry(result.data)
        return
    if result.command == "timeline" and result.data:
        _human_timeline(result.data)
        return
    if result.command == "lineage" and result.data:
        _human_lineage(result.data)
        return
    if result.command == "entities" and result.data:
        _human_entities(result.data)
        return
    if result.command == "detect" and result.data:
        explain = bool(args is not None and getattr(args, "explain", False))
        _human_detect(result.data, result.findings, explain)
        return
    if result.command == "rules list" and result.data:
        _human_rules(result.data)
        return
    if result.command in ("mitre", "mitre techniques") and result.data:
        _human_mitre(result.data)
        return
    if result.command in ("sigma list", "sigma run") and result.data:
        _human_sigma(result.data, result.findings)
        return
    if result.command == "correlate" and result.data:
        _human_correlate(result.data)
        return
    if result.command == "narrative" and result.data:
        _human_narrative(result.data)
        return
    if result.command == "report case" and result.data:
        _human_report(result.data)
        return
    if result.command == "notes" and result.data:
        _human_notes(result.data)
        return
    if result.command == "batch" and result.data:
        _human_batch(result.data)
        return
    if result.command == "export" and result.data:
        _human_export(result.data)
        return
    if result.data:
        for key, value in result.data.items():
            if key in ("evidence", "cases", "entries", "evidence_files"):
                continue
            if isinstance(value, (dict, list)):
                continue
            print(f"  {key}: {value}")
    if result.data.get("cases"):
        for case in result.data["cases"]:
            print(
                f"  {case['case_id']}: {case['name']} "
                f"({case['events']} events, {case['evidence']} evidence)"
            )
    if result.data.get("evidence_files"):
        for item in result.data["evidence_files"]:
            print(f"  #{item['id']} {item['filename']} sha256={item['sha256'][:16]}…")
    if result.data.get("evidence"):
        for item in result.data["evidence"]:
            print(f"  #{item['id']} {item['filename']} sha256={item['sha256'][:16]}…")
    warnings = result.data.get("parse_warnings") or []
    if warnings:
        print(f"  warnings ({len(warnings)}):")
        for warning in warnings[:5]:
            print(f"    - {warning}")
        if len(warnings) > 5:
            print(f"    … and {len(warnings) - 5} more (see --json)")
    if result.events:
        _human_events(result.events)


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    # Accept --json anywhere on the command line (argparse only allows
    # top-level optionals before the subcommand).
    raw = list(argv) if argv is not None else sys.argv[1:]
    as_json = "--json" in raw
    args = parser.parse_args([a for a in raw if a != "--json"])
    args.json = as_json or args.json
    if not args.command:
        parser.print_help()
        return EXIT_OK
    try:
        app_config = appconfig_mod.load_config(args.config)
    except ConfigError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    args.app_config = app_config
    if app_config.warnings:
        for warning in app_config.warnings:
            print(f"warning: {warning}", file=sys.stderr)
    try:
        state_dir = config_mod.resolve_state_dir(
            args.state_dir, config_value=app_config.state_dir
        )
    except OSError as exc:
        print(f"error: cannot use state directory: {exc}", file=sys.stderr)
        return EXIT_ERROR

    handlers = {
        "case": cmd_case,
        "ingest": cmd_ingest,
        "events": cmd_events,
        "audit": cmd_audit,
        "registry": cmd_registry,
        "timeline": cmd_timeline,
        "lineage": cmd_lineage,
        "entities": cmd_entities,
        "detect": cmd_detect,
        "rules": cmd_rules,
        "mitre": cmd_mitre,
        "sigma": cmd_sigma,
        "correlate": cmd_correlate,
        "narrative": cmd_narrative,
        "report": cmd_report,
        "notes": cmd_notes,
        "batch": cmd_batch,
        "export": cmd_export,
    }
    handler = handlers.get(args.command)
    if handler is None:  # pragma: no cover - argparse guards this
        print(f"error: unknown command {args.command!r}", file=sys.stderr)
        return EXIT_ERROR
    result, audit_case = handler(args, state_dir)
    if audit_case:
        _audit(audit_case, state_dir, args.command, args, result)
    render(result, args.json, args)
    return exit_code_for(result)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
