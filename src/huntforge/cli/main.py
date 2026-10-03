"""HuntForge CLI: ``huntforge case ...`` / ``huntforge ingest ...`` /
``huntforge events ...``.

Every command returns a shared result envelope, renders human-readable
text by default (``--json`` for automation), uses structured exit
codes (0 ok / 2 error; 1 is reserved for future detection findings),
and writes an audit record to the case when one is involved.
Diagnostics go to stderr; stdout carries only the requested output.

v0.1 is the foundation: case lifecycle, evidence ingest with real
hashing and provenance, a JSONL fixture loader for tests and early
use, and filtered queries over the normalized event store. Parsers,
timeline, detections, ATT&CK/Sigma, correlation, reports and the UI
arrive in later phases per the master plan.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from huntforge import __version__
from huntforge.cases.service import CaseService
from huntforge.core import config as config_mod
from huntforge.core import plugins as plugins_mod
from huntforge.core.results import (
    EXIT_ERROR,
    EXIT_OK,
    Result,
    exit_code_for,
)
from huntforge.events.query import EventQuery
from huntforge.ingest.service import ingest_path, load_fixture
from huntforge.store.db import CaseDB, CaseError

plugins_mod.register(
    plugins_mod.ModuleInfo(
        name="core",
        description="Core CLI, normalized event model, case store, ingest",
        version=__version__,
        commands=["case", "ingest", "events", "version"],
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
            + len(result.data.get("evidence", []) or [])
            + int(result.data.get("registered", 0) or 0)
            + int(fixture.get("loaded", 0) or 0)
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
        summary = ingest_path(db, path, recursive=not args.no_recursive)
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
            result.summary = (
                f"registered {summary['registered']} evidence file(s), "
                f"loaded {fixture_summary.get('loaded', 0)} event(s)"
            )
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


def render(result: Result, as_json: bool) -> None:
    if as_json:
        _print_json(result)
        return
    if result.status == "error":
        print(f"error: {result.summary}", file=sys.stderr)
        return
    print(result.summary or "ok")
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
        state_dir = config_mod.resolve_state_dir(args.state_dir)
    except OSError as exc:
        print(f"error: cannot use state directory: {exc}", file=sys.stderr)
        return EXIT_ERROR

    handlers = {
        "case": cmd_case,
        "ingest": cmd_ingest,
        "events": cmd_events,
        "audit": cmd_audit,
    }
    handler = handlers.get(args.command)
    if handler is None:  # pragma: no cover - argparse guards this
        print(f"error: unknown command {args.command!r}", file=sys.stderr)
        return EXIT_ERROR
    result, audit_case = handler(args, state_dir)
    if audit_case:
        _audit(audit_case, state_dir, args.command, args, result)
    render(result, args.json)
    return exit_code_for(result)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
