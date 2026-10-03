"""Per-case SQLite event store.

Each case lives at ``<state-dir>/cases/<CASE-ID>/store.db`` with four
tables:

- ``meta`` — case id, name, created timestamp, schema version.
- ``evidence`` — files registered by ``huntforge ingest``: path,
  size, SHA-256/MD5, ingest time, parser. Deduped by SHA-256.
- ``events`` — normalized events with provenance columns inlined.
  Indexed on (timestamp, host, user, event_id, process_name).
- ``audit`` — one row per CLI invocation touching the case.

Case IDs are validated to prevent path traversal: they may contain
letters, digits, ``.``, ``_`` and ``-`` only.
"""

from __future__ import annotations

import json
import re
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from huntforge.core.logging import utc_now_iso
from huntforge.models.events import NormalizedEvent

SCHEMA_VERSION = 1
CASE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS evidence (
    id INTEGER PRIMARY KEY,
    path TEXT NOT NULL,
    filename TEXT NOT NULL,
    size INTEGER NOT NULL,
    sha256 TEXT NOT NULL,
    md5 TEXT NOT NULL,
    ingested_at TEXT NOT NULL,
    parser TEXT NOT NULL DEFAULT 'ingest'
);
CREATE UNIQUE INDEX IF NOT EXISTS evidence_sha ON evidence(sha256);
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY,
    timestamp TEXT NOT NULL,
    timestamp_original TEXT,
    host TEXT,
    user TEXT,
    source TEXT NOT NULL,
    event_id TEXT NOT NULL,
    process_name TEXT,
    process_id INTEGER,
    parent_name TEXT,
    parent_id INTEGER,
    command_line TEXT,
    src_ip TEXT,
    src_port INTEGER,
    dst_ip TEXT,
    dst_port INTEGER,
    file_path TEXT,
    registry_key TEXT,
    hashes TEXT NOT NULL DEFAULT '{}',
    flags TEXT NOT NULL DEFAULT '[]',
    raw TEXT,
    evidence_id INTEGER REFERENCES evidence(id),
    prov_source_file TEXT NOT NULL,
    prov_record_index INTEGER NOT NULL,
    prov_parser_name TEXT NOT NULL,
    prov_parser_version TEXT NOT NULL,
    prov_ingest_time TEXT NOT NULL,
    prov_source_sha256 TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS events_time ON events(timestamp);
CREATE INDEX IF NOT EXISTS events_host ON events(host);
CREATE INDEX IF NOT EXISTS events_user ON events(user);
CREATE INDEX IF NOT EXISTS events_event_id ON events(event_id);
CREATE INDEX IF NOT EXISTS events_process ON events(process_name);
CREATE TABLE IF NOT EXISTS audit (
    id INTEGER PRIMARY KEY,
    ts TEXT NOT NULL,
    command TEXT NOT NULL,
    args_json TEXT NOT NULL,
    result_count INTEGER NOT NULL,
    status TEXT NOT NULL
);
"""


class CaseError(Exception):
    """Raised for case lifecycle problems (unknown case, bad ID, ...)."""


def validate_case_id(case_id: str) -> str:
    """Validate a case ID (also blocks path traversal)."""
    if not isinstance(case_id, str) or not CASE_ID_RE.match(case_id):
        raise CaseError(
            f"invalid case id {case_id!r}: use 1-64 chars of "
            "letters, digits, '.', '_' or '-'"
        )
    return case_id


def case_dir(state_dir: Path, case_id: str) -> Path:
    return state_dir / "cases" / validate_case_id(case_id)


@dataclass
class EvidenceRecord:
    id: int
    path: str
    filename: str
    size: int
    sha256: str
    md5: str
    ingested_at: str
    parser: str


class CaseDB:
    """SQLite store for a single case."""

    def __init__(self, state_dir: Path, case_id: str) -> None:
        validate_case_id(case_id)
        self.case_id = case_id
        self.dir = case_dir(state_dir, case_id)
        self.path = self.dir / "store.db"
        if not self.path.exists():
            raise CaseError(f"unknown case {case_id!r}")
        self._conn = sqlite3.connect(str(self.path))
        self._conn.row_factory = sqlite3.Row
        self._migrate()

    def _migrate(self) -> None:
        """Bring older databases up to the current schema (v0.1 -> v0.2)."""
        columns = {r["name"] for r in self._conn.execute("PRAGMA table_info(events)")}
        if "flags" not in columns:
            self._conn.execute(
                "ALTER TABLE events ADD COLUMN flags TEXT NOT NULL DEFAULT '[]'"
            )
            self._conn.commit()

    @classmethod
    def create(cls, state_dir: Path, case_id: str, name: str | None = None) -> CaseDB:
        validate_case_id(case_id)
        directory = case_dir(state_dir, case_id)
        if (directory / "store.db").exists():
            raise CaseError(f"case {case_id!r} already exists")
        directory.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(directory / "store.db"))
        try:
            conn.executescript(_SCHEMA)
            conn.execute("PRAGMA journal_mode=WAL")
            now = utc_now_iso()
            conn.executemany(
                "INSERT INTO meta(key, value) VALUES (?, ?)",
                [
                    ("case_id", case_id),
                    ("name", name or case_id),
                    ("created", now),
                    ("schema_version", str(SCHEMA_VERSION)),
                ],
            )
            conn.commit()
        finally:
            conn.close()
        return cls(state_dir, case_id)

    def close(self) -> None:
        self._conn.close()

    # -- meta ---------------------------------------------------------
    def meta(self) -> dict[str, str]:
        return {r["key"]: r["value"] for r in self._conn.execute("SELECT * FROM meta")}

    def event_count(self) -> int:
        row = self._conn.execute("SELECT COUNT(*) AS n FROM events").fetchone()
        return int(row["n"])

    def evidence_count(self) -> int:
        row = self._conn.execute("SELECT COUNT(*) AS n FROM evidence").fetchone()
        return int(row["n"])

    # -- evidence ------------------------------------------------------
    def add_evidence(
        self,
        path: str,
        filename: str,
        size: int,
        sha256: str,
        md5: str,
        parser: str = "ingest",
    ) -> EvidenceRecord:
        """Register an evidence file; duplicates (by SHA-256) are ignored."""
        now = utc_now_iso()
        self._conn.execute(
            """INSERT OR IGNORE INTO evidence
               (path, filename, size, sha256, md5, ingested_at, parser)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (path, filename, size, sha256, md5, now, parser),
        )
        self._conn.commit()
        row = self._conn.execute(
            "SELECT * FROM evidence WHERE sha256 = ?", (sha256,)
        ).fetchone()
        assert row is not None
        return EvidenceRecord(
            id=int(row["id"]),
            path=row["path"],
            filename=row["filename"],
            size=int(row["size"]),
            sha256=row["sha256"],
            md5=row["md5"],
            ingested_at=row["ingested_at"],
            parser=row["parser"],
        )

    def list_evidence(self) -> list[EvidenceRecord]:
        return [
            EvidenceRecord(
                id=int(r["id"]),
                path=r["path"],
                filename=r["filename"],
                size=int(r["size"]),
                sha256=r["sha256"],
                md5=r["md5"],
                ingested_at=r["ingested_at"],
                parser=r["parser"],
            )
            for r in self._conn.execute("SELECT * FROM evidence ORDER BY id")
        ]

    # -- events ---------------------------------------------------------
    def add_event(self, event: NormalizedEvent, evidence_id: int | None = None) -> int:
        cur = self._conn.execute(
            """INSERT INTO events
               (timestamp, timestamp_original, host, user, source, event_id,
                process_name, process_id, parent_name, parent_id, command_line,
                src_ip, src_port, dst_ip, dst_port, file_path, registry_key,
                hashes, flags, raw, evidence_id,
                prov_source_file, prov_record_index, prov_parser_name,
                prov_parser_version, prov_ingest_time, prov_source_sha256)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                event.timestamp,
                event.timestamp_original,
                event.host,
                event.user,
                event.source,
                event.event_id,
                event.process_name,
                event.process_id,
                event.parent_name,
                event.parent_id,
                event.command_line,
                event.src_ip,
                event.src_port,
                event.dst_ip,
                event.dst_port,
                event.file_path,
                event.registry_key,
                json.dumps(event.hashes, sort_keys=True),
                json.dumps(event.flags),
                event.raw,
                evidence_id,
                event.provenance.source_file,
                event.provenance.record_index,
                event.provenance.parser_name,
                event.provenance.parser_version,
                event.provenance.ingest_time,
                event.provenance.source_sha256,
            ),
        )
        self._conn.commit()
        row_id = cur.lastrowid
        if row_id is None:  # pragma: no cover - INSERT always sets rowid
            raise CaseError("failed to insert event")
        return row_id

    def query_events(
        self,
        host: str | None = None,
        user: str | None = None,
        event_id: str | None = None,
        process: str | None = None,
        keyword: str | None = None,
        limit: int = 200,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """Query events; all filters combine with AND (case-insensitive)."""
        clauses: list[str] = []
        params: list[Any] = []
        if host:
            clauses.append("LOWER(host) = LOWER(?)")
            params.append(host)
        if user:
            clauses.append("LOWER(user) = LOWER(?)")
            params.append(user)
        if event_id:
            clauses.append("event_id = ?")
            params.append(str(event_id))
        if process:
            clauses.append("LOWER(process_name) = LOWER(?)")
            params.append(process)
        if keyword:
            clauses.append(
                "(LOWER(command_line) LIKE ? OR LOWER(file_path) LIKE ? "
                "OR LOWER(registry_key) LIKE ? OR LOWER(process_name) LIKE ?)"
            )
            like = f"%{keyword.lower()}%"
            params.extend([like, like, like, like])
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        rows = self._conn.execute(
            f"SELECT * FROM events {where} ORDER BY timestamp ASC, id ASC "
            f"LIMIT ? OFFSET ?",
            (*params, limit, offset),
        ).fetchall()
        return [self._row_to_event(r) for r in rows]

    def all_events(self) -> list[dict[str, Any]]:
        """Every event in the case, ordered deterministically by
        (timestamp, row id). Unfiltered — callers (timeline, lineage,
        entities) apply their own views."""
        rows = self._conn.execute(
            "SELECT * FROM events ORDER BY timestamp ASC, id ASC"
        ).fetchall()
        return [self._row_to_event(r) for r in rows]

    @staticmethod
    def _row_to_event(row: sqlite3.Row) -> dict[str, Any]:
        try:
            hashes = json.loads(row["hashes"] or "{}")
        except json.JSONDecodeError:
            hashes = {}
        try:
            flags = json.loads(row["flags"] or "[]")
        except (json.JSONDecodeError, KeyError, IndexError):
            flags = []
        if not isinstance(flags, list):
            flags = []
        return {
            "id": int(row["id"]),
            "timestamp": row["timestamp"],
            "timestamp_original": row["timestamp_original"],
            "host": row["host"],
            "user": row["user"],
            "source": row["source"],
            "event_id": row["event_id"],
            "process_name": row["process_name"],
            "process_id": row["process_id"],
            "parent_name": row["parent_name"],
            "parent_id": row["parent_id"],
            "command_line": row["command_line"],
            "src_ip": row["src_ip"],
            "src_port": row["src_port"],
            "dst_ip": row["dst_ip"],
            "dst_port": row["dst_port"],
            "file_path": row["file_path"],
            "registry_key": row["registry_key"],
            "hashes": hashes,
            "flags": flags,
            "raw": row["raw"],
            "evidence_id": row["evidence_id"],
            "provenance": {
                "source_file": row["prov_source_file"],
                "record_index": int(row["prov_record_index"]),
                "parser_name": row["prov_parser_name"],
                "parser_version": row["prov_parser_version"],
                "ingest_time": row["prov_ingest_time"],
                "source_sha256": row["prov_source_sha256"],
            },
        }

    # -- audit ----------------------------------------------------------
    def audit(
        self, command: str, args: dict[str, Any], result_count: int, status: str
    ) -> None:
        safe_args = {k: v for k, v in args.items() if k != "state_dir"}
        self._conn.execute(
            "INSERT INTO audit(ts, command, args_json, result_count, status)"
            " VALUES (?, ?, ?, ?, ?)",
            (
                utc_now_iso(),
                command,
                json.dumps(safe_args, sort_keys=True, default=str),
                int(result_count),
                status,
            ),
        )
        self._conn.commit()

    def audit_log(self, limit: int = 100) -> list[dict[str, Any]]:
        return [
            {
                "id": int(r["id"]),
                "ts": r["ts"],
                "command": r["command"],
                "args": json.loads(r["args_json"]),
                "result_count": int(r["result_count"]),
                "status": r["status"],
            }
            for r in self._conn.execute(
                "SELECT * FROM audit ORDER BY id DESC LIMIT ?", (limit,)
            )
        ]


def list_cases(state_dir: Path) -> list[dict[str, Any]]:
    """List all cases in the state directory (sorted by case id)."""
    cases_dir = state_dir / "cases"
    if not cases_dir.is_dir():
        return []
    results: list[dict[str, Any]] = []
    for entry in sorted(cases_dir.iterdir(), key=lambda p: p.name):
        db_path = entry / "store.db"
        if not entry.is_dir() or not db_path.exists():
            continue
        try:
            db = CaseDB(state_dir, entry.name)
        except CaseError:
            continue
        try:
            meta = db.meta()
            results.append(
                {
                    "case_id": entry.name,
                    "name": meta.get("name", entry.name),
                    "created": meta.get("created", ""),
                    "events": db.event_count(),
                    "evidence": db.evidence_count(),
                }
            )
        finally:
            db.close()
    return results
