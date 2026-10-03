"""Case lifecycle service for HuntForge v0.1.

v0.1 covers create/show/list. Notes, findings, manifests and
chain-of-custody workflows arrive with the v0.8 case-management
phase; the audit table already records every CLI invocation.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from huntforge.store.db import CaseDB, list_cases


class CaseService:
    def __init__(self, state_dir: Path) -> None:
        self.state_dir = state_dir

    def create(self, case_id: str, name: str | None = None) -> dict[str, Any]:
        db = CaseDB.create(self.state_dir, case_id, name=name)
        try:
            meta = db.meta()
            return {
                "case_id": case_id,
                "name": meta["name"],
                "created": meta["created"],
                "events": 0,
                "evidence": 0,
            }
        finally:
            db.close()

    def show(self, case_id: str) -> dict[str, Any]:
        db = CaseDB(self.state_dir, case_id)
        try:
            meta = db.meta()
            return {
                "case_id": case_id,
                "name": meta.get("name", case_id),
                "created": meta.get("created", ""),
                "schema_version": meta.get("schema_version", ""),
                "events": db.event_count(),
                "evidence": db.evidence_count(),
                "evidence_files": [
                    {
                        "id": e.id,
                        "filename": e.filename,
                        "size": e.size,
                        "sha256": e.sha256,
                        "ingested_at": e.ingested_at,
                        "parser": e.parser,
                    }
                    for e in db.list_evidence()
                ],
            }
        finally:
            db.close()

    def list(self) -> list[dict[str, Any]]:
        return list_cases(self.state_dir)

    def open_db(self, case_id: str) -> CaseDB:
        """Open the case DB; raises :class:`CaseError` for unknown cases."""
        return CaseDB(self.state_dir, case_id)
