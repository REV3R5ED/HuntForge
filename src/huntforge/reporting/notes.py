"""Analyst notes service for HuntForge v0.8.

Notes are analyst-authored free text stored in the case database. They
are stored verbatim and always rendered under a clearly-marked
"Analyst notes" section. HuntForge itself never writes notes.
"""

from __future__ import annotations

from typing import Any

from huntforge.store.db import CaseDB


def add_note(db: CaseDB, text: str, author: str = "analyst") -> dict[str, Any]:
    """Append a note; returns the stored note."""
    note_id = db.add_note(text, author=author)
    notes = db.list_notes()
    for note in notes:
        if note["id"] == note_id:
            return note
    raise AssertionError("note just added but not found")  # pragma: no cover


def list_notes(db: CaseDB) -> list[dict[str, Any]]:
    """All analyst notes, oldest first."""
    return db.list_notes()
