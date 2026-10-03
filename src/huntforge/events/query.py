"""Filtered queries over a case's normalized event store.

All filters combine with AND semantics and are case-insensitive
(except ``event_id``, which matches exactly). Results are ordered
deterministically by (timestamp, row id).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from huntforge.store.db import CaseDB

DEFAULT_LIMIT = 200
MAX_LIMIT = 10_000


@dataclass
class EventQuery:
    host: str | None = None
    user: str | None = None
    event_id: str | None = None
    process: str | None = None
    keyword: str | None = None
    limit: int = DEFAULT_LIMIT
    offset: int = 0

    def __post_init__(self) -> None:
        if self.limit is not None:
            if not isinstance(self.limit, int) or self.limit < 1:
                raise ValueError("limit must be a positive int")
            self.limit = min(self.limit, MAX_LIMIT)
        if self.offset is not None:
            if not isinstance(self.offset, int) or self.offset < 0:
                raise ValueError("offset must be a non-negative int")

    def describe(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "user": self.user,
            "event_id": self.event_id,
            "process": self.process,
            "keyword": self.keyword,
            "limit": self.limit,
            "offset": self.offset,
        }

    def run(self, db: CaseDB) -> list[dict[str, Any]]:
        return db.query_events(
            host=self.host,
            user=self.user,
            event_id=self.event_id,
            process=self.process,
            keyword=self.keyword,
            limit=self.limit,
            offset=self.offset,
        )
