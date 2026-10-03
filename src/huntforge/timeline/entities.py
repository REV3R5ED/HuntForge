"""Entity resolution: normalize and link entities across sources (v0.4).

Normalization is mechanical and documented — never inference:

- ``host``: case-insensitive (``WS-FIN-014`` == ``ws-fin-014``).
- ``user``: ``DOMAIN\\user`` → ``user@domain`` (both lowercased);
  ``user@domain`` passes through lowercased; bare names and SIDs are
  lowercased as-is.
- ``ip``: stripped, lowercased (covers IPv6 hex).
- ``process``: image name lowercased (``PowerShell.EXE`` ==
  ``powershell.exe``).
- ``file``: Windows paths are case-insensitive → lowercased.
- ``hash``: ``<algo>:<digest>`` lowercased.
- ``registry``: registry key paths lowercased.

Every entity records the distinct observed spellings, the sources it
appeared in, an observation count, and first/last-seen timestamps
(from timed events only). Observation only: no verdicts.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from huntforge.store.db import CaseDB

ENTITY_TYPES = ("host", "user", "ip", "process", "file", "hash", "registry")


def normalize_user(value: str) -> str:
    text = value.strip()
    if "\\" in text:
        domain, _, user = text.partition("\\")
        return f"{user.strip().lower()}@{domain.strip().lower()}"
    return text.lower()


def normalize_host(value: str) -> str:
    return value.strip().lower()


def normalize_ip(value: str) -> str:
    return value.strip().lower()


def normalize_process(value: str) -> str:
    return value.strip().lower()


def normalize_file(value: str) -> str:
    return value.strip().lower()


def normalize_hash(algo: str, digest: str) -> str:
    return f"{algo.strip().lower()}:{digest.strip().lower()}"


def normalize_registry(value: str) -> str:
    return value.strip().lower()


@dataclass
class Entity:
    type: str
    value: str  # canonical normalized value
    observed_as: set[str] = field(default_factory=set)
    count: int = 0
    sources: set[str] = field(default_factory=set)
    first_seen: str | None = None
    last_seen: str | None = None

    def observe(
        self,
        raw: str,
        source: str,
        timestamp: str | None,
        timed: bool,
    ) -> None:
        self.observed_as.add(raw)
        self.count += 1
        self.sources.add(source)
        if timed and timestamp:
            if self.first_seen is None or timestamp < self.first_seen:
                self.first_seen = timestamp
            if self.last_seen is None or timestamp > self.last_seen:
                self.last_seen = timestamp

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.type,
            "value": self.value,
            "observed_as": sorted(self.observed_as),
            "count": self.count,
            "sources": sorted(self.sources),
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
        }


def resolve_entities(db: CaseDB) -> list[Entity]:
    """Resolve every entity observed in a case, grouped by type."""
    entities: dict[tuple[str, str], Entity] = {}

    def add(
        etype: str,
        canonical: str,
        raw: str,
        source: str,
        timestamp: str | None,
        timed: bool,
    ) -> None:
        if not canonical:
            return
        key = (etype, canonical)
        entity = entities.get(key)
        if entity is None:
            entity = Entity(type=etype, value=canonical)
            entities[key] = entity
        entity.observe(raw, source, timestamp, timed)

    for event in db.all_events():
        source = str(event.get("source") or "")
        ts = event.get("timestamp")
        timed = bool(event.get("timestamp_original"))
        host = event.get("host")
        if host:
            add("host", normalize_host(host), host, source, ts, timed)
        user = event.get("user")
        if user:
            add("user", normalize_user(user), user, source, ts, timed)
        for ip_field in ("src_ip", "dst_ip"):
            ip = event.get(ip_field)
            if ip:
                add("ip", normalize_ip(str(ip)), str(ip), source, ts, timed)
        proc = event.get("process_name")
        if proc:
            add("process", normalize_process(proc), proc, source, ts, timed)
        file_path = event.get("file_path")
        if file_path:
            add("file", normalize_file(file_path), file_path, source, ts, timed)
        reg_key = event.get("registry_key")
        if reg_key:
            add("registry", normalize_registry(reg_key), reg_key, source, ts, timed)
        hashes = event.get("hashes") or {}
        if isinstance(hashes, dict):
            for algo, digest in hashes.items():
                raw = f"{algo}:{digest}"
                add("hash", normalize_hash(algo, digest), raw, source, ts, timed)

    return sorted(entities.values(), key=lambda e: (e.type, e.value))
