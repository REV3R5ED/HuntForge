"""Process lineage: parent→child process trees (v0.4).

Instances are built from process-creation records (Sysmon EventID 1,
Security 4688, and generic exported Event XML carrying the same
fields). Any other event that names a ``process_id`` (network, file,
registry) is attached to the matching instance as a *reference* —
it corroborates the instance but never creates one.

PID reuse is handled honestly:

- One instance = one (host, pid, process image) observed starting.
  The same PID launching a different image later becomes a separate
  instance, and the PID is flagged ``pid_reused``.
- A child links to the candidate parent instance with the same
  (host, pid) whose start time is the latest one still **not after**
  the child's start (a parent must exist before its child). If more
  than one candidate qualifies, the link carries an explicit
  ``ambiguous_parent`` note naming every candidate — the ambiguity is
  surfaced, never silently merged.
- A child whose parent PID was never observed becomes an orphan root.

Observation only: no verdicts.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from huntforge.store.db import CaseDB

#: (source, event_id) pairs treated as process-creation records.
_CREATION_KEYS = {
    ("sysmon", "1"),
    ("security", "4688"),
    ("evtx-xml", "4688"),
    ("evtx-xml", "1"),
}


@dataclass
class ProcessInstance:
    """One observed start of one image under one PID on one host."""

    key: str  # "host\x00pid\x00image-lower"
    host: str | None
    pid: int
    image: str  # as observed (original case)
    start: str  # earliest creation timestamp (UTC ISO)
    start_original: str | None
    parent_pid: int | None
    parent_image: str | None
    user: str | None
    command_line: str | None
    event_ids: list[int] = field(default_factory=list)
    references: int = 0  # non-creation events naming this (host, pid)
    parent_key: str | None = None
    ambiguous_parent: list[str] = field(default_factory=list)
    orphan: bool = False

    def label(self) -> str:
        return f"{self.image} ({self.pid})"


def _is_creation(event: dict[str, Any]) -> bool:
    source = str(event.get("source") or "")
    base = source.split(":")[0]
    return (base, str(event.get("event_id"))) in _CREATION_KEYS


def _instance_key(host: str | None, pid: int, image: str) -> str:
    return f"{(host or '').lower()}\x00{pid}\x00{image.lower()}"


def build_lineage(db: CaseDB) -> dict[str, Any]:
    """Reconstruct the process forest for a case (observation only)."""
    instances: dict[str, ProcessInstance] = {}
    by_pid: dict[tuple[str, int], list[ProcessInstance]] = {}

    for event in db.all_events():
        pid = event.get("process_id")
        if not isinstance(pid, int):
            continue
        host = event.get("host")
        image = (event.get("process_name") or "").strip()
        if _is_creation(event) and image:
            key = _instance_key(host, pid, image)
            inst = instances.get(key)
            if inst is None:
                inst = ProcessInstance(
                    key=key,
                    host=host,
                    pid=pid,
                    image=image,
                    start=str(event.get("timestamp")),
                    start_original=event.get("timestamp_original"),
                    parent_pid=event.get("parent_id"),
                    parent_image=event.get("parent_name"),
                    user=event.get("user"),
                    command_line=event.get("command_line"),
                )
                instances[key] = inst
                by_pid.setdefault(((host or "").lower(), pid), []).append(inst)
            else:
                ts_ev = event.get("timestamp")
                if isinstance(ts_ev, str) and ts_ev < inst.start:
                    inst.start = ts_ev
                    inst.start_original = event.get("timestamp_original")
                if event.get("id") is not None:
                    inst.event_ids.append(int(event["id"]))
        else:
            # Reference: attach to the instance of this (host, pid) with
            # the latest start not after the event's own timestamp.
            ts = str(event.get("timestamp") or "")
            candidates = [
                c for c in by_pid.get(((host or "").lower(), pid), []) if c.start <= ts
            ]
            if candidates:
                best = max(candidates, key=lambda c: c.start)
                best.references += 1

    # Link children to parents.
    for inst in instances.values():
        if inst.parent_pid is None:
            inst.orphan = True
            continue
        candidates = [
            p
            for p in by_pid.get((inst.key.split("\x00")[0], inst.parent_pid), [])
            if p.start <= inst.start and p.key != inst.key
        ]
        if not candidates:
            inst.orphan = True
        elif len(candidates) == 1:
            inst.parent_key = candidates[0].key
        else:
            # Ambiguous: several instances share the parent PID and all
            # started before the child. Link to the latest-plausible one
            # and name every candidate explicitly.
            candidates.sort(key=lambda c: c.start)
            inst.parent_key = candidates[-1].key
            inst.ambiguous_parent = [c.label() for c in candidates]

    # PID-reuse flags: one PID, several images on the same host.
    reused_pids: set[tuple[str, int]] = set()
    for (host, pid), group in by_pid.items():
        if len({i.image.lower() for i in group}) > 1:
            reused_pids.add((host, pid))

    children: dict[str, list[str]] = {k: [] for k in instances}
    for inst in instances.values():
        if inst.parent_key and inst.parent_key in children:
            children[inst.parent_key].append(inst.key)
    for key in children:
        children[key].sort(key=lambda k: instances[k].start)

    roots = sorted(
        (k for k, v in instances.items() if v.parent_key is None),
        key=lambda k: instances[k].start,
    )

    return {
        "instances": instances,
        "children": children,
        "roots": roots,
        "reused_pids": sorted(f"{h or '-'}:{p}" for h, p in reused_pids),
        "instance_count": len(instances),
    }


def _tree_lines(
    forest: dict[str, Any],
    key: str,
    prefix: str,
    *,
    show_refs: bool = True,
) -> list[str]:
    instances: dict[str, ProcessInstance] = forest["instances"]
    children: dict[str, list[str]] = forest["children"]
    inst = instances[key]
    line = f"{inst.label()}  [{inst.start}]"
    if inst.user:
        line += f" user={inst.user}"
    notes: list[str] = []
    if inst.ambiguous_parent:
        notes.append(
            "ambiguous parent (pid reused): " + ", ".join(inst.ambiguous_parent)
        )
    if inst.orphan and inst.parent_pid is not None:
        notes.append(f"parent pid {inst.parent_pid} not observed")
    if show_refs and inst.references:
        notes.append(f"{inst.references} related event(s)")
    if notes:
        line += "  <" + "; ".join(notes) + ">"
    lines = [prefix + line]
    kids = children.get(key, [])
    for i, child in enumerate(kids):
        last = i == len(kids) - 1
        branch = "└─ " if last else "├─ "
        ext = "   " if last else "│  "
        lines.extend(_tree_lines(forest, child, prefix + ext + branch))
    return lines


def render_forest(forest: dict[str, Any], keys: list[str]) -> list[str]:
    """ASCII forest for the given root keys."""
    lines: list[str] = []
    for key in keys:
        lines.extend(_tree_lines(forest, key, ""))
        lines.append("")
    return lines


def ancestors(forest: dict[str, Any], key: str) -> list[str]:
    """Chain from the forest root down to *key* (inclusive)."""
    instances: dict[str, ProcessInstance] = forest["instances"]
    chain = [key]
    seen = {key}
    current = instances[key]
    while current.parent_key and current.parent_key not in seen:
        seen.add(current.parent_key)
        chain.append(current.parent_key)
        current = instances[current.parent_key]
    chain.reverse()
    return chain


def descendants(forest: dict[str, Any], key: str) -> list[str]:
    """*key* and every instance below it, depth-first."""
    children: dict[str, list[str]] = forest["children"]
    out = [key]
    for child in children.get(key, []):
        out.extend(descendants(forest, child))
    return out


def instance_to_dict(inst: ProcessInstance) -> dict[str, Any]:
    return {
        "host": inst.host,
        "pid": inst.pid,
        "image": inst.image,
        "start": inst.start,
        "start_original": inst.start_original,
        "parent_pid": inst.parent_pid,
        "parent_image": inst.parent_image,
        "user": inst.user,
        "command_line": inst.command_line,
        "parent_key": inst.parent_key,
        "ambiguous_parent": inst.ambiguous_parent,
        "orphan": inst.orphan,
        "references": inst.references,
        "event_ids": inst.event_ids,
    }
