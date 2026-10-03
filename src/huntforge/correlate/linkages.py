"""Deterministic, explainable linkage heuristics for v0.7 correlation.

Every detector takes the case's normalized events (db row dicts, see
``CaseDB.all_events``) and returns :class:`Linkage` hypotheses. Each
linkage is INFERRED — it states what matched (``basis``), how sure it
is (``confidence`` + ``confidence_reason``), the heuristic name, and
its known failure modes. See ``docs/CORRELATION.md`` for the full
write-up of each heuristic.

Design rules shared by all detectors:
- Only *timed* events are linked (``timestamp_original`` is not
  ``None``). An untimed event cannot be ordered, so any temporal claim
  about it would be invented — untimed events are never linked.
- Hosts must match (case-insensitive) for process/file linkages.
- A linkage never joins an event to itself.
- Duplicate pairs are deduplicated: (kind, min(id), max(id)).
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

from huntforge.correlate.model import Linkage

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

_PROC_CREATE = {
    ("sysmon", "1"),
    ("evtx:Security", "4688"),
    ("evtx:Microsoft-Windows-Sysmon/Operational", "1"),
}
_NETWORK = {("sysmon", "3")}
_FILE_CREATE = {("sysmon", "11")}

_SAME_PROCESS_WINDOW_S = 15 * 60  # PID reuse guard
_SAME_FILE_WINDOW_S = 60 * 60
_DOWNLOAD_WINDOW_S = 15 * 60


def _timed(event: dict[str, Any]) -> bool:
    """True when the event has a real (non-placeholder) timestamp."""
    return event.get("timestamp_original") is not None


def _ts(event: dict[str, Any]) -> datetime | None:
    raw = event.get("timestamp")
    if not raw:
        return None
    try:
        text = str(raw).strip()
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        moment = datetime.fromisoformat(text)
        if moment.tzinfo is None:
            moment = moment.replace(tzinfo=timezone.utc)
        return moment.astimezone(timezone.utc)
    except ValueError:
        return None


def _delta_s(a: dict[str, Any], b: dict[str, Any]) -> float | None:
    ta, tb = _ts(a), _ts(b)
    if ta is None or tb is None:
        return None
    return abs((ta - tb).total_seconds())


def _norm_host(event: dict[str, Any]) -> str:
    return str(event.get("host") or "").strip().lower()


def _norm_path(value: str | None) -> str:
    if not value:
        return ""
    return str(value).strip().lower().replace("/", "\\")


def _basename(path: str | None) -> str:
    if not path:
        return ""
    text = str(path).replace("/", "\\")
    return text.rsplit("\\", 1)[-1].strip().lower()


def _is_proc_create(event: dict[str, Any]) -> bool:
    return (
        str(event.get("source") or ""),
        str(event.get("event_id") or ""),
    ) in _PROC_CREATE


def _is_network(event: dict[str, Any]) -> bool:
    return (
        str(event.get("source") or ""),
        str(event.get("event_id") or ""),
    ) in _NETWORK or bool(event.get("dst_ip"))


def _is_runkey(event: dict[str, Any]) -> bool:
    if event.get("source") == "registry" and str(event.get("event_id")) == "run-key":
        return True
    if event.get("source") == "sysmon" and str(event.get("event_id")) in (
        "12",
        "13",
        "14",
    ):
        return bool(
            re.search(
                r"(?i)\\\\Run(Once)?(\\\\|$)", str(event.get("registry_key") or "")
            )
        )
    return False


def _is_task(event: dict[str, Any]) -> bool:
    return str(event.get("source") or "") == "tasks"


def _is_service(event: dict[str, Any]) -> bool:
    return str(event.get("source") or "") == "services"


_EXE_RE = re.compile(r'"([^"]+\.exe)"|\b([A-Za-z]:\\[^\s"]+\.exe)', re.IGNORECASE)


def _exe_from_command_line(command_line: str | None) -> str:
    if not command_line:
        return ""
    match = _EXE_RE.search(command_line)
    if not match:
        return ""
    return match.group(1) or match.group(2) or ""


def _persistence_target(event: dict[str, Any]) -> str:
    """Best-effort executable a persistence event points at."""
    if event.get("file_path"):
        return str(event.get("file_path"))
    exe = _exe_from_command_line(event.get("command_line"))
    if exe:
        return exe
    match = re.search(r'"([^"]+\.exe)"', str(event.get("raw") or ""), re.IGNORECASE)
    return match.group(1) if match else ""


def _is_persistence(event: dict[str, Any]) -> bool:
    return _is_runkey(event) or _is_task(event) or _is_service(event)


def _dedup(linkages: list[Linkage]) -> list[Linkage]:
    seen: set[tuple[str, int, int]] = set()
    unique: list[Linkage] = []
    for link in linkages:
        key = (
            link.kind,
            min(link.event_a, link.event_b),
            max(link.event_a, link.event_b),
        )
        if key in seen:
            continue
        seen.add(key)
        unique.append(link)
    return sorted(unique, key=lambda link: (link.event_a, link.event_b, link.kind))


# ---------------------------------------------------------------------------
# 1. same-process: (host, pid, image) match within a time window
# ---------------------------------------------------------------------------

_SAME_PROCESS_FAILURES = (
    "PID reuse: a PID may be recycled for a different process; the "
    "15-minute window and same-image requirement reduce but do not "
    "eliminate this. Two rapid executions of the same binary get the "
    "same PID only if the first exited, which this linkage cannot tell "
    "apart from continued execution."
)


def detect_same_process(events: list[dict[str, Any]]) -> list[Linkage]:
    """Link events referencing the same process instance.

    Heuristic: same host (case-insensitive) + same numeric PID + same
    process image basename, with the pair no more than 15 minutes
    apart. A network connection 30s after a process creation with the
    same PID/image/host is treated as that process's traffic.
    """
    linkages: list[Linkage] = []
    groups: dict[tuple[str, int, str], list[dict[str, Any]]] = {}
    for event in events:
        if not _timed(event):
            continue
        pid = event.get("process_id")
        image = _basename(event.get("process_name"))
        host = _norm_host(event)
        if pid is None or not image or not host:
            continue
        groups.setdefault((host, int(pid), image), []).append(event)
    for (host, pid, image), members in groups.items():
        if len(members) < 2:
            continue
        members.sort(
            key=lambda e: (str(e.get("timestamp") or ""), int(e.get("id") or 0))
        )
        for first, second in zip(members, members[1:], strict=False):
            delta = _delta_s(first, second)
            if delta is None or delta > _SAME_PROCESS_WINDOW_S:
                continue
            linkages.append(
                Linkage(
                    kind="same-process",
                    event_a=int(first["id"]),
                    event_b=int(second["id"]),
                    basis=(
                        f"same host ({host}), PID {pid}, and image "
                        f"({image}); {int(delta)}s apart"
                    ),
                    confidence=90,
                    confidence_reason=(
                        "host + numeric PID + image basename all agree "
                        "within a 15-minute window; distinct process "
                        "instances rarely share all three"
                    ),
                    heuristic="same-process (host, pid, image, 15m window)",
                    failure_modes=_SAME_PROCESS_FAILURES,
                )
            )
    return _dedup(linkages)


# ---------------------------------------------------------------------------
# 2. same-file: normalized path match across sources/event types
# ---------------------------------------------------------------------------

_SAME_FILE_FAILURES = (
    "Common system paths (e.g. C:\\Windows\\System32\\foo.dll) can "
    "coincide across unrelated activity; a basename-only match is "
    "weaker still (same filename, different directory). Prefetch only "
    "records the executable name, so prefetch links are basename-based."
)


def detect_same_file(events: list[dict[str, Any]]) -> list[Linkage]:
    """Link events that reference the same file path.

    Heuristic: exact normalized-path match (case-insensitive,
    separators normalized) across different events. A prefetch entry
    only carries the executable basename, so prefetch-to-creation
    links use basename matching within a 60-minute window at lower
    confidence.
    """
    linkages: list[Linkage] = []
    by_path: dict[str, list[dict[str, Any]]] = {}
    for event in events:
        if not _timed(event):
            continue
        path = _norm_path(event.get("file_path"))
        if not path:
            continue
        by_path.setdefault(path, []).append(event)
    for path, members in by_path.items():
        if len(members) < 2:
            continue
        for i, first in enumerate(members):
            for second in members[i + 1 :]:
                if first["id"] == second["id"]:
                    continue
                linkages.append(
                    Linkage(
                        kind="same-file",
                        event_a=int(first["id"]),
                        event_b=int(second["id"]),
                        basis=f"same normalized file path: {path}",
                        confidence=80,
                        confidence_reason=(
                            "exact normalized path agreement across "
                            "two events; unrelated events rarely "
                            "reference the identical path"
                        ),
                        heuristic="same-file (normalized path equality)",
                        failure_modes=_SAME_FILE_FAILURES,
                    )
                )
    # Prefetch <-> process creation via executable basename (prefetch
    # records only the name, e.g. POWERSHELL.EXE).
    prefetch = [
        e
        for e in events
        if _timed(e)
        and str(e.get("source") or "") == "prefetch"
        and _basename(e.get("process_name"))
    ]
    creations = [
        e
        for e in events
        if _timed(e) and _is_proc_create(e) and _basename(e.get("process_name"))
    ]
    for pf in prefetch:
        for created in creations:
            if pf["id"] == created["id"]:
                continue
            if _basename(pf.get("process_name")) != _basename(
                created.get("process_name")
            ):
                continue
            if _norm_host(pf) != _norm_host(created):
                continue
            delta = _delta_s(pf, created)
            if delta is None or delta > _SAME_FILE_WINDOW_S:
                continue
            linkages.append(
                Linkage(
                    kind="same-file",
                    event_a=int(pf["id"]),
                    event_b=int(created["id"]),
                    basis=(
                        f"prefetch executable basename "
                        f"({_basename(pf.get('process_name'))}) matches process "
                        f"creation image; {int(delta)}s apart (basename match)"
                    ),
                    confidence=65,
                    confidence_reason=(
                        "prefetch proves the executable ran on this host "
                        "near the observed creation time, but the match "
                        "is basename-only (prefetch has no full path)"
                    ),
                    heuristic="same-file (prefetch basename, 60m window)",
                    failure_modes=_SAME_FILE_FAILURES,
                )
            )
    return _dedup(linkages)


# ---------------------------------------------------------------------------
# 3. persistence-execution: persistence target observed executing
# ---------------------------------------------------------------------------

_PERSIST_EXEC_FAILURES = (
    "Basename-only comparison: C:\\evil\\svchost.exe and "
    "C:\\Windows\\System32\\svchost.exe share a basename. A full-path "
    "match is stronger. A persistence entry may also reference a "
    "binary that runs routinely for benign reasons."
)


def detect_persistence_execution(events: list[dict[str, Any]]) -> list[Linkage]:
    """Link a persistence mechanism to the execution of its target.

    Heuristic: a registry Run/RunOnce value, scheduled task, or service
    whose target executable (file_path, or parsed from the command
    line) matches the image of an observed process creation (or
    prefetch entry) on the same host. Full normalized-path agreement
    scores higher than basename agreement.
    """
    linkages: list[Linkage] = []
    executed: list[dict[str, Any]] = [
        e
        for e in events
        if _timed(e)
        and (_is_proc_create(e) or str(e.get("source") or "") == "prefetch")
        and (_basename(e.get("process_name")) or _norm_path(e.get("file_path")))
    ]
    for persist in events:
        if not _timed(persist) or not _is_persistence(persist):
            continue
        target = _persistence_target(persist)
        if not target:
            continue
        target_path = _norm_path(target)
        target_base = _basename(target)
        host = _norm_host(persist)
        for exe in executed:
            if exe["id"] == persist["id"] or _norm_host(exe) != host:
                continue
            exe_path = _norm_path(exe.get("file_path"))
            exe_base = _basename(exe.get("process_name")) or _basename(
                exe.get("file_path")
            )
            full_match = (
                bool(target_path) and bool(exe_path) and target_path == exe_path
            )
            base_match = (
                bool(target_base) and bool(exe_base) and target_base == exe_base
            )
            if not (full_match or base_match):
                continue
            if full_match:
                confidence, why = 80, "full normalized-path agreement"
            else:
                confidence, why = 60, "basename agreement only"
            linkages.append(
                Linkage(
                    kind="persistence-execution",
                    event_a=int(persist["id"]),
                    event_b=int(exe["id"]),
                    basis=(
                        f"persistence target ({target}) {why} with "
                        f"executed image "
                        f"({exe.get('process_name') or exe.get('file_path')})"
                    ),
                    confidence=confidence,
                    confidence_reason=(
                        "the binary a persistence mechanism points at "
                        f"was observed executing on the same host ({why})"
                    ),
                    heuristic="persistence-execution (target vs executed image)",
                    failure_modes=_PERSIST_EXEC_FAILURES,
                )
            )
    return _dedup(linkages)


# ---------------------------------------------------------------------------
# 4. download-execution: network -> file -> process within a window
# ---------------------------------------------------------------------------

_DOWNLOAD_EXEC_FAILURES = (
    "Temporal coincidence is not causation: the same process making an "
    "unrelated connection shortly before writing a file still links. "
    "Confidence rises when the downloading process is the parent of the "
    "executed process (lineage support). Browser and updater traffic "
    "routinely triggers this pattern benignly."
)


def _same_process_pair(a: dict[str, Any], b: dict[str, Any]) -> bool:
    """Same host + PID + image basename (no time bound here; the caller
    enforces ordering and the window)."""
    if a.get("process_id") is None or b.get("process_id") is None:
        return False
    return (
        _norm_host(a) == _norm_host(b)
        and _norm_host(a) != ""
        and int(a["process_id"]) == int(b["process_id"])
        and _basename(a.get("process_name")) == _basename(b.get("process_name"))
        and bool(_basename(a.get("process_name")))
    )


def detect_download_execution(events: list[dict[str, Any]]) -> list[Linkage]:
    """Link a network download to the execution of the downloaded file.

    Heuristic: on one host, a network connection event made by process
    P, then P creates a file, then a process creation whose image
    basename matches the created file's basename — strictly ordered
    within 15 minutes. The file creation must be attributed to the
    same process instance that made the connection (Sysmon records the
    creating process on file events); otherwise any host activity in
    the window would link spuriously. The linkage joins the network
    event to the process creation and cites the file event in its
    basis. When the connecting process is the parent of the executed
    process, confidence is higher.
    """
    linkages: list[Linkage] = []
    timed = [e for e in events if _timed(e) and _ts(e) is not None]
    networks = [e for e in timed if _is_network(e) and e.get("dst_ip")]
    creates = [
        e
        for e in timed
        if (str(e.get("source") or ""), str(e.get("event_id") or "")) in _FILE_CREATE
        and _basename(e.get("file_path"))
    ]
    procs = [
        e for e in timed if _is_proc_create(e) and _basename(e.get("process_name"))
    ]
    for net in networks:
        host = _norm_host(net)
        t_net = _ts(net)
        if t_net is None:
            continue
        for created in creates:
            if _norm_host(created) != host:
                continue
            if not _same_process_pair(net, created):
                # The file was not written by the connecting process:
                # linking here would blame any host activity in the
                # window for the download.
                continue
            t_file = _ts(created)
            if t_file is None:
                continue
            gap1 = (t_file - t_net).total_seconds()
            if gap1 < 0 or gap1 > _DOWNLOAD_WINDOW_S:
                continue
            created_base = _basename(created.get("file_path"))
            for proc in procs:
                if (
                    _norm_host(proc) != host
                    or _basename(proc.get("process_name")) != created_base
                ):
                    continue
                t_proc = _ts(proc)
                if t_proc is None:
                    continue
                gap2 = (t_proc - t_file).total_seconds()
                if gap2 < 0 or gap2 > _DOWNLOAD_WINDOW_S:
                    continue
                lineage = (
                    proc.get("parent_id") is not None
                    and net.get("process_id") is not None
                    and int(proc["parent_id"]) == int(net["process_id"])
                )
                if lineage:
                    confidence = 85
                    reason = (
                        "the connecting process wrote the file and is "
                        "the parent of the executed process; all three "
                        "strictly ordered within 15 minutes"
                    )
                else:
                    confidence = 70
                    reason = (
                        "the connecting process wrote the file that was "
                        "then executed, strictly ordered within 15 "
                        "minutes, but with no process-lineage support"
                    )
                linkages.append(
                    Linkage(
                        kind="download-execution",
                        event_a=int(net["id"]),
                        event_b=int(proc["id"]),
                        basis=(
                            f"{net.get('process_name')} (pid {net.get('process_id')}) "
                            f"connected to {net.get('dst_ip')}: "
                            f"{net.get('dst_port') or '?'} then "
                            f"wrote file {created.get('file_path')} (event "
                            f"#{created['id']}), executed as "
                            f"{proc.get('process_name')} (pid {proc.get('process_id')})"
                        ),
                        confidence=confidence,
                        confidence_reason=reason,
                        heuristic="download-execution "
                        "(same-proc net -> file -> proc, 15m)",
                        failure_modes=_DOWNLOAD_EXEC_FAILURES,
                    )
                )
    return _dedup(linkages)


def detect_all(events: list[dict[str, Any]]) -> list[Linkage]:
    """Run every linkage detector and return the deduplicated union."""
    found: list[Linkage] = []
    found.extend(detect_same_process(events))
    found.extend(detect_same_file(events))
    found.extend(detect_persistence_execution(events))
    found.extend(detect_download_execution(events))
    return _dedup(found)
