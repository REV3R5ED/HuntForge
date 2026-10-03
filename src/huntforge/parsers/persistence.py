"""Persistence-artifact parsers (v0.3): scheduled tasks, services, Run keys.

- Scheduled tasks: exported Task Scheduler XML (``schtasks /query /xml``)
  — triggers, actions, principals, author.
- Services: a documented JSON export schema, or the ``Services`` key of
  an offline ``SYSTEM`` hive (parsed with :mod:`huntforge.parsers.registry`).
- Registry persistence scan: ``Run``/``RunOnce`` values and services
  harvested from any offline hive.

Everything is stdlib-only and fully offline. Parser ``flags`` are
observations (``"image-in-temp-dir"``, ``"unquoted-service-path"``,
``"auto-start"``, ``"runs-as-system"``, ``"action-in-temp-dir"``) —
never verdicts; v0.5 detections may act on them.

Services JSON schema (array or ``{"services": [...]}``)::

    {"name": "BadSvc", "display_name": "Bad Service",
     "image_path": "C:\\\\Temp\\\\badsvc.exe -k netsvcs",
     "start_type": 2, "service_type": 16, "account": "LocalSystem"}

``start_type`` accepts the numeric value or a name (``"auto"``,
``"manual"``, ``"disabled"``, ``"boot"``, ``"system"``).
"""

from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from huntforge.models.events import EventValidationError, NormalizedEvent
from huntforge.parsers.common import (
    basename,
    blank,
    excerpt,
    find_child,
    fresh_ingest_time,
    localname,
    make_provenance,
)
from huntforge.parsers.registry import REGF_MAGIC, Hive, HiveError, RegValue

PARSER_VERSION = "0.3.0"

PARSER_TASKS_XML = "tasks-xml"
PARSER_SERVICES_JSON = "services-json"
PARSER_SERVICES_HIVE = "services-hive"
PARSER_REGISTRY_SCAN = "registry"

#: Run/RunOnce locations scanned in any hive (NTUSER.DAT, SOFTWARE, …).
RUN_KEY_PATHS = (
    r"Software\Microsoft\Windows\CurrentVersion\Run",
    r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
    r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
)

#: Services locations scanned in any hive (SYSTEM, …).
SERVICE_KEY_PATHS = (
    r"SYSTEM\CurrentControlSet\Services",
    r"ControlSet001\Services",
    r"ControlSet002\Services",
)

_START_TYPE_NAMES = {0: "boot", 1: "system", 2: "auto", 3: "manual", 4: "disabled"}
_START_NAME_TO_NUM = {v: k for k, v in _START_TYPE_NAMES.items()}

_SYSTEM_ACCOUNTS = {
    "system",
    "localsystem",
    "nt authority\\system",
    "s-1-5-18",
}


def _exe_of(command: str | None) -> str | None:
    """Best-effort executable portion of a command line (documented heuristic).

    Quoted paths are unquoted; unquoted paths are cut after ``.exe``
    (Windows services/tasks almost always point at executables), else
    the first whitespace-separated token is used.
    """
    if not command:
        return None
    text = command.strip()
    if not text:
        return None
    if text.startswith('"'):
        end = text.find('"', 1)
        text = text[1:end] if end > 0 else text[1:]
    else:
        exe_end = text.lower().find(".exe")
        text = text[: exe_end + 4] if exe_end != -1 else text.split(None, 1)[0]
    return text or None


def _in_temp_dir(path: str | None) -> bool:
    if not path:
        return False
    return "\\temp\\" in path.lower()


def _warn_cap(warnings: list[str], message: str, limit: int = 25) -> None:
    if len(warnings) < limit:
        warnings.append(message)


# ---------------------------------------------------------------------------
# Scheduled tasks (Task Scheduler XML)
# ---------------------------------------------------------------------------


def _trigger_summary(triggers_el: ET.Element | None) -> list[str]:
    summary: list[str] = []
    if triggers_el is None:
        return summary
    for trigger in triggers_el:
        kind = localname(trigger.tag)
        boundary = None
        for child in trigger:
            if localname(child.tag) == "StartBoundary" and child.text:
                boundary = child.text.strip()
        summary.append(kind + (f"@{boundary}" if boundary else ""))
    return summary


def _task_timestamp(
    triggers: list[str], reg_date: str | None, ingest_time: str
) -> tuple[str, str | None]:
    for trigger in triggers:
        if "@" in trigger:
            native = trigger.split("@", 1)[1]
            return native, native
    if reg_date:
        return reg_date, reg_date
    return ingest_time, None


def parse_tasks_xml(
    path: Path,
    *,
    source_sha256: str,
    ingest_time: str | None = None,
) -> tuple[list[NormalizedEvent], list[str]]:
    """Parse one Task Scheduler XML export (never raises)."""
    ingest_time = ingest_time or fresh_ingest_time()
    warnings: list[str] = []
    try:
        root = ET.parse(path).getroot()
    except ET.ParseError as exc:
        return [], [f"{path.name}: invalid XML ({exc})"]
    if localname(root.tag) != "Task":
        return [], [f"{path.name}: not a Task Scheduler export (root is {root.tag!r})"]

    events: list[NormalizedEvent] = []
    reg = find_child(root, "RegistrationInfo")
    uri = (find_child_text(reg, "URI") or path.stem).strip()
    author = find_child_text(reg, "Author")
    description = find_child_text(reg, "Description")
    reg_date = find_child_text(reg, "Date")
    triggers = _trigger_summary(find_child(root, "Triggers"))

    principal_user: str | None = None
    principals = find_child(root, "Principals")
    if principals is not None:
        for principal in principals:
            user = find_child_text(principal, "UserId")
            if user:
                principal_user = user.strip()
                break

    actions = find_child(root, "Actions")
    execs: list[tuple[str | None, str | None]] = []
    other_actions: list[str] = []
    if actions is not None:
        for action in actions:
            kind = localname(action.tag)
            if kind == "Exec":
                execs.append(
                    (
                        find_child_text(action, "Command"),
                        find_child_text(action, "Arguments"),
                    )
                )
            else:
                other_actions.append(kind)
    if not execs and other_actions:
        execs.append((None, None))  # non-Exec task: still recorded

    timestamp, original = _task_timestamp(triggers, reg_date, ingest_time)
    flags: list[str] = []
    if principal_user and principal_user.lower() in _SYSTEM_ACCOUNTS:
        flags.append("runs-as-system")

    for command, arguments in execs:
        if _in_temp_dir(command):
            task_flags = flags + ["action-in-temp-dir"]
        else:
            task_flags = list(flags)
        command_line = command if not arguments else f"{command} {arguments}"
        raw_bits = [f"task {uri}", f"triggers={'+'.join(triggers) or 'none'}"]
        if author:
            raw_bits.append(f"author={author}")
        if description:
            raw_bits.append(f"description={description[:80]}")
        if other_actions:
            raw_bits.append(f"other_actions={','.join(other_actions)}")
        try:
            events.append(
                NormalizedEvent(
                    timestamp=timestamp,
                    timestamp_original=original,
                    source="tasks",
                    event_id="task",
                    user=blank(principal_user),
                    process_name=basename(_exe_of(command)),
                    file_path=_exe_of(command),
                    command_line=blank(command_line),
                    flags=task_flags,
                    raw=excerpt(raw_bits),
                    provenance=make_provenance(
                        source_file=str(path),
                        record_index=len(events),
                        parser_name=PARSER_TASKS_XML,
                        parser_version=PARSER_VERSION,
                        ingest_time=ingest_time,
                        source_sha256=source_sha256,
                    ),
                )
            )
        except EventValidationError as exc:
            _warn_cap(warnings, f"{path.name}: skipping task ({exc})")
    return events, warnings


def find_child_text(element: ET.Element | None, name: str) -> str | None:
    """Text of the first child named *name* (namespace-agnostic)."""
    if element is None:
        return None
    for child in element:
        if localname(child.tag) == name and child.text and child.text.strip():
            return child.text.strip()
    return None


# ---------------------------------------------------------------------------
# Services (JSON export or offline hive)
# ---------------------------------------------------------------------------


def _service_flags(image_path: str | None, start: int | None) -> list[str]:
    flags: list[str] = []
    if start == 2:
        flags.append("auto-start")
    if _in_temp_dir(image_path):
        flags.append("image-in-temp-dir")
    exe = _exe_of(image_path)
    if exe and " " in exe and not (image_path or "").strip().startswith('"'):
        flags.append("unquoted-service-path")
    return flags


def _normalize_start(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value in _START_TYPE_NAMES else None
    if isinstance(value, str):
        return _START_NAME_TO_NUM.get(value.strip().lower())
    return None


def _service_event(
    *,
    name: str,
    display_name: str | None,
    image_path: str | None,
    start: int | None,
    account: str | None,
    registry_key: str | None,
    timestamp: str,
    timestamp_original: str | None,
    source_file: str,
    record_index: int,
    parser_name: str,
    source_sha256: str,
    ingest_time: str,
) -> NormalizedEvent:
    exe = _exe_of(image_path)
    start_name = _START_TYPE_NAMES.get(start) if start is not None else None
    raw_bits = [f"service {name}"]
    if display_name:
        raw_bits.append(f"display={display_name}")
    if start_name:
        raw_bits.append(f"start={start_name}")
    if account:
        raw_bits.append(f"account={account}")
    return NormalizedEvent(
        timestamp=timestamp,
        timestamp_original=timestamp_original,
        source="services",
        event_id="service",
        user=blank(account),
        process_name=basename(exe),
        file_path=exe,
        command_line=blank(image_path),
        registry_key=registry_key,
        flags=_service_flags(image_path, start),
        raw=excerpt(raw_bits),
        provenance=make_provenance(
            source_file=source_file,
            record_index=record_index,
            parser_name=parser_name,
            parser_version=PARSER_VERSION,
            ingest_time=ingest_time,
            source_sha256=source_sha256,
        ),
    )


def parse_services_json(
    path: Path,
    *,
    source_sha256: str,
    ingest_time: str | None = None,
) -> tuple[list[NormalizedEvent], list[str]]:
    """Parse a services JSON export (never raises)."""
    ingest_time = ingest_time or fresh_ingest_time()
    warnings: list[str] = []
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return [], [f"{path.name}: cannot parse services JSON ({exc})"]
    if isinstance(payload, dict) and isinstance(payload.get("services"), list):
        payload = payload["services"]
    if not isinstance(payload, list):
        return [], [f"{path.name}: expected a JSON array of service objects"]
    events: list[NormalizedEvent] = []
    for index, item in enumerate(payload):
        if not isinstance(item, dict):
            _warn_cap(warnings, f"{path.name}: record {index} is not an object")
            continue
        name = item.get("name") or item.get("ServiceName")
        if not name:
            _warn_cap(warnings, f"{path.name}: record {index} has no service name")
            continue
        try:
            events.append(
                _service_event(
                    name=str(name),
                    display_name=item.get("display_name") or item.get("DisplayName"),
                    image_path=item.get("image_path") or item.get("ImagePath"),
                    start=_normalize_start(item.get("start_type", item.get("Start"))),
                    account=item.get("account") or item.get("ObjectName"),
                    registry_key=None,
                    timestamp=ingest_time,
                    timestamp_original=None,
                    source_file=str(path),
                    record_index=index,
                    parser_name=PARSER_SERVICES_JSON,
                    source_sha256=source_sha256,
                    ingest_time=ingest_time,
                )
            )
        except EventValidationError as exc:
            _warn_cap(warnings, f"{path.name}: skipping service {name!r} ({exc})")
    return events, warnings


def _values_map(values: list[RegValue]) -> dict[str, RegValue]:
    return {v.name.lower(): v for v in values}


def parse_services_hive(
    data: bytes,
    *,
    source_file: str,
    source_sha256: str,
    ingest_time: str | None = None,
) -> tuple[list[NormalizedEvent], list[str]]:
    """Parse the Services key of an offline SYSTEM hive (never raises)."""
    ingest_time = ingest_time or fresh_ingest_time()
    warnings: list[str] = []
    try:
        hive = Hive(data)
    except HiveError as exc:
        return [], [f"{source_file}: {exc}"]
    services_path = next((p for p in SERVICE_KEY_PATHS if hive.key_exists(p)), None)
    if services_path is None:
        return [], [
            f"{source_file}: no Services key found "
            f"(tried {len(SERVICE_KEY_PATHS)} paths)"
        ]
    try:
        view = hive.list_key(services_path)
    except HiveError as exc:
        return [], [f"{source_file}: {exc}"]
    events: list[NormalizedEvent] = []
    for index, svc_name in enumerate(view.subkeys):
        svc_path = f"{services_path}\\{svc_name}"
        try:
            svc_view = hive.list_key(svc_path)
        except HiveError as exc:
            _warn_cap(warnings, f"{source_file}: cannot read {svc_path} ({exc})")
            continue
        vals = _values_map(svc_view.values)
        image = vals.get("imagepath")
        start_v = vals.get("start")
        account_v = vals.get("objectname")
        display_v = vals.get("displayname")
        image_path = str(image.data) if image and isinstance(image.data, str) else None
        start = start_v.data if start_v and isinstance(start_v.data, int) else None
        try:
            events.append(
                _service_event(
                    name=svc_name,
                    display_name=str(display_v.data)
                    if display_v and isinstance(display_v.data, str)
                    else None,
                    image_path=image_path,
                    start=start,
                    account=str(account_v.data)
                    if account_v and isinstance(account_v.data, str)
                    else None,
                    registry_key=svc_path,
                    timestamp=svc_view.last_write or ingest_time,
                    timestamp_original=svc_view.last_write,
                    source_file=source_file,
                    record_index=index,
                    parser_name=PARSER_SERVICES_HIVE,
                    source_sha256=source_sha256,
                    ingest_time=ingest_time,
                )
            )
        except EventValidationError as exc:
            _warn_cap(warnings, f"{source_file}: skipping service {svc_name!r} ({exc})")
    return events, warnings


def parse_services_file(
    path: Path,
    *,
    source_sha256: str,
    ingest_time: str | None = None,
) -> tuple[list[NormalizedEvent], list[str]]:
    """Dispatch ``services``: hive bytes -> registry parse, else JSON."""
    with path.open("rb") as fh:
        magic = fh.read(4)
    if magic == REGF_MAGIC:
        return parse_services_hive(
            path.read_bytes(),
            source_file=str(path),
            source_sha256=source_sha256,
            ingest_time=ingest_time,
        )
    return parse_services_json(
        path, source_sha256=source_sha256, ingest_time=ingest_time
    )


# ---------------------------------------------------------------------------
# Registry persistence scan (Run/RunOnce values + services)
# ---------------------------------------------------------------------------


def scan_registry_persistence(
    data: bytes,
    *,
    source_file: str,
    source_sha256: str,
    ingest_time: str | None = None,
) -> tuple[list[NormalizedEvent], list[str]]:
    """Harvest Run/RunOnce values and services from an offline hive."""
    ingest_time = ingest_time or fresh_ingest_time()
    warnings: list[str] = []
    try:
        hive = Hive(data)
    except HiveError as exc:
        return [], [f"{source_file}: {exc}"]
    events: list[NormalizedEvent] = []
    record_index = 0
    for key_path in RUN_KEY_PATHS:
        if not hive.key_exists(key_path):
            continue
        try:
            view = hive.list_key(key_path)
        except HiveError as exc:
            _warn_cap(warnings, f"{source_file}: cannot read {key_path} ({exc})")
            continue
        for value in view.values:
            command = (
                value.data
                if isinstance(value.data, str)
                else " ".join(value.data)
                if isinstance(value.data, list)
                else None
            )
            exe = _exe_of(command)
            try:
                events.append(
                    NormalizedEvent(
                        timestamp=view.last_write or ingest_time,
                        timestamp_original=view.last_write,
                        source="registry",
                        event_id="run-key",
                        process_name=basename(exe),
                        file_path=exe,
                        command_line=blank(command),
                        registry_key=f"{key_path}\\{value.name}"
                        if value.name
                        else key_path,
                        raw=excerpt(
                            [
                                f"run-key value {value.name or '(default)'}",
                                f"type={value.type_name}",
                            ]
                        ),
                        provenance=make_provenance(
                            source_file=source_file,
                            record_index=record_index,
                            parser_name=PARSER_REGISTRY_SCAN,
                            parser_version=PARSER_VERSION,
                            ingest_time=ingest_time,
                            source_sha256=source_sha256,
                        ),
                    )
                )
                record_index += 1
            except EventValidationError as exc:
                _warn_cap(
                    warnings, f"{source_file}: skipping value {value.name!r} ({exc})"
                )
    svc_events, svc_warnings = parse_services_hive(
        data,
        source_file=source_file,
        source_sha256=source_sha256,
        ingest_time=ingest_time,
    )
    # Re-index service events after the Run-key events.
    for offset, event in enumerate(svc_events):
        event.provenance.record_index = record_index + offset
    warnings.extend(svc_warnings)
    return events + svc_events, warnings


def scan_registry_file(
    path: Path,
    *,
    source_sha256: str,
    ingest_time: str | None = None,
) -> tuple[list[NormalizedEvent], list[str]]:
    """Scan one hive file for persistence artifacts (never raises)."""
    return scan_registry_persistence(
        path.read_bytes(),
        source_file=str(path),
        source_sha256=source_sha256,
        ingest_time=ingest_time,
    )
