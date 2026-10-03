"""Explainable detection rules (v0.5).

Each rule is a named, versioned Python function plus metadata. Rules
read normalized events only — they never touch raw evidence files —
and every finding cites the exact event rows that triggered it.
A rule never declares anything "malicious": it reports that a
technique-shaped pattern was *observed*, with a confidence score and
its reasoning, so the analyst makes the final call.

Rule IDs are stable (``HF-DET-XXX``); rule logic changes bump the
rule ``version``.
"""

from __future__ import annotations

import ipaddress
import re
from datetime import datetime, timedelta, timezone

from huntforge.detections.model import EvidenceRef, Finding, Rule, Severity

RULESET_VERSION = "0.5.0"

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

_SYSMON = "sysmon"
_SECURITY = "evtx:Security"
_POWERSHELL = "powershell"

_PROC_CREATE = ((_SYSMON, "1"), (_SECURITY, "4688"))


def _proc_create(events: list[dict]) -> list[dict]:
    """Process-creation events (Sysmon 1, Security 4688)."""
    return [
        e
        for e in events
        if (e.get("source"), e.get("event_id"))
        in (("sysmon", "1"), ("evtx:Security", "4688"))
    ]


def _base(name: object) -> str:
    """Lowercase basename of a path-ish value ('' when missing)."""
    if not name:
        return ""
    text = str(name).replace("/", "\\")
    return text.rsplit("\\", 1)[-1].lower()


def _evidence(event: dict, observation: str) -> EvidenceRef:
    return EvidenceRef(
        event_id=int(event["id"]),
        source=str(event.get("source") or "?"),
        source_event_id=str(event.get("event_id") or "?"),
        observation=observation,
    )


def _parse_ts(value: object) -> datetime | None:
    """Parse a normalized UTC timestamp; None when unparseable."""
    if not value:
        return None
    text = str(value).strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        moment = datetime.fromisoformat(text)
    except ValueError:
        return None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc)


# Encoded-command switch: -EncodedCommand / -enc / -e (word-boundary, case-insensitive).
_ENCODED_RE = re.compile(r"(?i)(?:^|\s)-(?:encodedcommand|enc|e)(?:\s|$|=|:)")


def _has_encoded_switch(command_line: object) -> bool:
    return bool(command_line) and bool(_ENCODED_RE.search(str(command_line)))


_WRITABLE_DIR_RES = [
    re.compile(r"(?i)\\temp\\|/temp/"),
    re.compile(r"(?i)\\tmp\\|/tmp/"),
    re.compile(r"(?i)\\windows\\temp\\"),
    re.compile(r"(?i)\\users\\[^\\]+\\appdata\\local\\temp\\"),
    re.compile(r"(?i)\\programdata\\"),
    re.compile(r"(?i)^[a-z]:\\temp\\"),
    re.compile(r"(?i)^[a-z]:\\tmp\\"),
]


def _in_writable_dir(path: object) -> bool:
    """True when a file path sits in a user-writable/temp directory.

    Heuristic over the normalized path string — see rule
    ``tempdir-execution`` docs for the false-positive profile.
    """
    if not path:
        return False
    text = str(path)
    return any(rx.search(text) for rx in _WRITABLE_DIR_RES)


def _is_external_ip(value: object) -> bool:
    """True when the IP is routable on the public internet."""
    if not value:
        return False
    try:
        addr = ipaddress.ip_address(str(value).strip())
    except ValueError:
        return False
    return not (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
    )


_EXE_QUOTED_RE = re.compile(r'^\s*"([^"]+)"')
_EXE_BARE_RE = re.compile(r"^\s*(\S+)")


def _exe_from_command_line(command_line: object) -> str | None:
    """Best-effort executable path from a command line.

    Returns the quoted program or first token when it looks like a
    path to an .exe; None otherwise. Documented heuristic.
    """
    if not command_line:
        return None
    text = str(command_line)
    match = _EXE_QUOTED_RE.match(text) or _EXE_BARE_RE.match(text)
    if not match:
        return None
    candidate = match.group(1)
    if "\\" in candidate or "/" in candidate or candidate.lower().endswith(".exe"):
        return candidate
    return None


# ---------------------------------------------------------------------------
# Rule 1: encoded PowerShell execution
# ---------------------------------------------------------------------------

_PWSH_NAMES = {"powershell.exe", "pwsh.exe"}


def _eval_encoded_powershell(events: list[dict], rule: Rule) -> list[Finding]:
    findings: list[Finding] = []
    for event in _proc_create(events):
        name = _base(event.get("process_name"))
        flagged = "encoded-command" in (event.get("flags") or [])
        switch = _has_encoded_switch(event.get("command_line"))
        if name in _PWSH_NAMES and (flagged or switch):
            cmd = (event.get("command_line") or "")[:160]
            why = []
            if flagged:
                why.append(
                    f"parser observation 'encoded-command' on event "
                    f"#{event['id']} (not a verdict — see rule docs)"
                )
            if switch:
                why.append("command line contains an -EncodedCommand/-enc switch")
            why.append(f"process is {name} (PowerShell host)")
            findings.append(
                Finding(
                    rule_id=rule.id,
                    rule_version=rule.version,
                    title=rule.title,
                    severity=rule.severity,
                    confidence=80,
                    confidence_reason=(
                        "Encoded execution is a well-known obfuscation "
                        "technique, but administrators also use "
                        "-EncodedCommand legitimately; one signal alone "
                        "cannot confirm intent."
                    ),
                    why=why,
                    what=(
                        f"PowerShell executed with an encoded command on "
                        f"{event.get('host') or 'unknown host'} as "
                        f"{event.get('user') or 'unknown user'}: {cmd}"
                    ),
                    evidence=[
                        _evidence(
                            event,
                            f"process creation: {name} pid "
                            f"{event.get('process_id')}, command line "
                            f"indicates encoded execution",
                        )
                    ],
                    observed=[
                        f"{name} started with an encoded-command switch "
                        f"at {event.get('timestamp')}"
                    ],
                    inferred=[
                        "the actor may be hiding the true command from "
                        "casual inspection (analyst judgment required)"
                    ],
                )
            )
    return findings


# ---------------------------------------------------------------------------
# Rule 2: PowerShell downloading remote content
# ---------------------------------------------------------------------------

_DOWNLOAD_RES = [
    re.compile(r"(?i)\bInvoke-WebRequest\b|\bIWR\b"),
    re.compile(r"(?i)\bInvoke-RestMethod\b|\bIRM\b"),
    re.compile(r"(?i)Net\.WebClient"),
    re.compile(r"(?i)DownloadString|DownloadFile"),
    re.compile(r"(?i)\bbitsadmin\b.*\btransfer\b|\bStart-BitsTransfer\b"),
    re.compile(r"(?i)\bcertutil\b.*\burlcache\b"),
    re.compile(r"(?i)\bcurl(\.exe)?\b.*\s-[oO]\b|\bwget(\.exe)?\b"),
]


def _has_download_pattern(text: object) -> str | None:
    """Return the matched pattern name, or None."""
    if not text:
        return None
    blob = str(text)
    for rx in _DOWNLOAD_RES:
        match = rx.search(blob)
        if match:
            return match.group(0)
    return None


def _eval_powershell_download(events: list[dict], rule: Rule) -> list[Finding]:
    findings: list[Finding] = []
    for event in events:
        source = event.get("source")
        text: object = None
        kind = ""
        if source == _POWERSHELL and str(event.get("event_id")) in (
            "4104",
            "4103",
        ):
            text = event.get("command_line")  # script-block excerpt
            kind = "script block"
        elif (source, str(event.get("event_id"))) in (
            ("sysmon", "1"),
            ("evtx:Security", "4688"),
        ) and _base(event.get("process_name")) in _PWSH_NAMES:
            text = event.get("command_line")
            kind = "process command line"
        else:
            continue
        matched = _has_download_pattern(text)
        if not matched:
            continue
        excerpt = (str(text or "")[:160]).replace("\n", " ")
        findings.append(
            Finding(
                rule_id=rule.id,
                rule_version=rule.version,
                title=rule.title,
                severity=rule.severity,
                confidence=75,
                confidence_reason=(
                    "Remote download via PowerShell is a common "
                    "staging technique, but updaters and admin "
                    "scripts do this routinely; context decides."
                ),
                why=[
                    f"{kind} on event #{event['id']} matches download "
                    f"pattern {matched!r}"
                ],
                what=(
                    f"PowerShell {kind} on "
                    f"{event.get('host') or 'unknown host'} shows remote "
                    f"content retrieval ({matched}): {excerpt}"
                ),
                evidence=[
                    _evidence(
                        event,
                        f"PowerShell {kind} contains download pattern {matched!r}",
                    )
                ],
                observed=[
                    f"download-related API/cmdlet {matched!r} present in "
                    f"PowerShell content at {event.get('timestamp')}"
                ],
                inferred=[
                    "the script may be staging a payload from the network "
                    "(analyst judgment required)"
                ],
            )
        )
    return findings


# ---------------------------------------------------------------------------
# Rule 3: Office application spawning a shell / script interpreter
# ---------------------------------------------------------------------------

_OFFICE_PARENTS = {
    "winword.exe",
    "excel.exe",
    "powerpnt.exe",
    "outlook.exe",
    "mspub.exe",
    "visio.exe",
    "winproj.exe",
    "onenote.exe",
    "msaccess.exe",
}
_SHELL_CHILDREN = {
    "powershell.exe",
    "pwsh.exe",
    "cmd.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "wmic.exe",
}


def _eval_office_shell_spawn(events: list[dict], rule: Rule) -> list[Finding]:
    findings: list[Finding] = []
    for event in _proc_create(events):
        parent = _base(event.get("parent_name"))
        child = _base(event.get("process_name"))
        if parent in _OFFICE_PARENTS and child in _SHELL_CHILDREN:
            findings.append(
                Finding(
                    rule_id=rule.id,
                    rule_version=rule.version,
                    title=rule.title,
                    severity=rule.severity,
                    confidence=70,
                    confidence_reason=(
                        "Office-to-shell ancestry is the classic macro / "
                        "maldoc execution pattern, but some enterprises "
                        "run legitimate Office automation; the command "
                        "line usually separates the two."
                    ),
                    why=[
                        f"parent process is {parent} (Office application)",
                        f"child process is {child} (shell/script host)",
                        f"parent pid {event.get('parent_id')} -> child pid "
                        f"{event.get('process_id')} on event #{event['id']}",
                    ],
                    what=(
                        f"{parent} spawned {child} on "
                        f"{event.get('host') or 'unknown host'}: "
                        f"{(event.get('command_line') or '')[:160]}"
                    ),
                    evidence=[
                        _evidence(
                            event,
                            f"process ancestry: {parent} (pid "
                            f"{event.get('parent_id')}) -> {child} (pid "
                            f"{event.get('process_id')})",
                        )
                    ],
                    observed=[
                        f"{child} created with parent {parent} at "
                        f"{event.get('timestamp')}"
                    ],
                    inferred=[
                        "a document may have executed embedded code "
                        "(analyst judgment required)"
                    ],
                )
            )
    return findings


# ---------------------------------------------------------------------------
# Rule 4: Run-key persistence (+ execution correlation)
# ---------------------------------------------------------------------------

_RUN_KEY_RE = re.compile(r"(?i)\\Run(Once)?(\\|$)")
_DETAILS_EXE_RE = re.compile(r'"([^"]+\.exe)"', re.IGNORECASE)


def _is_runkey_event(event: dict) -> bool:
    if event.get("source") == "registry" and str(event.get("event_id")) == "run-key":
        return True
    if event.get("source") == "sysmon" and str(event.get("event_id")) in (
        "12",
        "13",
        "14",
    ):
        return bool(_RUN_KEY_RE.search(str(event.get("registry_key") or "")))
    return False


def _runkey_target(event: dict) -> str:
    """Best-effort persistence target executable for a Run-key event."""
    exe = _exe_from_command_line(event.get("command_line"))
    if exe:
        return exe
    if event.get("file_path"):
        return str(event.get("file_path"))
    # Sysmon registry events carry the value data in the raw excerpt.
    match = _DETAILS_EXE_RE.search(str(event.get("raw") or ""))
    if match:
        return match.group(1)
    return ""


def _eval_runkey_persistence(events: list[dict], rule: Rule) -> list[Finding]:
    findings: list[Finding] = []
    executed = {_base(e.get("process_name")) for e in _proc_create(events)}
    # Prefetch also proves execution; its events carry process_name too.
    executed |= {
        _base(e.get("process_name"))
        for e in events
        if e.get("source") == "prefetch" and e.get("process_name")
    }
    for event in events:
        if not _is_runkey_event(event):
            continue
        exe = _runkey_target(event)
        image = _base(exe)
        ran = bool(image) and image in executed
        severity = Severity.HIGH if ran else Severity.MEDIUM
        key = event.get("registry_key") or "(unknown key)"
        why = [
            f"registry Run/RunOnce value sets persistence: {key}",
            f"persistence target: {exe or '(unparsed command)'}",
        ]
        observed = [f"Run-key value present at {event.get('timestamp')}: {key}"]
        if ran:
            why.append(
                f"the same binary ({image}) was observed executing in "
                "this case — persistence is armed and live"
            )
            observed.append(f"{image} observed executing in this case")
        else:
            why.append(
                "no execution of the target binary observed in this "
                "case (persistence may be dormant, stale, or the "
                "execution telemetry is missing)"
            )
        findings.append(
            Finding(
                rule_id=rule.id,
                rule_version=rule.version,
                title=rule.title,
                severity=severity,
                confidence=85 if ran else 60,
                confidence_reason=(
                    "Run-key persistence plus observed execution is a "
                    "strong indicator the binary survives reboot; a "
                    "Run key alone is weaker (many installers use Run "
                    "keys legitimately)."
                    if ran
                    else "Run keys are a standard persistence mechanism, "
                    "but legitimate installers also use them, and no "
                    "execution was observed in this case."
                ),
                why=why,
                what=(
                    f"Persistence via Run key {key} -> {exe or '(unknown)'}"
                    + ("; target observed executing" if ran else "")
                ),
                evidence=[
                    _evidence(
                        event,
                        f"Run-key value: {key} = "
                        f"{(event.get('command_line') or '')[:120]}",
                    )
                ],
                observed=observed,
                inferred=[
                    "the binary is configured to survive user logon "
                    "(analyst judgment required)"
                ],
            )
        )
    return findings


# ---------------------------------------------------------------------------
# Rules 5 & 6: service / scheduled task with user-writable image
# ---------------------------------------------------------------------------


def _eval_service_writable(events: list[dict], rule: Rule) -> list[Finding]:
    findings: list[Finding] = []
    for event in events:
        if event.get("source") != "services":
            continue
        path = event.get("file_path") or ""
        if not _in_writable_dir(path):
            continue
        findings.append(
            Finding(
                rule_id=rule.id,
                rule_version=rule.version,
                title=rule.title,
                severity=rule.severity,
                confidence=80,
                confidence_reason=(
                    "Services normally run from System32/Program Files; "
                    "a service image in a temp or user-writable "
                    "directory is unusual, though some third-party "
                    "software does install this way."
                ),
                why=[
                    f"service image path is in a user-writable/temp directory: {path}",
                    f"service runs as {event.get('user') or 'unknown account'}",
                ],
                what=(
                    f"Service with writable image path: {path} (event #{event['id']})"
                ),
                evidence=[
                    _evidence(
                        event,
                        f"service image in writable directory: {path}",
                    )
                ],
                observed=[f"service image path {path} at {event.get('timestamp')}"],
                inferred=[
                    "a non-privileged user may be able to replace the "
                    "service binary (analyst judgment required)"
                ],
            )
        )
    return findings


def _eval_task_writable(events: list[dict], rule: Rule) -> list[Finding]:
    findings: list[Finding] = []
    for event in events:
        if event.get("source") != "tasks":
            continue
        path = event.get("file_path") or ""
        if not _in_writable_dir(path):
            continue
        findings.append(
            Finding(
                rule_id=rule.id,
                rule_version=rule.version,
                title=rule.title,
                severity=rule.severity,
                confidence=60,
                confidence_reason=(
                    "Scheduled tasks pointing at temp/user-writable "
                    "binaries merit review, but updaters and user "
                    "software schedule such tasks legitimately."
                ),
                why=[
                    f"scheduled-task action path is in a "
                    f"user-writable/temp directory: {path}",
                ],
                what=(
                    f"Scheduled task executes from writable path: {path} "
                    f"(event #{event['id']})"
                ),
                evidence=[
                    _evidence(
                        event,
                        f"task action in writable directory: {path}",
                    )
                ],
                observed=[f"task action path {path} at {event.get('timestamp')}"],
                inferred=[
                    "the task payload may be replaceable by a "
                    "lower-privileged user (analyst judgment required)"
                ],
            )
        )
    return findings


# ---------------------------------------------------------------------------
# Rule 7: outbound connection to a rare external port
# ---------------------------------------------------------------------------

_COMMON_PORTS = {
    20,
    21,
    22,
    23,
    25,
    53,
    67,
    68,
    69,
    80,
    88,
    110,
    115,
    119,
    123,
    135,
    139,
    143,
    161,
    162,
    389,
    443,
    445,
    464,
    500,
    514,
    515,
    554,
    587,
    636,
    993,
    995,
    1194,
    1433,
    1723,
    1935,
    3306,
    3389,
    4500,
    5060,
    5061,
    5432,
    5900,
    5985,
    5986,
    6379,
    8000,
    8080,
    8443,
    9200,
    27017,
}


def _eval_rare_external_port(events: list[dict], rule: Rule) -> list[Finding]:
    findings: list[Finding] = []
    for event in events:
        if event.get("source") != _SYSMON or str(event.get("event_id")) != "3":
            continue
        port = event.get("dst_port")
        dst = event.get("dst_ip")
        if port is None or port in _COMMON_PORTS:
            continue
        if not _is_external_ip(dst):
            continue
        findings.append(
            Finding(
                rule_id=rule.id,
                rule_version=rule.version,
                title=rule.title,
                severity=rule.severity,
                confidence=40,
                confidence_reason=(
                    "Unusual ports can indicate C2, tunneling, or data "
                    "exfiltration — but also custom business apps, "
                    "gaming, and P2P; this is a pivot lead, not "
                    "evidence of compromise."
                ),
                why=[
                    f"outbound connection to {dst}:{port} (event #{event['id']})",
                    f"port {port} is outside the common-service port list",
                    "destination is a public (non-private) IP",
                ],
                what=(
                    f"{event.get('process_name') or 'unknown process'} "
                    f"connected to external {dst}:{port} on "
                    f"{event.get('host') or 'unknown host'}"
                ),
                evidence=[
                    _evidence(
                        event,
                        f"network connection to external {dst}:{port}",
                    )
                ],
                observed=[
                    f"outbound connection to {dst}:{port} at {event.get('timestamp')}"
                ],
                inferred=[
                    "worth pivoting: check the process, the destination "
                    "reputation, and surrounding timeline "
                    "(analyst judgment required)"
                ],
            )
        )
    return findings


# ---------------------------------------------------------------------------
# Rule 8: failed-logon burst
# ---------------------------------------------------------------------------

_BURST_COUNT = 5
_BURST_WINDOW = timedelta(minutes=10)


def _eval_logon_burst(events: list[dict], rule: Rule) -> list[Finding]:
    findings: list[Finding] = []
    failed = [
        e
        for e in events
        if e.get("source") == _SECURITY and str(e.get("event_id")) == "4625"
    ]
    groups: dict[tuple[str, str], list[dict]] = {}
    for event in failed:
        moment = _parse_ts(event.get("timestamp"))
        if moment is None:
            continue
        key = (str(event.get("user") or "?"), str(event.get("src_ip") or "?"))
        groups.setdefault(key, []).append(event)
    for (user, src_ip), items in sorted(groups.items()):
        items.sort(key=lambda e: str(e.get("timestamp")))
        # Sliding window: find the densest burst.
        best: list[dict] = []
        start = 0
        # All items in this group parsed successfully (filtered above).
        stamps = [t for t in (_parse_ts(e.get("timestamp")) for e in items)]
        assert all(t is not None for t in stamps)
        moments = [t for t in stamps if t is not None]
        for end in range(len(items)):
            while moments[end] - moments[start] > _BURST_WINDOW:
                start += 1
            window = items[start : end + 1]
            if len(window) > len(best):
                best = window
        if len(best) < _BURST_COUNT:
            continue
        first_ts = best[0].get("timestamp")
        last_ts = best[-1].get("timestamp")
        findings.append(
            Finding(
                rule_id=rule.id,
                rule_version=rule.version,
                title=rule.title,
                severity=rule.severity,
                confidence=60,
                confidence_reason=(
                    "Repeated failed logons suggest password guessing, "
                    "but also mistyped passwords, stale cached "
                    "credentials, and service accounts with expired "
                    "passwords."
                ),
                why=[
                    f"{len(best)} failed logons (4625) for {user} from {src_ip}",
                    f"within a 10-minute window ({first_ts} .. {last_ts})",
                ],
                what=(
                    f"Possible password guessing: {len(best)} failed "
                    f"logons for {user} from {src_ip}"
                ),
                evidence=[_evidence(e, "failed logon (4625)") for e in best],
                observed=[
                    f"{len(best)} failed logons for {user} from {src_ip} "
                    f"between {first_ts} and {last_ts}"
                ],
                inferred=[
                    "may indicate brute-force or password spraying "
                    "(analyst judgment required)"
                ],
            )
        )
    return findings


# ---------------------------------------------------------------------------
# Rule 9: first-seen privileged logon from a new host
# ---------------------------------------------------------------------------

_ADMIN_RE = re.compile(r"(?i)(^|[^a-z])admin([^a-z]|$)")


def _is_admin_like(user: object) -> bool:
    """True for admin-like account names (domain prefix stripped).

    Matches a bare ``administrator`` or an ``admin`` token ("adm-jdoe",
    "jdoe-admin"); deliberately conservative — see rule docs.
    """
    if not user:
        return False
    name = str(user).split("\\")[-1].split("@")[0].strip().lower()
    return name == "administrator" or bool(_ADMIN_RE.search(name))


def _eval_admin_new_host(events: list[dict], rule: Rule) -> list[Finding]:
    findings: list[Finding] = []
    logons = [
        e
        for e in events
        if e.get("source") == _SECURITY
        and str(e.get("event_id")) == "4624"
        and _parse_ts(e.get("timestamp")) is not None
    ]
    logons.sort(key=lambda e: str(e.get("timestamp")))
    seen_hosts: dict[str, set[str]] = {}
    for event in logons:
        user = str(event.get("user") or "?")
        if not _is_admin_like(user):
            continue
        host = str(event.get("src_ip") or "").strip()
        if not host or host == "-":
            continue
        known = seen_hosts.setdefault(user, set())
        if known and host not in known:
            findings.append(
                Finding(
                    rule_id=rule.id,
                    rule_version=rule.version,
                    title=rule.title,
                    severity=rule.severity,
                    confidence=45,
                    confidence_reason=(
                        "Admins do log on from new hosts legitimately "
                        "(new workstation, VPN egress change), but a new "
                        "source for a privileged account is worth a "
                        "look — especially paired with other findings."
                    ),
                    why=[
                        f"privileged account {user} logged on from "
                        f"{host} (event #{event['id']})",
                        f"earlier logons for {user} in this case came "
                        f"from: {', '.join(sorted(known))}",
                    ],
                    what=(
                        f"First-seen logon source for {user}: {host} at "
                        f"{event.get('timestamp')}"
                    ),
                    evidence=[
                        _evidence(
                            event,
                            f"successful logon (4624) for {user} from "
                            f"new source {host}",
                        )
                    ],
                    observed=[
                        f"{user} logged on from {host} at "
                        f"{event.get('timestamp')}; prior sources: "
                        f"{', '.join(sorted(known)) or 'none'}"
                    ],
                    inferred=[
                        "could indicate credential use from an "
                        "unexpected location (analyst judgment required)"
                    ],
                )
            )
        known.add(host)
    return findings


# ---------------------------------------------------------------------------
# Rule 10: execution from a user-writable / temp directory
# ---------------------------------------------------------------------------


def _eval_tempdir_execution(events: list[dict], rule: Rule) -> list[Finding]:
    findings: list[Finding] = []
    for event in _proc_create(events):
        path = _exe_from_command_line(event.get("command_line"))
        if path is None or not _in_writable_dir(path):
            continue
        findings.append(
            Finding(
                rule_id=rule.id,
                rule_version=rule.version,
                title=rule.title,
                severity=rule.severity,
                confidence=65,
                confidence_reason=(
                    "User-writable execution locations are favored for "
                    "payload drops, but installers, updaters, and "
                    "portable apps also run from temp directories."
                ),
                why=[
                    f"executed image path is in a user-writable/temp directory: {path}",
                    f"event #{event['id']}: "
                    f"{event.get('process_name')} (pid "
                    f"{event.get('process_id')})",
                ],
                what=(
                    f"Execution from writable location: {path} on "
                    f"{event.get('host') or 'unknown host'}"
                ),
                evidence=[
                    _evidence(
                        event,
                        f"process image in writable directory: {path}",
                    )
                ],
                observed=[
                    f"{event.get('process_name')} executed from {path} "
                    f"at {event.get('timestamp')}"
                ],
                inferred=[
                    "the binary may have been dropped rather than "
                    "installed (analyst judgment required)"
                ],
            )
        )
    return findings


# ---------------------------------------------------------------------------
# Rule registry
# ---------------------------------------------------------------------------


def _rule(
    id: str,
    title: str,
    description: str,
    severity: Severity,
    required_sources: list[tuple[str, str]],
    logic: str,
    false_positives: str,
    evidence_requirements: str,
    evaluate: object,
    mitre: list[str],
) -> Rule:
    return Rule(
        id=id,
        title=title,
        description=description,
        severity=severity,
        version=RULESET_VERSION,
        required_sources=required_sources,
        logic=logic,
        false_positives=false_positives,
        evidence_requirements=evidence_requirements,
        evaluate=evaluate,  # type: ignore[arg-type]
        mitre=mitre,
    )


RULES: list[Rule] = [
    _rule(
        id="HF-DET-ENCPSH",
        title="Encoded PowerShell execution",
        description=(
            "A PowerShell host process started with an encoded-command "
            "switch (-EncodedCommand / -enc)."
        ),
        severity=Severity.HIGH,
        required_sources=[("sysmon", "1"), ("evtx:Security", "4688")],
        logic=(
            "Match process-creation events whose process is powershell.exe "
            "or pwsh.exe AND (the parser recorded the 'encoded-command' "
            "observation OR the command line matches an encoded switch). "
            "Each matching event becomes one finding."
        ),
        false_positives=(
            "Administrators and deployment tools use -EncodedCommand "
            "legitimately (SCCM, scripts avoiding quoting issues). "
            "Corroborate with parent process (rule HF-DET-OFFICE), "
            "downloads (HF-DET-DLPSH), and timeline context."
        ),
        evidence_requirements=(
            "Sysmon EventID 1 or Security 4688 with command line. Without "
            "command-line logging (Sysmon config / 4688 command-line "
            "auditing) this rule cannot fire."
        ),
        evaluate=_eval_encoded_powershell,
        mitre=["T1059.001"],
    ),
    _rule(
        id="HF-DET-DLPSH",
        title="PowerShell downloading remote content",
        description=(
            "PowerShell script content or command line shows remote "
            "download behavior (WebClient, IWR/IRM, bitsadmin, certutil)."
        ),
        severity=Severity.HIGH,
        required_sources=[
            ("powershell", "4104"),
            ("powershell", "4103"),
            ("sysmon", "1"),
            ("evtx:Security", "4688"),
        ],
        logic=(
            "Scan PowerShell script-block excerpts (4104/4103) and "
            "powershell.exe/pwsh.exe command lines for download-related "
            "patterns (Invoke-WebRequest, Net.WebClient, DownloadString, "
            "bitsadmin transfer, certutil urlcache, curl/wget output "
            "flags). Each match becomes one finding."
        ),
        false_positives=(
            "Updaters, package managers (winget/choco scripts), and admin "
            "tooling download files routinely. The matched pattern name "
            "is shown so the analyst can judge intent."
        ),
        evidence_requirements=(
            "PowerShell Script Block Logging (4104) or process command "
            "lines. Script blocks are excerpted (500 chars) in the "
            "normalized event; the full text stays in the evidence file."
        ),
        evaluate=_eval_powershell_download,
        mitre=["T1105"],
    ),
    _rule(
        id="HF-DET-OFFICE",
        title="Office application spawning shell/script interpreter",
        description=(
            "An Office host process (winword, excel, ...) is the parent "
            "of a shell or script interpreter."
        ),
        severity=Severity.HIGH,
        required_sources=[("sysmon", "1"), ("evtx:Security", "4688")],
        logic=(
            "Match process-creation events where the parent image is an "
            "Office application and the child image is a shell/script "
            "host (powershell, cmd, wscript, cscript, mshta, rundll32, "
            "regsvr32, wmic)."
        ),
        false_positives=(
            "Legitimate Office automation and add-ins occasionally spawn "
            "cmd/powershell. The child command line (shown in the "
            "finding) usually separates benign automation from maldocs."
        ),
        evidence_requirements=(
            "Process-creation telemetry with parent image names (Sysmon 1 "
            "or Security 4688 with parent process name)."
        ),
        evaluate=_eval_office_shell_spawn,
        mitre=["T1204.002"],
    ),
    _rule(
        id="HF-DET-RUNKEY",
        title="Run-key persistence",
        description=(
            "A Run/RunOnce registry value points at an executable; "
            "severity rises when that binary is observed executing."
        ),
        severity=Severity.MEDIUM,
        required_sources=[
            ("registry", "run-key"),
            ("sysmon", "12"),
            ("sysmon", "13"),
            ("sysmon", "14"),
            ("sysmon", "1"),
            ("evtx:Security", "4688"),
            ("prefetch", "prefetch"),
        ],
        logic=(
            "For each Run/RunOnce persistence event — offline-hive "
            "Run-key values or Sysmon 12/13/14 writes under a "
            "\\Run(Once) key — extract the target executable and check "
            "whether the same image was observed executing (process "
            "creation or prefetch). Fires MEDIUM for persistence alone, "
            "HIGH when execution is corroborated."
        ),
        false_positives=(
            "Installers and updaters legitimately use Run keys. A lone "
            "Run key for a known-vendor binary is usually benign; "
            "temp-dir targets and unsigned/unknown binaries deserve "
            "scrutiny."
        ),
        evidence_requirements=(
            "Registry Run-key events (offline hive) or Sysmon 12/13/14 "
            "writes under \\Run(Once) keys. Sysmon targets are parsed "
            "from the value-data excerpt (best effort). Execution "
            "correlation needs process-creation or prefetch telemetry "
            "in the same case."
        ),
        evaluate=_eval_runkey_persistence,
        mitre=["T1547.001"],
    ),
    _rule(
        id="HF-DET-SVC",
        title="Service with user-writable image path",
        description=(
            "A Windows service whose image lives in a temp or user-writable directory."
        ),
        severity=Severity.HIGH,
        required_sources=[("services", "service")],
        logic=(
            "Match service-definition events whose image path falls under "
            "a writable/temp directory pattern (\\Temp\\, \\Users\\...\\"
            "AppData\\Local\\Temp, \\ProgramData\\, C:\\Windows\\Temp)."
        ),
        false_positives=(
            "Some third-party software installs services from "
            "ProgramData. Check the vendor, the service account, and "
            "whether the binary is signed (signature data is not "
            "currently parsed — see limitations)."
        ),
        evidence_requirements="Service definitions (offline Services export).",
        evaluate=_eval_service_writable,
        mitre=["T1543.003"],
    ),
    _rule(
        id="HF-DET-TASK",
        title="Scheduled task with user-writable action",
        description=(
            "A scheduled task whose executed program lives in a temp or "
            "user-writable directory."
        ),
        severity=Severity.MEDIUM,
        required_sources=[("tasks", "task")],
        logic=(
            "Match scheduled-task events whose action path falls under a "
            "writable/temp directory pattern."
        ),
        false_positives=(
            "Updaters (browsers, chat apps) commonly schedule tasks "
            "running from AppData. Review the task author, triggers, "
            "and binary reputation."
        ),
        evidence_requirements="Scheduled-task XML exports.",
        evaluate=_eval_task_writable,
        mitre=["T1053.005"],
    ),
    _rule(
        id="HF-DET-RAREPORT",
        title="Outbound connection to rare external port",
        description=(
            "A process connected to a public IP on a port outside the "
            "common-service list."
        ),
        severity=Severity.LOW,
        required_sources=[("sysmon", "3")],
        logic=(
            "Match Sysmon network-connection events whose destination is "
            "a public IP and whose destination port is not in the "
            "built-in common-service list. Internal-only traffic never "
            "fires."
        ),
        false_positives=(
            "High: custom business applications, remote-access tools, "
            "gaming, and P2P software all use uncommon ports. Treat as "
            "a pivot lead — check the process and destination."
        ),
        evidence_requirements=(
            "Sysmon EventID 3 with destination IP/port. No reputation "
            "lookup is performed (offline by design)."
        ),
        evaluate=_eval_rare_external_port,
        mitre=["T1571"],
    ),
    _rule(
        id="HF-DET-BRUTE",
        title="Failed-logon burst",
        description=(
            "Five or more failed logons (4625) for one account from one "
            "source within ten minutes."
        ),
        severity=Severity.MEDIUM,
        required_sources=[("evtx:Security", "4625")],
        logic=(
            "Group 4625 events by (user, source IP); a sliding 10-minute "
            "window with >= 5 failures fires one finding per (user, "
            "source) pair, citing the densest window."
        ),
        false_positives=(
            "Mistyped passwords, stale cached credentials, and service "
            "accounts with expired passwords. A burst followed by a "
            "successful 4624 from the same source is far more "
            "interesting — check the timeline."
        ),
        evidence_requirements=(
            "Security log 4625 events with timestamps, target user, and source IP."
        ),
        evaluate=_eval_logon_burst,
        mitre=["T1110"],
    ),
    _rule(
        id="HF-DET-ADMINHOST",
        title="Privileged logon from first-seen host",
        description=(
            "An admin-like account logs on from a source IP it has not "
            "used before in this case."
        ),
        severity=Severity.LOW,
        required_sources=[("evtx:Security", "4624")],
        logic=(
            "Order 4624 events chronologically per admin-like account "
            "(name matches admin/administrator). When an account with an "
            "established source history logs on from a new source IP, "
            "fire one finding. Accounts with no history never fire."
        ),
        false_positives=(
            "Admins get new workstations; VPN/DHCP churn changes source "
            "IPs. This is a low-confidence tripwire, best combined with "
            "other findings."
        ),
        evidence_requirements=(
            "Security log 4624 events with target user and source IP. "
            "Needs enough history to establish 'normal' sources."
        ),
        evaluate=_eval_admin_new_host,
        mitre=["T1078"],
    ),
    _rule(
        id="HF-DET-TEMPEXEC",
        title="Execution from user-writable directory",
        description=("A process started from a temp or user-writable directory."),
        severity=Severity.MEDIUM,
        required_sources=[("sysmon", "1"), ("evtx:Security", "4688")],
        logic=(
            "Extract the executable path from each process-creation "
            "command line (quoted program or first token) and match it "
            "against writable/temp directory patterns."
        ),
        false_positives=(
            "Installers, self-updaters, and portable apps run from temp "
            "directories. The executable-path extraction is heuristic — "
            "unquoted or obfuscated command lines may be missed or "
            "misread (documented in the finding)."
        ),
        evidence_requirements=(
            "Process-creation events with command lines (Sysmon 1 or "
            "Security 4688 with command-line auditing)."
        ),
        evaluate=_eval_tempdir_execution,
        mitre=["T1204.002"],
    ),
]


def list_rules() -> list[Rule]:
    """All rules in stable ID order."""
    return sorted(RULES, key=lambda r: r.id)


def get_rule(rule_id: str) -> Rule:
    """Look up a rule by ID (case-insensitive); KeyError when unknown."""
    needle = rule_id.strip().upper()
    for rule in RULES:
        if rule.id.upper() == needle:
            return rule
    raise KeyError(f"unknown rule {rule_id!r}")
