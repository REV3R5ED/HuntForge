"""Generate static v0.4 fixtures (run once; outputs are committed).

Extends the v0.2 intrusion chain (winword -> powershell -enc ->
outbound -> dropped svchost.exe -> Run key) with prefetch, scheduled
task, and registry-hive artifacts so the timeline/lineage/entities
demo tells the full story end to end. All synthetic, never real data.

Also generates ``pidreuse_sysmon.json`` for the PID-reuse lineage test.
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from conftest import build_hive, build_prefetch  # noqa: E402

FIXTURES = Path(__file__).resolve().parent

T0 = datetime(2026, 10, 2, 9, 11, 3, tzinfo=timezone.utc)

TASK_UPDATER = """<?xml version="1.0" encoding="UTF-8"?>
<!-- Synthetic Task Scheduler export (schtasks /query /xml). Fictional. -->
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Date>2026-10-02T09:15:00</Date>
    <Author>FIN-014\\m.alvarez</Author>
    <URI>\\Updater</URI>
    <Description>Keep the updater running</Description>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <StartBoundary>2026-10-02T09:15:00</StartBoundary>
      <Enabled>true</Enabled>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>FIN-014\\m.alvarez</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Actions Context="Author">
    <Exec>
      <Command>C:\\Users\\m.alvarez\\AppData\\Local\\Temp\\svchost.exe</Command>
      <Arguments>/silent</Arguments>
    </Exec>
  </Actions>
</Task>
"""

TASK_NODATE = """<?xml version="1.0" encoding="UTF-8"?>
<!-- Synthetic task with no triggers and no registration date: its
     event carries no original timestamp (untimed in the timeline). -->
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Author>FIN-014\\m.alvarez</Author>
    <URI>\\Helper</URI>
  </RegistrationInfo>
  <Actions Context="Author">
    <Exec>
      <Command>C:\\Windows\\System32\\notepad.exe</Command>
    </Exec>
  </Actions>
</Task>
"""


def _sysmon_event(
    record_id: int,
    event_id: int,
    utc_time: str,
    event_data: dict[str, str],
) -> dict[str, object]:
    return {
        "Channel": "Microsoft-Windows-Sysmon/Operational",
        "Computer": "WS-FIN-014",
        "EventData": event_data,
        "EventID": event_id,
        "EventRecordID": record_id,
        "Provider": "Microsoft-Windows-Sysmon",
        "TimeCreated": utc_time,
    }


PS_IMAGE = "C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe"
WORD_IMAGE = (
    "C:\\\\Program Files\\\\Microsoft Office\\\\root\\\\Office16\\\\WINWORD.EXE"
)
SYS32 = "C:\\\\Windows\\\\System32"


def main() -> None:
    # Prefetch: POWERSHELL.EXE executed at the moment of the -enc launch.
    pf = build_prefetch(
        version=30,
        executable="POWERSHELL.EXE",
        run_count=3,
        last_runs=[
            datetime(2026, 10, 2, 9, 12, 41, tzinfo=timezone.utc),
            datetime(2026, 10, 1, 17, 44, 2, tzinfo=timezone.utc),
        ],
        filenames=[
            "\\DEVICE\\HARDDISKVOLUME2\\WINDOWS\\SYSTEM32\\WINDOWSPOWERSHELL\\V1.0\\POWERSHELL.EXE",
            "\\DEVICE\\HARDDISKVOLUME2\\WINDOWS\\SYSTEM32\\KERNEL32.DLL",
        ],
    )
    (FIXTURES / "intrusion_powershell.pf").write_bytes(pf)

    # Scheduled task persistence for the dropped payload.
    (FIXTURES / "intrusion_task.xml").write_text(TASK_UPDATER, encoding="utf-8")
    # Task with no temporal information -> untimed timeline section.
    (FIXTURES / "intrusion_task_nodate.xml").write_text(TASK_NODATE, encoding="utf-8")

    # Registry hive: Run key persistence, last-write matches the
    # Sysmon EventID 13 SetValue (2026-10-02T09:14:55Z).
    hive = build_hive(
        timestamp=datetime(2026, 10, 2, 9, 14, 55, tzinfo=timezone.utc),
        run_values=[
            (
                "Updater",
                "C:\\Users\\m.alvarez\\AppData\\Local\\Temp\\svchost.exe /silent",
            )
        ],
    )
    (FIXTURES / "intrusion_runkey.dat").write_bytes(hive)

    # PID reuse: pid 7422 first runs powershell.exe (09:12), later
    # notepad.exe (12:00); calc.exe (12:01) names parent pid 7422.
    reuse = [
        _sysmon_event(
            301,
            1,
            "2026-10-02T09:12:41.1230000Z",
            {
                "CommandLine": "powershell.exe -enc aQBmAA==",
                "Image": PS_IMAGE,
                "ParentImage": WORD_IMAGE,
                "ParentProcessId": "3131",
                "ProcessId": "7422",
                "User": "FIN-014\\m.alvarez",
                "UtcTime": "2026-10-02 09:12:41.123",
            },
        ),
        _sysmon_event(
            302,
            1,
            "2026-10-02T12:00:05.0000000Z",
            {
                "CommandLine": f'"{SYS32}\\notepad.exe"',
                "Image": f"{SYS32}\\notepad.exe",
                "ParentImage": f"{SYS32}\\explorer.exe",
                "ParentProcessId": "2048",
                "ProcessId": "7422",
                "User": "FIN-014\\m.alvarez",
                "UtcTime": "2026-10-02 12:00:05.000",
            },
        ),
        _sysmon_event(
            303,
            1,
            "2026-10-02T12:01:17.0000000Z",
            {
                "CommandLine": f'"{SYS32}\\calc.exe"',
                "Image": f"{SYS32}\\calc.exe",
                "ParentImage": f"{SYS32}\\notepad.exe",
                "ParentProcessId": "7422",
                "ProcessId": "9001",
                "User": "FIN-014\\m.alvarez",
                "UtcTime": "2026-10-02 12:01:17.000",
            },
        ),
    ]
    (FIXTURES / "pidreuse_sysmon.json").write_text(
        json.dumps(reuse, indent=1), encoding="utf-8"
    )
    print("v0.4 fixtures written")


if __name__ == "__main__":
    main()
