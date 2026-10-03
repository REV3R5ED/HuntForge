"""Generate static v0.3 fixtures (run once; outputs are committed).

Prefetch/hive fixtures are built programmatically via the conftest
builders — never from real forensic data. Task XML and services JSON
are hand-written synthetic exports.
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from conftest import build_hive, build_prefetch  # noqa: E402

FIXTURES = Path(__file__).resolve().parent

PAST = datetime(2026, 9, 15, 8, 30, tzinfo=timezone.utc)


def main() -> None:
    pf = build_prefetch(
        version=30,
        executable="MALWARE.EXE",
        run_count=14,
        last_runs=[
            datetime(2026, 10, 1, 8, 30, tzinfo=timezone.utc),
            datetime(2026, 9, 30, 17, 5, tzinfo=timezone.utc),
        ],
        filenames=[
            "\\DEVICE\\HARDDISKVOLUME2\\WINDOWS\\TEMP\\MALWARE.EXE",
            "\\DEVICE\\HARDDISKVOLUME2\\WINDOWS\\SYSTEM32\\KERNEL32.DLL",
            "\\DEVICE\\HARDDISKVOLUME2\\WINDOWS\\SYSTEM32\\NTDLL.DLL",
        ],
    )
    (FIXTURES / "malware_run.pf").write_bytes(pf)
    (FIXTURES / "truncated.pf").write_bytes(pf[:64])
    (FIXTURES / "bad_hive.dat").write_bytes(b"regf" + b"\x00" * 100 + b"garbage")
    (FIXTURES / "synthetic_hive.dat").write_bytes(build_hive(timestamp=PAST))
    print("fixtures written")


if __name__ == "__main__":
    main()
