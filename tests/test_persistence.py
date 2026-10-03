"""Tests for v0.3 persistence artifacts: Prefetch, registry hives,
scheduled tasks, services, the registry CLI command and ingest wiring.

Fixtures are synthetic (built programmatically in conftest or committed
under tests/fixtures/) — never real forensic data. Timestamps asserted
relatively where "now" is involved (no time-bomb tests).
"""

from __future__ import annotations

import hashlib
import json
import struct
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from conftest import (
    _HiveBuilder,
    _sz,
    build_hive,
    build_prefetch,
    datetime_to_filetime,
)

from huntforge.cli.main import main as cli_main
from huntforge.ingest.service import ingest_path
from huntforge.parsers import detect_source, parse_file
from huntforge.parsers import persistence as persistence_mod
from huntforge.parsers import prefetch as prefetch_mod
from huntforge.parsers import registry as registry_mod
from huntforge.parsers.persistence import (
    _exe_of,
    _in_temp_dir,
    _normalize_start,
    find_child_text,
)

FIXTURES = Path(__file__).parent / "fixtures"


def sha_of(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Prefetch
# ---------------------------------------------------------------------------


class TestPrefetch:
    def test_v30_parses(self):
        two_hours_ago = utcnow() - timedelta(hours=2)
        data = build_prefetch(
            version=30,
            executable="MALWARE.EXE",
            run_count=14,
            last_runs=[two_hours_ago],
            filenames=["\\DEVICE\\HARDDISKVOLUME2\\WINDOWS\\TEMP\\MALWARE.EXE"],
        )
        info = prefetch_mod.parse_prefetch(data, filename="MALWARE.EXE-AB12.pf")
        assert info.version == 30
        assert info.executable == "MALWARE.EXE"
        assert info.run_count == 14
        assert len(info.last_runs) == 1
        parsed = datetime.fromisoformat(info.last_runs[0].replace("Z", "+00:00"))
        assert abs((parsed - two_hours_ago).total_seconds()) < 5
        assert info.filenames == [
            "\\DEVICE\\HARDDISKVOLUME2\\WINDOWS\\TEMP\\MALWARE.EXE"
        ]
        assert info.volumes[0]["device_path"] == "\\Device\\HarddiskVolume2"
        assert info.volumes[0]["serial"] == "A1B2C3D4"

    def test_v26_and_v23_parse(self):
        for version in (26, 23):
            data = build_prefetch(version=version, executable="TEST.EXE", run_count=3)
            info = prefetch_mod.parse_prefetch(data)
            assert info.version == version
            assert info.executable == "TEST.EXE"
            assert info.run_count == 3
            assert info.last_runs, f"v{version} should have a last run"
            assert len(info.filenames) == 2

    def test_static_fixture(self):
        # Keep this regression test self-contained: generated fixture bytes are
        # deterministic and avoid relying on an untracked binary .pf file.
        data = build_prefetch(
            executable="MALWARE.EXE",
            run_count=14,
        )
        info = prefetch_mod.parse_prefetch(data)
        assert info.executable == "MALWARE.EXE"
        assert info.run_count == 14
        assert info.last_runs
        assert len(info.filenames) == 2

    def test_bad_magic(self):
        with pytest.raises(prefetch_mod.PrefetchError, match="bad SCCA"):
            prefetch_mod.parse_prefetch(b"\x00" * 200)

    def test_truncated(self):
        with pytest.raises(prefetch_mod.PrefetchError, match="truncated"):
            prefetch_mod.parse_prefetch(b"SCCA" + b"\x00" * 10)

    def test_static_truncated_fixture_warns(self):
        events, warnings = prefetch_mod.parse_prefetch_file(
            FIXTURES / "truncated.pf", source_sha256="ab" * 32
        )
        assert events == [] and len(warnings) == 1

    def test_unsupported_version(self):
        data = bytearray(build_prefetch(version=30))
        struct.pack_into("<I", data, 0, 99)
        with pytest.raises(prefetch_mod.PrefetchError, match="unsupported.*99"):
            prefetch_mod.parse_prefetch(bytes(data))

    def test_compressed_mam_rejected(self):
        with pytest.raises(prefetch_mod.PrefetchError, match="compressed.*MAM"):
            prefetch_mod.parse_prefetch(b"MAM\x04" + b"\x00" * 100)

    def test_empty_executable_rejected(self):
        data = bytearray(build_prefetch())
        data[16:76] = b"\x00" * 60
        with pytest.raises(prefetch_mod.PrefetchError, match="empty executable"):
            prefetch_mod.parse_prefetch(bytes(data))

    def test_filetime_zero_is_none(self):
        assert prefetch_mod.filetime_to_iso(0) is None

    def test_filetime_garbage_is_none(self):
        assert prefetch_mod.filetime_to_iso(0xFFFFFFFFFFFFFFFF) is None

    def test_filetime_roundtrip(self):
        moment = utcnow().replace(microsecond=0)
        iso = prefetch_mod.filetime_to_iso(datetime_to_filetime(moment))
        assert iso == moment.strftime("%Y-%m-%dT%H:%M:%SZ")

    def test_parse_file_event(self, tmp_path):
        target = tmp_path / "X.EXE-1234.pf"
        target.write_bytes(build_prefetch(executable="X.EXE", run_count=5))
        events, warnings = prefetch_mod.parse_prefetch_file(
            target, source_sha256=sha_of(target), ingest_time="2026-10-03T00:00:00Z"
        )
        assert warnings == []
        assert len(events) == 1
        event = events[0]
        assert event.source == "prefetch"
        assert event.event_id == "prefetch"
        assert event.process_name == "X.EXE"
        assert "run_count=5" in (event.raw or "")
        assert event.provenance.parser_name == "prefetch"
        assert event.provenance.source_sha256 == sha_of(target)

    def test_parse_file_no_runs_falls_back_to_ingest_time(self):
        data = build_prefetch(run_count=0, last_runs=[])
        info = prefetch_mod.parse_prefetch(data)
        assert info.last_runs == []
        event = prefetch_mod.prefetch_to_event(
            info,
            source_file="x.pf",
            record_index=0,
            source_sha256="ab" * 32,
            ingest_time="2026-10-03T00:00:00Z",
        )
        assert event.timestamp == "2026-10-03T00:00:00Z"

    def test_oversized_file_skipped(self, tmp_path, monkeypatch):
        monkeypatch.setattr(prefetch_mod, "MAX_PARSE_BYTES", 10)
        target = tmp_path / "big.pf"
        target.write_bytes(build_prefetch())
        events, warnings = prefetch_mod.parse_prefetch_file(
            target, source_sha256="ab" * 32
        )
        assert events == [] and warnings and "exceeds size limit" in warnings[0]

    def test_absurd_metrics_count_rejected(self):
        data = bytearray(build_prefetch(version=30))
        struct.pack_into("<I", data, 84 + 4, 200_000)
        with pytest.raises(prefetch_mod.PrefetchError, match="absurd metrics"):
            prefetch_mod.parse_prefetch(bytes(data))

    def test_absurd_volume_count_rejected(self):
        data = bytearray(build_prefetch(version=30))
        struct.pack_into("<I", data, 84 + 28, 999)
        with pytest.raises(prefetch_mod.PrefetchError, match="absurd volume"):
            prefetch_mod.parse_prefetch(bytes(data))


# ---------------------------------------------------------------------------
# Registry hives
# ---------------------------------------------------------------------------


class TestRegistry:
    def test_run_key_values(self):
        hive = registry_mod.Hive(build_hive())
        view = hive.list_key(r"Software\Microsoft\Windows\CurrentVersion\Run")
        assert view.last_write is not None
        by_name = {v.name: v for v in view.values}
        assert by_name["Updater"].type_name == "REG_SZ"
        assert by_name["Updater"].data == (
            "C:\\Users\\test\\AppData\\Roaming\\updater.exe --silent"
        )
        assert by_name["BadThing"].data == "C:\\Temp\\evil.exe"

    def test_case_insensitive_path(self):
        hive = registry_mod.Hive(build_hive())
        view = hive.list_key(r"software\microsoft\windows\currentversion\run")
        assert len(view.values) == 2

    def test_forward_slashes(self):
        hive = registry_mod.Hive(build_hive())
        assert hive.key_exists("Software/Microsoft/Windows/CurrentVersion/RunOnce")

    def test_root_and_subkeys(self):
        hive = registry_mod.Hive(build_hive())
        root = hive.list_key("")
        assert root.subkeys == ["ControlSet001", "Software"]
        assert hive.root_name == "ROOT"
        assert hive.key_exists("Nope") is False

    def test_service_values(self):
        hive = registry_mod.Hive(build_hive())
        view = hive.list_key(r"ControlSet001\Services\BadSvc")
        by_name = {v.name: v for v in view.values}
        assert by_name["Start"].data == 2
        assert by_name["Start"].type_name == "REG_DWORD"
        assert by_name["ImagePath"].type_name == "REG_EXPAND_SZ"
        assert by_name["Type"].data == 0x10

    def test_value_types(self):
        b = _HiveBuilder()
        now = utcnow()
        values = [
            b.vk("sz", 1, _sz("hello")),
            b.vk("multi", 7, "a\x00b".encode("utf-16-le") + b"\x00\x00\x00\x00"),
            b.vk("dword", 4, struct.pack("<I", 42)),
            b.vk("dwordbe", 5, struct.pack(">I", 42)),
            b.vk("qword", 11, struct.pack("<Q", 2**40)),
            b.vk("bin", 3, b"\xde\xad\xbe\xef"),
            b.vk("none", 0, b"\x01\x02"),
        ]
        leaf = b.nk("Leaf", timestamp=now, values=values)
        root = b.nk("ROOT", timestamp=now, subkeys=[leaf])
        header = bytearray(0x1000)
        header[0:4] = b"regf"
        struct.pack_into("<I", header, 0x24, root)
        hbin = bytearray(0x1000)
        hbin[0:4] = b"hbin"
        for offset, cell in b._cells:
            hbin[offset : offset + len(cell)] = cell
        hive = registry_mod.Hive(bytes(header) + bytes(hbin))
        view = hive.list_key("Leaf")
        by_name = {v.name: v for v in view.values}
        assert by_name["sz"].data == "hello"
        assert by_name["multi"].data == ["a", "b"]
        assert by_name["multi"].type_name == "REG_MULTI_SZ"
        assert by_name["dword"].data == 42
        assert by_name["dwordbe"].data == 42
        assert by_name["qword"].data == 2**40
        assert by_name["bin"].data == "deadbeef"
        assert by_name["none"].data == "0102"

    def test_to_dict_json_safe(self):
        hive = registry_mod.Hive(build_hive())
        view = hive.list_key(r"ControlSet001\Services\BadSvc")
        json.dumps(view.to_dict())  # must not raise

    def test_missing_key(self):
        hive = registry_mod.Hive(build_hive())
        with pytest.raises(registry_mod.KeyNotFoundError):
            hive.list_key("Software\\Nope")

    def test_bad_magic(self):
        with pytest.raises(registry_mod.HiveError, match="bad regf"):
            registry_mod.Hive(b"NOPE" + b"\x00" * 5000)

    def test_truncated(self):
        with pytest.raises(registry_mod.HiveError, match="truncated"):
            registry_mod.Hive(b"regf")

    def test_static_bad_hive(self):
        with pytest.raises(registry_mod.HiveError):
            registry_mod.Hive((FIXTURES / "bad_hive.dat").read_bytes())

    def test_last_write_relative(self):
        moment = utcnow() - timedelta(hours=3)
        hive = registry_mod.Hive(build_hive(timestamp=moment))
        view = hive.list_key("Software")
        parsed = datetime.fromisoformat(view.last_write.replace("Z", "+00:00"))
        assert abs((parsed - moment).total_seconds()) < 5


# ---------------------------------------------------------------------------
# Scheduled tasks
# ---------------------------------------------------------------------------


class TestTasks:
    def test_malicious_task(self):
        path = FIXTURES / "task_malicious.xml"
        events, warnings = persistence_mod.parse_tasks_xml(
            path, source_sha256=sha_of(path), ingest_time="2026-10-03T00:00:00Z"
        )
        assert warnings == []
        assert len(events) == 1
        event = events[0]
        assert event.source == "tasks"
        assert event.event_id == "task"
        assert event.timestamp == "2026-09-28T14:30:00Z"  # first StartBoundary
        assert event.user == "S-1-5-18"
        assert event.process_name == "evil.exe"
        assert event.command_line == "C:\\Temp\\evil.exe --silent --persist"
        assert event.flags == ["runs-as-system", "action-in-temp-dir"]
        assert event.provenance.parser_name == "tasks-xml"

    def test_malformed_xml_warns(self):
        events, warnings = persistence_mod.parse_tasks_xml(
            FIXTURES / "malformed_task.xml", source_sha256="ab" * 32
        )
        assert events == [] and len(warnings) == 1

    def test_non_task_xml_warns(self, tmp_path):
        target = tmp_path / "other.xml"
        target.write_text("<Events><Event><System/></Event></Events>", encoding="utf-8")
        events, warnings = persistence_mod.parse_tasks_xml(
            target, source_sha256="ab" * 32
        )
        assert events == [] and warnings and "not a Task" in warnings[0]

    def test_no_triggers_falls_back_to_ingest_time(self, tmp_path):
        target = tmp_path / "notriggers.xml"
        target.write_text(
            '<?xml version="1.0"?><Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">'
            "<RegistrationInfo><URI>\\T</URI></RegistrationInfo>"
            "<Actions><Exec><Command>C:\\a.exe</Command></Exec></Actions></Task>",
            encoding="utf-8",
        )
        events, _ = persistence_mod.parse_tasks_xml(
            target, source_sha256="ab" * 32, ingest_time="2026-10-03T00:00:00Z"
        )
        assert len(events) == 1
        assert events[0].timestamp == "2026-10-03T00:00:00Z"
        # v0.4: an explicit None original is preserved (untimed in the
        # timeline) — the model only fills it in when the argument is
        # omitted entirely.
        assert events[0].timestamp_original is None

    def test_registration_date_used_when_no_boundary(self, tmp_path):
        target = tmp_path / "regdate.xml"
        target.write_text(
            '<?xml version="1.0"?><Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">'
            "<RegistrationInfo><URI>\\T</URI><Date>2026-08-01T10:00:00</Date></RegistrationInfo>"
            "<Triggers><BootTrigger><Enabled>true</Enabled></BootTrigger></Triggers>"
            "<Actions><Exec><Command>C:\\a.exe</Command></Exec></Actions></Task>",
            encoding="utf-8",
        )
        events, _ = persistence_mod.parse_tasks_xml(
            target, source_sha256="ab" * 32, ingest_time="2026-10-03T00:00:00Z"
        )
        assert events[0].timestamp == "2026-08-01T10:00:00Z"

    def test_find_child_text_none(self):
        assert find_child_text(None, "URI") is None


# ---------------------------------------------------------------------------
# Services
# ---------------------------------------------------------------------------


class TestServices:
    def test_json_export(self):
        path = FIXTURES / "services_export.json"
        events, warnings = persistence_mod.parse_services_json(
            path, source_sha256=sha_of(path), ingest_time="2026-10-03T00:00:00Z"
        )
        assert warnings == []
        assert len(events) == 3
        by_proc = {e.process_name: e for e in events}
        bad = by_proc["badsvc.exe"]
        assert bad.flags == ["auto-start", "image-in-temp-dir"]
        assert bad.user == "LocalSystem"
        assert bad.timestamp == "2026-10-03T00:00:00Z"
        assert by_proc["good svc.exe"].flags == []
        assert by_proc["unquoted.exe"].flags == ["unquoted-service-path"]

    def test_bad_json_warns(self):
        path = FIXTURES / "services_bad.json"
        events, warnings = persistence_mod.parse_services_json(
            path, source_sha256=sha_of(path), ingest_time="2026-10-03T00:00:00Z"
        )
        assert len(events) == 1  # nameless record skipped, others kept
        assert len(warnings) == 2

    def test_invalid_json_file(self, tmp_path):
        target = tmp_path / "bad.json"
        target.write_text("{nope", encoding="utf-8")
        events, warnings = persistence_mod.parse_services_json(
            target, source_sha256="ab" * 32
        )
        assert events == [] and len(warnings) == 1

    def test_services_from_hive(self):
        events, warnings = persistence_mod.parse_services_hive(
            build_hive(),
            source_file="SYSTEM",
            source_sha256="ab" * 32,
            ingest_time="2026-10-03T00:00:00Z",
        )
        assert warnings == []
        assert len(events) == 2
        by_proc = {e.process_name: e for e in events}
        bad = by_proc["badsvc.exe"]
        assert bad.flags == ["auto-start", "image-in-temp-dir"]
        assert bad.registry_key == "ControlSet001\\Services\\BadSvc"
        assert bad.provenance.parser_name == "services-hive"
        assert by_proc["svchost.exe"].flags == []

    def test_services_hive_without_services_key(self):
        b = _HiveBuilder()
        now = utcnow()
        root = b.nk("ROOT", timestamp=now)
        header = bytearray(0x1000)
        header[0:4] = b"regf"
        struct.pack_into("<I", header, 0x24, root)
        hbin = bytearray(0x1000)
        hbin[0:4] = b"hbin"
        for offset, cell in b._cells:
            hbin[offset : offset + len(cell)] = cell
        events, warnings = persistence_mod.parse_services_hive(
            bytes(header) + bytes(hbin),
            source_file="NTUSER.DAT",
            source_sha256="ab" * 32,
        )
        assert events == [] and warnings and "no Services key" in warnings[0]

    def test_parse_services_file_dispatch(self, tmp_path):
        hive_path = tmp_path / "SYSTEM"
        hive_path.write_bytes(build_hive())
        events, _ = persistence_mod.parse_services_file(
            hive_path, source_sha256="ab" * 32, ingest_time="2026-10-03T00:00:00Z"
        )
        assert len(events) == 2
        assert events[0].provenance.parser_name == "services-hive"
        events, _ = persistence_mod.parse_services_file(
            FIXTURES / "services_export.json",
            source_sha256="ab" * 32,
            ingest_time="2026-10-03T00:00:00Z",
        )
        assert events[0].provenance.parser_name == "services-json"


class TestHelpers:
    def test_exe_of(self):
        assert _exe_of('"C:\\Program Files\\a.exe" --x') == "C:\\Program Files\\a.exe"
        assert _exe_of("C:\\Temp\\evil.exe --silent") == "C:\\Temp\\evil.exe"
        assert _exe_of("C:\\Program Files\\Vendor\\unquoted.exe --run") == (
            "C:\\Program Files\\Vendor\\unquoted.exe"
        )
        assert _exe_of(None) is None
        assert _exe_of("  ") is None

    def test_in_temp_dir(self):
        assert _in_temp_dir("C:\\Temp\\x.exe")
        assert _in_temp_dir("C:\\WINDOWS\\TEMP\\x.exe")
        assert not _in_temp_dir("C:\\Windows\\System32\\x.exe")
        assert not _in_temp_dir(None)

    def test_normalize_start(self):
        assert _normalize_start(2) == 2
        assert _normalize_start("auto") == 2
        assert _normalize_start("Manual") == 3
        assert _normalize_start(99) is None
        assert _normalize_start("bogus") is None
        assert _normalize_start(None) is None
        assert _normalize_start(True) is None


# ---------------------------------------------------------------------------
# Registry persistence scan
# ---------------------------------------------------------------------------


class TestRegistryScan:
    def test_scan_finds_run_keys_and_services(self):
        events, warnings = persistence_mod.scan_registry_persistence(
            build_hive(),
            source_file="synthetic.dat",
            source_sha256="ab" * 32,
            ingest_time="2026-10-03T00:00:00Z",
        )
        assert warnings == []
        assert len(events) == 5  # 3 Run/RunOnce values + 2 services
        kinds = [(e.source, e.event_id) for e in events]
        assert kinds.count(("registry", "run-key")) == 3
        assert kinds.count(("services", "service")) == 2
        # record indexes are sequential across both groups
        assert [e.provenance.record_index for e in events] == [0, 1, 2, 3, 4]
        run = next(e for e in events if e.process_name == "evil.exe")
        assert run.registry_key.endswith("Run\\BadThing")
        assert run.command_line == "C:\\Temp\\evil.exe"

    def test_scan_bad_hive_warns(self):
        events, warnings = persistence_mod.scan_registry_persistence(
            (FIXTURES / "bad_hive.dat").read_bytes(),
            source_file="bad.dat",
            source_sha256="ab" * 32,
        )
        assert events == [] and len(warnings) == 1

    def test_scan_registry_file(self, tmp_path):
        target = tmp_path / "NTUSER.DAT"
        target.write_bytes(build_hive())
        events, warnings = persistence_mod.scan_registry_file(
            target, source_sha256=sha_of(target)
        )
        assert len(events) == 5 and warnings == []


# ---------------------------------------------------------------------------
# detect_source / parse_file / ingest wiring
# ---------------------------------------------------------------------------


class TestWiring:
    def test_detect_prefetch(self, tmp_path):
        target = tmp_path / "A.EXE-1234.pf"
        target.write_bytes(build_prefetch())
        assert detect_source(target) == "prefetch"

    def test_detect_registry(self, tmp_path):
        target = tmp_path / "NTUSER.DAT"
        target.write_bytes(build_hive())
        assert detect_source(target) == "registry"

    def test_detect_tasks(self):
        assert detect_source(FIXTURES / "task_malicious.xml") == "tasks"

    def test_detect_services_json(self):
        assert detect_source(FIXTURES / "services_export.json") == "services"

    def test_event_xml_not_mistaken_for_task(self):
        # Windows Event XML contains <Task> inside <System>; root decides.
        assert detect_source(FIXTURES / "sysmon_intrusion.xml") == "sysmon"

    def test_parse_file_unknown_kind(self, tmp_path):
        target = tmp_path / "x.bin"
        target.write_bytes(b"\x00" * 16)
        with pytest.raises(ValueError, match="unknown source kind"):
            parse_file(target, "nope", source_sha256="ab" * 32)

    def test_ingest_directory(self, tmp_path, case_db):
        evidence = tmp_path / "evidence"
        evidence.mkdir()
        (evidence / "MALWARE.EXE-AB12.pf").write_bytes(build_prefetch(run_count=14))
        (evidence / "NTUSER.DAT").write_bytes(build_hive())
        (evidence / "task.xml").write_bytes(
            (FIXTURES / "task_malicious.xml").read_bytes()
        )
        (evidence / "services.json").write_bytes(
            (FIXTURES / "services_export.json").read_bytes()
        )
        summary = ingest_path(case_db, evidence)
        assert summary["registered"] == 4
        assert summary["parsed_by_source"]["prefetch"] == 1
        assert summary["parsed_by_source"]["registry"] == 5
        assert summary["parsed_by_source"]["tasks"] == 1
        assert summary["parsed_by_source"]["services"] == 3

    def test_ingest_source_override(self, tmp_path, case_db):
        target = tmp_path / "mystery.bin"
        target.write_bytes(build_prefetch())
        summary = ingest_path(case_db, target, source="prefetch")
        assert summary["parsed_by_source"]["prefetch"] == 1

    def test_ingest_unknown_source_rejected(self, tmp_path, case_db):
        with pytest.raises(ValueError, match="unknown source"):
            ingest_path(case_db, tmp_path, source="nope")

    def test_ingest_truncated_prefetch_warns(self, tmp_path, case_db):
        target = tmp_path / "broken.pf"
        target.write_bytes((FIXTURES / "truncated.pf").read_bytes())
        summary = ingest_path(case_db, target)
        assert summary["parsed_events"] == 0
        assert summary["parse_warnings"]  # warning, exit stays 0


# ---------------------------------------------------------------------------
# CLI: huntforge registry
# ---------------------------------------------------------------------------


def run_cli(argv: list[str], monkeypatch, tmp_path) -> tuple[int, str]:
    monkeypatch.setenv("HUNTFORGE_STATE_DIR", str(tmp_path / "state"))
    import io
    from contextlib import redirect_stderr, redirect_stdout

    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = cli_main(argv)
    return code, out.getvalue() + err.getvalue()


class TestRegistryCli:
    def test_registry_human(self, tmp_path, monkeypatch):
        hive = tmp_path / "NTUSER.DAT"
        hive.write_bytes(build_hive())
        code, output = run_cli(
            ["registry", str(hive), r"Software\Microsoft\Windows\CurrentVersion\Run"],
            monkeypatch,
            tmp_path,
        )
        assert code == 0
        assert "2 value(s)" in output
        assert "BadThing [REG_SZ] = C:\\Temp\\evil.exe" in output

    def test_registry_json(self, tmp_path, monkeypatch):
        hive = tmp_path / "NTUSER.DAT"
        hive.write_bytes(build_hive())
        code, output = run_cli(
            ["registry", str(hive), "ControlSet001", "--json"], monkeypatch, tmp_path
        )
        assert code == 0
        payload = json.loads(output)
        assert payload["status"] == "ok"
        assert payload["data"]["subkeys"] == ["Services"]

    def test_registry_not_a_hive(self, tmp_path, monkeypatch):
        target = tmp_path / "x.dat"
        target.write_bytes(b"not a hive")
        code, output = run_cli(
            ["registry", str(target), "Software"], monkeypatch, tmp_path
        )
        assert code == 2
        assert "cannot parse hive" in output

    def test_registry_missing_key(self, tmp_path, monkeypatch):
        hive = tmp_path / "NTUSER.DAT"
        hive.write_bytes(build_hive())
        code, output = run_cli(
            ["registry", str(hive), "Software\\Nope"], monkeypatch, tmp_path
        )
        assert code == 2
        assert "key not found" in output

    def test_registry_missing_file(self, tmp_path, monkeypatch):
        code, output = run_cli(
            ["registry", str(tmp_path / "nope.dat"), "Software"], monkeypatch, tmp_path
        )
        assert code == 2
        assert "cannot read hive file" in output
