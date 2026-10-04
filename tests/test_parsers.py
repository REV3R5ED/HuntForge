"""HuntForge v0.2 telemetry parser tests.

Covers the parsers package (Sysmon, Security log, PowerShell,
exported Event XML), source auto-detection, ingest wiring, and the
flags column migration. Fixtures are synthetic Windows telemetry in
``tests/fixtures/``.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from huntforge import __version__
from huntforge.cli.main import main as cli_main
from huntforge.ingest.service import ingest_path
from huntforge.models.events import NormalizedEvent
from huntforge.parsers import (
    SOURCE_KINDS,
    detect_source,
    ensure_registered,
    parse_file,
)
from huntforge.parsers.common import (
    MAX_PARSE_BYTES,
    clean_ip,
    flag_encoded_command,
    parse_hashes,
    parse_pid,
    truncate_fractional_seconds,
)
from huntforge.parsers.evtx import EvtxBinaryError, is_evtx_binary, parse_evtx_xml
from huntforge.parsers.powershell import parse_powershell_xml
from huntforge.parsers.security import (
    parse_security_json,
    parse_security_xml,
)
from huntforge.parsers.sysmon import parse_sysmon_json, parse_sysmon_xml

FIXTURES = Path(__file__).parent / "fixtures"
SHA = "ab" * 32

SYSMON_XML = FIXTURES / "sysmon_intrusion.xml"
SYSMON_JSON = FIXTURES / "sysmon_intrusion.json"
SECURITY_XML = FIXTURES / "security_events.xml"
SECURITY_JSON = FIXTURES / "security_events.json"
POWERSHELL_XML = FIXTURES / "powershell_events.xml"
GENERIC_EVTx = FIXTURES / "generic_evtx.xml"
MALFORMED_XML = FIXTURES / "malformed.xml"
MALFORMED_JSON = FIXTURES / "malformed.json"
# Self-contained synthetic binary EVTX (magic + zeros); no binary fixture.
BINARY_EVTX_BYTES = b"ElfFile\x00" + b"\x00" * 1024


def by_event_id(events: list[NormalizedEvent]) -> dict[str, list[NormalizedEvent]]:
    grouped: dict[str, list[NormalizedEvent]] = {}
    for event in events:
        grouped.setdefault(event.event_id, []).append(event)
    return grouped


# ---------------------------------------------------------------------------
# Version + registration
# ---------------------------------------------------------------------------


class TestPackaging:
    def test_version_is_0_9(self) -> None:
        assert __version__ == "0.9.0"

    def test_source_kinds(self) -> None:
        assert set(SOURCE_KINDS) == {
            "sysmon",
            "security",
            "powershell",
            "evtx-xml",
            "prefetch",
            "registry",
            "tasks",
            "services",
        }

    def test_registration_idempotent(self) -> None:
        ensure_registered()
        ensure_registered()  # must not raise


# ---------------------------------------------------------------------------
# Source detection
# ---------------------------------------------------------------------------


class TestDetection:
    @pytest.mark.parametrize(
        "path,kind",
        [
            (SYSMON_XML, "sysmon"),
            (SECURITY_XML, "security"),
            (POWERSHELL_XML, "powershell"),
            (GENERIC_EVTx, "evtx-xml"),
            (SYSMON_JSON, "sysmon"),
            (SECURITY_JSON, "security"),
        ],
    )
    def test_detect_fixtures(self, path: Path, kind: str) -> None:
        assert detect_source(path) == kind

    def test_detect_binary_evtx(self, tmp_path: Path) -> None:
        # Self-contained: synthetic binary EVTX, no binary fixture.
        target = tmp_path / "binary_test.evtx"
        target.write_bytes(BINARY_EVTX_BYTES)
        assert detect_source(target) == "evtx-binary"

    def test_detect_garbage_bytes(self, tmp_path: Path) -> None:
        target = tmp_path / "junk.bin"
        target.write_bytes(b"\x00\x01\x02garbage-not-telemetry" * 10)
        assert detect_source(target) is None

    def test_detect_plain_text(self, tmp_path: Path) -> None:
        target = tmp_path / "notes.txt"
        target.write_text("just some analyst notes\nnothing to parse\n")
        assert detect_source(target) is None


# ---------------------------------------------------------------------------
# Common helpers
# ---------------------------------------------------------------------------


class TestCommonHelpers:
    def test_truncate_seven_fractional_digits(self) -> None:
        # Windows emits 7 digits; Python 3.10 fromisoformat caps at 6.
        assert (
            truncate_fractional_seconds("2026-10-02T09:12:41.1234567Z")
            == "2026-10-02T09:12:41.123456Z"
        )
        assert (
            truncate_fractional_seconds("2026-10-02T09:12:41.123Z")
            == "2026-10-02T09:12:41.123Z"
        )
        assert truncate_fractional_seconds("2026-10-02") == "2026-10-02"

    def test_parse_pid_hex_and_decimal(self) -> None:
        assert parse_pid("0xc3b") == 3131
        assert parse_pid("0x1CFE") == 7422
        assert parse_pid("7422") == 7422
        assert parse_pid("-") is None
        assert parse_pid("0") is None
        assert parse_pid("0x0") is None

    def test_parse_hashes(self) -> None:
        hashes = parse_hashes("SHA256=AAA,MD5=BBB,IMPHASH=CCC")
        assert hashes == {"sha256": "AAA", "md5": "BBB", "imphash": "CCC"}
        assert parse_hashes("-") == {}
        assert parse_hashes("SHA256=") == {}

    def test_flag_encoded_command(self) -> None:
        assert flag_encoded_command("-EncodedCommand aQBm")
        assert flag_encoded_command("-enc aQBm")
        assert flag_encoded_command("/enc aQBm")
        assert not flag_encoded_command("-NoProfile -Command dir")
        assert not flag_encoded_command(None)

    def test_clean_ip(self) -> None:
        assert clean_ip("-") is None
        assert clean_ip("") is None
        assert clean_ip("203.0.113.44") == "203.0.113.44"

    def test_max_parse_bytes_constant(self) -> None:
        assert MAX_PARSE_BYTES >= 100_000_000


# ---------------------------------------------------------------------------
# Sysmon
# ---------------------------------------------------------------------------


class TestSysmonXml:
    def test_record_count(self) -> None:
        events, warnings = parse_sysmon_xml(SYSMON_XML, source_sha256=SHA)
        assert len(events) == 7
        assert warnings == []

    def test_process_creation_mapping(self) -> None:
        events, _ = parse_sysmon_xml(SYSMON_XML, source_sha256=SHA)
        ps = by_event_id(events)["1"][2]  # powershell.exe (intrusion)
        assert ps.source == "sysmon"
        assert ps.process_name == "powershell.exe"
        assert ps.process_id == 7422
        assert ps.parent_name == "WINWORD.EXE"
        assert ps.parent_id == 3131
        assert ps.user == "FIN-014\\m.alvarez"
        assert ps.host == "WS-FIN-014"
        assert "-EncodedCommand" in (ps.command_line or "")
        assert ps.hashes["sha256"].startswith("1111")
        assert ps.hashes["md5"].startswith("2222")
        assert "encoded-command" in ps.flags

    def test_network_connection_mapping(self) -> None:
        events, _ = parse_sysmon_xml(SYSMON_XML, source_sha256=SHA)
        net = by_event_id(events)["3"][1]  # outbound C2
        assert net.src_ip == "192.168.1.50"
        assert net.src_port == 52310
        assert net.dst_ip == "203.0.113.44"
        assert net.dst_port == 443
        assert net.process_name == "powershell.exe"
        assert "203.0.113.44:443" in (net.raw or "")

    def test_file_creation_mapping(self) -> None:
        events, _ = parse_sysmon_xml(SYSMON_XML, source_sha256=SHA)
        file_event = by_event_id(events)["11"][0]
        assert file_event.file_path == (
            "C:\\Users\\m.alvarez\\AppData\\Local\\Temp\\svchost.exe"
        )

    def test_registry_mapping(self) -> None:
        events, _ = parse_sysmon_xml(SYSMON_XML, source_sha256=SHA)
        reg = by_event_id(events)["13"][0]
        assert reg.registry_key == (
            "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater"
        )
        assert "SetValue" in (reg.raw or "")

    def test_benign_events_have_no_flags(self) -> None:
        events, _ = parse_sysmon_xml(SYSMON_XML, source_sha256=SHA)
        explorer = by_event_id(events)["1"][0]
        assert explorer.process_name == "explorer.exe"
        assert explorer.flags == []
        chrome = by_event_id(events)["3"][0]
        assert chrome.process_name == "chrome.exe"
        assert chrome.flags == []

    def test_seven_digit_timestamp_truncated(self) -> None:
        events, _ = parse_sysmon_xml(SYSMON_XML, source_sha256=SHA)
        ps = by_event_id(events)["1"][2]
        assert ps.timestamp == "2026-10-02T09:12:41Z"
        # timestamp_original keeps the exact value Windows emitted
        assert ps.timestamp_original == "2026-10-02T09:12:41.1234567Z"

    def test_provenance_complete_on_every_event(self) -> None:
        events, _ = parse_sysmon_xml(SYSMON_XML, source_sha256=SHA)
        for index, event in enumerate(events):
            prov = event.provenance
            assert prov.source_file == str(SYSMON_XML)
            assert prov.record_index == index
            assert prov.parser_name == "sysmon-xml"
            assert prov.parser_version == "0.2.0"
            assert prov.source_sha256 == SHA
            assert prov.ingest_time  # ISO UTC stamp


class TestSysmonJson:
    def test_record_count_and_mapping(self) -> None:
        events, warnings = parse_sysmon_json(SYSMON_JSON, source_sha256=SHA)
        assert len(events) == 5
        assert warnings == []
        ps = by_event_id(events)["1"][1]
        assert ps.process_name == "powershell.exe"
        assert ps.process_id == 7422
        assert ps.parent_name == "WINWORD.EXE"
        assert "encoded-command" in ps.flags
        net = by_event_id(events)["3"][0]
        assert net.dst_ip == "203.0.113.44"
        assert net.dst_port == 443
        reg = by_event_id(events)["13"][0]
        assert reg.registry_key.endswith("Run\\Updater")
        for index, event in enumerate(events):
            assert event.provenance.parser_name == "sysmon-json"
            assert event.provenance.record_index == index


# ---------------------------------------------------------------------------
# Security log
# ---------------------------------------------------------------------------


class TestSecurityXml:
    def test_record_count(self) -> None:
        events, warnings = parse_security_xml(SECURITY_XML, source_sha256=SHA)
        assert len(events) == 5
        assert warnings == []

    def test_logon_4624(self) -> None:
        events, _ = parse_security_xml(SECURITY_XML, source_sha256=SHA)
        logon = by_event_id(events)["4624"][0]
        assert logon.source == "evtx:Security"
        assert logon.user == "FIN-014\\m.alvarez"
        assert logon.src_ip == "127.0.0.1"
        assert "logon_type=2" in (logon.raw or "")

    def test_failed_logon_4625(self) -> None:
        events, _ = parse_security_xml(SECURITY_XML, source_sha256=SHA)
        failed = by_event_id(events)["4625"][0]
        assert failed.user == "CORP\\Administrator"
        assert failed.src_ip == "203.0.113.99"
        assert "0xC000006D" in (failed.raw or "")

    def test_logoff_4634(self) -> None:
        events, _ = parse_security_xml(SECURITY_XML, source_sha256=SHA)
        logoff = by_event_id(events)["4634"][0]
        assert logoff.user == "FIN-014\\m.alvarez"

    def test_process_4688_hex_pid_and_parent(self) -> None:
        events, _ = parse_security_xml(SECURITY_XML, source_sha256=SHA)
        word = by_event_id(events)["4688"][0]
        assert word.process_name == "WINWORD.EXE"
        assert word.process_id == 3131  # 0xc3b
        assert word.parent_name == "explorer.exe"
        assert word.parent_id == 2048  # 0x800
        assert word.user == "FIN-014\\m.alvarez"

    def test_process_4688_encoded_command_flag(self) -> None:
        events, _ = parse_security_xml(SECURITY_XML, source_sha256=SHA)
        ps = by_event_id(events)["4688"][1]
        assert ps.process_id == 7422  # 0x1cfe
        # observation only: the flag records what the parser saw;
        # no detection verdict is attached anywhere on the event
        assert ps.flags == ["encoded-command"]

    def test_provenance_complete(self) -> None:
        events, _ = parse_security_xml(SECURITY_XML, source_sha256=SHA)
        for event in events:
            assert event.provenance.parser_name == "security-xml"
            assert event.provenance.parser_version == "0.2.0"


class TestSecurityJson:
    def test_json_events(self) -> None:
        events, warnings = parse_security_json(SECURITY_JSON, source_sha256=SHA)
        assert len(events) == 3
        assert warnings == []
        ps = by_event_id(events)["4688"][0]
        assert ps.process_id == 7422
        assert "encoded-command" in ps.flags  # /enc variant


# ---------------------------------------------------------------------------
# PowerShell
# ---------------------------------------------------------------------------


class TestPowershell:
    def test_record_count(self) -> None:
        events, warnings = parse_powershell_xml(POWERSHELL_XML, source_sha256=SHA)
        assert len(events) == 4
        assert warnings == []

    def test_script_block_4104(self) -> None:
        events, _ = parse_powershell_xml(POWERSHELL_XML, source_sha256=SHA)
        block = by_event_id(events)["4104"][0]
        assert block.source == "powershell"
        assert "DownloadString" in (block.command_line or "")
        assert "203.0.113.44" in (block.command_line or "")
        assert "split across multiple 4104 records" in (block.raw or "")
        assert block.user == "S-1-5-21-1111111111-2222222222-3333333333-1001"

    def test_context_4103(self) -> None:
        events, _ = parse_powershell_xml(POWERSHELL_XML, source_sha256=SHA)
        ctx = by_event_id(events)["4103"][0]
        assert "ConsoleHost" in (ctx.raw or "")

    def test_start_stop_4105_4106(self) -> None:
        events, _ = parse_powershell_xml(POWERSHELL_XML, source_sha256=SHA)
        assert by_event_id(events)["4105"]
        assert by_event_id(events)["4106"]


# ---------------------------------------------------------------------------
# Generic EVTX adapter
# ---------------------------------------------------------------------------


class TestEvtxAdapter:
    def test_generic_channel_parsed(self) -> None:
        events, warnings = parse_evtx_xml(GENERIC_EVTx, source_sha256=SHA)
        assert len(events) == 1
        assert warnings == []
        event = events[0]
        assert event.source == "evtx:Application"
        assert event.event_id == "1000"
        assert event.host == "WS-FIN-014"

    def test_binary_magic_detected(self, tmp_path: Path) -> None:
        # Self-contained: synthetic binary EVTX, no binary fixture.
        target = tmp_path / "binary_test.evtx"
        target.write_bytes(BINARY_EVTX_BYTES)
        assert is_evtx_binary(target)

    def test_binary_parse_raises_with_wevtutil_guidance(self, tmp_path: Path) -> None:
        # Self-contained: synthetic binary EVTX, no binary fixture.
        target = tmp_path / "binary_test.evtx"
        target.write_bytes(BINARY_EVTX_BYTES)
        with pytest.raises(EvtxBinaryError) as exc_info:
            parse_file(target, "evtx-binary", source_sha256=SHA)
        message = str(exc_info.value)
        assert "wevtutil" in message
        assert "/f:xml" in message

    def test_json_dispatch(self) -> None:
        result = parse_file(
            FIXTURES / "generic_evtx.json", "evtx-xml", source_sha256=SHA
        )
        assert result.source_kind == "evtx-xml"
        assert len(result.events) == 1
        event = result.events[0]
        assert event.source == "evtx:Application"
        assert event.event_id == "1000"
        assert event.provenance.parser_name == "evtx-json"

    def test_xml_dispatch_by_extensionless_json(self, tmp_path: Path) -> None:
        # content sniffing wins over the file extension
        target = tmp_path / "export.dat"
        target.write_bytes((FIXTURES / "generic_evtx.json").read_bytes())
        assert detect_source(target) == "evtx-xml"

    def test_parse_file_source_kind_validation(self) -> None:
        with pytest.raises(ValueError, match="unknown source kind"):
            parse_file(SYSMON_XML, "bogus-kind", source_sha256=SHA)


# ---------------------------------------------------------------------------
# Malformed inputs: no crash, warnings recorded
# ---------------------------------------------------------------------------


class TestMalformedInputs:
    def test_malformed_xml(self) -> None:
        events, warnings = parse_sysmon_xml(MALFORMED_XML, source_sha256=SHA)
        assert events == []
        assert len(warnings) == 1
        assert "malformed" in warnings[0].lower()

    def test_malformed_json(self) -> None:
        events, warnings = parse_sysmon_json(MALFORMED_JSON, source_sha256=SHA)
        assert events == []
        # every bad line is reported; ingest continues
        assert warnings
        assert all("malformed.json" in w for w in warnings)

    def test_record_without_timestamp_skipped_with_warning(
        self, tmp_path: Path
    ) -> None:
        target = tmp_path / "no_time.xml"
        target.write_text(
            '<Events><Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
            '<System><Provider Name="Microsoft-Windows-Sysmon"/>'
            "<EventID>1</EventID><Channel>Microsoft-Windows-Sysmon/Operational</Channel>"
            "<Computer>WS-1</Computer></System><EventData>"
            '<Data Name="ProcessId">1</Data></EventData></Event></Events>'
        )
        events, warnings = parse_sysmon_xml(target, source_sha256=SHA)
        assert events == []
        assert len(warnings) == 1
        assert "no usable timestamp" in warnings[0]


# ---------------------------------------------------------------------------
# Ingest wiring
# ---------------------------------------------------------------------------


class TestIngestParsers:
    def test_ingest_parses_sysmon_fixture(self, case_db, tmp_path: Path) -> None:
        dest = tmp_path / "sysmon_intrusion.xml"
        dest.write_bytes(SYSMON_XML.read_bytes())
        summary = ingest_path(case_db, dest)
        assert summary["registered"] == 1
        assert summary["parsed_events"] == 7
        assert summary["parsed_by_source"] == {"sysmon": 7}
        assert summary["parse_warnings"] == []
        events = case_db.query_events(process="powershell.exe")
        assert len(events) == 3  # EventIDs 1, 3 and 11 all ran as powershell.exe
        ps = [e for e in events if e["event_id"] == "1"][0]
        assert ps["process_id"] == 7422
        assert ps["parent_name"] == "WINWORD.EXE"
        assert "encoded-command" in ps["flags"]

    def test_ingest_mixed_directory(self, case_db, tmp_path: Path) -> None:
        evidence = tmp_path / "evidence"  # keep clear of the state dir
        evidence.mkdir()
        for src in (SYSMON_XML, SECURITY_XML, POWERSHELL_XML, GENERIC_EVTx):
            (evidence / src.name).write_bytes(src.read_bytes())
        summary = ingest_path(case_db, evidence)
        assert summary["registered"] == 4
        assert summary["parsed_events"] == 7 + 5 + 4 + 1
        assert summary["parsed_by_source"] == {
            "sysmon": 7,
            "security": 5,
            "powershell": 4,
            "evtx-xml": 1,
        }

    def test_ingest_binary_evtx_warns_and_registers(
        self, case_db, tmp_path: Path
    ) -> None:
        dest = tmp_path / "binary_test.evtx"
        dest.write_bytes(BINARY_EVTX_BYTES)
        summary = ingest_path(case_db, dest)
        assert summary["registered"] == 1
        assert summary["parsed_events"] == 0
        assert len(summary["parse_warnings"]) == 1
        assert "wevtutil" in summary["parse_warnings"][0]
        # ingest still exits cleanly: registered as evidence
        assert case_db.list_evidence()[0].filename == "binary_test.evtx"

    def test_ingest_malformed_warns_but_exits_clean(
        self, case_db, tmp_path: Path
    ) -> None:
        dest = tmp_path / "malformed.xml"
        dest.write_bytes(MALFORMED_XML.read_bytes())
        summary = ingest_path(case_db, dest)
        assert summary["registered"] == 1
        assert summary["parsed_events"] == 0
        assert summary["parse_warnings"]

    def test_ingest_unknown_content_registered_not_parsed(
        self, case_db, tmp_path: Path
    ) -> None:
        dest = tmp_path / "notes.txt"
        dest.write_text("analyst notes\n")
        summary = ingest_path(case_db, dest)
        assert summary["registered"] == 1
        assert summary["parsed_events"] == 0
        assert summary["parse_warnings"] == []

    def test_no_parse_flag(self, case_db, tmp_path: Path) -> None:
        dest = tmp_path / "sysmon_intrusion.xml"
        dest.write_bytes(SYSMON_XML.read_bytes())
        summary = ingest_path(case_db, dest, parse=False)
        assert summary["registered"] == 1
        assert summary["parsed_events"] == 0
        assert case_db.query_events() == []

    def test_source_override(self, case_db, tmp_path: Path) -> None:
        dest = tmp_path / "mislabeled.log"
        dest.write_bytes(SECURITY_XML.read_bytes())
        summary = ingest_path(case_db, dest, source="security")
        assert summary["parsed_by_source"] == {"security": 5}

    def test_source_override_invalid(self, case_db, tmp_path: Path) -> None:
        with pytest.raises(ValueError, match="unknown source"):
            ingest_path(case_db, tmp_path, source="bogus")

    def test_ingested_events_carry_provenance(self, case_db, tmp_path: Path) -> None:
        dest = tmp_path / "sysmon_intrusion.xml"
        dest.write_bytes(SYSMON_XML.read_bytes())
        ingest_path(case_db, dest)
        for event in case_db.query_events():
            prov = event["provenance"]
            assert prov["parser_name"] == "sysmon-xml"
            assert prov["parser_version"] == "0.2.0"
            assert prov["source_sha256"]
            assert prov["record_index"] is not None
            assert prov["ingest_time"]

    def test_flags_survive_db_roundtrip(self, case_db, tmp_path: Path) -> None:
        dest = tmp_path / "sysmon_intrusion.xml"
        dest.write_bytes(SYSMON_XML.read_bytes())
        ingest_path(case_db, dest)
        rows = case_db.query_events(process="powershell.exe")
        flagged = [r for r in rows if "encoded-command" in r["flags"]]
        assert len(flagged) == 1


class TestFlagsMigration:
    def test_v01_database_gains_flags_column(
        self, case_db, isolated_state: Path
    ) -> None:
        from huntforge.store.db import CaseDB

        # Simulate a v0.1 database: drop the flags column, then reopen.
        case_db._conn.execute("ALTER TABLE events DROP COLUMN flags")
        case_db._conn.commit()
        case_db.close()
        db = CaseDB(isolated_state, "CASE-001")
        columns = {r[1] for r in db._conn.execute("PRAGMA table_info(events)")}
        assert "flags" in columns
        db.close()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


class TestCliV02:
    def test_ingest_cli_reports_parsed(
        self, isolated_state: Path, tmp_path: Path, capsys: pytest.CaptureFixture
    ) -> None:
        dest = tmp_path / "sysmon_intrusion.xml"
        dest.write_bytes(SYSMON_XML.read_bytes())
        assert cli_main(["case", "create", "cli02"]) == 0
        code = cli_main(["ingest", str(dest), "--case", "cli02"])
        assert code == 0
        out = capsys.readouterr().out
        assert "parsed 7 event(s)" in out

    def test_ingest_cli_source_override(
        self, isolated_state: Path, tmp_path: Path, capsys: pytest.CaptureFixture
    ) -> None:
        dest = tmp_path / "odd_extension.log"
        dest.write_bytes(SECURITY_JSON.read_bytes())
        assert cli_main(["case", "create", "cli02"]) == 0
        code = cli_main(
            ["ingest", str(dest), "--case", "cli02", "--source", "security"]
        )
        assert code == 0
        out = capsys.readouterr().out
        assert "parsed 3 event(s)" in out

    def test_ingest_cli_binary_warning(
        self, isolated_state: Path, tmp_path: Path, capsys: pytest.CaptureFixture
    ) -> None:
        dest = tmp_path / "binary_test.evtx"
        dest.write_bytes(BINARY_EVTX_BYTES)
        assert cli_main(["case", "create", "cli02"]) == 0
        code = cli_main(["ingest", str(dest), "--case", "cli02"])
        assert code == 0  # exit 0: registered as evidence, warning shown
        out = capsys.readouterr().out
        assert "wevtutil" in out

    def test_events_filter_over_sysmon_data(
        self, isolated_state: Path, tmp_path: Path, capsys: pytest.CaptureFixture
    ) -> None:
        dest = tmp_path / "sysmon_intrusion.xml"
        dest.write_bytes(SYSMON_XML.read_bytes())
        assert cli_main(["case", "create", "cli02"]) == 0
        assert cli_main(["ingest", str(dest), "--case", "cli02"]) == 0
        capsys.readouterr()
        # existing v0.1 filters cover host/user/event-id/process/keyword
        assert (
            cli_main(["events", "--process", "powershell.exe", "--case", "cli02"]) == 0
        )
        out = capsys.readouterr().out
        assert "powershell.exe" in out
        assert "encoded-command" in out  # flags shown in human output
        assert (
            cli_main(["events", "--event-id", "13", "--json", "--case", "cli02"]) == 0
        )
        data = json.loads(capsys.readouterr().out)
        assert len(data["events"]) == 1
        assert "Run\\Updater" in data["events"][0]["registry_key"]

    def test_ingest_audit_records_parsed_count(
        self, isolated_state: Path, tmp_path: Path
    ) -> None:
        from huntforge.store.db import CaseDB

        dest = tmp_path / "sysmon_intrusion.xml"
        dest.write_bytes(SYSMON_XML.read_bytes())
        assert cli_main(["case", "create", "cli02"]) == 0
        assert cli_main(["ingest", str(dest), "--case", "cli02"]) == 0
        db = CaseDB(isolated_state, "cli02")
        entries = db.audit_log(limit=5)
        ingest_entries = [e for e in entries if e["command"] == "ingest"]
        assert ingest_entries
        assert ingest_entries[0]["result_count"] >= 7


# ---------------------------------------------------------------------------
# Socket guard: parsers must never touch the network
# ---------------------------------------------------------------------------


class TestNoNetwork:
    @pytest.mark.parametrize(
        "module",
        ["common", "sysmon", "security", "powershell", "evtx"],
    )
    def test_parser_modules_have_no_network_imports(self, module: str) -> None:
        import ast

        source = (
            Path(__file__).parent.parent
            / "src"
            / "huntforge"
            / "parsers"
            / f"{module}.py"
        ).read_text()
        tree = ast.parse(source)
        banned = {"socket", "urllib", "http", "requests", "subprocess"}
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(a.name.split(".")[0] for a in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".")[0])
        assert not (imported & banned), f"{module}.py imports {imported & banned}"
