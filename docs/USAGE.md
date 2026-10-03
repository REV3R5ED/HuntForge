# HuntForge Usage Guide

Scenario-driven walkthroughs for HuntForge v0.1. All output below is
genuine — produced by running the commands against synthetic evidence.

## Scenario: a compromised workstation

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
