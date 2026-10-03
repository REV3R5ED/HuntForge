# Changelog

All notable changes to HuntForge are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.2.0] - 2026-10-03

### Added
- Telemetry parsers (`huntforge.parsers`, stdlib-only, fully offline,
  registered in the plugin registry as `parsers` v0.2.0):
  - Sysmon XML/JSON exports — EventID 1 (process creation: image,
    command line, parent, hashes, user), 3 (network connection:
    src/dst IP/port), 7 (image load), 11 (file creation), 12/13/14
    (registry). Streaming XML parse; memory-safe for large files.
  - Security log XML/JSON — 4624/4625 (logon: user, logon type,
    source IP/workstation), 4634/4647 (logoff), 4688 (process
    creation with hex-PID decoding, parent image).
  - PowerShell operational log XML/JSON — 4103/4104 (script-block
    text capture with multi-record reassembly note), 4105/4106,
    4100; other IDs parsed generically.
  - Exported Windows Event XML/JSON adapter for any other channel
    (`source: "evtx:<Channel>"`).
- Binary EVTX detection by magic bytes: clean error naming the file
  and the exact `wevtutil qe "C:\path\to\file.evtx" /lf:true /f:xml`
  export command (honest limitation, documented in README).
- `ingest` parsing: source kind auto-detected by content
  (`--source sysmon|security|powershell|evtx-xml` overrides,
  `--no-parse` registers evidence only); summary reports
  `parsed_events`, `parsed_by_source`, `parse_warnings`. Malformed
  records warn, never crash; ingest stays exit 0.
- `flags` on `NormalizedEvent`: parser observations such as
  `encoded-command` (`-EncodedCommand`/`-enc`/`/enc` on a command
  line) — observation only, never a verdict. Shown in human `events`
  output as `flags: encoded-command (parser observation)`.
- SQLite `events.flags` column with automatic migration for v0.1
  databases.
- 7-fractional-digit Windows timestamps handled: truncated to 6 for
  parsing, exact original preserved in `timestamp_original`.
- Tests: `tests/test_parsers.py` (67 tests) and 9 synthetic fixtures
  under `tests/fixtures/` (intrusion chain, malformed inputs, binary
  EVTX stub).
- Docs: `docs/USAGE.md` v0.2 scenario (export → ingest → process
  lineage) with a real terminal screenshot
  (`docs/images/02-ingest.png`).

## [0.1.0] - 2026-10-03

### Added
- Core CLI (`huntforge`): `case create/show/list`, `ingest`, `events`,
  `audit`, `--version`; `--json` on every command; exit codes 0/2.
- Normalized event model (`huntforge.models.events`): the v1.0-stable
  core — UTC-normalized timestamps with originals preserved, host/user,
  source + event id, process/parent (name/pid), command line, network
  tuple, file path, registry key, hashes, raw reference, and mandatory
  provenance (source file, record index, parser name/version, ingest
  time, source SHA-256) validated at construction.
- Per-case SQLite event store (`~/.huntforge/cases/<CASE-ID>/store.db`,
  `HUNTFORGE_STATE_DIR` override): meta, evidence, events (indexed on
  timestamp/host/user/event-id/process), audit tables.
- Evidence ingest: SHA-256 + MD5 hashing, dedupe by SHA-256, sources
  never modified; `--fixture` JSONL loader for normalized events
  (malformed lines skipped and counted, never fatal).
- Filtered event queries: `--host`, `--user`, `--event-id`,
  `--process`, `--keyword` (AND, case-insensitive), `--limit`/`--offset`,
  deterministic (timestamp, id) ordering.
- Audit trail: every CLI invocation touching a case is logged.
- Plugin registry with `core` v0.1.0 registered.
- Docs: README, docs/USAGE.md scenario walkthrough with a real
  terminal screenshot, SECURITY.md, CONTRIBUTING.md.

### Limitations
- No artifact parsers yet (v0.2+); no timeline/detections/ATT&CK/
  correlation/reports (v0.4+). See README.
