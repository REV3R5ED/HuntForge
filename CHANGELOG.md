# Changelog

All notable changes to HuntForge are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.6.0] - 2026-10-03

### Added
- MITRE ATT&CK mapping (`huntforge.mitre`, stdlib-only, fully offline,
  registered in the plugin registry as `mitre` v0.6.0):
  - Curated local technique table (`techniques.json`, 23 techniques
    for endpoint forensics, stamped ATT&CK v16.1 Oct 2026 — a
    documented subset, not the full matrix). Each entry carries its
    name, tactics, a HuntForge-written description, and the
    `(source, event_id)` pairs that can evidence it; techniques no
    parser covers yet (T1003.001 LSASS, T1070.001/004) are listed with
    empty sources as honest gaps.
  - Every v0.5 detection rule mapped to its technique(s) (mapping
    enforced by `validate_mapping()` in tests); the engine copies the
    mapping onto findings and the case store persists `mitre` +
    `provenance` (new columns, auto-migrated on old databases).
  - `huntforge mitre --case ID`: technique coverage over stored
    findings — techniques with findings (rules + finding UIDs),
    gaps (no findings), and unobservable techniques. `--json` for
    automation.
  - `huntforge mitre techniques [--json]`: the curated table.
  - `docs/ATTACK.md`: the table, per-rule mapping with reasoning,
    coverage philosophy (technique *use*, never attribution), and
    the Sigma-subset documentation.
- Sigma-subset rule support (`huntforge.sigma`, stdlib-only,
  registered as `sigma` v0.6.0):
  - Documented JSON rule schema (title, id, logsource, detection
    selections, condition, level, tags) plus a best-effort YAML
    importer via a hand-written subset parser (flat shapes only;
    tabs, flow collections, block scalars, anchors fail loudly).
  - Supported: named selections (AND of fields, OR of values), `*`
    wildcards, conditions (`selection`, `and`/`or`/`not`,
    `1 of sel*`, `all of sel*`), Sigma field-name mapping,
    logsource category filtering. Rejected at load time (never
    silently): `|contains`-style modifiers, aggregations, `near`,
    nested selections.
  - `huntforge sigma list`: four bundled samples (3 JSON + 1 YAML).
    `huntforge sigma run --case ID --rule FILE`: evaluates one rule,
    persists findings (exit 1 when found) with provenance
    `huntforge.sigma` v0.6.0; `attack.t*` tags become `mitre` IDs.
  - 335 tests, 87.5% coverage.

## [0.5.0] - 2026-10-03

### Added
- Explainable detection rules (`huntforge.detections`, stdlib-only,
  fully offline, registered in the plugin registry as `detections`
  v0.5.0). Ten named, versioned rules over normalized events:
  encoded PowerShell execution, PowerShell downloading remote content,
  Office application spawning a shell/script interpreter, Run-key
  persistence (MEDIUM, escalated to HIGH when the target binary is
  observed executing), service with user-writable image path,
  scheduled task with user-writable action, outbound connection to a
  rare external port, failed-logon burst (5+/10 min), privileged logon
  from a first-seen host, execution from a user-writable directory.
- `huntforge detect --case ID [--rule ID] [--severity high+]
  [--explain]`: runs the rule catalog (or selected rules), prints each
  finding with its reasoning (`why`/`what`), cited evidence
  (`event #N`), confidence plus justification, and observed-vs-inferred
  separation. Findings are stored in the case (UIDs `HF-0001`, …) via
  a new `findings` table and returned in the result envelope;
  exit code is 1 when findings exist (`EXIT_FINDINGS`).
- `huntforge rules list`: the detection rule catalog with severity,
  description, and evidence requirements.
- `docs/DETECTIONS.md`: per-rule documentation — logic,
  false-positive profile, evidence requirements — plus the severity
  model and deliberate omissions (no LSASS rule yet, no signature
  data, no impossible travel, no `critical` from heuristics).
- Findings feed back into the case store like v0.1 case findings;
  272 tests, 88.5% coverage.

### Changed
- Exit codes are now 0 ok / 1 findings / 2 error (1 was previously
  reserved for detections).


## [0.4.0] - 2026-10-03

### Added
- Observation layer (`huntforge.timeline`, stdlib-only, fully offline,
  registered in the plugin registry as `timeline` v0.4.0). All three
  tools reorganize ingested evidence — no verdicts, no invented
  timestamps (v0.5 does detections):
  - `huntforge timeline --case ID [--from TS] [--to TS] [--source TYPE]
    [--limit N]`: one UTC-chronological view across every ingested
    source, with per-source coverage (event counts, first/last seen).
    Events whose parser could not recover an original timestamp are
    listed in an `untimed` section — never dropped, never placed.
    `--from`/`--to` do not affect untimed events (documented).
  - `huntforge lineage --case ID [--pid N | --image NAME]`: parent→child
    process trees from Sysmon EventID 1 / Security 4688 creation
    records, rendered as ASCII trees and JSON. Same (host, PID, image)
    merges into one instance; non-creation events attach as
    corroborating references. PID reuse becomes separate instances
    (reused PIDs flagged); an ambiguous child links to the latest
    plausible parent with an explicit note naming every candidate;
    unobserved parents are labeled, never invented.
  - `huntforge entities --case ID [--type T]`: cross-source entity
    resolution — hosts case-insensitive, `DOMAIN\user` →
    `user@domain`, file paths and registry keys case-insensitive,
    hashes lowercased — with every observed spelling, per-source
    observation counts, and first/last seen. Types: host, user, ip,
    process, file, hash, registry.
- `CaseDB.all_events()`: unfiltered deterministic event access for the
  observation tools (no schema change).
- New synthetic fixtures: `intrusion_powershell.pf`,
  `intrusion_task.xml`, `intrusion_task_nodate.xml` (untimed),
  `intrusion_runkey.dat`, `pidreuse_sysmon.json`
  (`tests/fixtures/make_fixtures_04.py`); `build_hive` now accepts
  custom Run values.
- Docs: `docs/USAGE.md` v0.4 intrusion-reconstruction scenario with
  genuine output, `docs/images/04-timeline.png` (house style),
  README v0.4 section.
- Tests: `tests/test_timeline.py` (28 tests). Total: 227 tests,
  87.5% coverage.

### Fixed
- `NormalizedEvent`: an explicit `timestamp_original=None` (parser
  could not recover an original timestamp) is now preserved instead
  of being filled in with the placeholder timestamp. Omitting the
  argument still fills in the ingested value (sentinel-based; backward
  compatible). This is what lets the timeline's `untimed` section work.

## [0.3.0] - 2026-10-03

### Added
- Persistence-artifact parsers (`huntforge.parsers.prefetch`,
  `huntforge.parsers.registry`, `huntforge.parsers.persistence`;
  stdlib-only, fully offline, registered in the plugin registry as
  `parsers` v0.3.0):
  - Prefetch (`.pf`, format versions 23/26/30): 84-byte header
    (`SCCA` signature, UTF-16LE executable name, prefetch hash),
    run count, last-run FILETIMEs, referenced filenames via the
    file-metrics array, volume device path/serial/creation time.
    One `prefetch:prefetch` execution-evidence event per file.
    Compressed (MAM) prefetch and version 31 are rejected with
    clean guidance.
  - Offline registry hives (`regf`): pure-Python NK/VK cell parser
    with lf/lh/li/ri subkey lists; decodes `REG_SZ`,
    `REG_EXPAND_SZ`, `REG_BINARY`, `REG_DWORD`,
    `REG_DWORD_BIG_ENDIAN`, `REG_MULTI_SZ`, `REG_QWORD`
    (anything else → hex). New `huntforge registry <hive-file>
    <key-path> [--json]` command for targeted forensic reads
    (no case required, no audit record).
  - Registry persistence scan on ingest: `Run`/`RunOnce` values →
    `registry:run-key` events (timestamp = key last-write time);
    `Services` key → `services:service` events (image path, start
    type, service account).
  - Scheduled tasks (`schtasks /query /xml`): triggers, Exec
    actions, principals, author → `tasks:task` events; new parser
    observations `runs-as-system`, `action-in-temp-dir`.
  - Services JSON exports (documented schema) → `services:service`
    events; new observations `auto-start`, `image-in-temp-dir`,
    `unquoted-service-path`.
- `ingest` source auto-detection extended: `SCCA` magic → `prefetch`,
  `regf` magic → `registry`, `<Task>` root → `tasks`,
  `"image_path"` JSON → `services`
  (`--source prefetch|registry|tasks|services` overrides).
- All parser flags remain observations, never verdicts (v0.5).
- Tests: `tests/test_persistence.py` (62 tests); 8 new synthetic
  fixtures under `tests/fixtures/` (programmatically built
  Prefetch/hive binaries, task XML, services JSON, malformed
  inputs). Total: 199 tests, 86.7% coverage.

### Fixed
- Task Scheduler XML detection skips the XML declaration and leading
  comments before matching the `<Task>` root (Windows Event XML also
  contains `<Task>` inside `<System>` — the root tag decides).

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
