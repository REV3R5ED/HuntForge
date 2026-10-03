# Changelog

All notable changes to HuntForge are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

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
