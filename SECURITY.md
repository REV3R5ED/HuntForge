# Security Policy

## Scope

HuntForge is a defensive security tool: it analyzes endpoint telemetry
and forensic artifacts you already own. It performs no offensive
actions — no exploitation, no payload delivery, no credential access.

## Reporting a vulnerability

If you find a security issue in HuntForge (e.g. path traversal in case
handling, unsafe fixture parsing, secret leakage in output), please
report it responsibly:

- Do **not** open a public issue for the report itself.
- Email the maintainer with a description and, if possible, a minimal
  reproducer.

## Security-relevant design (v0.1)

- **Evidence is read-only**: ingest hashes files but never modifies,
  moves, or deletes them.
- **Case ID validation**: case identifiers are restricted to
  `[A-Za-z0-9._-]` (max 64 chars), blocking path traversal out of the
  state directory.
- **Fixture loading is defensive**: malformed JSONL lines are skipped
  and counted; oversized lines are rejected; a bad line never aborts
  the load or crashes the CLI.
- **No secrets in output**: provenance records file hashes, never file
  contents; audit logs record argument names and values as given —
  avoid passing secrets as CLI arguments.
- **Local trust boundary**: the SQLite case store has no access
  control. Keep `~/.huntforge` (or your `HUNTFORGE_STATE_DIR`) on
  trusted, access-controlled storage.

## Supported versions

Only the latest released minor version receives security fixes.
