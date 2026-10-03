# Contributing to HuntForge

## Ground rules

- **Defensive only.** HuntForge analyzes evidence; it never attacks.
  Do not add offensive capabilities.
- **Observed vs. inferred.** Detections and reports must distinguish
  what was observed from what is inferred. Never label something
  malicious from a heuristic alone.
- **Provenance is sacred.** Every event carries full provenance.
  Parsers must preserve the source file, record index, and source
  hash — no event without it.
- **Stdlib only** for runtime dependencies (Python 3.10–3.13).

## Development setup

```bash
python -m pip install -e '.[dev]'
pytest -q
ruff check . && ruff format --check . && mypy src
```

- Run pytest with the bare `pytest` binary from the repo root
  (never `python -m pytest` — it masks broken absolute imports).
- Tests import helpers with `from conftest import ...`
  (never `from tests. ...`).
- Coverage gate is 80%; keep new code tested.

## Pull requests

- One concern per PR; include tests and docs (README/CHANGELOG/
  docs/USAGE.md where user-visible).
- Update CHANGELOG.md under an `## [Unreleased]` section.
- Keep the CLI contract stable: `--json` output shapes only grow
  new keys; commands/flags are not renamed without deprecation.

## Release process

Releases are cut by the maintainer: version bump (`__init__.py` +
`pyproject.toml`), CHANGELOG entry, CI green on all supported
Pythons, tagged release with a limitations section.
