"""Batch triage and JSONL export for SIEM ingestion (v0.9).

Registers the ``batch`` module and re-exports the public API: the
batch runner, the case-name sanitizer, and the JSONL exporters.
"""

from huntforge import __version__
from huntforge.batch.batch import (
    MANIFEST_NAME,
    MAX_BATCH_FILES,
    MAX_BATCH_TOTAL_BYTES,
    SUMMARY_NAME,
    BatchRunner,
    file_sha256,
    sanitize_case_name,
)
from huntforge.batch.export import (
    SCHEMA_EVENT,
    SCHEMA_FINDING,
    export_events,
    export_findings,
    export_what,
)
from huntforge.core import plugins as plugins_mod

plugins_mod.register(
    plugins_mod.ModuleInfo(
        name="batch",
        description="Batch evidence triage and JSONL export for SIEM ingestion",
        version=__version__,
        commands=["batch", "export"],
    )
)

__all__ = [
    "BatchRunner",
    "MANIFEST_NAME",
    "MAX_BATCH_FILES",
    "MAX_BATCH_TOTAL_BYTES",
    "SCHEMA_EVENT",
    "SCHEMA_FINDING",
    "SUMMARY_NAME",
    "export_events",
    "export_findings",
    "export_what",
    "file_sha256",
    "sanitize_case_name",
]
