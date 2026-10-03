"""State-directory resolution for HuntForge.

Resolution order (later wins):
  1. built-in default ``~/.huntforge``
  2. ``HUNTFORGE_STATE_DIR`` environment variable
  3. explicit ``--state-dir`` CLI flag
"""

from __future__ import annotations

import os
from pathlib import Path

ENV_VAR = "HUNTFORGE_STATE_DIR"
DEFAULT_DIR_NAME = ".huntforge"


def default_state_dir() -> Path:
    """Return the default state directory (``~/.huntforge``)."""
    return Path.home() / DEFAULT_DIR_NAME


def resolve_state_dir(explicit: str | None = None) -> Path:
    """Resolve the state directory, creating it if needed."""
    if explicit:
        path = Path(explicit).expanduser()
    elif ENV_VAR in os.environ:
        path = Path(os.environ[ENV_VAR]).expanduser()
    else:
        path = default_state_dir()
    path.mkdir(parents=True, exist_ok=True)
    return path
