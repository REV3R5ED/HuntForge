"""State-directory resolution for HuntForge.

Resolution order (later wins):
  1. built-in default ``~/.huntforge``
  2. ``state_dir`` from the analyst config file (``~/.huntforge/config.toml``)
  3. ``HUNTFORGE_STATE_DIR`` environment variable
  4. explicit ``--state-dir`` CLI flag
"""

from __future__ import annotations

import os
from pathlib import Path

ENV_VAR = "HUNTFORGE_STATE_DIR"
DEFAULT_DIR_NAME = ".huntforge"


def default_state_dir() -> Path:
    """Return the default state directory (``~/.huntforge``)."""
    return Path.home() / DEFAULT_DIR_NAME


def resolve_state_dir(
    explicit: str | None = None, config_value: str | None = None
) -> Path:
    """Resolve the state directory, creating it if needed.

    ``config_value`` is the ``state_dir`` from the analyst config file
    (``core.appconfig``); it sits between the built-in default and the
    environment variable.
    """
    if explicit:
        path = Path(explicit).expanduser()
    elif ENV_VAR in os.environ:
        path = Path(os.environ[ENV_VAR]).expanduser()
    elif config_value:
        path = Path(config_value).expanduser()
    else:
        path = default_state_dir()
    path.mkdir(parents=True, exist_ok=True)
    return path
