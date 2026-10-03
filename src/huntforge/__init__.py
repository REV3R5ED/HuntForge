"""HuntForge — endpoint threat-hunting and Windows forensics platform.

"Hunt the endpoint. Reconstruct the attack."

v0.2 is telemetry ingestion: Sysmon, Security log and PowerShell
parsers, exported Event XML/JSON, and binary-EVTX detection with
``wevtutil`` export guidance.
"""

__version__ = "0.2.0"
__author__ = "Pouya Shini Karim"

from huntforge.core import config, logging, plugins, results

__all__ = [
    "__version__",
    "config",
    "logging",
    "plugins",
    "results",
]
