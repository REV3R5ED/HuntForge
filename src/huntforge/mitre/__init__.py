"""MITRE ATT&CK mapping (v0.6).

Curated local technique table (``techniques.json`` — a subset for
endpoint forensics, versioned, with an ATT&CK snapshot stamp),
rule → technique mapping for every built-in detection rule, and
technique coverage over a case's stored findings.

A finding mapped to a technique is evidence that the technique was
*used*. It is never attribution of actor intent, and a technique with
no findings is a gap in evidence, not proof of absence.
"""

from huntforge import __version__
from huntforge.core import plugins as plugins_mod
from huntforge.mitre.mapping import coverage_from_findings, rule_techniques
from huntforge.mitre.table import KNOWN_IDS, TABLE, Technique, TechniqueTable

plugins_mod.register(
    plugins_mod.ModuleInfo(
        name="mitre",
        description="Curated ATT&CK technique table and case coverage",
        version=__version__,
        commands=["mitre"],
    )
)

__all__ = [
    "KNOWN_IDS",
    "TABLE",
    "Technique",
    "TechniqueTable",
    "coverage_from_findings",
    "rule_techniques",
]
