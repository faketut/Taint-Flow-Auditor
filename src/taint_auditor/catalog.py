"""Load and normalize the source/sink/sanitizer YAML catalogs."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml


CATALOG_DIR = Path(__file__).resolve().parents[2] / "catalog"


@dataclass(frozen=True)
class Catalog:
    source_decorators: frozenset[str]
    source_attribute_reads: frozenset[str]
    source_calls: frozenset[str]
    sink_calls: frozenset[str]
    sink_severity: dict[str, str]
    sink_fix_suggestion: dict[str, str]
    sanitizer_calls: frozenset[str]
    extra: dict = field(default_factory=dict)

    def severity_for(self, sink_pattern: str) -> str:
        return self.sink_severity.get(sink_pattern, "medium")

    def fix_for(self, sink_pattern: str) -> str | None:
        return self.sink_fix_suggestion.get(sink_pattern)


def _load_yaml(path: Path) -> dict:
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def load_catalog(catalog_dir: Path | None = None) -> Catalog:
    base = catalog_dir or CATALOG_DIR
    sources = _load_yaml(base / "sources.yaml")
    sinks = _load_yaml(base / "sinks.yaml")
    sanitizers = _load_yaml(base / "sanitizers.yaml")

    sink_severity: dict[str, str] = {}
    for level, patterns in (sinks.get("severities") or {}).items():
        for p in patterns:
            sink_severity[p] = level

    return Catalog(
        source_decorators=frozenset(sources.get("decorators", []) or []),
        source_attribute_reads=frozenset(sources.get("attribute_reads", []) or []),
        source_calls=frozenset(sources.get("calls", []) or []),
        sink_calls=frozenset(sinks.get("calls", []) or []),
        sink_severity=sink_severity,
        sink_fix_suggestion=dict(sinks.get("fix_suggestions") or {}),
        sanitizer_calls=frozenset(sanitizers.get("calls", []) or []),
    )
