"""Output formatters: human-readable pretty print and SARIF 2.1.0."""

from __future__ import annotations

import json
from typing import Iterable

from .analyzer import Finding


_SEV_COLOR = {"high": "\033[31m", "medium": "\033[33m", "low": "\033[36m"}
_RESET = "\033[0m"


def render_pretty(findings: Iterable[Finding], *, color: bool = True) -> str:
    out: list[str] = []
    for f in findings:
        tag = f.severity.upper()
        if color:
            tag = f"{_SEV_COLOR.get(f.severity, '')}{tag}{_RESET}"
        out.append(
            f"{tag:<6}  {f.sink_file}:{f.sink_line}"
            f"  sink={f.sink_pattern}"
        )
        out.append(f"        source: {f.source_fqn}  ({f.source_reason})")
        out.append("        path:   " + "  ->  ".join(f.path_fqns))
        if f.sanitized:
            out.append("        note:   path crosses a known sanitizer (severity demoted)")
        if f.fix_suggestion:
            out.append(f"        fix:    {f.fix_suggestion}")
        out.append("")
    if not out:
        out.append("No taint findings.")
    return "\n".join(out)


def render_sarif(findings: Iterable[Finding]) -> str:
    """Emit a SARIF 2.1.0 document compatible with GitLab's SAST report ingest."""
    findings = list(findings)
    rules: dict[str, dict] = {}
    results: list[dict] = []

    for f in findings:
        rule_id = f"taint/{f.sink_pattern}"
        rules.setdefault(
            rule_id,
            {
                "id": rule_id,
                "name": f"TaintReachable_{f.sink_pattern.replace('.', '_')}",
                "shortDescription": {"text": f"Untrusted input reaches {f.sink_pattern}"},
                "defaultConfiguration": {"level": _sarif_level(f.severity)},
                "helpUri": "https://gitlab.com/gitlab-org/orbit/knowledge-graph",
            },
        )
        results.append(
            {
                "ruleId": rule_id,
                "level": _sarif_level(f.severity),
                "message": {
                    "text": (
                        f"Untrusted input from {f.source_fqn} ({f.source_reason}) "
                        f"reaches sink {f.sink_pattern} via "
                        f"{' -> '.join(f.path_fqns)}."
                    )
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": f.sink_file},
                            "region": {"startLine": f.sink_line},
                        }
                    }
                ],
                "partialFingerprints": {"taintFlow/v1": f.dedupe_key()},
                "properties": {
                    "severity": f.severity,
                    "sanitized": f.sanitized,
                    "pathFqns": f.path_fqns,
                    "fix": f.fix_suggestion,
                },
            }
        )

    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "taint-flow-auditor",
                        "informationUri": "https://gitlab.com/gitlab-org/orbit/knowledge-graph",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(doc, indent=2)


def _sarif_level(severity: str) -> str:
    return {"high": "error", "medium": "warning", "low": "note"}.get(severity, "warning")
