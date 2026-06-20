"""Optional integration: post findings as a single MR discussion or issues.

Designed for use inside a GitLab CI job. Reads CI_PROJECT_ID, CI_MERGE_REQUEST_IID,
and a token from the environment. No-op (and logs a hint) if those are not set.
"""

from __future__ import annotations

import os
import textwrap
from typing import Iterable

import httpx

from .analyzer import Finding


def _summary_markdown(findings: list[Finding]) -> str:
    if not findings:
        return "**Taint-Flow Auditor:** no reachable taint paths found in this MR's scope."

    by_sev: dict[str, list[Finding]] = {"high": [], "medium": [], "low": []}
    for f in findings:
        by_sev.setdefault(f.severity, []).append(f)

    lines = ["**Taint-Flow Auditor** — interprocedural reachability report\n"]
    for sev in ("high", "medium", "low"):
        bucket = by_sev.get(sev) or []
        if not bucket:
            continue
        lines.append(f"### {sev.upper()} ({len(bucket)})\n")
        for f in bucket[:25]:
            lines.append(
                f"- `{f.sink_file}:{f.sink_line}` "
                f"`{f.sink_pattern}` "
                f"← `{f.source_fqn}`"
            )
            lines.append("  <details><summary>path</summary>\n")
            lines.append("  " + " → ".join(f"`{p}`" for p in f.path_fqns))
            if f.fix_suggestion:
                lines.append(f"\n  **fix:** {f.fix_suggestion}")
            lines.append("</details>")
        if len(bucket) > 25:
            lines.append(f"_… and {len(bucket) - 25} more._")
        lines.append("")
    lines.append(
        "_Powered by [GitLab Orbit](https://gitlab.com/gitlab-org/orbit/knowledge-graph). "
        "Sources/sinks are configured in `catalog/`._"
    )
    return "\n".join(lines)


def post_mr_discussion(findings: Iterable[Finding]) -> bool:
    """Post a summary discussion to the active MR. Returns True on success."""
    findings = list(findings)
    project_id = os.environ.get("CI_PROJECT_ID")
    mr_iid = os.environ.get("CI_MERGE_REQUEST_IID")
    token = os.environ.get("TAINT_GITLAB_TOKEN") or os.environ.get("CI_JOB_TOKEN")
    base = os.environ.get("CI_API_V4_URL", "https://gitlab.com/api/v4")

    if not project_id or not mr_iid or not token:
        print(
            textwrap.dedent(
                """
                [taint-audit] Skipping MR post: requires CI_PROJECT_ID, CI_MERGE_REQUEST_IID,
                and TAINT_GITLAB_TOKEN (or CI_JOB_TOKEN) to be set.
                """
            ).strip()
        )
        return False

    body = _summary_markdown(findings)
    url = f"{base}/projects/{project_id}/merge_requests/{mr_iid}/discussions"
    r = httpx.post(url, headers={"PRIVATE-TOKEN": token}, data={"body": body}, timeout=20)
    if r.status_code >= 300:
        print(f"[taint-audit] MR post failed: {r.status_code} {r.text}")
        return False
    return True
