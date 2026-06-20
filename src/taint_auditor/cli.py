"""Command-line entry point for taint-flow-auditor."""

from __future__ import annotations

import sys
from pathlib import Path

import click

from .analyzer import Analyzer
from .catalog import CATALOG_DIR, load_catalog
from .gitlab_post import post_mr_discussion
from .orbit import DEFAULT_DB_PATH, OrbitClient, run_orbit_index
from .report import render_pretty, render_sarif


@click.group()
@click.version_option(package_name="taint-flow-auditor")
def main() -> None:
    """Interprocedural reachability auditor powered by GitLab Orbit."""


@main.command()
@click.argument("repo", type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.option("--db", type=click.Path(path_type=Path), default=None,
              help=f"Orbit DuckDB path (default: {DEFAULT_DB_PATH}).")
@click.option("--catalog", "catalog_dir", type=click.Path(path_type=Path), default=None,
              help=f"Catalog directory (default: {CATALOG_DIR}).")
@click.option("--output", type=click.Path(path_type=Path), default=None,
              help="Write SARIF 2.1.0 to this path.")
@click.option("--pretty/--no-pretty", default=True, help="Print human-readable findings.")
@click.option("--max-path-len", type=int, default=8, show_default=True)
@click.option("--index/--no-index", default=False,
              help="Run `orbit index` before scanning.")
@click.option("--post-mr", is_flag=True,
              help="Post a summary discussion on the active GitLab MR (requires CI env).")
@click.option("--fail-on", type=click.Choice(["never", "low", "medium", "high"]),
              default="never", show_default=True,
              help="Exit non-zero when findings of >= this severity exist.")
def scan(
    repo: Path,
    db: Path | None,
    catalog_dir: Path | None,
    output: Path | None,
    pretty: bool,
    max_path_len: int,
    index: bool,
    post_mr: bool,
    fail_on: str,
) -> None:
    """Scan a repo for source -> sink reachability."""
    repo_abs = str(repo.resolve())
    if index:
        click.echo(f"[taint-audit] orbit index {repo_abs} ...", err=True)
        run_orbit_index(repo)

    client = OrbitClient(db)
    catalog = load_catalog(catalog_dir)
    analyzer = Analyzer(catalog, max_path_len=max_path_len)

    definitions = list(client.python_definitions(repo_root=repo_abs))
    edges = client.call_edges(repo_root=repo_abs)
    client.close()

    if not definitions:
        click.echo(
            f"[taint-audit] No Python definitions found for {repo_abs}. "
            "Did you run `orbit index .` in the repo?",
            err=True,
        )

    findings = analyzer.analyze(definitions, edges)

    if pretty:
        click.echo(render_pretty(findings, color=sys.stdout.isatty()))

    if output:
        output.write_text(render_sarif(findings), encoding="utf-8")
        click.echo(f"[taint-audit] wrote {output} ({len(findings)} findings)", err=True)

    if post_mr:
        post_mr_discussion(findings)

    if fail_on != "never":
        rank = {"low": 0, "medium": 1, "high": 2}
        threshold = rank[fail_on]
        bad = [f for f in findings if rank.get(f.severity, -1) >= threshold]
        if bad:
            click.echo(f"[taint-audit] {len(bad)} findings at >= {fail_on}", err=True)
            sys.exit(2)


@main.command()
@click.option("--db", type=click.Path(path_type=Path), default=None)
def doctor(db: Path | None) -> None:
    """Inspect the Orbit DuckDB graph and report table availability."""
    try:
        client = OrbitClient(db)
    except FileNotFoundError as exc:
        click.echo(f"ERROR: {exc}", err=True)
        sys.exit(1)
    tables = client.tables()
    click.echo(f"DB: {client.db_path}")
    click.echo(f"Tables ({len(tables)}):")
    for t in tables:
        click.echo(f"  - {t}")
    client.close()


if __name__ == "__main__":
    main()
