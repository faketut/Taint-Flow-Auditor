"""Thin read-only client over the Orbit Local DuckDB graph.

Two responsibilities:

1. Pull the rows the analyzer needs (Python ``Definition`` rows, call edges).
2. Populate ``Definition.content`` by reading the source file from disk and
   slicing on the line range stored on the node. Orbit's schema does not (as
   of v0.78.0) store source content on the row, despite docs that suggest it
   does — so we re-hydrate from the filesystem.

The DB is opened ``read_only=True`` so we never block a concurrent indexer.
"""

from __future__ import annotations

import os
import subprocess
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

import duckdb

from . import queries


DEFAULT_DB_PATH = Path.home() / ".orbit" / "graph.duckdb"


@dataclass(frozen=True)
class Definition:
    id: int
    file_path: str         # absolute path on disk
    fqn: str
    name: str
    definition_type: str   # "Function", "Method", "Class", "DecoratedFunction"
    start_line: int        # 1-based, inclusive
    end_line: int          # 1-based, inclusive
    content: str           # source slice of the definition (may be empty on error)


class OrbitClient:
    """Read-only DuckDB view of an Orbit Local graph."""

    def __init__(self, db_path: Path | None = None) -> None:
        self.db_path = Path(db_path or DEFAULT_DB_PATH)
        if not self.db_path.exists():
            raise FileNotFoundError(
                f"Orbit graph not found at {self.db_path}. "
                "Run `orbit index .` first."
            )
        self._conn = duckdb.connect(str(self.db_path), read_only=True)

    # --- introspection ------------------------------------------------------

    def tables(self) -> list[str]:
        return [r[0] for r in self._conn.execute(queries.Q_LIST_TABLES).fetchall()]

    # --- data ---------------------------------------------------------------

    def python_definitions(self, repo_root: str | None = None) -> Iterator[Definition]:
        repo = os.path.abspath(repo_root) if repo_root else None
        rows = self._conn.execute(
            queries.Q_PYTHON_DEFINITIONS,
            [repo, repo],
        ).fetchall()

        # Cache file reads since many Definitions share a file.
        file_cache: dict[str, list[str]] = {}

        for id_, repo_path, file_path, fqn, name, dtype, sl, el in rows:
            abs_path = os.path.join(repo_path, file_path)
            content = self._slice_lines(file_cache, abs_path, sl, el)
            yield Definition(
                id=id_,
                file_path=abs_path,
                fqn=fqn,
                name=name,
                definition_type=dtype,
                start_line=sl,
                end_line=el,
                content=content,
            )

    def call_edges(self, repo_root: str | None = None) -> list[tuple[int, int]]:
        repo = os.path.abspath(repo_root) if repo_root else None
        return [
            (s, t)
            for s, t in self._conn.execute(
                queries.Q_CALL_EDGES_DEF_DEF, [repo, repo]
            ).fetchall()
        ]

    # --- helpers ------------------------------------------------------------

    @staticmethod
    def _slice_lines(
        cache: dict[str, list[str]],
        path: str,
        start_line: int,
        end_line: int,
    ) -> str:
        lines = cache.get(path)
        if lines is None:
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as fh:
                    lines = fh.read().splitlines(keepends=True)
            except OSError:
                lines = []
            cache[path] = lines
        if not lines:
            return ""
        s = max(0, start_line - 1)
        e = min(len(lines), end_line)
        return "".join(lines[s:e])

    def close(self) -> None:
        self._conn.close()


def run_orbit_index(repo_root: Path) -> None:
    """Best-effort: ensure the repo has been indexed."""
    subprocess.run(
        ["orbit", "index", str(repo_root)],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def orbit_sql_cli(sql: str) -> list[dict]:
    """Fallback: shell out to ``orbit sql`` and parse JSON output."""
    result = subprocess.run(
        ["orbit", "sql", "--format", "json", sql],
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(result.stdout or "[]")
