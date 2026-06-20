"""Analyzer unit tests.

These tests construct fake Orbit Definition rows + call edges by hand, so they
run without an installed orbit binary. They lock in the analyzer's contract:
the planted vulnerabilities are detected and the negative cases are not flagged
at HIGH.
"""

from __future__ import annotations

import textwrap

from taint_auditor.analyzer import Analyzer
from taint_auditor.catalog import load_catalog
from taint_auditor.orbit import Definition


def _defn(
    id_: int,
    file_path: str,
    name: str,
    content: str,
    *,
    fqn: str | None = None,
    definition_type: str = "Function",
    start_line: int = 1,
    end_line: int = 1,
) -> Definition:
    return Definition(
        id=id_,
        file_path=file_path,
        fqn=fqn or f"{file_path.split('/')[-1].removesuffix('.py')}.{name}",
        name=name,
        definition_type=definition_type,
        start_line=start_line,
        end_line=end_line,
        content=textwrap.dedent(content),
    )


def test_finds_sql_injection_path():
    """views.search -> db.run_search -> db.run_query (cursor.execute) is HIGH."""
    catalog = load_catalog()
    analyzer = Analyzer(catalog)

    run_query = _defn(
        1, "/repo/db.py", "run_query",
        """
        def run_query(sql):
            cursor = conn.cursor()
            cursor.execute(sql)
        """,
    )
    run_search = _defn(
        2, "/repo/db.py", "run_search",
        """
        def run_search(q):
            sql = "SELECT * FROM x WHERE t = '" + q + "'"
            return run_query(sql)
        """,
    )
    search = _defn(
        3, "/repo/views.py", "search",
        """
        @app.route("/search")
        def search():
            q = request.args.get("q")
            return run_search(q)
        """,
        definition_type="DecoratedFunction",
    )

    edges = [(3, 2), (2, 1)]
    findings = analyzer.analyze([run_query, run_search, search], edges)

    sql_findings = [f for f in findings if f.sink_pattern == "cursor.execute"]
    assert sql_findings, f"expected a cursor.execute finding, got: {findings}"
    f = sql_findings[0]
    assert f.severity == "high"
    assert f.source_fqn.endswith("search")
    assert any(p.endswith("run_query") for p in f.path_fqns)


def test_sanitized_path_is_demoted():
    """A path that crosses shlex.quote is demoted to low severity."""
    catalog = load_catalog()
    analyzer = Analyzer(catalog)

    do_safe = _defn(
        10, "/repo/cmd.py", "do_safe_ping",
        """
        def do_safe_ping(host):
            safe = shlex.quote(host)
            subprocess.run(f"ping {safe}", shell=True)
        """,
    )
    handler = _defn(
        11, "/repo/views.py", "healthy_ping",
        """
        @app.route("/healthy_ping")
        def healthy_ping():
            host = request.args.get("host")
            return do_safe_ping(host)
        """,
        definition_type="DecoratedFunction",
    )

    edges = [(11, 10)]
    findings = analyzer.analyze([do_safe, handler], edges)

    sub = [f for f in findings if f.sink_pattern == "subprocess.run"]
    assert sub, "expected the subprocess.run path to surface"
    assert all(f.severity == "low" for f in sub), [f.severity for f in sub]
    assert all(f.sanitized for f in sub)


def test_non_handler_does_not_become_source():
    """A non-handler that calls cursor.execute(literal) must not surface."""
    catalog = load_catalog()
    analyzer = Analyzer(catalog)

    run_query = _defn(
        20, "/repo/db.py", "run_query",
        """
        def run_query(sql):
            cursor.execute(sql)
        """,
    )
    dump_table = _defn(
        21, "/repo/cli.py", "dump_table",
        """
        def dump_table(table):
            if table not in ALLOWED:
                raise SystemExit()
            run_query("SELECT * FROM " + table)
        """,
    )

    edges = [(21, 20)]
    findings = analyzer.analyze([run_query, dump_table], edges)

    assert not findings, f"unexpected findings: {findings}"
