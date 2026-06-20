"""Demo: a CLI utility that calls into db.run_query.

This file is NOT a Flask route, has no request.args decoration, and is not
listed in catalog/sources.yaml as a source. The auditor should reach the SQL
sink only via the HTTP route, never via this CLI -- this is the decoy.
"""

import sys

from db import run_query

ALLOWED_TABLES = {"items", "users"}


def dump_table(table: str) -> None:
    if table not in ALLOWED_TABLES:
        raise SystemExit(f"unknown table: {table}")
    # Allow-listed, literal-built SQL. cursor.execute is reached but the
    # auditor should not classify dump_table as a source.
    sql = f"SELECT * FROM {table}"
    print(run_query(sql))


if __name__ == "__main__":
    dump_table(sys.argv[1] if len(sys.argv) > 1 else "items")
