"""Demo: SQL helpers, including a planted SQL-injection sink."""

import sqlite3


def _connect():
    return sqlite3.connect(":memory:")


def build_query(q: str) -> str:
    # VULN: untrusted q is concatenated into SQL.
    return "SELECT id, title FROM items WHERE title LIKE '%" + q + "%'"


def run_query(sql: str):
    conn = _connect()
    cursor = conn.cursor()
    # SINK: string-formatted execute. taint-audit flags this only when the
    # first arg is non-literal.
    cursor.execute(sql)
    return cursor.fetchall()


def run_search(q: str):
    sql = build_query(q)
    return run_query(sql)
