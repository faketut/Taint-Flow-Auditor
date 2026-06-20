# Demo: vulnerable Flask app

A deliberately vulnerable mini-app used to demonstrate Taint-Flow Auditor.

Three planted flows the auditor must find:

1. **SQL injection** — `views.search` → `db.build_query` → `db.run_query` →
   `cursor.execute` with string-formatted SQL.
2. **Command injection** — `views.ping` → `cmd.do_ping` → `subprocess.run` with
   `shell=True` and an interpolated host.
3. **Path traversal** — `views.export` → `files.read_export` → `open(path)`.

Two **negative cases** the auditor must *not* flag:

- `views.healthy_ping` → `cmd.do_safe_ping` — sanitized via `shlex.quote`.
- `cli.dump_table` → `db.run_query` — reachable in the graph, but `cli.dump_table`
  is invoked from `if __name__ == "__main__":` with `sys.argv` whitelisted via
  an allow-list (decoy, demonstrates non-source paths).

Run:

```bash
orbit index .
taint-audit scan . --pretty
```
