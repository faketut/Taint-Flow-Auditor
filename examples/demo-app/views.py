"""Demo Flask app: request handlers (sources of untrusted input)."""

from flask import Flask, request

from db import run_search
from cmd import do_ping, do_safe_ping
from files import read_export

app = Flask(__name__)


@app.route("/search")
def search():
    q = request.args.get("q", "")
    rows = run_search(q)
    return {"rows": rows}


@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    return {"output": do_ping(host)}


@app.route("/healthy_ping")
def healthy_ping():
    # Negative case: passes through shlex.quote before reaching subprocess.
    host = request.args.get("host", "127.0.0.1")
    return {"output": do_safe_ping(host)}


@app.route("/export")
def export():
    path = request.args.get("path", "/tmp/out.txt")
    return {"content": read_export(path)}
