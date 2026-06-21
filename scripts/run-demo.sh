#!/usr/bin/env bash
# Beats 1-4 of the demo. Prints big banners, runs each command with brief
# pauses so the result is editable in CapCut. No voiceover; rhythm doesn't
# matter — every beat ends with a 1.5s pause so you can cut on the boundary.
set -e

REPO="${REPO:-/Users/fenjian/code/uw/hackthon/gitlab}"
cd "$REPO"

# Style helpers
banner() {
  printf '\n\033[1;36m================================================================\n'
  printf '== %s\n' "$1"
  printf '================================================================\033[0m\n\n'
  sleep 1.0
}
say() {
  printf '\033[1;33m# %s\033[0m\n' "$1"
  sleep 0.6
}
run() {
  printf '\033[1;32m$\033[0m %s\n' "$*"
  sleep 0.4
  eval "$@"
  sleep 1.0
}

# Activate venv so taint-audit is in PATH
# shellcheck disable=SC1091
source .venv/bin/activate

clear

# ---------- BEAT 1 — title (5s of static text) ----------
banner "Taint-Flow Auditor"
cat <<'TITLE'
   Interprocedural taint reachability auditor
   GitLab Transcend Hackathon · Showcase Track
   Powered by GitLab Orbit Local

TITLE
sleep 4

# ---------- BEAT 2 — the graph behind the bug ----------
banner "Beat 2 — three files, one bug, three function hops"
cd examples/demo-app

say "Flask route: reads request.args, calls run_search"
run "cat views.py"

say "run_search: builds SQL by string concat, calls run_query"
say "run_query: cursor.execute(sql)  ← the actual sink"
run "cat db.py"

# ---------- BEAT 3 — first run ----------
banner "Beat 3 — index with Orbit, scan with taint-audit"

say "Orbit only indexes directories that look like git repos."
say "demo-app ships nested in the parent repo, so we init one here."
run "git init -q && git add -A && git -c user.email=demo@local -c user.name=demo commit -q -m demo"

say "Wipe any previous Orbit graph for a clean indexer animation"
run "rm -rf ~/.orbit/graph.duckdb"

say "Index ~6 files in <1s, then walk the call graph"
run "orbit index ."

run "taint-audit scan . --pretty"

# ---------- BEAT 4 — decoy, sanitised path, self-scan ----------
banner "Beat 4 — proof this isn't pattern matching"

say "(1) The LOW finding above crosses shlex.quote — demoted, not dropped"
run "sed -n '15,25p' cmd.py"

say "(2) cli.dump_table calls run_query too — but it's not a source."
say "    Look at the scan output above: no finding for cli.dump_table."
run "cat cli.py"

say "(3) Now scan the AUDITOR ITSELF — zero exemptions"
run "cd $REPO && rm -rf ~/.orbit/graph.duckdb && orbit index . >/dev/null 2>&1"
run "taint-audit scan . --pretty"

say "That MEDIUM is the scanner's own httpx.post in gitlab_post.py."
say "Honest tools are trustworthy tools."
run "sed -n '60,80p' src/taint_auditor/gitlab_post.py"

banner "End of recorded section — Beats 5/6 are browser + slide"
sleep 3

# Clean up nested git so workspace doesn't drift
rm -rf "$REPO/examples/demo-app/.git"
