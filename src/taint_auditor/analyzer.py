"""Source/sink/sanitizer classifier + interprocedural BFS over Orbit's call graph.

Design (post-spike):

  * **Reachability** uses Orbit's ``Definition CALLS Definition`` edges
    directly. We do not synthesize call edges from AST.
  * **Classification** of each Definition as source / sink / sanitizer is
    done by AST-parsing just that Definition's source slice, because the
    call edges are at module granularity ("foo calls the subprocess module"),
    which is too coarse for predicates like "first arg of cursor.execute is
    not a string literal".

Source detection:
  * ``definition_type == 'DecoratedFunction'`` whose decorator dotted name
    matches the catalog (e.g. ``app.route``).
  * Any Definition whose body reads a catalog attribute chain
    (``request.args``, ``request.form``, ...).
  * Any Definition whose body calls a catalog source call (``input``,
    ``os.environ.get``, ...).

Sink detection:
  * Body calls a dotted name matching ``catalog.sink_calls``. ``cursor.execute``
    and ``connection.execute`` only fire when the first argument is a
    non-literal (the canonical SQL-injection pattern).

Sanitizer presence:
  * Body calls a dotted name in ``catalog.sanitizer_calls``. A path that
    crosses a sanitized Definition demotes the finding severity to ``low``.

Reachability:
  * BFS from each source Definition over Orbit's call edges, bounded by
    ``max_path_len``. Each (source, sink, sink_pattern, path) tuple is
    de-duplicated by a content hash.
"""

from __future__ import annotations

import ast
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Iterable

from .catalog import Catalog
from .orbit import Definition


# ----- AST helpers ------------------------------------------------------------


def _attr_chain(node: ast.AST) -> str | None:
    """Flatten ``a.b.c`` (or the func of ``a.b.c(...)``) into 'a.b.c'.

    Returns None for chains we cannot statically resolve (subscript, call in
    the middle, dynamic getattr, etc.).
    """
    parts: list[str] = []
    cur: ast.AST | None = node
    while cur is not None:
        if isinstance(cur, ast.Attribute):
            parts.append(cur.attr)
            cur = cur.value
        elif isinstance(cur, ast.Name):
            parts.append(cur.id)
            cur = None
        elif isinstance(cur, ast.Call):
            return None  # foo().bar — receiver not statically known
        else:
            return None
    return ".".join(reversed(parts))


def _decorator_name(dec: ast.expr) -> str | None:
    target = dec.func if isinstance(dec, ast.Call) else dec
    return _attr_chain(target)


def _is_literal_string(node: ast.expr) -> bool:
    return isinstance(node, ast.Constant) and isinstance(node.value, str)


# ----- Per-definition AST scan ------------------------------------------------


@dataclass
class CallSite:
    callee: str
    line: int
    non_literal_first_arg: bool


@dataclass
class DefScan:
    decorators: list[str] = field(default_factory=list)
    attribute_reads: set[str] = field(default_factory=set)
    calls: list[CallSite] = field(default_factory=list)


class _DefVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.scan = DefScan()

    def _visit_decorated(self, node: ast.AST) -> None:
        for d in getattr(node, "decorator_list", []) or []:
            name = _decorator_name(d)
            if name:
                self.scan.decorators.append(name)
        for stmt in getattr(node, "body", []) or []:
            self.visit(stmt)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:  # noqa: D401
        self._visit_decorated(node)

    visit_AsyncFunctionDef = visit_FunctionDef  # type: ignore[assignment]

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self._visit_decorated(node)

    def visit_Call(self, node: ast.Call) -> None:
        callee = _attr_chain(node.func)
        if callee:
            non_lit = bool(node.args) and not _is_literal_string(node.args[0])
            self.scan.calls.append(
                CallSite(callee=callee, line=node.lineno, non_literal_first_arg=non_lit)
            )
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        chain = _attr_chain(node)
        if chain:
            self.scan.attribute_reads.add(chain)
        self.generic_visit(node)


def scan_definition(content: str) -> DefScan:
    """AST-scan a single Definition's source slice.

    The slice often does not start at column 0 (the function may be nested or
    indented inside a class). We tolerate that by dedenting first.
    """
    if not content.strip():
        return DefScan()
    import textwrap

    source = textwrap.dedent(content)
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return DefScan()
    visitor = _DefVisitor()
    visitor.visit(tree)
    return visitor.scan


# ----- Findings ---------------------------------------------------------------


@dataclass
class Finding:
    source_def_id: int
    source_fqn: str
    sink_def_id: int
    sink_fqn: str
    sink_pattern: str
    sink_file: str
    sink_line: int
    severity: str
    path_def_ids: list[int]
    path_fqns: list[str]
    sanitized: bool
    fix_suggestion: str | None
    source_reason: str

    def dedupe_key(self) -> str:
        import hashlib
        h = hashlib.sha256()
        h.update(self.source_fqn.encode())
        h.update(b"->")
        h.update(self.sink_fqn.encode())
        h.update(b"@")
        h.update(self.sink_pattern.encode())
        h.update(b"#")
        h.update(",".join(self.path_fqns).encode())
        return h.hexdigest()[:16]


# ----- Analyzer ---------------------------------------------------------------


@dataclass
class _Node:
    defn: Definition
    scan: DefScan
    is_source: bool
    source_reason: str
    sink_hits: list[tuple[str, int]]
    has_sanitizer: bool


class Analyzer:
    """Combines Orbit data + catalog into a list of Findings."""

    def __init__(self, catalog: Catalog, *, max_path_len: int = 8) -> None:
        self.catalog = catalog
        self.max_path_len = max_path_len

    def analyze(
        self,
        definitions: Iterable[Definition],
        call_edges: Iterable[tuple[int, int]],
    ) -> list[Finding]:
        definitions = list(definitions)
        nodes: dict[int, _Node] = {
            d.id: self._classify(d) for d in definitions
        }

        edges: dict[int, set[int]] = defaultdict(set)
        for src, dst in call_edges:
            if src in nodes and dst in nodes and src != dst:
                edges[src].add(dst)

        return self._bfs(nodes, edges)

    # -- classification --------------------------------------------------------

    def _classify(self, d: Definition) -> _Node:
        scan = scan_definition(d.content)
        cat = self.catalog

        is_source = False
        source_reason = ""

        if d.definition_type == "DecoratedFunction":
            for dec in scan.decorators:
                if dec in cat.source_decorators:
                    is_source = True
                    source_reason = f"@{dec}"
                    break
                # Match suffix too: ``app.route`` should also match
                # ``api.app.route`` or similar aliased forms.
                for pat in cat.source_decorators:
                    if dec.endswith("." + pat) or dec == pat:
                        is_source = True
                        source_reason = f"@{dec}"
                        break
                if is_source:
                    break

        if not is_source:
            for attr in scan.attribute_reads:
                if attr in cat.source_attribute_reads:
                    is_source = True
                    source_reason = f"reads {attr}"
                    break
                # prefix match: ``request.args.get`` matches ``request.args``
                for pat in cat.source_attribute_reads:
                    if attr == pat or attr.startswith(pat + "."):
                        is_source = True
                        source_reason = f"reads {attr}"
                        break
                if is_source:
                    break

        if not is_source:
            for c in scan.calls:
                if c.callee in cat.source_calls:
                    is_source = True
                    source_reason = f"calls {c.callee}"
                    break

        sink_hits: list[tuple[str, int]] = []
        has_sanitizer = False
        for c in scan.calls:
            if c.callee in cat.sink_calls:
                if c.callee.endswith(".execute") and not c.non_literal_first_arg:
                    continue  # literal SQL is safe
                sink_hits.append((c.callee, c.line + d.start_line - 1))
            if c.callee in cat.sanitizer_calls:
                has_sanitizer = True

        return _Node(
            defn=d,
            scan=scan,
            is_source=is_source,
            source_reason=source_reason,
            sink_hits=sink_hits,
            has_sanitizer=has_sanitizer,
        )

    # -- BFS -------------------------------------------------------------------

    def _bfs(
        self,
        nodes: dict[int, _Node],
        edges: dict[int, set[int]],
    ) -> list[Finding]:
        findings: list[Finding] = []
        seen_keys: set[str] = set()
        sources = [n for n in nodes.values() if n.is_source]

        for src in sources:
            queue: deque[tuple[int, tuple[int, ...], bool]] = deque(
                [(src.defn.id, (src.defn.id,), src.has_sanitizer)]
            )
            best_depth: dict[int, int] = {}

            while queue:
                cur_id, path, sanitized = queue.popleft()
                cur = nodes[cur_id]

                for pattern, line in cur.sink_hits:
                    severity = self.catalog.severity_for(pattern)
                    if sanitized and severity != "low":
                        severity = "low"
                    f = Finding(
                        source_def_id=src.defn.id,
                        source_fqn=src.defn.fqn,
                        sink_def_id=cur.defn.id,
                        sink_fqn=cur.defn.fqn,
                        sink_pattern=pattern,
                        sink_file=cur.defn.file_path,
                        sink_line=line,
                        severity=severity,
                        path_def_ids=list(path),
                        path_fqns=[nodes[i].defn.fqn for i in path],
                        sanitized=sanitized,
                        fix_suggestion=self.catalog.fix_for(pattern),
                        source_reason=src.source_reason,
                    )
                    key = f.dedupe_key()
                    if key not in seen_keys:
                        seen_keys.add(key)
                        findings.append(f)

                if len(path) >= self.max_path_len:
                    continue
                prev = best_depth.get(cur_id)
                if prev is not None and prev <= len(path):
                    continue
                best_depth[cur_id] = len(path)

                for nxt in edges.get(cur_id, ()):
                    if nxt in path:
                        continue
                    queue.append(
                        (
                            nxt,
                            path + (nxt,),
                            sanitized or nodes[nxt].has_sanitizer,
                        )
                    )

        sev_rank = {"high": 0, "medium": 1, "low": 2}
        findings.sort(key=lambda f: (sev_rank.get(f.severity, 3), len(f.path_def_ids)))
        return findings
