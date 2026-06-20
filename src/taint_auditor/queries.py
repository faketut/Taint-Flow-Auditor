"""SQL the analyzer issues against the Orbit Local DuckDB graph.

Schema confirmed against orbit 0.78.0 by running ``orbit schema`` on a real
index. Tables and notable columns:

    _orbit_manifest        repo_path, project_id, branch, commit_sha, status
    gl_directory           id, project_id, path, name
    gl_file                id, project_id, path, name, extension, language
    gl_definition          id, project_id, file_path, fqn, name,
                           definition_type, start_line, end_line,
                           start_byte, end_byte
    gl_imported_symbol     id, project_id, file_path, import_type,
                           import_path, identifier_name, identifier_alias

All edges are stored in one table keyed by (source_kind, target_kind,
relationship_kind):

    gl_edge   source_id, source_kind, relationship_kind,
              target_id, target_kind

Observed relationship_kinds:

    Directory  CONTAINS  Directory | File
    File       DEFINES   Definition
    File       IMPORTS   ImportedSymbol
    Definition CALLS     Definition | ImportedSymbol
    File       CALLS     Definition | ImportedSymbol

The auditor uses two slices of this graph:
    1. Definition CALLS Definition  -> interprocedural reachability
    2. The Definitions themselves   -> AST'd for source/sink/sanitizer matches
"""

T_DEFINITION = "gl_definition"
T_FILE = "gl_file"
T_DIRECTORY = "gl_directory"
T_IMPORTED_SYMBOL = "gl_imported_symbol"
T_EDGE = "gl_edge"
T_MANIFEST = "_orbit_manifest"


Q_LIST_TABLES = """
SELECT table_name
FROM information_schema.tables
WHERE table_schema = 'main'
ORDER BY table_name
"""

# Python Definitions whose absolute path on disk is under ``?`` (or all of them
# if the param is NULL). We compute the abs path as ``repo_path || '/' ||
# file_path`` because Orbit stores file_path repo-relative.
Q_PYTHON_DEFINITIONS = f"""
SELECT d.id,
       m.repo_path,
       d.file_path,
       d.fqn,
       d.name,
       d.definition_type,
       d.start_line,
       d.end_line
FROM {T_DEFINITION} d
JOIN {T_FILE} f
       ON f.project_id = d.project_id
      AND f.path       = d.file_path
JOIN {T_MANIFEST} m
       ON m.project_id = d.project_id
WHERE lower(f.language) = 'python'
  AND m.status = 'indexed'
  AND (? IS NULL OR (m.repo_path || '/' || d.file_path) LIKE ? || '%')
"""

# Inter-procedural call graph: (caller_def_id, callee_def_id). Scoped to a
# path prefix the same way as Q_PYTHON_DEFINITIONS so the two slices agree.
Q_CALL_EDGES_DEF_DEF = f"""
SELECT e.source_id, e.target_id
FROM {T_EDGE} e
JOIN {T_DEFINITION} d ON d.id = e.source_id
JOIN {T_MANIFEST}   m ON m.project_id = d.project_id
WHERE e.relationship_kind = 'CALLS'
  AND e.source_kind = 'Definition'
  AND e.target_kind = 'Definition'
  AND m.status = 'indexed'
  AND (? IS NULL OR (m.repo_path || '/' || d.file_path) LIKE ? || '%')
"""
