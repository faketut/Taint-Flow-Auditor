"""Demo: filesystem read — planted path-traversal sink."""


def read_export(path: str) -> str:
    # SINK: open() with untrusted path.
    with open(path, "r", encoding="utf-8") as fh:
        return fh.read()
