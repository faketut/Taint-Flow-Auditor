"""Demo: command helpers — one vulnerable, one sanitized."""

import shlex
import subprocess


def do_ping(host: str) -> str:
    # VULN: shell=True with interpolated input.
    result = subprocess.run(
        f"ping -c 1 {host}",
        shell=True,
        capture_output=True,
        text=True,
    )
    return result.stdout


def do_safe_ping(host: str) -> str:
    # Negative case: sanitised via shlex.quote -> taint-audit demotes severity.
    safe = shlex.quote(host)
    result = subprocess.run(
        f"ping -c 1 {safe}",
        shell=True,
        capture_output=True,
        text=True,
    )
    return result.stdout
