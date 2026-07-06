"""Command line entrypoint for Ops Pulse."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import TextIO

from ops_pulse.reporting import render_incident_digest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="ops-pulse")
    parser.add_argument("events_file", help="Path to a JSON file containing events")
    args = parser.parse_args(argv)
    return render_file(args.events_file, stdout=sys.stdout, stderr=sys.stderr)


def render_file(path: str, *, stdout: TextIO, stderr: TextIO) -> int:
    """Render ``path`` to stdout and return a process exit code."""

    try:
        raw = Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        print(f"ops-pulse: cannot read {path}: {exc}", file=stderr)
        return 2

    try:
        events = json.loads(raw)
    except json.JSONDecodeError as exc:
        print(f"ops-pulse: invalid JSON in {path}: {exc.msg}", file=stderr)
        return 2

    if not isinstance(events, list):
        print(f"ops-pulse: {path} must contain a JSON array of events", file=stderr)
        return 2

    stdout.write(render_incident_digest(events))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
