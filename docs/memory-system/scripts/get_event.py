#!/usr/bin/env python3
"""Resolve an event ID to full event text (citation support).

Usage:
    python get_event.py evt-001 [--project-root PATH]
    python get_event.py 1 [--project-root PATH]

Output: Full event block (heading + body) or error message.
Exit: 0 if found, 1 if not found or error.
"""

import argparse
import sys
from pathlib import Path

_SCRIPT_DIR = Path(__file__).resolve().parent
try:
    from _events_common import read_events_from_file
except ImportError:
    sys.path.insert(0, str(_SCRIPT_DIR))
    from _events_common import read_events_from_file


def get_event(project_root: Path, evt_id: str) -> str | None:
    """Return full raw text for evt_id (e.g. evt-001 or 1), or None if not found."""
    evt_id = evt_id.strip().lower()
    if evt_id.isdigit():
        evt_id = f"evt-{int(evt_id):03d}"
    elif not evt_id.startswith("evt-"):
        evt_id = f"evt-{evt_id}"

    changelog = project_root / "CHANGELOG.md"
    if changelog.exists():
        for ev in read_events_from_file(changelog):
            if ev.event_id.lower() == evt_id:
                return ev.raw_text

    archive = project_root / "CHANGELOG-archive.md"
    if archive.exists():
        for ev in read_events_from_file(archive):
            if ev.event_id.lower() == evt_id:
                return ev.raw_text

    return None


def main() -> None:
    parser = argparse.ArgumentParser(description="Get full event text by evt-ID (citation support)")
    parser.add_argument("evt_id", help="Event ID (e.g. evt-001 or 1)")
    parser.add_argument("--project-root", type=Path, default=Path.cwd(), help="Project root")
    args = parser.parse_args()

    project_root = args.project_root.resolve()
    text = get_event(project_root, args.evt_id)
    if text is None:
        print(f"Event {args.evt_id} not found", file=sys.stderr)
        sys.exit(1)
    print(text)
    sys.exit(0)


if __name__ == "__main__":
    main()
