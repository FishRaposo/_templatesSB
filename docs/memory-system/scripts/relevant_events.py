#!/usr/bin/env python3
"""Return relevant events for boot injection (compact index by scope/tag/query).

Usage:
    python relevant_events.py [QUERY] [--scope SCOPE] [--tag TAG] [--limit 5] [--project-root PATH]

Output: One line per event: evt-ID | type | scope | one-line summary. Use with get_event.py to fetch full text.
"""

import argparse
import sys
from pathlib import Path

_SCRIPT_DIR = Path(__file__).resolve().parent
try:
    from _events_common import read_all_events
except ImportError:
    sys.path.insert(0, str(_SCRIPT_DIR))
    from _events_common import read_all_events


def _matches(ev, query: str, scope: str, tag: str) -> bool:
    if query and query.lower() not in (ev.summary + " " + ev.scope + " " + ev.tags).lower():
        return False
    if scope and scope.lower() not in ev.scope.lower():
        return False
    if tag:
        tags = {t.strip().lower() for t in ev.tags.split(",")}
        if tag.lower() not in tags:
            return False
    return True


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("query", nargs="?", default="")
    ap.add_argument("--project-root", type=Path, default=Path.cwd())
    ap.add_argument("--scope", default="")
    ap.add_argument("--tag", default="")
    ap.add_argument("--limit", type=int, default=5)
    ap.add_argument("--exclude-sensitive", action="store_true", default=True)
    ap.add_argument("--include-sensitive", action="store_false", dest="exclude_sensitive")
    args = ap.parse_args()

    root = args.project_root.resolve()
    events = read_all_events(root, include_archive=False)
    if args.exclude_sensitive:
        events = [e for e in events if not e.is_sensitive()]

    out = [e for e in reversed(events) if _matches(e, args.query, args.scope, args.tag)][: args.limit]
    for ev in out:
        print(ev.one_line())
    sys.exit(0)


if __name__ == "__main__":
    main()
