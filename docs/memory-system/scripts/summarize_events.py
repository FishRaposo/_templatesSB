#!/usr/bin/env python3
"""Summarize a range of events (for context.md or archive). Rule-based; no LLM required.

Usage:
    python summarize_events.py [--start 1] [--end 20] [--project-root PATH]
    python summarize_events.py --last 10

Output: Short summary (bullet list of evt-ID and summary). Excludes sensitive events by default.
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


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--project-root", type=Path, default=Path.cwd())
    ap.add_argument("--start", type=int, default=1, help="First evt number")
    ap.add_argument("--end", type=int, default=None, help="Last evt number (inclusive)")
    ap.add_argument("--last", type=int, default=0, help="Summarize last N events (overrides start/end)")
    ap.add_argument("--exclude-sensitive", action="store_true", default=True, help="Exclude private/sensitive (default: true)")
    ap.add_argument("--include-sensitive", action="store_true", dest="exclude_sensitive", help="Include all events")
    args = ap.parse_args()

    root = args.project_root.resolve()
    events = read_all_events(root, include_archive=True)

    if args.exclude_sensitive:
        events = [e for e in events if not e.is_sensitive()]

    if args.last:
        events = events[-args.last:]
    else:
        events = [e for e in events if args.start <= e.num <= (args.end or 99999)]

    for ev in events:
        print(f"- **{ev.event_id}** ({ev.type}) {ev.scope}: {ev.summary}")
    sys.exit(0)


if __name__ == "__main__":
    main()
