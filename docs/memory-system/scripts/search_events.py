#!/usr/bin/env python3
"""Search event log with optional timeline and privacy filter.

Usage:
    python search_events.py [QUERY] [--type TYPE] [--scope SCOPE] [--tag TAG] [--limit N]
    python search_events.py --timeline evt-005 [--context 3]
    python search_events.py --list-ids

Options:
    --exclude-sensitive   Exclude events with Tags 'private' or 'sensitive'
    --include-archive     Search CHANGELOG-archive.md too
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


def _matches(ev, query: str, type_f: str, scope_f: str, tag_f: str) -> bool:
    if query:
        q = query.lower()
        if q not in ev.summary.lower() and q not in ev.scope.lower() and q not in ev.tags.lower() and q not in ev.details.lower():
            return False
    if type_f and ev.type != type_f:
        return False
    if scope_f and scope_f.lower() not in ev.scope.lower():
        return False
    if tag_f:
        tags = {t.strip().lower() for t in ev.tags.split(",")}
        if tag_f.lower() not in tags:
            return False
    return True


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("query", nargs="?", default="")
    ap.add_argument("--project-root", type=Path, default=Path.cwd())
    ap.add_argument("--type", dest="type_filter", default="")
    ap.add_argument("--scope", dest="scope_filter", default="")
    ap.add_argument("--tag", dest="tag_filter", default="")
    ap.add_argument("--limit", type=int, default=50)
    ap.add_argument("--exclude-sensitive", action="store_true")
    ap.add_argument("--include-archive", action="store_true")
    ap.add_argument("--timeline", metavar="evt-ID", dest="timeline_id", default="")
    ap.add_argument("--context", type=int, default=3)
    ap.add_argument("--list-ids", action="store_true")
    args = ap.parse_args()

    root = args.project_root.resolve()
    events = read_all_events(root, include_archive=args.include_archive or bool(args.timeline_id))

    if args.list_ids:
        for ev in events:
            if args.exclude_sensitive and ev.is_sensitive():
                continue
            print(ev.event_id)
        sys.exit(0)

    if args.timeline_id:
        num = int(args.timeline_id.replace("evt-", "")) if args.timeline_id.startswith("evt-") else int(args.timeline_id)
        idx = next((i for i, e in enumerate(events) if e.num == num), None)
        if idx is None:
            print(f"Event {args.timeline_id} not found", file=sys.stderr)
            sys.exit(1)
        start = max(0, idx - args.context)
        end = min(len(events), idx + args.context + 1)
        for ev in events[start:end]:
            if args.exclude_sensitive and ev.is_sensitive():
                print(f"{ev.event_id} | (redacted)")
            else:
                print(ev.raw_text)
            print("---")
        sys.exit(0)

    out = []
    for ev in events:
        if args.exclude_sensitive and ev.is_sensitive():
            continue
        if _matches(ev, args.query, args.type_filter, args.scope_filter, args.tag_filter):
            out.append(ev)
            if len(out) >= args.limit:
                break
    for ev in out:
        print(ev.one_line())
    sys.exit(0)


if __name__ == "__main__":
    main()
