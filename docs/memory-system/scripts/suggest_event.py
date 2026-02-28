#!/usr/bin/env python3
"""Suggest draft event(s) from git diff or stdin for approval before appending to CHANGELOG.

Usage:
    python suggest_event.py --from-git [--project-root PATH]
    python suggest_event.py --from-stdin  # read summary from stdin
    echo "Fixed auth bug" | python suggest_event.py --from-stdin --scope auth

Output: Draft event block(s) in Event Log format. Review and paste into CHANGELOG ## Event Log.
"""

import argparse
import subprocess
import sys
from pathlib import Path
from datetime import datetime

_SCRIPT_DIR = Path(__file__).resolve().parent
try:
    from _events_common import read_events_from_file
except ImportError:
    sys.path.insert(0, str(_SCRIPT_DIR))
    from _events_common import read_events_from_file


def next_evt_id(project_root: Path) -> int:
    changelog = project_root / "CHANGELOG.md"
    if not changelog.exists():
        return 1
    max_num = 0
    for ev in read_events_from_file(changelog):
        max_num = max(max_num, ev.num)
    archive = project_root / "CHANGELOG-archive.md"
    if archive.exists():
        for ev in read_events_from_file(archive):
            max_num = max(max_num, ev.num)
    return max_num + 1


def draft_event(
    evt_num: int,
    summary: str,
    scope: str = "project",
    event_type: str = "modify",
    agent: str = "human",
    details: list[str] | None = None,
    refs: str = "none",
    tags: str = "",
) -> str:
    now = datetime.now()
    ts = now.strftime("%Y-%m-%d %H:%M")
    detail_lines = "\n".join(f"- {d}" for d in (details or []))
    return f"""### evt-{evt_num:03d} | {ts} | {agent} | {event_type}

**Scope**: {scope}
**Summary**: {summary}

**Details**:
{detail_lines or "- (add key: value)"}

**Refs**: {refs}
**Tags**: {tags}
"""


def main() -> None:
    ap = argparse.ArgumentParser(description="Suggest draft event(s) for CHANGELOG Event Log")
    ap.add_argument("--project-root", type=Path, default=Path.cwd())
    ap.add_argument("--from-git", action="store_true", help="Use git diff --stat since last event or HEAD~1")
    ap.add_argument("--from-stdin", action="store_true", help="Use stdin as summary line")
    ap.add_argument("--scope", default="project", help="Scope for drafted event")
    ap.add_argument("--type", dest="event_type", default="modify", help="Event type (default: modify)")
    ap.add_argument("--agent", default="human")
    ap.add_argument("--tags", default="")
    args = ap.parse_args()

    root = args.project_root.resolve()
    nxt = next_evt_id(root)

    if args.from_stdin:
        summary = sys.stdin.read().strip() or "Session activity"
        print(draft_event(nxt, summary, scope=args.scope, event_type=args.event_type, agent=args.agent, tags=args.tags))
        sys.exit(0)

    if args.from_git:
        try:
            r = subprocess.run(
                ["git", "diff", "--stat", "HEAD~1"],
                capture_output=True,
                text=True,
                cwd=root,
                timeout=5,
            )
            diff_stat = (r.stdout or "").strip()
        except Exception:
            diff_stat = "(git diff failed)"
        summary = "Session changes (git diff since last commit)"
        details = [f"diff_stat: {len(diff_stat)} chars"]
        if diff_stat:
            details.append("Files changed: " + ", ".join(line.split()[-1] for line in diff_stat.split("\n")[-10:] if line.strip()))
        print(draft_event(nxt, summary, scope=args.scope, event_type=args.event_type, agent=args.agent, details=details, tags=args.tags or "session,draft"))
        sys.exit(0)

    print("Use --from-git or --from-stdin", file=sys.stderr)
    sys.exit(1)


if __name__ == "__main__":
    main()
