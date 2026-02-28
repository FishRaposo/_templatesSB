#!/usr/bin/env python3
"""Generate a static HTML viewer for the memory system (events, graph, context).

Usage:
    python generate_memory_viewer.py [--project-root PATH] [--output PATH]

Output: Single HTML file with event log, graph, and context; evt-IDs link to anchors.
"""

import argparse
import html
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
    ap.add_argument("--output", type=Path, default=None, help="Output HTML path (default: .memory/memory-viewer.html)")
    args = ap.parse_args()

    root = args.project_root.resolve()
    out_path = args.output or (root / ".memory" / "memory-viewer.html")
    out_path.parent.mkdir(parents=True, exist_ok=True)

    events = read_all_events(root, include_archive=True)
    events = [e for e in events if not e.is_sensitive()]

    graph_path = root / ".memory" / "graph.md"
    context_path = root / ".memory" / "context.md"

    graph_html = ""
    if graph_path.exists():
        graph_html = "<pre>" + html.escape(graph_path.read_text(encoding="utf-8")) + "</pre>"

    context_html = ""
    if context_path.exists():
        context_html = "<pre>" + html.escape(context_path.read_text(encoding="utf-8")) + "</pre>"

    events_html = ""
    for ev in events:
        events_html += f'<div id="{ev.event_id}" class="event"><pre>' + html.escape(ev.raw_text) + "</pre></div>\n"

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Memory System Viewer</title>
<style>
body {{ font-family: system-ui, sans-serif; max-width: 900px; margin: 1rem auto; padding: 0 1rem; }}
h1 {{ font-size: 1.25rem; }}
h2 {{ font-size: 1rem; margin-top: 1.5rem; }}
.event {{ margin: 1rem 0; padding: 0.5rem; border-left: 3px solid #ccc; }}
pre {{ white-space: pre-wrap; font-size: 0.875rem; }}
a {{ color: #06c; }}
nav {{ margin: 1rem 0; }}
</style>
</head>
<body>
<h1>Memory System Viewer</h1>
<nav><a href="#events">Event Log</a> | <a href="#graph">Graph</a> | <a href="#context">Context</a></nav>

<h2 id="events">Event Log</h2>
{events_html or "<p>No events.</p>"}

<h2 id="graph">Graph</h2>
{graph_html or "<p>No graph.md</p>"}

<h2 id="context">Context</h2>
{context_html or "<p>No context.md</p>"}
</body>
</html>
"""
    out_path.write_text(html_content, encoding="utf-8")
    print(f"Wrote {out_path}")
    sys.exit(0)


if __name__ == "__main__":
    main()
