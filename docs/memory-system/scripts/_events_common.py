# Shared helpers for memory system event scripts.
# Used by get_event, search_events, summarize_events, relevant_events.

from __future__ import annotations

import re
from pathlib import Path
from dataclasses import dataclass
from typing import Iterator


EVENT_HEADING_RE = re.compile(
    r'^### (evt-(\d+)) \| (\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}) \| ([^|]+) \| (\w+)\s*$',
    re.MULTILINE
)
SENSITIVE_TAGS = frozenset({"private", "sensitive"})


@dataclass
class ParsedEvent:
    event_id: str
    num: int
    date: str
    time: str
    agent: str
    type: str
    raw_text: str
    scope: str
    summary: str
    details: str
    refs: str
    tags: str

    def is_sensitive(self) -> bool:
        if not self.tags:
            return False
        tag_set = {t.strip().lower() for t in self.tags.split(",")}
        return bool(tag_set & SENSITIVE_TAGS)

    def one_line(self) -> str:
        return f"{self.event_id} | {self.type} | {self.scope} | {self.summary[:80]}"


def extract_event_sections(content: str) -> list[tuple[str, str]]:
    """Split content into (heading_line, body) for each event."""
    parts = re.split(r'^(### evt-\d+ \|[^\n]+)$', content, flags=re.MULTILINE)
    out = []
    i = 1
    while i < len(parts):
        heading = parts[i].strip()
        body = parts[i + 1] if i + 1 < len(parts) else ""
        out.append((heading, body))
        i += 2
    return out


def parse_event(event_id: str, heading: str, body: str) -> ParsedEvent | None:
    m = EVENT_HEADING_RE.match(heading)
    if not m:
        return None
    full_id, num, date, time, agent, typ = m.groups()
    raw = heading + "\n" + body

    scope = _extract_field(body, "Scope")
    summary = _extract_field(body, "Summary")
    details = _extract_field(body, "Details")
    refs = _extract_field(body, "Refs")
    tags = _extract_field(body, "Tags")

    return ParsedEvent(
        event_id=full_id,
        num=int(num),
        date=date,
        time=time,
        agent=agent.strip(),
        type=typ,
        raw_text=raw.strip(),
        scope=scope or "",
        summary=summary or "",
        details=details or "",
        refs=refs or "",
        tags=tags or "",
    )


def _extract_field(body: str, name: str) -> str:
    pat = re.compile(
        r"\*\*" + re.escape(name) + r"\*\*:\s*(.*?)(?=\n\s*\*\*|\n\n|\Z)",
        re.DOTALL
    )
    m = pat.search(body)
    if not m:
        return ""
    return m.group(1).strip()


def read_events_from_file(path: Path) -> Iterator[ParsedEvent]:
    """Yield parsed events from a CHANGELOG-style file (Event Log section only)."""
    text = path.read_text(encoding="utf-8")
    if "## Event Log" not in text:
        return
    log_section = text.split("## Event Log")[-1]
    for heading, body in extract_event_sections(log_section):
        ev = parse_event("", heading, body)
        if ev:
            yield ev


def read_all_events(
    project_root: Path, include_archive: bool = True
) -> list[ParsedEvent]:
    """Read events from CHANGELOG.md and optionally CHANGELOG-archive.md. Order: by evt num."""
    events = []
    changelog = project_root / "CHANGELOG.md"
    if changelog.exists():
        for ev in read_events_from_file(changelog):
            events.append(ev)
    if include_archive:
        archive = project_root / "CHANGELOG-archive.md"
        if archive.exists():
            for ev in read_events_from_file(archive):
                events.append(ev)
    events.sort(key=lambda e: e.num)
    return events
