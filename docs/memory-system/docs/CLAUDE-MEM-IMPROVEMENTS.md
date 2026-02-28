# Using Claude-Mem–Style Features to Improve This Memory System

This note maps [claude-mem](https://github.com/thedotmack/claude-mem) features to **concrete improvements** for our event-sourced, markdown-based memory system. The goal is to keep our protocol (CHANGELOG as source of truth, .memory/graph, .memory/context, git as database) while adding optional capabilities inspired by claude-mem.

---

## 1. Automatic or semi-automatic event capture

**Claude-mem:** Captures tool use and session activity via lifecycle hooks; no manual logging.

**Our system today:** Events are appended only when an agent or human explicitly writes to the Event Log.

**Improvement — “Event suggester”:**

- Add a **post-session script or hook** (e.g. after a Cursor/Claude session, or on a timer) that:
  - Consumes recent activity (e.g. git diff since last event, or last N lines of a transcript),
  - Calls an LLM or simple rules to **draft** one or more candidate events (evt-NNN blocks with Scope, Summary, Details, type),
  - Outputs them for **human or agent approval** before appending to CHANGELOG.
- Events remain **append-only and deliberate**; the tool only *suggests*, it does not write.
- **Optional:** A Cursor/Claude rule or skill: “At end of task, suggest an event for CHANGELOG from what we did” and paste the block into the Event Log after approval.

**Result:** Fewer missed events; less manual drafting; protocol unchanged.

**Implementation:** `docs/memory-system/scripts/suggest_event.py` — `--from-git` (draft from git diff) or `--from-stdin` (summary from stdin); outputs next evt-ID and event block for manual append. See protocol §15 and `docs/memory-system/README.md` (Retrieval and Tools).

---

## 2. AI summarization of events

**Claude-mem:** Compresses raw observations into semantic summaries with an AI model.

**Our system today:** Events are human/agent-authored; context.md is filled by rules (last 20 events, graph nodes, etc.) or by hand.

**Improvement — “Summarize event ranges”:**

- **Option A — Enrich context.md:** A script (or scheduled job) reads the last N events from CHANGELOG, calls an LLM to produce a short “Session summary” or “Recent narrative” paragraph, and appends it to a dedicated section in .memory/context.md (or a separate .memory/summaries.md). Regenerate that section when the event horizon advances.
- **Option B — On-demand summaries:** When regenerating context.md, optionally call an API to turn “last 20 events” into 3–5 bullet points for “Recent Changes” instead of raw event list. Keeps context.md as the single “what matters now” view but makes it denser.
- **Option C — Archive summaries:** When archiving old events to CHANGELOG-archive.md, generate a short summary of the archived range (e.g. “evt-001–evt-050: initial setup, memory-system-setup skill, three skills established”) and store it in a Meta section or a separate index file. Helps “what happened in that era?” without reading every event.

**Result:** Faster scanning and better use of context window; event log stays the source of truth.

**Implementation:** `docs/memory-system/scripts/summarize_events.py` — rule-based bullet list for event range (`--last N`, `--start`/`--end`); supports `--exclude-sensitive` (default). See protocol §15 and memory-system README (Retrieval and Tools). LLM-based enrichment (Options A/B) not implemented.

---

## 3. Search over the event log and graph

**Claude-mem:** Hybrid (keyword + vector) search; MCP tools `search`, `timeline`, `get_observations`; progressive disclosure (index → timeline → full fetch) to save tokens.

**Our system today:** Retrieval = reading .memory/context.md, .memory/graph.md, and CHANGELOG.md in full (or grep).

**Improvement — “Search and progressive disclosure”:**

- **Layer 1 — Keyword search (no new deps):** A small script (or MCP server) that:
  - Parses the Event Log section of CHANGELOG.md into events (evt-ID, type, scope, summary, tags),
  - Accepts queries (e.g. by type, scope, tag, or free-text grep on Summary/Details),
  - Returns a **compact index**: list of (evt-ID, type, scope, one-line summary). ~50–100 tokens per result.
- **Layer 2 — Timeline:** Same tool can return “events around evt-NNN” (e.g. N before, N after) for chronological context.
- **Layer 3 — Get full event:** Given evt-NNN, return the full event text (or file:line reference). Agents only fetch full content for selected IDs.
- **Optional — Semantic search:** Index event summaries (and optionally graph node names) in a local vector store (e.g. Chroma, or embeddings script). Expose a “semantic search” that returns evt-IDs + snippet; then use “get full event” for details. Same 3-step pattern (search → timeline → get full) as claude-mem, but over our event log and graph.

**Result:** Token-efficient retrieval; “find what we decided about X” without loading the whole CHANGELOG; optional MCP tools for Cursor/Claude.

**Implementation:** `docs/memory-system/scripts/search_events.py` (keyword search, `--type`/`--scope`/`--tag`, free-text query, `--timeline evt-NNN --context N`, `--list-ids`) and `get_event.py` (resolve evt-ID to full text from CHANGELOG or archive). Progressive disclosure: search → timeline → get_event. See protocol §15 and memory-system README. Semantic search (vector store) not implemented.

---

## 4. Context injection at session start

**Claude-mem:** Injects relevant past context into new sessions automatically.

**Our system today:** Agents read context.md at boot and check staleness (event horizon vs last event); they may read graph.md. No search-driven injection.

**Improvement — “Relevant past events” at boot:**

- **Staleness + regeneration:** Keep current rule: if context.md’s event horizon ≠ last event in CHANGELOG, regenerate context. Optionally, the regeneration script can call an LLM to summarize recent events into “Active Mission” and “Recent Changes” (see §2).
- **Relevance:** Before or after loading context.md, run a **targeted search**:
  - e.g. “last 5 events touching scope X” (if the user’s first message mentions X), or
  - semantic search for the first user message,
  - then inject only those event IDs (or their one-line summaries) into a “Relevant past events” block. So the agent gets context.md *plus* a short, relevant slice of history.
- **Progressive:** First message could be “what’s relevant to [user query]?” → get evt-IDs → then “get full events” only for 2–3 IDs. Reduces noise and token use.

**Result:** New sessions start with “what matters now” (context.md) plus a minimal, relevant slice of the event log.

**Implementation:** `docs/memory-system/scripts/relevant_events.py` — compact one-line-per-event index by optional QUERY, `--scope`, `--tag`, `--limit` (default 5); `--exclude-sensitive` (default). For use at session start. See protocol §15 and memory-system README.

---

## 5. Citations and traceability

**Claude-mem:** Observation IDs; API to fetch by ID; citations in responses.

**Our system today:** We have **Refs** (evt-XXX) inside events; no standard way to “resolve” an evt-ID to full text or a link.

**Improvement — “Resolve evt-ID”:**

- **Script or MCP tool:** `get_event(evt-NNN)` returns the full event text from CHANGELOG (or CHANGELOG-archive), or the file path and line range. Agents and docs can say “as per evt-007” and the reader (or another agent) fetches it.
- **Convention:** In context.md and in agent answers, prefer citing by evt-ID (e.g. “see evt-007”). Link to a viewer or to the raw file.
- **Optional — Web viewer:** A simple local viewer (e.g. static HTML generator from CHANGELOG + .memory/*.md, or a tiny server on localhost) that lists events, graph, and context and turns evt-IDs into clickable links to the right section. Like claude-mem’s localhost:37777 but for our files.

**Result:** Clear audit trail; “why did we do this?” → evt-012 → full event.

**Implementation:** `docs/memory-system/scripts/get_event.py` — `get_event.py evt-NNN` or `1` (normalized to evt-001); reads CHANGELOG then CHANGELOG-archive. `generate_memory_viewer.py` — static HTML at `.memory/memory-viewer.html` with Event Log (evt-ID anchors), graph.md, context.md; sensitive events excluded. See protocol §15 and memory-system README.

---

## 6. Privacy / exclusions

**Claude-mem:** `<private>` tag to exclude content from storage.

**Our system today:** Events are deliberate, so sensitive data is only stored if someone writes it. No automatic capture of private content.

**Improvement — “Sensitive event” convention:**

- In event **Details** or **Tags**, support a marker, e.g. `sensitive: true` or `private: true`.
- Any **search, summary, or injection** script:
  - Excludes these events from results, or
  - Returns only “evt-NNN (redacted)” without Summary/Details.
- Document this in the protocol so agents and humans know not to surface private events in shared context.

**Result:** Accidental logging of secrets or private info can be filtered at retrieval time without changing the append-only log.

**Implementation:** Tags `private` or `sensitive` (case-insensitive) in event **Tags** mark an event as sensitive. `search_events.py`, `summarize_events.py`, `relevant_events.py` default to `--exclude-sensitive`; `generate_memory_viewer.py` omits sensitive events. Documented in protocol §15 (Privacy convention) and memory-system README.

---

## 7. Implementation order (suggested)

| Priority | Feature | Effort | Keeps protocol | Status |
|----------|---------|--------|----------------|--------|
| 1 | **Resolve evt-ID** (get_event script or MCP) | Low | Yes | ✅ Implemented (`get_event.py`) |
| 2 | **Keyword search** over Event Log (script or MCP: search → get_event) | Low–medium | Yes | ✅ Implemented (`search_events.py`) |
| 3 | **Event suggester** (draft event from git diff or transcript; approve then append) | Medium | Yes | ✅ Implemented (`suggest_event.py`) |
| 4 | **Summarize event ranges** for context.md or archive | Medium | Yes | ✅ Implemented (`summarize_events.py`, rule-based) |
| 5 | **Progressive disclosure** (index → timeline → full) in retrieval | Medium | Yes | ✅ Implemented (search_events + get_event) |
| 6 | **Relevant past events** at boot (search-driven injection) | Medium | Yes | ✅ Implemented (`relevant_events.py`) |
| 7 | **Semantic search** (embeddings + vector store) | Higher | Yes | Optional / not implemented |
| 8 | **Web viewer** for events/graph/context | Optional | Yes | ✅ Implemented (`generate_memory_viewer.py`) |

All of the above are **add-ons**: scripts, optional MCP server, optional viewer. The core protocol (append-only CHANGELOG, materialize graph, regenerate context, read at boot) stays unchanged and works without any of them.

---

## References

- [claude-mem](https://github.com/thedotmack/claude-mem) — Claude Code plugin for persistent memory (capture, compress, search, inject).
- `docs/protocols/MEMORY-SYSTEM-PROTOCOL.md` — This repo’s memory system protocol.
- `memory-system/` (or `docs/memory-system/`) — Scripts and templates for the 4-layer system.
