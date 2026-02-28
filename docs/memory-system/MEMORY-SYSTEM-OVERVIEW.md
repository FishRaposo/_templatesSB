# Memory System — Full Overview

**Event-sourced multi-agent cognition for AI development.** This document gives a single, end-to-end picture of how the memory system works: layers, files, events, agent lifecycle, retrieval tools, and operations.

---

## 1. What It Is and Why

The memory system turns AI agents into **stateless workers** that share one source of truth: an **append-only event log** plus **derived views** (knowledge graph, narrative). Agents do not “remember”; they **read files** at boot, execute, **append** results, and terminate. No runtime, no database — just markdown and git.

**Design principles:**

| Principle | Meaning |
|-----------|--------|
| **Memory is infrastructure** | Agents read and write files; no in-process state between sessions |
| **Append-only truth** | If it’s not in the event log, it didn’t happen |
| **One-way data flow** | Event Log → Graph → Narrative; never edit upstream to “fix” downstream |
| **Stateless agents** | Boot from files, execute, write, die |
| **Git is the database** | Commits are transactions; history is immutable |
| **Pure markdown** | All layers are human- and machine-readable markdown |

---

## 2. The Four Layers

Four layers separate **behavior**, **history**, **structure**, and **trajectory**:

```
┌─────────────────────────────────────────────────────────┐
│  Layer 3: NARRATIVE (.memory/context.md)                 │
│  "What matters right now" — derived from L1 + L2         │
│  Ephemeral. Regenerate when stale.                       │
├─────────────────────────────────────────────────────────┤
│  Layer 2: KNOWLEDGE GRAPH (.memory/graph.md)            │
│  Entities, relations, states — materialized from L1    │
│  Queryable. Update only by materializing new events.     │
├─────────────────────────────────────────────────────────┤
│  Layer 1: EVENT LOG (CHANGELOG.md)                      │
│  Source of truth — every decision, change, result        │
│  Append-only. Immutable once committed.                  │
├─────────────────────────────────────────────────────────┤
│  Layer 0: BEHAVIORAL CORE (AGENTS.md)                   │
│  Constitution — rules, constraints, Three Pillars       │
│  Immutable during execution. Read at boot only.         │
└─────────────────────────────────────────────────────────┘
```

| Layer | File | Role | Rule |
|-------|------|------|------|
| **L0** | `AGENTS.md` | Behavioral core | Read at boot; never change during execution |
| **L1** | `CHANGELOG.md` (root) | Event log | Append-only; `## Event Log` + `### evt-NNN` events |
| **L2** | `.memory/graph.md` | Knowledge graph | Materialize from L1 only; never edit by hand |
| **L3** | `.memory/context.md` | Narrative | Regenerate from L1 + L2 when stale |

**Trust order when things conflict:** L0 > L1 > L2 > L3. Always fix by regenerating downstream from the event log, never by editing the log or the graph to match the narrative.

---

## 3. File Layout

**In the project:**

```
project/
├── AGENTS.md              ← Layer 0: rules, constraints (read at boot)
├── CHANGELOG.md           ← Layer 1: event log (append under ## Event Log)
├── TODO.md                ← Optional (Full tier): task tracker
└── .memory/
    ├── graph.md           ← Layer 2: nodes + edges (Full tier)
    └── context.md         ← Layer 3: current trajectory (Core/Full tier)
```

- **CHANGELOG.md** has a top section (e.g. “What’s new”) and a dedicated **## Event Log** section. All events live under Event Log as `### evt-NNN | ...`.
- **.memory/** must be tracked by git (not gitignored). Both `graph.md` and `context.md` are derived; they can be recreated from the event log.

---

## 4. Events: Format and Types

Each event is one markdown block under **## Event Log** in `CHANGELOG.md`.

**Heading format:**

```text
### evt-NNN | YYYY-MM-DD HH:MM | agent-name | type
```

**Body fields:**

- **Scope** — Area affected (e.g. module, path, system).
- **Summary** — One-line description (must stand alone).
- **Details** — Optional bullet list (key-value or narrative).
- **Refs** — Related event IDs (e.g. `evt-001, evt-003`) or `none`.
- **Tags** — Comma-separated labels (e.g. `memory-system, skill`). Tags `private` or `sensitive` trigger privacy filtering in scripts.

**Event types** (examples): `decision`, `create`, `modify`, `delete`, `test`, `fix`, `dependency`, `blocker`, `milestone`, `escalation`, `handoff`. Each type can drive how the graph is updated (e.g. `create` → new node, `blocker` → new edge).

**Rules:**

- Only **append**; never edit or delete existing events.
- One event per logical action.
- Sequential IDs (`evt-001`, `evt-002`, …).
- Timestamps should reflect when the thing happened.

---

## 5. How Agents Use the Memory System

### Boot (load memory)

Every agent, every session:

1. **Read** `AGENTS.md` — behavioral constraints.
2. **Read** `.memory/context.md` — current trajectory. If missing, create it from `CHANGELOG.md` (and `.memory/graph.md` if present) per the protocol.
3. **Check staleness:** In `context.md`, find the `Event horizon` comment (e.g. `Event horizon: evt-004`). In `CHANGELOG.md`, find the last event under `## Event Log`. If they **differ** or context is missing, **regenerate** `.memory/context.md` (and `.memory/graph.md` if used) from the event log before doing work.
4. **Optional:** If `docs/memory-system/scripts/relevant_events.py` (or `memory-system/scripts/relevant_events.py`) exists, run it for a compact recent-events index to inject at session start.

Rule files (AGENTS.md, CLAUDE.md, CURSOR.md, WINDSURF.md) spell out this sequence so all agents load memory the same way.

### Execute

- Work within the constraints from AGENTS.md and context.
- **Only append** to the event log; do not edit existing events or the graph by hand.

### Shutdown (after every task)

1. **Append** a new event to `CHANGELOG.md` under `## Event Log` (next `evt-NNN`).
2. **Update** derived views: materialize new events into `.memory/graph.md`, then regenerate `.memory/context.md`.
3. **Commit** all changes in one commit.
4. If conventions changed, update AGENTS.md (and other rule files as needed).

---

## 6. Staleness and Regeneration

- **context.md** includes a comment like `Event horizon: evt-NNN`. It must match the **last event ID** in `CHANGELOG.md` under `## Event Log`.
- **If they match** — context is fresh; use it as is.
- **If they differ or context is missing** — context is stale; regenerate it from the event log (and graph) before proceeding. Regenerate the graph first if you added events that change nodes/edges.

Never “patch” the narrative or graph to match a desired story; always regenerate from Layer 1.

---

## 7. Retrieval and Tools

Optional scripts (in `docs/memory-system/scripts/` or project-local `memory-system/scripts/`) support resolve, search, timeline, summarize, suggest, boot index, and a static viewer. Run from project root; use `--project-root PATH` if needed.

| Tool | Purpose |
|------|--------|
| **get_event.py** `evt-NNN` or `1` | Return full event text from CHANGELOG (or CHANGELOG-archive). Numeric `1` is normalized to `evt-001`. |
| **search_events.py** `[QUERY]` `--type` `--scope` `--tag` | Keyword search; compact index. `--timeline evt-NNN --context N` for surrounding events; `--list-ids` for IDs only. |
| **relevant_events.py** `[QUERY]` `--scope` `--tag` `--limit N` | Compact one-line-per-event index for session boot (default limit 5). |
| **summarize_events.py** `--last N` or `--start` / `--end` | Bullet list of events in a range (rule-based). |
| **suggest_event.py** `--from-git` or `--from-stdin` | Draft one event for approval; does not append. Paste into CHANGELOG after review. |
| **generate_memory_viewer.py** `[--output .memory/memory-viewer.html]` | Single HTML file: Event Log (with evt-ID anchors), graph, context. |

**Progressive disclosure:** Use **search** (compact index) → **timeline** (context around an ID) → **get_event** (full text) to keep token use low.

**Privacy:** Events whose **Tags** include `private` or `sensitive` are excluded (or omitted from the viewer) by default in these tools. Use `--include-sensitive` where supported to include them. The log itself is unchanged; filtering is at retrieval only.

---

## 8. Archival

When the event log grows large (e.g. >50 events), older events can be **moved** (not deleted) to `CHANGELOG-archive.md`:

- Keep a clear boundary (e.g. last N events + events referenced by the graph stay in CHANGELOG).
- Prefix archived blocks with something like `## Archive: evt-001 through evt-NNN | Archived YYYY-MM-DD`.
- Append an `archive` event to the main CHANGELOG recording the move.
- **get_event** and **search_events** can read from the archive when `--include-archive` is used. Archived events remain valid refs.

---

## 9. Tiers

Not every project needs all four layers:

| Tier | Use case | Files |
|------|----------|--------|
| **MVP** | Solo, short-lived, prototype | `CHANGELOG.md` only |
| **Core** | Team or multi-agent, 1–6 months | `CHANGELOG.md` + `.memory/context.md` |
| **Full** | Long-lived, complex deps, “what blocks what?” | `CHANGELOG.md` + `TODO.md` + `.memory/graph.md` + `.memory/context.md` |

Agents still boot the same way: read AGENTS.md, read context (if present), check staleness, then execute. Graph and context are optional by tier.

---

## 10. Data Flow and Anti-Drift

**One-way flow:**

```text
Agent action → append to CHANGELOG.md (Event Log)
            → materialize new events into graph.md
            → regenerate context.md from event log + graph
```

Agents must **not**:

- Edit the graph to “fix” the changelog (append a corrective event instead).
- Edit the narrative to change the graph (append, then rematerialize and regenerate).
- Edit past events in the event log.

**When in doubt:** Treat the event log as truth; rebuild graph and context from it.

---

## 11. Where to Go Next

| Need | Where to look |
|------|----------------|
| **Full protocol** (validation, handoffs, ACID, multi-agent) | `docs/protocols/MEMORY-SYSTEM-PROTOCOL.md` |
| **Setup in a new project** | Memory System Setup skill (`.agents/skills/memory-system-setup/SKILL.md` or global Cursor skill **memory-system-setup**) |
| **Scripts and retrieval** | `docs/memory-system/README.md` (Retrieval and Tools); protocol §15 |
| **Event format and graph materialization** | `docs/memory-system/README.md`; skill’s `event-format-and-types.md` |
| **AGENTS.md integration** | Skill’s `agents-integration-snippet.md` (paste into AGENTS.md; includes load-memory and staleness check) |

---

*This overview summarizes the memory system as used in this repository. For normative rules and validation, see `docs/protocols/MEMORY-SYSTEM-PROTOCOL.md`.*
