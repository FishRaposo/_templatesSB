# Memory System

Event-sourced multi-agent cognition — pure markdown implementation.

## What This Is

A 4-layer memory system that turns AI agents into stateless workers operating on shared, immutable state. No runtime, no database, no JSON — just markdown files deployed to a `.memory/` folder.

## The Four Layers

| Layer | File | Role | Rule |
|-------|------|------|------|
| **L0** | `AGENTS.md` | Behavioral Core | Immutable during execution |
| **L1** | `CHANGELOG.md` (root) | Event Log | Append-only |
| **L2** | `.memory/graph.md` | Knowledge Graph | Updated only from L1 |
| **L3** | `.memory/context.md` | Narrative | Regenerated from L1 + L2 |

## Quick Start

1. Copy `changelog.md` to your project root as `CHANGELOG.md` (Layer 1)
2. Copy `graph.md` and `context.md` into your project's `.memory/` folder
3. Your `AGENTS.md` is Layer 0 — it already exists
4. Start appending events to `CHANGELOG.md` as you work
5. Update `.memory/graph.md` when events create or change entities
6. Regenerate `.memory/context.md` when starting a new session

## Agent Lifecycle

```
BOOT:     Read AGENTS.md → Read context.md → Check staleness → Read graph.md
EXECUTE:  Work within constraints → Append events to CHANGELOG.md
SHUTDOWN: Append → Update graph → Regenerate context → Commit
```

## Core Rules

1. **Append-only** — never edit existing events in the changelog
2. **One-way flow** — changelog → graph → context; never backward
3. **Stateless agents** — boot from files, work, write results, die
4. **Rebuild, don't repair** — if derived layers are wrong, regenerate from upstream

---

## Event Format

Copy this template for each new event appended to `changelog.md`:

```markdown
### evt-NNN | YYYY-MM-DD HH:MM | agent-name | type

**Scope**: area affected
**Summary**: one-line description

**Details**:
- key: value

**Refs**: evt-XXX (or "none")
**Tags**: tag1, tag2
```

### Event Types

| Type | When to Use |
|------|-------------|
| `decision` | Architectural or design choice made |
| `create` | New file, component, or entity created |
| `modify` | Existing code or config changed |
| `delete` | File or component removed |
| `test` | Test executed or result recorded |
| `fix` | Bug fixed |
| `dependency` | External dependency added or changed |
| `blocker` | Something is blocking progress |
| `milestone` | Significant threshold reached |
| `escalation` | Issue escalated to human |
| `handoff` | Pipeline handoff between agents |

### Event Rules

1. **Only append** — never edit, delete, or reorder existing events
2. **One event per action** — do not batch multiple decisions into one event
3. **Self-contained summaries** — the Summary must make sense without reading Details
4. **Reference prior events** — use Refs to link cause-and-effect chains
5. **Sequential IDs** — increment the event number for each new event

---

## Materialization Rules

After appending events to `changelog.md`, update `graph.md` using these rules:

| Event Type | Graph Update |
|-----------|-------------|
| `create` | Add a new row to the Nodes table |
| `modify` | Update the existing node's Status, Last Event, and relevant Attributes |
| `delete` | Set node Status to `deprecated` (do not remove the row) |
| `decision` | Add a `decision` node + `implements` edge to affected components |
| `dependency` | Add/update `dependency` node + `depends_on` edge |
| `blocker` | Add a `blocks` edge between the two entities |
| `test` | Update the target node's Attributes (e.g., test coverage) |
| `fix` | Update target node; remove `blocks` edges if the fix resolves them |
| `milestone` | Add/update `milestone` node |
| `handoff` | Update `task` node: change Phase, Assignee |

### Graph Rules

1. **Never edit graph.md without a corresponding changelog event** — every change traces to an event
2. **Never delete rows** — set Status to `deprecated` instead
3. **If inconsistent** — regenerate the graph by replaying all events from `changelog.md`

### Node Types

`component` | `task` | `dependency` | `decision` | `document` | `milestone`

### Node Statuses

`active` | `blocked` | `completed` | `deprecated` | `planned`

### Edge Relations

`depends_on` | `blocks` | `implements` | `tests` | `documents` | `contains` | `precedes` | `related_to`

---

## Context Regeneration

Regenerate `context.md` at the start of every new session:

1. Read `graph.md` — list all nodes with Status = `active` or `blocked`
2. Read `changelog.md` — read events from the last 48 hours or last 20 events (whichever is more)
3. Fill in each section mechanically — do not editorialize or speculate:
   - **Active Mission** — from most recent milestone or decision events
   - **Current Sprint** — from graph task nodes with status = active
   - **Active Constraints** — from recent decision events
   - **Blockers** — from graph `blocks` edges where target is active
   - **Recent Changes** — chronological event summaries, newest first
   - **Key Dependencies** — from graph `depends_on` edges for active components
   - **Next Actions** — active tasks minus blockers, respecting `precedes` edges

### Staleness Check

Compare the `Event horizon` comment in `context.md` with the last event in `changelog.md`:
- **Match** → context is fresh, use directly
- **Mismatch** → context is stale, regenerate before proceeding
- **Missing** → generate from scratch

---

## Archival Protocol

When `changelog.md` exceeds **50 events**, archive older events to prevent the file from becoming unwieldy.

### When to Archive

- **Trigger**: changelog.md has more than 50 events
- **Frequency**: At milestone boundaries (natural breakpoints)
- **Retain in changelog.md**: The last 20 events + all events referenced by active graph nodes

### How to Archive

1. Identify the archive boundary — the oldest event that is still referenced by an active graph node or is within the last 20 events
2. Move all events **before** the boundary from `changelog.md` to `changelog-archive.md`
3. Add an archive marker at the top of the moved events section in `changelog-archive.md`
4. Add a reference comment in `changelog.md` noting what was archived
5. **Do not modify** the archived events after moving them — they remain append-only
6. Append an `archive` event to `changelog.md` recording the archival action

### Archive Marker Format

In `changelog-archive.md`, prefix each batch:

```markdown
---
## Archive: evt-001 through evt-030 | Archived YYYY-MM-DD
<!-- Archived at milestone: [milestone name] -->
---
```

### Rules

1. **Never delete events** — archiving means moving, not removing
2. **Archived events are still valid refs** — agents can read the archive if they need historical context
3. **The graph is not affected** — it already materialized these events; the nodes/edges remain
4. **Context regeneration** only reads recent events — archived events are already reflected in the graph

---

## Task Management

`TODO.md` (at project root) tracks tasks:

- **In Progress**: Tasks currently being worked on (1–3 max)
- **Up Next**: Next up, ordered by priority, with dependency tracking
- **Completed**: Done tasks with completion dates and event refs
- **Backlog**: Future work, roughly priority-ordered

Every task completion should have a corresponding event in `CHANGELOG.md`.

---

## Templates

| Template | Deploys As | Layer | Purpose |
|----------|-----------|-------|---------|
| `changelog.md` | `CHANGELOG.md` (root) | L1 | Event log — append-only, source of truth |
| `graph.md` | `.memory/graph.md` | L2 | Knowledge graph — nodes and edges, materialized from L1 |
| `context.md` | `.memory/context.md` | L3 | Current narrative — derived projection, regenerated per session |

## Examples

- **`_examples/worked-example.md`** — Complete walkthrough: 8 events flowing through all 4 layers

## Related

- `MEMORY-SYSTEM-PROTOCOL.md` — Full protocol specification (includes ACID guarantees, multi-agent coordination, tier scaling)
- `_complete_archive/PROJECT-MEMORY-SYSTEM-REFERENCE.md` — Archive's original memory system (predecessor)
