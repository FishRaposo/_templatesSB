# Memory System

Event-sourced multi-agent cognition — pure markdown implementation.

A 4-layer memory system that turns AI agents into stateless workers operating on shared, immutable state. No runtime, no database, no JSON — just markdown files deployed to a `.memory/` folder.

---

## Directory Structure

```
memory-system/
├── README.md                     # This file — comprehensive documentation
├── templates/                    # Deployable files
│   ├── changelog.md              # → deploys as CHANGELOG.md (project root)
│   ├── graph.md                  # → deploys as .memory/graph.md
│   ├── context.md                # → deploys as .memory/context.md
│   ├── context.md.tpl.md         # Jinja2 template with variables
│   └── graph.md.tpl.md           # Jinja2 template with variables
├── skill/                        # Implementation skill (for AI agents)
│   ├── SKILL.md                  # Step-by-step deployment instructions
│   ├── config.json               # Skill triggers and configuration
│   └── README.md                 # Skill overview
├── docs/                         # Supporting documentation
│   ├── ARCHITECTURE-AUDIT.md     # Architecture audit & gap analysis
│   ├── VALIDATION-SCRIPT.md      # Validation script reference
│   └── INITIALIZATION-SCRIPT.md  # Initialization script reference
└── _examples/                    # Usage examples
    └── worked-example.md         # 8 events flowing through all 4 layers
```

### Deployed Structure

When deployed to a target project:

```
target-project/
├── AGENTS.md                     # Layer 0: Behavioral Core
├── CHANGELOG.md                  # Layer 1: Event Log (from templates/changelog.md)
├── TODO.md                       # Layer 1 Extension (Full tier only)
└── .memory/                      # Derived views
    ├── graph.md                  # Layer 2: Knowledge Graph (Full tier)
    └── context.md                # Layer 3: Narrative (Core/Full tier)
```

---

## The Four Layers

```
┌─────────────────────────────────────────────────────────┐
│  Layer 3: NARRATIVE (context.md)                        │
│  Derived projection — "what matters right now"          │
│  Ephemeral. Rebuilt from Layer 1 + Layer 2.             │
├─────────────────────────────────────────────────────────┤
│  Layer 2: KNOWLEDGE GRAPH (graph.md)                    │
│  Materialized view — entities, relations, states        │
│  Queryable. Updated only by materialization from L1.    │
├─────────────────────────────────────────────────────────┤
│  Layer 1: EVENT LOG (CHANGELOG.md)                      │
│  Source of truth — every decision, change, result       │
│  Append-only. Immutable once committed.                 │
├─────────────────────────────────────────────────────────┤
│  Layer 0: BEHAVIORAL CORE (AGENTS.md)                   │
│  Constitution — rules, constraints, Three Pillars       │
│  Immutable during execution. Read at boot only.         │
└─────────────────────────────────────────────────────────┘
```

| Layer | File | Role | Rule |
|-------|------|------|------|
| **L0** | `AGENTS.md` | Behavioral Core | Immutable during execution |
| **L1** | `CHANGELOG.md` (root) | Event Log | Append-only, source of truth |
| **L2** | `.memory/graph.md` | Knowledge Graph | Materialized from L1 only |
| **L3** | `.memory/context.md` | Narrative | Regenerated from L1 + L2 |

### Design Principles

| Principle | Description |
|-----------|-------------|
| **Memory is infrastructure** | Agents read files, no internal state |
| **Append-only truth** | Events never edited once committed |
| **One-way data flow** | L1 → L2 → L3, never backward |
| **Stateless agents** | Boot from files, execute, write, die |
| **Git is the database** | Commits are transactions |
| **Pure markdown** | No JSON runtime, no tooling required |

### Trust Hierarchy

When layers conflict, resolve by trust order:

```
L0 (AGENTS.md)    → Highest authority — behavioral rules always win
L1 (CHANGELOG.md) → Source of truth for all facts
L2 (graph.md)     → Must match L1 — if not, rematerialize
L3 (context.md)   → Must match L1+L2 — if not, regenerate
```

---

## Tiers

Not every project needs all four layers:

| Signal | MVP | Core | Full |
|--------|-----|------|------|
| Solo developer, < 1 month | ✅ | | |
| Multiple agents/developers, 1–6 months | | ✅ | |
| Complex dependencies, 6+ months, multi-agent | | | ✅ |

| Tier | Files Deployed |
|------|---------------|
| **MVP** | `CHANGELOG.md` only |
| **Core** | `CHANGELOG.md` + `.memory/context.md` |
| **Full** | `CHANGELOG.md` + `TODO.md` + `.memory/graph.md` + `.memory/context.md` |

### Quick Start by Tier

**MVP**:
```bash
cp templates/changelog.md CHANGELOG.md
```

**Core**:
```bash
cp templates/changelog.md CHANGELOG.md
mkdir -p .memory
cp templates/context.md .memory/context.md
```

**Full**:
```bash
cp templates/changelog.md CHANGELOG.md
mkdir -p .memory
cp templates/graph.md .memory/graph.md
cp templates/context.md .memory/context.md
```

---

## Agent Lifecycle

```
BOOT:     Read AGENTS.md → Read context.md → Check staleness → Read graph.md
EXECUTE:  Work within constraints → Append events to CHANGELOG.md
SHUTDOWN: Append → Update graph → Regenerate context → Commit
```

### Core Rules

1. **Append-only** — never edit existing events in the changelog
2. **One-way flow** — changelog → graph → context; never backward
3. **Stateless agents** — boot from files, work, write results, die
4. **Rebuild, don't repair** — if derived layers are wrong, regenerate from upstream

---

## Layer 1: Event Log

### Event Format

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
| `decision` | Architectural or design choice — include `from`, `to`, `rationale` |
| `create` | New file/component/entity — include `entity`, `path`, `purpose` |
| `modify` | Existing code changed — include `entity`, `changes` |
| `delete` | File/component removed — include `entity`, `reason` |
| `test` | Test executed — include `target`, `result` |
| `fix` | Bug fixed — include `symptom`, `root_cause`, `resolution` |
| `dependency` | External dep added/changed — include `entity`, `version` |
| `blocker` | Progress blocked — include `blocked_entity`, `blocking_entity` |
| `milestone` | Significant threshold — include `name`, `criteria_met` |
| `escalation` | Escalated to human — include `reason`, `requested_action` |
| `handoff` | Pipeline handoff — include `from_agent`, `to_agent` |

### Event Rules

1. **Only append** — never edit, delete, or reorder existing events
2. **One event per action** — do not batch multiple decisions into one event
3. **Self-contained summaries** — the Summary must make sense without reading Details
4. **Reference prior events** — use Refs to link cause-and-effect chains
5. **Sequential IDs** — increment the event number for each new event

---

## Layer 2: Knowledge Graph

### Materialization Rules

After appending events to `CHANGELOG.md`, update `graph.md`:

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
3. **If inconsistent** — regenerate the graph by replaying all events from `CHANGELOG.md`

### Graph Schema

- **Node Types**: `component` | `task` | `dependency` | `decision` | `document` | `milestone`
- **Node Statuses**: `active` | `blocked` | `completed` | `deprecated` | `planned`
- **Edge Relations**: `depends_on` | `blocks` | `implements` | `tests` | `documents` | `contains` | `precedes` | `related_to`

---

## Layer 3: Context Narrative

### Regeneration Algorithm

Regenerate `context.md` at the start of every new session:

1. Read `graph.md` — list all nodes with Status = `active` or `blocked`
2. Read `CHANGELOG.md` — read events from the last 48 hours or last 20 events (whichever is more)
3. Fill in each section mechanically — do not editorialize or speculate:
   - **Active Mission** — from most recent milestone or decision events
   - **Current Sprint** — from graph task nodes with status = active
   - **Active Constraints** — from recent decision events
   - **Blockers** — from graph `blocks` edges where target is active
   - **Recent Changes** — chronological event summaries, newest first
   - **Key Dependencies** — from graph `depends_on` edges for active components
   - **Next Actions** — active tasks minus blockers, respecting `precedes` edges

### Staleness Check

Compare the `Event horizon` comment in `context.md` with the last event in `CHANGELOG.md`:
- **Match** → context is fresh, use directly
- **Mismatch** → context is stale, regenerate before proceeding
- **Missing** → generate from scratch

---

## Archival Protocol

When `CHANGELOG.md` exceeds **50 events**, archive older events.

### When to Archive

- **Trigger**: changelog has more than 50 events
- **Frequency**: At milestone boundaries (natural breakpoints)
- **Retain**: The last 20 events + all events referenced by active graph nodes

### How to Archive

1. Identify the archive boundary — the oldest event still referenced by an active graph node or within the last 20 events
2. Move all events **before** the boundary to `changelog-archive.md`
3. Add an archive marker: `## Archive: evt-001 through evt-NNN | Archived YYYY-MM-DD`
4. Add a reference comment in `CHANGELOG.md` noting what was archived
5. Append an `archive` event to `CHANGELOG.md` recording the archival action

### Archival Rules

1. **Never delete events** — archiving means moving, not removing
2. **Archived events are still valid refs** — agents can read the archive for historical context
3. **The graph is not affected** — it already materialized these events; nodes/edges remain
4. **Context regeneration** only reads recent events — archived events are already reflected in the graph

---

## Task Management (Full Tier)

`TODO.md` (at project root) tracks tasks:

- **In Progress**: Tasks currently being worked on (1–3 max)
- **Up Next**: Next up, ordered by priority, with dependency tracking
- **Completed**: Done tasks with completion dates and event refs
- **Backlog**: Future work, roughly priority-ordered

Every task completion should have a corresponding event in `CHANGELOG.md`.

---

## AGENTS.md Integration

Add this to a project's AGENTS.md to integrate the memory system:

```markdown
## Memory System Protocol

This project uses an event-sourced memory system. See `.memory/` for live state.

- **Layer 0 — Behavioral Core** (`AGENTS.md`): Immutable during execution. Read at boot only.
- **Layer 1 — Event Log** (`CHANGELOG.md`): Append-only source of truth.
- **Layer 2 — Knowledge Graph** (`.memory/graph.md`): Materialized view of entities and relations.
- **Layer 3 — Narrative** (`.memory/context.md`): Derived projection. Regenerate when stale.

### Core Rules
1. Append-only — if it is not in the event log, it did not happen
2. One-way data flow — Event Log → Graph → Narrative; never backward
3. Stateless agents — boot from files, execute, write results, die
4. Rebuild, don't repair — regenerate derived layers from upstream when inconsistent
```

---

## Templates

| Template | Deploys As | Layer |
|----------|-----------|-------|
| `templates/changelog.md` | `CHANGELOG.md` (root) | L1 — Event log |
| `templates/graph.md` | `.memory/graph.md` | L2 — Knowledge graph |
| `templates/context.md` | `.memory/context.md` | L3 — Narrative |
| `templates/graph.md.tpl.md` | `.memory/graph.md` | L2 — Jinja2 with variables |
| `templates/context.md.tpl.md` | `.memory/context.md` | L3 — Jinja2 with variables |

---

## Validation Checklist

When auditing a deployed memory system:

- [ ] `CHANGELOG.md` exists at project root with `## Event Log` section
- [ ] Events use correct format: `### evt-NNN | YYYY-MM-DD HH:MM | agent | type`
- [ ] Every event has **Scope** and **Summary** fields
- [ ] No existing events have been modified (append-only)
- [ ] Event IDs are sequential
- [ ] `.memory/` directory exists (Core/Full tier)
- [ ] `.memory/graph.md` event horizon matches last event in `CHANGELOG.md` (Full tier)
- [ ] `.memory/context.md` event horizon matches last event in `CHANGELOG.md` (Core/Full tier)
- [ ] `TODO.md` exists at project root (Full tier)
- [ ] `AGENTS.md` includes a Memory System Protocol section

---

## Examples

See `_examples/worked-example.md` for a complete walkthrough: 8 events flowing through all 4 layers for an authentication module.

## Further Reading

- `docs/ARCHITECTURE-AUDIT.md` — Architecture deep-dive with Mermaid diagrams and gap analysis
- `docs/VALIDATION-SCRIPT.md` — Automated validation script reference
- `docs/INITIALIZATION-SCRIPT.md` — Project initialization script reference
- `skill/SKILL.md` — Step-by-step skill for AI agents deploying the memory system
