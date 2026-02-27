---
name: memory-system
description: Use this skill when deploying, maintaining, or troubleshooting an event-sourced memory system for AI agent projects. This includes initializing the 4-layer architecture (CHANGELOG.md at root, .memory/ for graph and context), creating the .memory/ folder, configuring tier-appropriate memory (MVP/Core/Full), archiving old events, and integrating memory protocol into AGENTS.md.
---

# Memory System

I'll help you deploy and maintain an event-sourced memory system that turns AI agents into stateless, deterministic workers operating on shared, immutable state. The system uses pure markdown — no JSON, no tooling, no runtime required.

# Core Concept

Four layers separate **behavior**, **history**, **structure**, and **trajectory**:

```
L0: AGENTS.md        → Behavioral Core (immutable during execution)
L1: CHANGELOG.md     → Event Log (root, append-only, source of truth)
L2: .memory/graph.md → Knowledge Graph (materialized from L1)
L3: .memory/context.md → Narrative (derived from L1 + L2, ephemeral)
```

**Data flows one way**: L1 → L2 → L3. Never backward.

**Agents are stateless**: They boot from files, execute, write results, and die. No retained state.

# Step-by-Step Instructions

## 1. Assess Tier

Not every project needs all four layers. Determine the right tier before deploying:

| Signal | MVP | Core | Full |
|--------|-----|------|------|
| Solo developer, < 1 month | ✅ | | |
| Multiple agents/developers, 1-6 months | | ✅ | |
| Complex dependencies, 6+ months, need "what blocks what?" | | | ✅ |

| Tier | Files Deployed |
|------|--------------|
| **MVP** | `CHANGELOG.md` (root) only |
| **Core** | `CHANGELOG.md` (root) + `.memory/context.md` |
| **Full** | `CHANGELOG.md` (root) + `TODO.md` (root) + `.memory/graph.md` + `.memory/context.md` |

## 2. Create the File Layout

Set up the memory system files:

```
project/
├── AGENTS.md                    ← Layer 0 (already exists or will be created)
├── CHANGELOG.md                 ← Layer 1: Event Log (append-only, source of truth)
├── TODO.md                      ← Layer 1 Extension: Task Tracker (Full tier)
├── .memory/                     ← Derived views
│   ├── graph.md                 ← Layer 2: Knowledge Graph (Full tier)
│   └── context.md               ← Layer 3: Narrative (Core/Full tier)
└── ...
```

For MVP tier, only create `CHANGELOG.md`. Add other files as the project grows.

**Template Deployment**: Copy templates from this skill's `memory-system/templates/` directory:

- MVP: `memory-system/templates/changelog.md` → `CHANGELOG.md`
- Core: Add `memory-system/templates/context.md` → `.memory/context.md`
- Full: Add `memory-system/templates/graph.md` → `.memory/graph.md`

## 3. Initialize CHANGELOG.md (Layer 1)

Copy `memory-system/templates/changelog.md` to the project root as `CHANGELOG.md`. The file has two sections:
- **Categorized summary** at top (Keep a Changelog format for quick scanning)
- **Structured Event Log** below (source of truth for graph and context)

Update the initial event with your project details:
- Set YYYY-MM-DD HH:MM to current timestamp
- Replace "project-name" and "brief project description"
- Set Tier to MVP | Core | Full

### Event Format

Every event follows this template:

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

### Append Rules

1. **Only append** — never edit, delete, or reorder existing events
2. **One event per action** — do not batch multiple decisions
3. **Self-contained summaries** — Summary must make sense without Details
4. **Reference prior events** — use Refs to link cause-and-effect
5. **Sequential IDs** — increment for each new event

## 4. Initialize graph.md (Layer 2 — Full Tier)

Copy `memory-system/templates/graph.md` to `.memory/graph.md`. The knowledge graph tracks entities and relationships.

For projects with existing components, update the initial rows in the Nodes and Edges tables to reflect the current state.

### Materialization Rules

After appending events, update the graph:

| Event Type | Graph Update |
|-----------|-------------|
| `create` | Add row to Nodes table |
| `modify` | Update node's Last Event and Attributes |
| `delete` | Set Status to `deprecated` (never remove) |
| `decision` | Add decision node + `implements` edge |
| `dependency` | Add dependency node + `depends_on` edge |
| `blocker` | Add `blocks` edge |
| `fix` | Update node; remove `blocks` edges if resolved |
| `milestone` | Add/update milestone node |

**Node Types**: `component` | `task` | `dependency` | `decision` | `document` | `milestone`

**Node Statuses**: `active` | `blocked` | `completed` | `deprecated` | `planned`

**Edge Relations**: `depends_on` | `blocks` | `implements` | `tests` | `documents` | `contains` | `precedes` | `related_to`

## 5. Initialize context.md (Layer 3 — Core/Full Tier)

Copy `memory-system/templates/context.md` to `.memory/context.md`. The narrative provides current trajectory.

Fill in the initial sections based on the project's current state:
- **Active Mission**: One paragraph describing the project's current goal
- **Current Sprint**: Active tasks (if any)
- **Active Constraints**: Recent decision events that define boundaries

### Regeneration

Regenerate `context.md` at the start of every new session:

1. Read `graph.md` — list nodes with Status = `active` or `blocked`
2. Read `changelog.md` — last 20 events or 48 hours
3. Fill each section mechanically — do not editorialize

### Staleness Check

Compare the `Event horizon` in `context.md` with the last event in `changelog.md`:
- **Match** → fresh, use directly
- **Mismatch** → stale, regenerate
- **Missing** → generate from scratch

## 6. Initialize TODO.md (Layer 1 Extension — Full Tier)

Create `TODO.md` at the project root for task tracking:

```markdown
# TODO

> Pending tasks, planned work, and progress tracking.

## In Progress
- [ ] **Task** — description (evt-NNN)

## Up Next
- [ ] **Task** — description

## Completed
- [x] **Task** — description (evt-NNN)

## Backlog
- [ ] **Task** — description
```

Every task completion should have a corresponding event in `CHANGELOG.md`.

## 7. Integrate into AGENTS.md

Add a Memory System Protocol section to the project's AGENTS.md:

```markdown
## Memory System Protocol

This project uses an event-sourced memory system. See `.memory/` for the live state.

- **Layer 0 — Behavioral Core** (`AGENTS.md`): Immutable during execution. Read at boot only.
- **Layer 1 — Event Log** (`CHANGELOG.md`): Append-only source of truth.
- **Layer 2 — Knowledge Graph** (`.memory/graph.md`): Materialized view of entities and relations.
- **Layer 3 — Narrative** (`.memory/context.md`): Derived projection. Regenerate when stale.

### Agent Lifecycle

BOOT:     Read AGENTS.md → Read context.md → Check staleness → Query graph
EXECUTE:  Work within constraints → Append events to CHANGELOG.md
SHUTDOWN: Append → Materialize → Regenerate → Commit → Die

### Core Rules

1. **Append-only** — if it is not in the event log, it did not happen
2. **One-way data flow** — Event Log → Graph → Narrative; never backward
3. **Stateless agents** — boot from files, execute, write results, die
4. **Rebuild, don't repair** — regenerate derived layers from upstream when inconsistent
```

## 8. Handle Archival

When `CHANGELOG.md` exceeds **50 events**, archive older events:

1. **Boundary**: Oldest event still referenced by an active graph node or within the last 20 events
2. **Move**: Transfer events before the boundary to `changelog-archive.md`
3. **Mark**: Prefix the batch with `## Archive: evt-001 through evt-NNN | Archived YYYY-MM-DD`
4. **Log**: Append an `archive` event to `changelog.md`
5. **Never delete** — archiving is moving, not removing
6. **Graph unaffected** — archived events were already materialized

# Best Practices

- **Start with MVP** — add layers only when you need them
- **One event per action** — granularity enables precise graph updates
- **Self-contained summaries** — agents skim summaries, not details
- **Reference prior events** — build cause-and-effect chains
- **Regenerate context every session** — stale context causes drift
- **Archive at milestones** — natural breakpoints for moving old events
- **Trust the hierarchy** — L0 > L1 > L2 > L3 when layers conflict

# Validation Checklist

When auditing a deployed memory system:

- [ ] `CHANGELOG.md` exists at project root with `## Event Log` section and sequential event IDs
- [ ] Events use the correct heading format: `### evt-NNN | YYYY-MM-DD HH:MM | agent | type`
- [ ] Every event has **Scope** and **Summary** fields
- [ ] No existing events have been modified (append-only)
- [ ] `.memory/` directory exists and is not gitignored (Core/Full tier)
- [ ] `.memory/graph.md` Meta event horizon matches the last event in `CHANGELOG.md` (Full tier)
- [ ] `.memory/context.md` Event horizon matches the last event in `CHANGELOG.md` (Core/Full tier)
- [ ] `TODO.md` exists at project root (Full tier)
- [ ] AGENTS.md includes a Memory System Protocol section

# Troubleshooting

## Issue: Context Is Stale

**Symptoms**: Agent acts on outdated information, misses recent decisions or blockers

**Solution**:
- Check the Event horizon comment in `context.md` against the last event in `CHANGELOG.md`
- If they differ, regenerate `context.md` from `CHANGELOG.md` + `graph.md`
- Add a staleness check to the agent's boot sequence

## Issue: Graph Inconsistent With Changelog

**Symptoms**: Graph shows nodes/edges that don't trace to events, or missing entities that were created

**Solution**:
- Regenerate `graph.md` by replaying all events from `CHANGELOG.md`
- Update Meta section with the correct event horizon and counts
- Append a corrective event noting the inconsistency

## Issue: Changelog Too Large

**Symptoms**: `CHANGELOG.md` is slow to parse, agents miss early events

**Solution**:
- Run the archival protocol (Step 8) — move old events to `changelog-archive.md`
- Retain the last 20 events + all events referenced by active graph nodes
- The graph already has all historical information materialized

## Issue: Multiple Agents Conflict

**Symptoms**: Two agents modify the same component, graph shows contradictory state

**Solution**:
- Both events remain in the changelog (append-only prevents data loss)
- The later event's graph update takes precedence for current state
- If needed, append a `decision` event to explicitly resolve the conflict
- Use `blocks` edges to prevent parallel work on the same component

# Supporting Files

- See `../README.md` for the complete operational reference (event format, materialization rules, context regeneration, archival protocol)
- See `memory-system/_examples/worked-example.md` for 8 events flowing through all 4 layers
- For full protocol documentation: See the parent `memory-system/README.md`

## Related Skills

- **generating-agents-md** — Generate AGENTS.md files that include memory system integration
- **skill-builder** — Create AI agent skills that operate within the memory system
