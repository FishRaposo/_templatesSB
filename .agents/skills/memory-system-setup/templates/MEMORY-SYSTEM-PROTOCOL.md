# Memory System Protocol

**Event-Sourced Multi-Agent Cognition for AI Development**

This protocol is a **Protocol** template (one of seven template types). It is designed to be placed in `docs/protocols/MEMORY-SYSTEM-PROTOCOL.md` by the **memory-system-setup** skill and referenced by agents and Rules (e.g. AGENTS.md) for the memory lifecycle.

This protocol transforms AI agents from stateful, hallucinating oracles into stateless, deterministic workers that manipulate an immutable event log, navigate a queryable knowledge graph, and execute within behavioral constraints — enabling parallel agents to build complex systems without drift, coordination overhead, or catastrophic forgetting.

---

## Table of Contents

1. [Architecture](#1-architecture)
2. [File Layout](#2-file-layout)
3. [Layer 0: Behavioral Core](#3-layer-0-behavioral-core)
4. [Layer 1: Event Log](#4-layer-1-event-log)
5. [Layer 2: Knowledge Graph](#5-layer-2-knowledge-graph)
6. [Layer 3: Narrative](#6-layer-3-narrative)
7. [Agent Lifecycle](#7-agent-lifecycle)
8. [Handoff Protocol](#8-handoff-protocol)
9. [Data Flow and Anti-Drift](#9-data-flow-and-anti-drift)
10. [Multi-Agent Coordination](#10-multi-agent-coordination)
11. [ACID Guarantees](#11-acid-guarantees)
12. [Validation](#12-validation)
13. [Tier Scaling](#13-tier-scaling)
14. [Three Pillars Integration](#14-three-pillars-integration)
15. [Retrieval and Tools](#15-retrieval-and-tools)

For step-by-step deployment (tier choice, file layout, templates, AGENTS.md integration), use the **memory-system-setup** skill (`.agents/skills/memory-system-setup/`), which installs this protocol into `docs/protocols/` and maps each protocol section to skill steps.

---

## 1. Architecture

Four layers separate **behavior**, **history**, **structure**, and **trajectory** into distinct, immutable concerns:

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

### Design Principles

1. **Memory is infrastructure, not cognition** — agents do not "remember"; they read files
2. **Append-only truth** — if it is not in the event log, it did not happen
3. **One-way data flow** — Event Log → Graph → Narrative; never backward
4. **Stateless agents** — agents boot from files, execute, write results, die; no retained state
5. **Git is the database** — all persistence through version-controlled files; commits are transactions
6. **Pure markdown** — all layers are readable, writable markdown files; no JSON, no tooling required

---

## 2. File Layout

```
project/
├── AGENTS.md                        ← Layer 0: Behavioral Core
├── CHANGELOG.md                     ← Layer 1: Event Log (append-only, source of truth)
├── TODO.md                          ← Layer 1 Extension: Task Tracker
├── .memory/                         ← Derived views
│   ├── graph.md                     ← Layer 2: Knowledge Graph (materialized from L1)
│   └── context.md                   ← Layer 3: Narrative (derived from L1 + L2)
└── ...
```

**Rules**:
- `CHANGELOG.md` is append-only — never edit or delete existing events in the Event Log section
- `TODO.md` is the single source of truth for tasks
- `.memory/` directory must be tracked by git (not gitignored)
- `graph.md` is a materialized view — regenerable from `CHANGELOG.md`
- `context.md` is ephemeral — regenerable from `CHANGELOG.md` + `graph.md`

---

## 3. Layer 0: Behavioral Core

**File**: `AGENTS.md`
**Role**: The constitution. Defines what agents can and cannot do.
**Analogy**: The firmware — burned in before boot, not modifiable at runtime.

### What It Contains
- Project identity and scope
- Structural rules (Do / Don't)
- File conventions and naming
- Workflow definitions
- Three Pillars requirements
- Validation protocol references
- Boundary definitions

### Immutability Rules
- Loaded once at agent boot
- Never modified during task execution
- Changes require explicit human approval and a dedicated commit
- Agents that need to change behavioral rules must escalate to a human

### Boot-Time Contract
When an agent reads `AGENTS.md`, it accepts a binding contract:
- I will only act within the defined boundaries
- I will follow all structural rules without exception
- I will satisfy all Three Pillars before reporting completion
- I will append all decisions and changes to the event log

---

## 4. Layer 1: Event Log

**File**: `CHANGELOG.md` (root)
**Role**: Source of truth. The temporal lobe — every decision, change, and result lives here.
**Format**: Markdown — Keep a Changelog summary at top, structured event log below. One H3 section per event, append-only.

### Event Format

Each event is a markdown section appended to the `## Event Log` area:

```markdown
### evt-NNN | YYYY-MM-DD HH:MM | agent-name | type

**Scope**: area affected
**Summary**: one-line description

**Details**:
- key: value
- key: value

**Refs**: evt-XXX, evt-YYY (or "none")
**Tags**: tag1, tag2
```

### Required Fields

| Field | Description |
|-------|-------------|
| **Event ID** | Unique ID in heading: `evt-NNN` (sequential) |
| **Timestamp** | Date and time in heading: `YYYY-MM-DD HH:MM` |
| **Agent** | Agent identifier in heading (e.g., `architect-01`, `cascade`, `human`) |
| **Type** | Event type in heading (see below) |
| **Scope** | What area this affects (module name, file path, system area) |
| **Summary** | One-line human-readable description |

### Optional Fields

| Field | Description |
|-------|-------------|
| **Details** | Type-specific key-value pairs as a bullet list |
| **Refs** | IDs of related prior events |
| **Tags** | Searchable labels |

### Event Types

| Type | When Used | Required Details |
|------|-----------|-----------------|
| `decision` | Architectural or design choice made | `entity`, `attribute`, `from`, `to`, `rationale` |
| `create` | New file, component, or entity created | `entity`, `path`, `purpose` |
| `modify` | Existing code or file changed | `entity`, `path`, `changes[]` |
| `delete` | File, component, or entity removed | `entity`, `path`, `reason` |
| `test` | Test executed or test result recorded | `target`, `result` (pass/fail/skip), `coverage` |
| `fix` | Bug fixed | `entity`, `symptom`, `root_cause`, `resolution` |
| `dependency` | External dependency added, changed, or noted | `entity`, `version`, `reason` |
| `blocker` | Something is blocking progress | `blocked_entity`, `blocking_entity`, `resolution_path` |
| `milestone` | Significant threshold reached | `name`, `criteria_met[]` |
| `escalation` | Issue escalated to human or higher authority | `reason`, `context`, `requested_action` |
| `handoff` | Agent pipeline handoff | `from_agent`, `to_agent`, `payload_summary` |

### Append Rules

1. **Only append** — never edit, delete, or reorder existing events
2. **One event per action** — do not batch multiple decisions into one event
3. **Timestamp accuracy** — use actual time, not estimated or fabricated
4. **Self-contained summaries** — the Summary must be understandable without reading Details
5. **Reference prior events** — use Refs to link cause-and-effect chains
6. **Sequential IDs** — increment the event number for each new event

### Archival Protocol

When `CHANGELOG.md` exceeds **50 events**, archive older events:

1. **Boundary**: Identify the oldest event still referenced by an active graph node or within the last 20 events
2. **Move**: Transfer all events before the boundary to `CHANGELOG-archive.md`
3. **Mark**: Prefix each archived batch with `## Archive: evt-001 through evt-NNN | Archived YYYY-MM-DD`
4. **Log**: Append an `archive` event to `CHANGELOG.md` recording the action
5. **Never delete** — archiving means moving, not removing; archived events are still valid refs
6. **Graph unaffected** — nodes/edges from archived events remain; they were already materialized

---

## 5. Layer 2: Knowledge Graph

**File**: `.memory/graph.md`
**Role**: The structural map. Semantic memory — queryable entities and relationships.
**Format**: Two markdown tables (Nodes + Edges) plus a Meta section.

### Structure

```markdown
## Nodes
| Node | Type | Status | Created (evt) | Last Event | Attributes |
|------|------|--------|---------------|------------|------------|
| auth_module | component | active | evt-001 | evt-005 | path: src/auth/, coverage: 87% |

## Edges
| From | To | Relation | Created (evt) | Attributes |
|------|----|----------|---------------|------------|
| auth_module | database | depends_on | evt-002 | (none) |

## Meta
- **Last updated**: 2025-02-10 12:30
- **Event horizon**: evt-008
- **Nodes**: 5
- **Edges**: 5
```

### Node Types

| Type | Represents | Key Attributes |
|------|-----------|----------------|
| `component` | Code module, service, or feature | `path`, `owner`, `test_coverage` |
| `task` | Work item | `priority`, `assignee`, `pipeline_phase` |
| `dependency` | External dependency or blocker | `version`, `eta`, `source` |
| `decision` | Architectural decision record | `rationale`, `alternatives_considered` |
| `document` | Documentation file | `path`, `last_updated` |
| `milestone` | Project milestone | `criteria`, `target_date`, `progress` |

### Node Statuses

`active` | `blocked` | `completed` | `deprecated` | `planned`

### Edge Relations

| Relation | Meaning | Example |
|----------|---------|---------|
| `depends_on` | A requires B to function | `auth_module` → `database` |
| `blocks` | A prevents B from progressing | `visa_timeline` → `incorporation` |
| `implements` | A implements the decision in B | `auth_module` → `decision_use_jwt` |
| `tests` | A tests B | `auth_test_suite` → `auth_module` |
| `documents` | A documents B | `auth_docs` → `auth_module` |
| `contains` | A is a parent of B | `backend` → `auth_module` |
| `precedes` | A must happen before B in a pipeline | `architecture_phase` → `build_phase` |
| `related_to` | Soft association | Any two related nodes |

### Materialization Rules

The graph is **never edited directly**. It is updated only by processing new events from `CHANGELOG.md`.

**When to materialize**: After appending events to `CHANGELOG.md`.

**How to materialize** — for each new event since Meta's event horizon:

| Event Type | Graph Update |
|-----------|-------------|
| `create` | Add row to Nodes table: type, status=active, created=event ID |
| `modify` | Update existing node's Last Event and relevant Attributes |
| `delete` | Set node Status to `deprecated` (do not remove the row) |
| `decision` | Add `decision` node + `implements` edge to affected components |
| `dependency` | Add/update `dependency` node + `depends_on` edge |
| `blocker` | Add `blocks` edge between entities |
| `test` | Update target node's Attributes (e.g., coverage) |
| `fix` | Update target node; remove `blocks` edges if fix resolves them |
| `milestone` | Add/update `milestone` node |
| `handoff` | Update `task` node: change Phase, Assignee |

**After materialization**: Update Meta section (last updated, event horizon, counts).

### Graph Rules

1. **Never edit graph.md without a corresponding CHANGELOG event** — every change traces to an event
2. **Never delete rows** — set Status to `deprecated` instead
3. **If inconsistent** — regenerate the graph by replaying all events from `CHANGELOG.md`

### Query Patterns

Agents query the graph by reading `graph.md` and scanning the tables:

| Query | How to Execute |
|-------|---------------|
| "What is blocking X?" | Find Edges rows where To = X and Relation = `blocks` |
| "What depends on X?" | Find Edges rows where To = X and Relation = `depends_on` |
| "What is the status of X?" | Find Nodes row where Node = X, read Status column |
| "What changed recently?" | Find Nodes rows with highest Last Event numbers |
| "What tasks are in progress?" | Find Nodes rows where Type = `task` and Status = `active` |
| "What is untested?" | Find Nodes rows where Type = `component` with no `tests` edge |

---

## 6. Layer 3: Narrative

**File**: `.memory/context.md`
**Role**: The prefrontal cortex — "what matters right now." Human-readable current trajectory.
**Key trait**: Ephemeral. If destroyed, it is rebuilt from Layer 1 + Layer 2. It is a **projection, not a source**.

### Sections

The narrative contains 7 fill-in sections, each derived mechanically from L1 + L2:

| Section | Source | Format |
|---------|--------|--------|
| **Active Mission** | Most recent milestone or decision events | One paragraph |
| **Current Sprint** | Graph nodes where Type = task, Status = active | Table with priority, assignee, blockers |
| **Active Constraints** | Recent decision events defining boundaries | Bullet list: constraint — evt-NNN |
| **Blockers** | Graph `blocks` edges where target is active | Bullet list: X blocks Y — evt-NNN |
| **Recent Changes** | Last 48h or last 20 events, newest first | Bullet list: date — summary — evt-NNN |
| **Key Dependencies** | Graph `depends_on` edges for active components | Bullet list: X depends on Y — evt-NNN |
| **Next Actions** | Active tasks minus blockers, respecting `precedes` edges | Numbered list in priority order |

### Generation Algorithm

1. Read `graph.md` — list all nodes with Status = `active` or `blocked`
2. Read `CHANGELOG.md` — read events from the last 48 hours or last 20 events (whichever is more)
3. Fill in each section mechanically — do not editorialize or speculate

### Staleness Rules

- **Fresh**: Event horizon in `context.md` matches last event in `CHANGELOG.md` — use directly
- **Stale**: Event horizons do not match — regenerate before proceeding
- **Missing**: File does not exist — generate from scratch before proceeding

**Staleness check**: Compare the `Event horizon` comment in `context.md` with the last event ID in `CHANGELOG.md`. If they differ, the narrative is stale.

---

## 7. Agent Lifecycle

Agents are **ephemeral processes** that hydrate from the filesystem. They carry no state between tasks.

### Boot Sequence

Every agent, every task, every time:

```
1. READ    AGENTS.md              → Load behavioral constraints (Layer 0)
2. READ    .memory/context.md     → Load current mission and trajectory (Layer 3)
3. CHECK   Staleness              → If context.md is stale or missing, regenerate it
4. READ    .memory/graph.md       → Query local neighborhood of current task (Layer 2)
5. VERIFY  Constraints            → Confirm task is within behavioral boundaries
6. EXECUTE Task                   → Perform work within constraints
```

**If any boot step fails**: Stop. Do not proceed with partial context. Report the failure.

### Execution Constraints

During task execution, agents:
- **Can** read any layer at any time
- **Can** append to `CHANGELOG.md` (Layer 1)
- **Cannot** edit `graph.md` directly (Layer 2 — materialization only)
- **Cannot** edit existing events in `CHANGELOG.md` (Layer 1 — append-only)
- **Cannot** modify `AGENTS.md` (Layer 0 — immutable during execution)
- **Can** regenerate `context.md` (Layer 3 — it is a projection)

### Shutdown Sequence

After task completion, before the agent terminates:

```
1. APPEND        All decisions and changes to CHANGELOG.md     (Layer 1)
2. MATERIALIZE   New events into graph.md                     (Layer 2)
3. REGENERATE    context.md from updated L1 + L2              (Layer 3)
4. COMMIT        All changes in a single git commit
6. HANDOFF       If in a pipeline, write handoff payload     (see §8)
7. DIE           Purge all local/working memory
```

**If shutdown is interrupted**: The next agent detects the incomplete state during boot (stale context.md, unmatched event_horizon) and recovers by re-materializing from the event log.

### Recovery Protocol

When an agent boots and detects inconsistency:

1. **Trust Layer 1** — `CHANGELOG.md` is always the source of truth
2. **Rebuild Layer 2** — Regenerate `graph.md` by replaying all events from `CHANGELOG.md`
3. **Rebuild Layer 3** — Regenerate `context.md` from the rebuilt graph + recent events
4. **Verify Layer 0** — Confirm `AGENTS.md` has not been modified
5. **Resume** — Continue with the original task using clean state

---

## 8. Handoff Protocol

**Tier scope:** Handoff events and pipeline coordination apply in **Core** and **Full** tiers. Graph-based coordination (querying "what blocks what?", task nodes) applies in **Full** tier only; Core tier uses `context.md` and the event log only.

When agents operate in a pipeline (e.g., Architect → Builder → Tester → Doc Manager → Validator), handoffs transfer scoped context forward.

### Handoff Mechanism

Handoffs are **event log entries** of type `handoff`, not separate files:

```markdown
### evt-012 | 2025-02-10 10:30 | architect-01 | handoff

**Scope**: auth_module
**Summary**: Architecture phase complete, handing off to builder

**Details**:
- From agent: architect-01
- To agent: builder
- Invariants: JWT tokens only, no session storage
- Boundaries: src/auth/ only, max 5 files
- Constraints: Do not modify database schema
- Artifacts: evt-008, evt-010

**Refs**: evt-008, evt-010
**Tags**: handoff, architecture-to-build
```

### Handoff Payloads by Agent Role

| From → To | Payload Contents |
|-----------|-----------------|
| **Architect → Builder** | Invariants, module boundaries, allowed dependencies, folder structure, no-go zones, tier constraints |
| **Builder → Tester** | New/modified functions, expected behaviors, modified flows, implementation notes, suggested test targets |
| **Tester → Doc Manager** | Behavior changes detected, new test cases, uncovered paths, validation results, regression notes |
| **Doc Manager → Validator** | Documentation updates, API changes, migration entries, roadmap adjustments, parity status |

### Handoff Rules

1. **Forward-only** — handoffs go forward in the pipeline, never backward
2. **Scoped** — only information relevant to the next agent's role
3. **Artifact references** — point to event IDs, not raw data (the receiver reads the events)
4. **No forbidden memory** — never include: personal preferences, undocumented assumptions, partial code from other tasks, cross-role opinions
5. **Consumed once** — the receiving agent reads the handoff event, then proceeds; it does not re-read it

---

## 9. Data Flow and Anti-Drift

### One-Way Flow

Information propagates in **one direction only**:

```
Agent Action
    ↓ (append)
Layer 1: Event Log (CHANGELOG.md)
    ↓ (materialize)
Layer 2: Knowledge Graph (graph.md)
    ↓ (project)
Layer 3: Narrative (context.md)
    ↓ (project)
CHANGELOG.md (human-readable)
```

**No reverse flow**. An agent cannot:
- Edit the graph to "fix" the CHANGELOG → append a corrective event instead
- Edit the narrative to change the graph → append an event, rematerialize, regenerate
- Edit the CHANGELOG to match the narrative → the narrative is wrong; regenerate it

### Anti-Drift Mechanisms

| Threat | Defense |
|--------|---------|
| Agent hallucinates a past decision | Changelog has no such event; graph has no such node/edge; ground truth wins |
| Agent modifies graph directly | Detected: graph.md event horizon does not match last event in CHANGELOG.md; rematerialize |
| Narrative drifts from reality | Detected: staleness check fails; regenerate from L1 + L2 |
| Agent retains state from previous task | Impossible: agent died and rebooted; no memory persists outside files |
| Two agents record conflicting decisions | Git merge conflict on CHANGELOG.md; resolved by commit order (see §10) |
| AGENTS.md modified during execution | Detected: git status shows uncommitted changes to AGENTS.md; halt and escalate |

### Ground Truth Hierarchy

When layers conflict, resolve by trust order:

```
Layer 0 (AGENTS.md)     → Highest authority — behavioral rules always win
Layer 1 (CHANGELOG.md)   → Source of truth for all facts
Layer 2 (graph.md)       → Must match Layer 1 — if not, rematerialize
Layer 3 (context.md)     → Must match L1+L2 — if not, regenerate
CHANGELOG.md             → Must match Layer 1 — if not, regenerate
```

---

## 10. Multi-Agent Coordination

**Tier scope:** Full coordination features (graph-based blocking, task nodes, pipeline phases) require **Full** tier. In **Core** tier, agents coordinate via the event log and `context.md` only.

### Shared Substrate

All agents read from the same files. No message passing between agents.

- **Read**: Any number of agents can read any layer concurrently
- **Write**: Only to `CHANGELOG.md` (append) and derived files (materialize/regenerate)
- **Coordination**: Via state changes in the graph, not via direct communication

### Write Serialization

Concurrent writes are serialized by **git**:

1. Agent A appends event to `CHANGELOG.md` and commits
2. Agent B appends a different event and attempts to commit
3. If conflict: Agent B pulls, rebases (append-only guarantees no semantic conflict), re-commits
4. Both events appear in the log in commit order

**Why append-only prevents semantic conflicts**: Two agents appending different events to the end of a markdown file never edit the same section. Git's merge strategy can auto-resolve this in most cases. If it cannot, the later agent rebases.

### Communication via State

Agents do not talk to each other. They communicate through the graph:

- Agent A records `blocker` event → graph gains a `blocks` edge
- Agent B boots, queries graph, sees the blocker, adjusts its plan
- Agent C resolves the blocker → appends `fix` event → graph edge removed by materialization
- Agent B boots again, sees blocker resolved, proceeds

### Race Condition Handling

| Scenario | Resolution |
|----------|-----------|
| Two agents modify the same component | Both events appear in log; later event wins for current state in graph |
| Agent reads stale graph, acts on old state | Agent's changes are valid per its context; if they conflict with newer state, the materialization reveals the conflict and a corrective event is needed |
| Agent pipeline phase executes out of order | Graph tracks `pipeline_phase` per task; validator detects phase skip and rejects |

---

## 11. ACID Guarantees

This system provides database-grade guarantees for AI cognition:

| Property | Implementation |
|----------|---------------|
| **Atomicity** | Each CHANGELOG entry + its git commit is a single indivisible transaction. Either the event is committed or it is not. |
| **Consistency** | The graph is always a valid materialization of the CHANGELOG. Validation checks (§12) enforce structural rules. Layer 0 constraints are checked at boot. |
| **Isolation** | Agents work on local git working copies. Conflicts are resolved at commit time (push/rebase), not during execution. No agent sees another's uncommitted work. |
| **Durability** | Git history is immutable. No committed event can be lost or secretly altered. Force-pushes are detectable and prohibited by branch protection. |

### Ungameability

- **Cannot forget constraints** — `AGENTS.md` is read-only at boot; modifying it requires human approval
- **Cannot hallucinate history** — the CHANGELOG is append-only; fabricated events have no commit hash
- **Cannot fake dependencies** — every graph edge traces to a CHANGELOG event ID
- **Cannot bypass validation** — the validator agent checks graph consistency as the final pipeline phase
- **Cannot silently drift** — staleness checks detect narrative/graph divergence from the event log

---

## 12. Validation

### Per-Layer Checks

#### Layer 0 Validation
- `AGENTS.md` exists and is non-empty
- `AGENTS.md` has not been modified since last commit (during execution)
- All referenced protocol files exist

#### Layer 1 Validation
- `CHANGELOG.md` exists and has a `## Event Log` section
- Every event has the required heading format: `### evt-NNN | YYYY-MM-DD HH:MM | agent | type`
- Every event has **Scope** and **Summary** fields
- Event IDs are unique and sequential
- Timestamps are monotonically non-decreasing
- **Refs** point to existing event IDs
- No existing events have been modified (compare git diff)

#### Layer 2 Validation
- `graph.md` has Nodes table, Edges table, and Meta section
- Meta event horizon matches an actual event ID in the CHANGELOG
- Every node's Created and Last Event columns reference valid event IDs
- Every edge's Created column references a valid event ID
- No orphan edges (both From and To nodes exist in the Nodes table)
- Node Statuses are valid enum values

#### Layer 3 Validation
- `context.md` exists (or can be generated)
- Event horizon comment matches Meta event horizon in graph.md
- All referenced task/blocker/dependency names exist as graph nodes

### Cross-Layer Consistency

| Check | How |
|-------|-----|
| L1 ↔ L2 consistency | Replay all events from CHANGELOG.md; compare resulting graph with stored graph.md |
| L2 ↔ L3 consistency | Regenerate context.md from graph; compare with stored context.md |
| L0 ↔ L1 | Verify no event violates AGENTS.md behavioral rules |

### Self-Healing

When validation fails:
1. **Identify the authoritative layer** (L0 > L1 > L2 > L3)
2. **Rebuild downstream** — regenerate L2 from L1, then L3 from L1+L2
3. **Append corrective event** — log the inconsistency and repair as an event
4. **Never edit upstream** — do not modify L0 or L1 to fix downstream issues

---

## 13. Tier Scaling

Not every project needs all four layers. Scale the memory system to match project complexity. All tiers use pure markdown.

### MVP Tier (Solo, < 1 month, prototype)

**Files used**: `AGENTS.md` + `CHANGELOG.md`

- Layer 0: `AGENTS.md` — behavioral constraints
- Layer 1: `CHANGELOG.md` — event log (append-only)
- Layer 2: Not used — scope is small enough to track mentally
- Layer 3: Not used — the CHANGELOG IS the narrative

**Upgrade trigger**: When you need to track dependencies between components, or when the CHANGELOG exceeds 30 events and you lose track of what connects to what.

### Core Tier (Team, 1-6 months, real project)

**Files used**: `AGENTS.md` + `CHANGELOG.md` + `.memory/context.md`

- Layer 0: `AGENTS.md`
- Layer 1: `CHANGELOG.md` — event log
- Layer 2: Not used — dependencies tracked informally in context.md
- Layer 3: `.memory/context.md` — regenerated per session

**Upgrade trigger**: When dependency tracking becomes complex, when you need to answer "what blocks what?" by scanning structured data, or when more than 3 agents operate concurrently.

### Full Tier (Enterprise, 6+ months, team/multi-agent)

**Files used**: All four layers

- Layer 0: `AGENTS.md`
- Layer 1: `CHANGELOG.md` — event log with archival
- Layer 2: `.memory/graph.md` — materialized knowledge graph (nodes + edges tables)
- Layer 3: `.memory/context.md` — regenerated per session

**All validation, anti-drift, ACID guarantees, and multi-agent coordination features active.**

### Tier Selection

| Signal | MVP | Core | Full |
|--------|-----|------|------|
| Solo developer | ✅ | | |
| Multiple agents or developers | | ✅ | |
| Complex dependency chains | | | ✅ |
| Duration < 1 month | ✅ | | |
| Duration 1-6 months | | ✅ | |
| Duration > 6 months | | | ✅ |
| Need "what blocks what?" queries | | | ✅ |
| Formal handoff protocols needed | | ✅ | ✅ |

---

## 14. Three Pillars Integration

### AUTOMATING

- **Prefer scripts over manual steps**: If a task can be done with a script (especially a reusable one), use the script instead of doing it manually.
- **Event log append**: Every automated action appends its result to `CHANGELOG.md`
- **Materialization**: Graph updates are a deterministic function of the event log — automatable
- **Projection**: `context.md` and `CHANGELOG.md` generation is algorithmic — automatable
- **Validation**: All consistency checks can run as pre-commit hooks or CI steps

### TESTING

- **Event log integrity**: Validate event format, required fields, referential integrity
- **Graph consistency**: Replay events and compare with stored graph
- **Narrative freshness**: Check event horizon matches across layers
- **Anti-drift**: Verify no direct edits to materialized views (graph, narrative, CHANGELOG.md)
- **Behavioral compliance**: Verify no event violates Layer 0 constraints

### DOCUMENTING

- **Self-documenting**: Every decision is an event with a summary and rationale
- **Auto-generated artifacts**: `context.md` and `CHANGELOG.md` are always current
- **Audit trail**: Git history + event log = complete, tamper-evident history
- **Handoff records**: Pipeline handoffs are events with structured payloads, not ephemeral conversations

---

## 15. Retrieval and Tools

Optional scripts (in `docs/memory-system/scripts/` or project-local `memory-system/scripts/`) support **resolve**, **search**, **timeline**, **summarize**, **suggest**, **boot injection**, and **viewer** without changing the core protocol. Run from project root with `--project-root PATH` when needed.

### Resolve event by ID

**Script:** `get_event.py`

Given an event ID (e.g. `evt-001` or `1`), returns the full event text from `CHANGELOG.md` or `CHANGELOG-archive.md`. Use for citations and traceability.

```bash
python docs/memory-system/scripts/get_event.py evt-001 [--project-root PATH]
python docs/memory-system/scripts/get_event.py 1
```

Exit code 1 if not found. Numeric input (e.g. `1`) is normalized to `evt-001` (three-digit).

### Search and progressive disclosure

**Script:** `search_events.py`

- **Keyword search:** Filter by free-text query and/or `--type`, `--scope`, `--tag`; optional `--limit`, `--exclude-sensitive` (default), `--include-archive`. Output: compact index lines `evt-ID | type | scope | summary`.
- **Timeline:** `--timeline evt-NNN --context N` returns full text of that event plus N events before and after.
- **List IDs:** `--list-ids` prints only event IDs.

Workflow: **search** (compact index) → **timeline** (context around an ID) → **get_event** (full event). Saves tokens by fetching full content only for selected IDs.

```bash
python docs/memory-system/scripts/search_events.py [QUERY] [--type TYPE] [--scope SCOPE] [--tag TAG] [--limit N] [--exclude-sensitive] [--include-archive]
python docs/memory-system/scripts/search_events.py --timeline evt-005 --context 2
python docs/memory-system/scripts/search_events.py --list-ids
```

### Event suggester

**Script:** `suggest_event.py`

Drafts one candidate event for approval before appending. Does not write to CHANGELOG.

- `--from-git`: derive draft from `git diff` since last commit (heuristic, no LLM).
- `--from-stdin`: use a one-line summary from stdin as Summary.
- Optional: `--scope`, `--type`, `--agent`, `--tags`. Output: next evt-ID and a full event block to paste into the Event Log after approval.

```bash
python docs/memory-system/scripts/suggest_event.py --from-git [--scope SCOPE] [--type modify]
echo "Summary of changes" | python docs/memory-system/scripts/suggest_event.py --from-stdin
```

### Summarize event ranges

**Script:** `summarize_events.py`

Produces a bullet list of events in a range (for context or archive). Use `--start evt-NNN`, `--end evt-NNN`, or `--last N`. Default: `--exclude-sensitive`; use `--include-sensitive` to include events tagged `private` or `sensitive`.

```bash
python docs/memory-system/scripts/summarize_events.py --last 10 [--exclude-sensitive]
python docs/memory-system/scripts/summarize_events.py --start evt-001 --end evt-020
```

### Relevant events at boot

**Script:** `relevant_events.py`

Returns a compact one-line-per-event index (evt-ID, type, scope, summary) for injection at session start. Optional `QUERY`, `--scope`, `--tag`, `--limit` (default 5). Reads only current CHANGELOG (no archive). Use `--exclude-sensitive` (default) or `--include-sensitive`.

```bash
python docs/memory-system/scripts/relevant_events.py [QUERY] [--scope SCOPE] [--tag TAG] [--limit N]
```

### Web viewer

**Script:** `generate_memory_viewer.py`

Generates a single static HTML file (default `.memory/memory-viewer.html`) with Event Log (anchors by evt-ID), graph.md content, and context.md content. Sensitive events (tags `private` or `sensitive`) are omitted.

```bash
python docs/memory-system/scripts/generate_memory_viewer.py [--project-root PATH] [--output PATH]
```

### Privacy convention

Events whose **Tags** include `private` or `sensitive` (case-insensitive) are treated as sensitive:

- **search_events**, **summarize_events**, **relevant_events**: by default exclude these events from results; use `--include-sensitive` to include them.
- **generate_memory_viewer**: omits sensitive events from the generated HTML.

The event log remains append-only; no content is altered. Filtering is at retrieval time only. Document this convention so agents and humans do not surface private events in shared context.

---

## Quick Reference

### Agent Cheat Sheet

```
BOOT:    Read AGENTS.md → Read context.md → Check staleness → Query graph → Verify constraints
EXECUTE: Work within boundaries → Append events to CHANGELOG.md
SHUTDOWN: Append → Materialize → Regenerate → Commit → Handoff → Die
RECOVER: Trust L1 → Rebuild L2 → Rebuild L3 → Resume
```

### File Trust Order

```
AGENTS.md  >  CHANGELOG.md  >  graph.md  >  context.md
(immutable)   (source of truth) (derived)   (ephemeral)
```

### Data Flow Direction

```
Agent → CHANGELOG.md → graph.md → context.md
       (append only)   (materialize) (regenerate)
```

### When In Doubt

1. **Read the event log** — it is the only truth
2. **Rebuild, don't repair** — regenerate derived layers from upstream
3. **Append, don't edit** — wrong? append a corrective event
4. **Escalate, don't guess** — if constraints are unclear, ask a human
