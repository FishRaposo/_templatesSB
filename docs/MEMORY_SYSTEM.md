# Memory System Protocol — Detailed Guide

_Event-sourced memory for multi-agent cognition_

## The Four Layers

```
┌─────────────────────────────────────────┐
│ L3: Narrative    (Derived, ephemeral)   │
│    .memory/context.md                   │
├─────────────────────────────────────────┤
│ L2: Knowledge Graph (Materialized view) │
│    .memory/graph.md                     │
├─────────────────────────────────────────┤
│ L1: Event Log    (Append-only source)   │
│    CHANGELOG.md                         │
├─────────────────────────────────────────┤
│ L0: Behavioral Core (Immutable at boot) │
│    AGENTS.md                            │
└─────────────────────────────────────────┘
```

## Layer 0: Behavioral Core (AGENTS.md)

**Purpose:** Constraints and rules for all agents

**Characteristics:**
- Immutable during execution
- Read once at boot
- Never modified by running agents
- Updated only by external processes

**Contains:**
- Do/Don't rules
- File naming conventions
- Workflow definitions
- Key file roles

## Layer 1: Event Log (CHANGELOG.md)

**Purpose:** Append-only source of truth

**Characteristics:**
- Append-only (never edit or delete)
- Chronological order
- Every decision, change, result
- Human-readable but structured

**Format:**
```markdown
## YYYY-MM-DD HH:MM — Event Title

**Type:** [decision|change|result|milestone]
**Scope:** [project|pack|skill|file]

### What
Description of what happened.

### Why
Reasoning behind the decision.

### Impact
What this affects, what to watch for.

### Next Steps
What happens next.
```

**Rules:**
1. If it's not in the event log, it didn't happen
2. One event per logical unit of work
3. Link to affected files
4. Include reasoning, not just what

## Layer 2: Knowledge Graph (.memory/graph.md)

**Purpose:** Queryable view of entities and relations

**Characteristics:**
- Materialized from L1
- Regenerated when stale
- Graph structure (nodes + edges)
- Supports complex queries

**Format:**
```markdown
# Knowledge Graph

## Entities

### Skills
- [[skill-id]] — Name — Status — Pack

### Packs
- [[pack-id]] — Name — Completion % — Skills count

### Files
- [[file-path]] — Type — Related entities

## Relations

### Depends On
- [[skill-a]] → [[skill-b]]

### Part Of
- [[skill-x]] → [[pack-y]]

### References
- [[file-a]] → [[file-b]]
```

**Regeneration trigger:**
- After significant batch of events
- When query results seem stale
- Before complex planning tasks
- On agent handoff

## Layer 3: Narrative (.memory/context.md)

**Purpose:** Current trajectory and immediate context

**Characteristics:**
- Derived from L1 and L2
- Ephemeral (regenerated per session)
- Human-readable summary
- Focus on "where we are now"

**Format:**
```markdown
# Current Context

## Session Summary
What we're working on right now.

## Recent Events
Last 5-10 events from CHANGELOG.

## Active Entities
Skills, packs, files currently in focus.

## Blockers/Issues
Anything preventing progress.

## Next Actions
What should happen next.
```

**Regenerated:** Every session start

## One-Way Data Flow

```
AGENTS.md ──read──┐
                  │
CHANGELOG.md ─────┼──→ graph.md ──→ context.md
   (append)       │      (rebuild)    (regenerate)
                  │
             (never backward)
```

**Critical rule:** Never write backward. Event Log is source of truth.

## Agent Lifecycle

### BOOT Phase

```
1. Read AGENTS.md (L0)
   └── Load constraints and rules

2. Read context.md (L3)
   └── Understand current trajectory
   └── Check if stale (compare timestamps)

3. If stale or missing:
   a. Query graph.md (L2) for relevant entities
   b. Or regenerate graph from CHANGELOG (L1)
   c. Regenerate context.md

4. Ready to execute
```

### EXECUTE Phase

```
1. Work within constraints from AGENTS.md
2. Follow trajectory from context.md
3. Query graph.md for relationships
4. Do the work
```

### SHUTDOWN Phase

```
1. APPEND events to CHANGELOG.md (L1)
   └── One event per logical unit
   └── Include what, why, impact, next steps

2. If significant changes:
   MATERIALIZE graph.md (L2)
   └── Scan recent events
   └── Update entity statuses
   └── Add new relations
   └── Remove stale ones

3. REGENERATE context.md (L3)
   └── Summarize new state
   └── Update trajectory
   └── List next actions

4. COMMIT all changes
   └── CHANGELOG.md
   └── .memory/graph.md
   └── .memory/context.md
   └── Any modified content files

5. HANDOFF (if applicable)
   └── Package state for next agent
   └── Include recent events
   └── Highlight active entities

6. DIE
   └── No retained state
   └── Fresh boot next time
```

## Statelessness

**Principle:** Agents are stateless. All state is in files.

**Implications:**
- Boot from files every session
- No "remembering" across sessions
- No in-memory state that matters
- If files are lost, state is lost

**Benefits:**
- Resilience (crash = just reboot)
- Auditability (everything in git)
- Parallelization (agents don't conflict)
- Reproducibility (same files = same behavior)

## ACID Guarantees

**Atomicity:** Events are atomic units. One event = one logical change.

**Consistency:** L2 and L3 are always consistent with L1. Regenerate if unsure.

**Isolation:** Agents work in isolation, commit when done. No mid-work visibility.

**Durability:** Commits are durable (git). Events survive crashes.

## Handoff Protocol

When passing work between agents:

### Payload

```json
{
  "handoff": {
    "from": "agent-a",
    "to": "agent-b",
    "timestamp": "ISO-8601",
    "reason": "session timeout | task complete | escalation"
  },
  "state": {
    "recent_events": ["last-5-events"],
    "active_entities": ["skill-foo", "pack-bar"],
    "blockers": ["if any"],
    "next_actions": ["what to do next"]
  },
  "files": {
    "modified": ["list of changed files"],
    "committed": "commit-hash",
    "changelog_updated": true
  }
}
```

### Process

1. Current agent completes work
2. Appends to CHANGELOG
3. Regenerates graph and context
4. Commits everything
5. Creates handoff payload
6. Next agent boots, reads payload
7. Next agent reads context.md for trajectory
8. Continues work

## Validation

### L1 Validation (CHANGELOG.md)

- [ ] Chronological order
- [ ] No edits to old entries
- [ ] All entries have timestamps
- [ ] All entries have types
- [ ] References link to real files

### L2 Validation (graph.md)

- [ ] All entities exist in L1
- [ ] All relations valid
- [ ] No orphaned entities
- [ ] Statuses match L1

### L3 Validation (context.md)

- [ ] Generated from fresh L1/L2
- [ ] Recent events match L1
- [ ] Active entities exist in L2
- [ ] Next actions are clear

## Troubleshooting

### "I don't know where we are"

→ Regenerate context.md from CHANGELOG

### "This info seems wrong"

→ Check if graph.md is stale, regenerate from L1

### "I can't find X"

→ Query graph.md, or grep CHANGELOG for X

### "Two agents conflicted"

→ Check CHANGELOG order. Later event wins.

### "Files are inconsistent"

→ Rebuild L2 and L3 from L1 (source of truth)

---

*See also: `../AGENTS.md` (Memory System Protocol section)*
