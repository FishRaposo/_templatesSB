Add this section to the project's AGENTS.md:

```markdown
## Memory System Protocol

This project uses an event-sourced memory system. See `.memory/` for live state. **Full protocol:** `docs/protocols/MEMORY-SYSTEM-PROTOCOL.md` (Protocols template type).

- **Layer 0** (`AGENTS.md`): Immutable during execution. Read at boot only.
- **Layer 1** (`CHANGELOG.md`): Append-only source of truth (use `## Event Log` and evt-NNN).
- **Layer 2** (`.memory/graph.md`): Materialized view. Update only from L1.
- **Layer 3** (`.memory/context.md`): Derived projection. Regenerate when stale.

### Agent lifecycle
BOOT:   Read AGENTS.md → Read .memory/context.md → Check staleness (Event horizon vs last evt in CHANGELOG Event Log) → If stale/missing, regenerate context (and graph) → Optionally run relevant_events.py for recent index
EXECUTE: Work within constraints → Append events to CHANGELOG.md (Event Log section)
SHUTDOWN: Append → Materialize → Regenerate → Commit

### Core rules
1. Append-only — if it is not in the event log, it did not happen
2. One-way flow — Event Log → Graph → Narrative; never backward
3. Stateless agents — boot from files, execute, write, terminate
4. Rebuild, don't repair — regenerate derived layers from upstream when inconsistent

**Before every task (load memory):**
1. Read AGENTS.md — behavioral constraints
2. Read .memory/context.md — current trajectory (if missing, create from CHANGELOG + graph per protocol)
3. Check staleness: Event horizon in .memory/context.md must match last event ID in CHANGELOG.md (under ## Event Log). If they differ or context is missing, regenerate .memory/context.md (and .memory/graph.md if in use) before proceeding
4. Optionally: when docs/memory-system/scripts/relevant_events.py (or memory-system/scripts/relevant_events.py) exists, run it for a compact recent-events index

**After every task:**
1. Append event to CHANGELOG.md (under ## Event Log, next evt-NNN)
2. Update derived views (graph.md, context.md)
3. Update AGENTS.md if conventions changed

Follow `docs/protocols/MEMORY-SYSTEM-PROTOCOL.md` for the complete process (retrieval tools, tier scaling, validation, etc.).
```
