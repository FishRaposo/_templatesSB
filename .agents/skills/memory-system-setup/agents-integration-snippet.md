Add this section to the project's AGENTS.md:

```markdown
## Memory System Protocol

This project uses an event-sourced memory system. See `.memory/` for live state.

- **Layer 0** (`AGENTS.md`): Immutable during execution. Read at boot only.
- **Layer 1** (`CHANGELOG.md`): Append-only source of truth.
- **Layer 2** (`.memory/graph.md`): Materialized view. Update only from L1.
- **Layer 3** (`.memory/context.md`): Derived projection. Regenerate when stale.

### Agent lifecycle
BOOT:   Read AGENTS.md → Read context.md → Check staleness → Query graph
EXECUTE: Work within constraints → Append events to CHANGELOG.md
SHUTDOWN: Append → Materialize → Regenerate → Commit

### Core rules
1. Append-only — if it is not in the event log, it did not happen
2. One-way flow — Event Log → Graph → Narrative; never backward
3. Stateless agents — boot from files, execute, write, terminate
4. Rebuild, don't repair — regenerate derived layers from upstream when inconsistent
```
