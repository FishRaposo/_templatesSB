# .memory/ Folder Guide

_How to use the memory system_

## Files

| File | Purpose | Update Frequency |
|------|---------|------------------|
| `graph.md` | Knowledge graph (entities/relations) | After skill creation batches |
| `context.md` | Current trajectory | Every session |

## Workflow

### Session Start

1. Read `graph.md` — Understand skill landscape
2. Read `context.md` — Understand current work
3. Proceed with task

### Session End

1. Update `graph.md` — Add new skills/relations
2. Regenerate `context.md` — New trajectory
3. Commit both files

## Cross-Project

See also:
- [openclaw-memories/.memory/](../../openclaw-memories/.memory/)
- [kindred-ai/.memory/](../../kindred-ai/.memory/)

---
