# CHANGELOG.md

_Event log for _templates repository — all changes, decisions, and milestones_

## Format

```markdown
## YYYY-MM-DD HH:MM — Event Title

**Type:** [decision|change|result|milestone]
**Scope:** [repository|skill-pack|skill|docs]

### What
Description of what happened.

### Why
Reasoning behind the decision.

### Impact
What this affects.

### Next Steps
What happens next.
```

---

## 2026-02-23 02:00 — Implement Unified Memory System

**Type:** decision
**Scope:** repository

### What
Created unified 5-layer memory system across all projects:
- L0: AGENTS.md (behavioral core)
- L1: CHANGELOG.md (this file — event log)
- L2: .memory/graph.md (knowledge graph)
- L3: .memory/context.md (narrative)
- L4: lessons/*.md (critical patterns)

### Why
Need consistent memory system across openclaw-memories, _templates, and kindred-ai for agent continuity.

### Impact
All three projects now use same memory architecture. Agents can move between projects seamlessly.

### Next Steps
- Populate L2, L3, L4 with existing knowledge
- Create cross-project references
- Update AGENTS.md to reference unified system

---

## 2026-02-23 01:30 — Cross-Project AGENTS.md Standardization

**Type:** change
**Scope:** docs

### What
Standardized AGENTS.md across all three projects with feature parity.

### Changes
- Added Three Pillars section to all
- Added Prompt Validation to all
- Added Security Patterns to all
- Created docs/ folders with auxiliary guides
- Sub-agent patterns, editing strategies

### Impact
Consistent agent behavior across projects.

---

## 2026-02-23 01:00 — Create Comprehensive Documentation

**Type:** change
**Scope:** docs

### What
Added detailed guides to docs/ folders:
- THREE_PILLARS.md
- MEMORY_SYSTEM.md
- SUB_AGENT_PATTERNS.md
- EDITING_STRATEGIES.md

### Impact
Better agent onboarding and reference.

---

## Earlier Events

*See git log for history prior to unified memory system implementation.*

```bash
git log --oneline -30
```

---

*Append-only — never edit past entries*
