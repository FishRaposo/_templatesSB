# System Map — _templatesSB

_Architecture overview — keep this current with every structural change._

**Last updated**: 2026-02-27 (evt-012)

---

## System Overview

```
                    ┌─────────────────────────────────────────┐
                    │  L0: AGENTS.md (Constitution)           │
                    │  Rules: AGENTS, CLAUDE, CURSOR, WINDSURF│
                    └──────────────────┬──────────────────────┘
                                       │ governs
                    ┌──────────────────▼──────────────────────┐
                    │  L1: CHANGELOG.md (Event Log)           │
                    │  Append-only source of truth            │
                    └──────┬─────────────────────┬───────────┘
         materializes     │                     │ derives
    ┌─────────────────────▼──┐         ┌───────▼────────────┐
    │  L2: .memory/graph.md  │         │  L3: .memory/       │
    │  Nodes, edges, horizon │         │  context.md         │
    └────────────────────────┘         └─────────────────────┘
                    │
    ┌───────────────┴───────────────────────────────────────────┐
    │  docs/protocols/   (PROMPT-VALIDATION, MEMORY-SYSTEM)     │
    │  .agents/skills/   (nine skills — setup + protocol)       │
    │  docs/             (INDEX, guides, memory-system, etc.)   │
    │  _documentation-blueprint/  (blueprint + templates)        │
    └───────────────────────────────────────────────────────────┘
```

---

## Component Inventory

| Component | Purpose | Location | Owner | Status |
|-----------|---------|----------|-------|--------|
| Rules | Agent behavioral constraints | `AGENTS.md`, `CLAUDE.md`, `CURSOR.md`, `WINDSURF.md` | Maintainers | Active |
| Protocols | Process definitions (prompt validation, memory) | `docs/protocols/` | prompt-validation-setup, memory-system-setup skills | Active |
| Skills | Reusable capabilities (setup, protocol install) | `.agents/skills/` (nine skills) | Maintainers | Active |
| Memory L1 | Event log | `CHANGELOG.md` (## Event Log) | All agents | Active |
| Memory L2 | Knowledge graph | `.memory/graph.md` | Materialized from L1 | Active |
| Memory L3 | Narrative context | `.memory/context.md` | Regenerated from L1+L2 | Active |
| Docs hub | Index, guides, protocols, memory-system | `docs/` | Maintainers | Active |
| Documentation blueprint | Baseline and templates | `_documentation-blueprint/` | Maintainers | Active |
| Archive | Legacy content | `_complete_archive/` | Read-only | Archived |

---

## Data Flow

1. **Boot**: Agent reads AGENTS.md (L0) → .memory/context.md (L3) → checks staleness (event horizon vs CHANGELOG last event) → if stale, regenerate context (and graph) from CHANGELOG.
2. **Execute**: Agent works within Rules; may invoke Skills; references Protocols (e.g. docs/protocols/PROMPT-VALIDATION-PROTOCOL.md) for validation and memory steps.
3. **Shutdown**: Append event(s) to CHANGELOG.md (L1) → materialize .memory/graph.md (L2) → regenerate .memory/context.md (L3) → commit.

**One-way**: L1 → L2 → L3. Never edit L2 or L3 backward to match an older state.

---

## Dependency Map

### External Dependencies

| Dependency | Purpose | Risk |
|------------|---------|------|
| Git | Version control, history | Low |
| Python 3 | JSON validation, optional scripts | Low |
| Markdown/JSON/YAML | Content format | Low |

### Internal Dependencies

- Rules reference Protocols (by path) and template framework (AGENTIC-ASSETS-FRAMEWORK.md).
- Skills are standalone but reference project paths (e.g. AGENTS.md, docs/protocols/).
- Memory: context.md and graph.md depend only on CHANGELOG.md; graph horizon must match last event.

---

## Architecture Decisions

| Decision | Event | Rationale Summary |
|----------|-------|-------------------|
| Protocols as seventh template type | evt-006 | Process docs (prompt validation, memory) live in docs/protocols/; protocol skills install them. |
| skill-builder → skill-setup; nine skills | evt-007 | Naming consistency with *-setup skills; protocol-setup added for Protocols type. |
| Memory and prompt validation as protocol skills | evt-008 | Both install/maintain protocol files; Rules link to protocols, do not duplicate. |
| Documentation blueprint vs current comparison | evt-011, evt-012 | Align repo with Core tier; bidirectional improvements (blueprint ↔ current). |

For full event details, see `CHANGELOG.md` (## Event Log).

---

## Boundaries and Constraints

- **Append-only CHANGELOG**: Never edit or delete existing events; append only.
- **No modification of _complete_archive/**: Read-only reference; do not change archived files.
- **Graph/context from L1 only**: .memory/graph.md and .memory/context.md are derived from CHANGELOG; regenerate when stale, never hand-edit to match an older event.

---

_Update this file whenever architecture changes. Log the update as a `modify` event in CHANGELOG.md._
