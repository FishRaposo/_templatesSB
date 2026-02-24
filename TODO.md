# TODO

> Pending tasks, planned work, and progress tracking for the Skills Repository.

---

## In Progress

- [ ] **Pack 4–60 creation** — Build remaining 56 skill packs following the established pattern
  - Priority: high
  - Depends on: Pack 3 (validates the workflow for post-infrastructure packs)

---

## Up Next

(none — In Progress is the immediate queue)

---

## Completed

- [x] **Pack 1 (programming-core)** — 12 skills, 19 reference files, multi-language JS/Python/Go/Rust — evt-001
- [x] **Pack 2 (code-quality)** — 12 skills, 19 reference files, multi-language JS/Python/Go — evt-002
- [x] **Pack 3 (testing-mastery)** — 12 skills, verification tasks defined, multi-language JS/Python/Go — evt-019
- [x] **Prompt validation system** — Created skill, converted to protocol, integrated into AGENTS.md — evt-003, evt-004
- [x] **Archive documentation** — PROMPT-VALIDATION-SYSTEM-REFERENCE.md and PROJECT-MEMORY-SYSTEM-REFERENCE.md — evt-005, evt-006
- [x] **Memory system architecture** — 4-layer event-sourced design, protocol spec, pure-markdown templates — evt-007 through evt-012
- [x] **Memory system self-application** — .memory/ folder tracking this project's own state — evt-012
- [x] **Memory system finalization** — Eliminated dual-file pattern, merged into single root files — evt-018

---

## Backlog

- [ ] **Standalone skill: skill-builder** — Verify and polish the existing skill-builder skill
  - Priority: medium

- [ ] **Standalone skill: generating-agents-md** — Verify and polish the existing generating-agents-md skill
  - Priority: medium

- [ ] **Archive index maintenance** — Keep ARCHIVE-DOCUMENTATION-INDEX.md current as new references are created
  - Priority: low

---

## Guidelines

### Task Format
```markdown
- [ ] **Task title** — Brief description
  - Owner: who is responsible (or unassigned)
  - Priority: high | medium | low
  - Depends on: prerequisite tasks
  - Refs: evt-NNN (event IDs from CHANGELOG.md)
```

### Rules
1. Move tasks to **Completed** (with `[x]`) when done — never delete them
2. Every completion should have a corresponding event in `CHANGELOG.md`
3. Keep **In Progress** to 1–3 items — work in progress is inventory, minimize it
4. **Up Next** contains the immediately actionable queue
5. **Backlog** contains everything else, roughly ordered by priority
