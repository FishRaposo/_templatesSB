# AGENTS.md — TestProject

_Behavioral core for all AI agents working on this project. Read this at boot. This is your constitution._

**Project**: TestProject  
**Stack**: python  
**Tier**: core

---

## Project Identity

A test project for validation

**Repository**: {{FILL_ME:REPO_URL}}  
**Primary language**: Python

---

## Do

- Follow the exact directory structure defined in this file
- Append all decisions and changes to `CHANGELOG.md` before closing any task
- Satisfy all Three Pillars before declaring a task complete
- Keep `README.md` under 150 lines — long content belongs in `docs/`
- Validate prompt before starting any task (see docs/PROMPT-VALIDATION.md - Core+)
- Update `.memory/graph.md` (Core+) and `.memory/context.md` after significant changes
- Use the right tool for the job — invoke skills when available, spawn subagents for parallel work
- Escalate to a human when constraints are unclear — do not guess

## Don't

- Modify `AGENTS.md` during task execution — it is immutable at runtime
- Edit existing events in `CHANGELOG.md` — append only
- Edit `.memory/graph.md` directly (Core+ tier) — materialize from `CHANGELOG.md` only
- Skip documentation updates because "it's a small change"
- Add new top-level files or directories without explicit human approval

---

## File Naming Conventions

- **Source files**: follow `python` conventions
- **Documentation**: `UPPER_CASE.md` for project-level, `kebab-case.md` for topic docs
- **Memory files**: `.memory/graph.md` (Core+), `.memory/context.md`

---

## Project Structure

```
TestProject/
├── AGENTS.md                   ← L0: You are here
├── CHANGELOG.md                ← L1: Event log (append-only)
├── README.md                   ← Project gateway
├── TODO.md                     ← Task tracker            [Core tier+]
├── QUICKSTART.md               ← Fast setup guide        [Core tier+]
├── CONTRIBUTING.md             ← Contribution guidelines [Core tier+]
├── SECURITY.md                 ← Security policy         [Core tier+]
├── .memory/
│   ├── graph.md                ← L2: Knowledge graph     [Core tier+]
│   └── context.md              ← L3: Current narrative
└── docs/
    ├── SYSTEM-MAP.md           ← Architecture map        [Core tier+]
    └── PROMPT-VALIDATION.md    ← Prompt validation       [Core tier+]
```

---

## Workflow

### Boot Sequence (every agent, every task)

```
1. READ    AGENTS.md              → Load constraints
2. READ    .memory/context.md     → Load trajectory
3. CHECK   Staleness              → Regenerate if stale or missing
4. READ    .memory/graph.md       → Query task neighborhood [Core tier+]
5. VERIFY  Constraints            → Confirm task is in bounds
6. EXECUTE Task
```

### Shutdown Sequence

```
1. APPEND        All changes to CHANGELOG.md
2. MATERIALIZE   New events into .memory/graph.md [Core tier+]
3. REGENERATE    .memory/context.md
4. COMMIT        All changes in one git commit
5. HANDOFF       Write handoff event if in pipeline
```

---

## Three Pillars

A task is **not complete** until all three pass:

### AUTOMATING

**ALWAYS prioritize scripts over manual inspection.** If a script can check it, the script MUST check it.

**Priority order**: (1) Use existing project scripts → (2) Use standard tools (grep, find, markdownlint) → (3) Write a new one-liner → (4) Manual only as last resort

- [ ] **Structure validator** run — 0 errors
- [ ] **Placeholder scanner** run — `grep -r '{{' .` returns 0 matches
- [ ] **Link checker** run — 0 broken links
- [ ] **Linter / formatter** run — `ruff check .` returns 0 errors
- [ ] All automated checks exited with 0 errors

### TESTING

- [ ] All code examples are runnable
- [ ] Setup instructions verified end-to-end
- [ ] All internal links resolve

### DOCUMENTING

- [ ] `CHANGELOG.md` has an event for this change
- [ ] All affected documentation matches implementation
- [ ] `.memory/graph.md` and `.memory/context.md` regenerated [Core tier+]

---

## Memory System

| Layer | File | Role | Rule |
|-------|------|------|------|
| L0 | `AGENTS.md` | Constitution | Immutable during execution |
| L1 | `CHANGELOG.md` | Event log | Append-only |
| L2 | `.memory/graph.md` | Knowledge graph | Materialize from L1 only [Core+] |
| L3 | `.memory/context.md` | Narrative | Regenerate from L1 + L2 |

**Trust order**: L0 > L1 > L2 > L3. When layers conflict, higher layer wins.

---

## Prompt Validation

Before starting any task, run Quick Validation (4 checks must pass):

1. **Purpose in first line** — can you state the task in one sentence?
2. **All variables defined** — no undefined `{{` + `PLACEHOLDER` + `}}` or `[VARIABLE]`?
3. **No dangerous patterns** — no script injection, command injection, or path traversal?
4. **Output format specified** — does the prompt define what the output should look like?

If any check fails: stop and ask for clarification.

See `docs/PROMPT-VALIDATION.md` (Core+ tier) for full validation protocol.

---

## Documentation Parity

| Change Type | Update These Files |
|-------------|-------------------|
| New feature | README.md, CHANGELOG.md |
| API change | API docs, CHANGELOG.md, QUICKSTART.md (Core+) |
| Dependency | CONTRIBUTING.md (Core+), QUICKSTART.md (Core+), CHANGELOG.md |
| Security fix | SECURITY.md (Core+), CHANGELOG.md |
| Architecture | SYSTEM-MAP.md (Core+), AGENTS.md if behavioral, CHANGELOG.md |

---

_Last updated_: 2026-02-28
