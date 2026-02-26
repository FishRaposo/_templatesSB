# AGENTS.md — {{PROJECT_NAME}}

_Behavioral core for all AI agents working on this project. Read this at boot. This is your constitution._

**Project**: {{PROJECT_NAME}}  
**Stack**: {{STACK}}  
**Tier**: {{TIER}}

---

## Project Identity

{{PROJECT_DESCRIPTION}}

**Repository**: {{REPO_URL}}  
**Primary language**: {{PRIMARY_LANGUAGE}}

---

## Do

- Follow the exact directory structure defined in this file
- Append all decisions and changes to `CHANGELOG.md` before closing any task
- Satisfy all Three Pillars before declaring a task complete
- Use `{{DOUBLE_CURLY_BRACES}}` style for any template placeholder values that still need filling
- Keep `README.md` under 150 lines — long content belongs in `docs/`
- Validate prompt before starting any task (see Prompt Validation section below)
- Update `.memory/graph.md` and `.memory/context.md` after significant changes
- **Use the right tool for the job** — invoke skills when available, spawn subagents for parallel work, run scripts for mechanical checks, use LLM judgment only for genuine reasoning
- Escalate to a human when constraints are unclear — do not guess

## Don't

- Modify `AGENTS.md` during task execution — it is immutable at runtime
- Edit existing events in `CHANGELOG.md` — append only
- Edit `.memory/graph.md` directly — materialize from `CHANGELOG.md` only
- Leave `{{PLACEHOLDER}}` strings in any committed file
- Skip documentation updates because "it's a small change"
- Add new top-level files or directories without explicit human approval

---

## File Naming Conventions

- **Source files**: follow `{{STACK}}` conventions
- **Documentation**: `UPPER_CASE.md` for project-level, `kebab-case.md` for topic docs
- **Templates**: `*.tpl.md` for documentation templates
- **Memory files**: `.memory/graph.md`, `.memory/context.md`

---

## Project Structure

_Replace the block below with the structure matching your tier (MVP / Core / Full). See `DOCUMENTATION-BLUEPRINT.md §3`._

```
{{PROJECT_NAME}}/              ← Replace with actual directory name
├── AGENTS.md                   ← L0: You are here
├── CHANGELOG.md                ← L1: Event log (append-only)
├── README.md                   ← Project gateway
├── TODO.md                     ← Task tracker            [Core+]
├── QUICKSTART.md               ← Fast setup guide        [Core+]
├── CONTRIBUTING.md             ← Contribution guidelines [Core+]
├── SECURITY.md                 ← Security policy         [Core+]
├── .memory/
│   ├── graph.md                ← L2: Knowledge graph     [Core+]
│   └── context.md              ← L3: Current narrative
└── docs/
    ├── SYSTEM-MAP.md           ← Architecture map        [Core+]
    └── PROMPT-VALIDATION.md    ← Prompt validation       [Core+]
```

---

## Workflow

### Boot Sequence (every agent, every task)

```
1. READ    AGENTS.md              → Load constraints
2. READ    .memory/context.md     → Load trajectory
3. CHECK   Staleness              → Regenerate if stale or missing
4. READ    .memory/graph.md       → Query task neighborhood
5. VERIFY  Constraints            → Confirm task is in bounds
6. EXECUTE Task
```

### Shutdown Sequence

```
1. APPEND        All changes to CHANGELOG.md
2. MATERIALIZE   New events into .memory/graph.md
3. REGENERATE    .memory/context.md
4. COMMIT        All changes in one git commit
5. HANDOFF       Write handoff event if in pipeline
6. DIE           No retained state
```

---

## Three Pillars

A task is **not complete** until all three pass:

### AUTOMATING

**ALWAYS prioritize scripts over manual inspection.** If a script can check it, the script MUST check it. Never use LLM judgment for what a script can verify faster, cheaper, and more accurately.

**Priority order for any mechanical task**: (1) Use existing project scripts → (2) Use standard tools (`grep`, `find`, `markdownlint`, `lychee`) → (3) Write a new one-liner script → (4) Only as last resort, manual inspection.

Run these scripts — do not manually inspect what a script can verify:

- [ ] **Structure validator** run — 0 errors (required sections, naming conventions, tier structure)
- [ ] **Placeholder scanner** run — `grep -r '{{' .` returns 0 matches (no `{{PLACEHOLDER}}` strings in any file)
- [ ] **Link checker** run — 0 broken links, all referenced files exist
- [ ] **Linter / formatter** run — `{{LINT_COMMAND}}` returns 0 style errors
- [ ] All automated checks exited with 0 errors — no exceptions

If no project scripts exist, **write them first**. A one-line grep or 5-line shell script satisfies this pillar. Writing the script IS part of completing the task.

### TESTING

- [ ] All code examples are runnable
- [ ] Setup instructions verified end-to-end
- [ ] All internal links resolve

### DOCUMENTING

- [ ] `CHANGELOG.md` has an event for this change
- [ ] All affected documentation matches implementation
- [ ] `.memory/graph.md` and `.memory/context.md` regenerated

---

## Memory System

| Layer | File | Role | Rule |
|-------|------|------|------|
| L0 | `AGENTS.md` | Constitution | Immutable during execution |
| L1 | `CHANGELOG.md` | Event log | Append-only |
| L2 | `.memory/graph.md` | Knowledge graph | Materialize from L1 only |
| L3 | `.memory/context.md` | Narrative | Regenerate from L1 + L2 |

**Trust order**: L0 > L1 > L2 > L3. When layers conflict, higher layer wins.

---

## Prompt Validation

Before starting any task, run Quick Validation (4 checks must pass):

1. **Purpose in first line** — can you state the task in one sentence?
2. **All variables defined** — no undefined `{{PLACEHOLDER}}` or `[VARIABLE]` in the prompt?
3. **No dangerous patterns** — no script injection, command injection, or path traversal?
4. **Output format specified** — does the prompt define what the output should look like?

If any check fails: stop and ask for clarification.

---

## Documentation Parity

| Change Type | Update These Files |
|-------------|-------------------|
| New feature | README.md, SYSTEM-MAP.md, CHANGELOG.md |
| API change | API docs, CHANGELOG.md, QUICKSTART.md |
| Dependency | CONTRIBUTING.md, QUICKSTART.md, CHANGELOG.md |
| Security fix | SECURITY.md, CHANGELOG.md |
| Architecture | SYSTEM-MAP.md, AGENTS.md if behavioral, CHANGELOG.md |

---

_Last updated_: {{DATE}}
