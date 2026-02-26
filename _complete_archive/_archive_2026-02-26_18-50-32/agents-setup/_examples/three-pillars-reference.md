# Three Pillars Framework — Comprehensive Reference

**Purpose**: Deep reference for implementing the Three Pillars Framework (AUTOMATING, TESTING, DOCUMENTING) in any AGENTS.md file. Use this alongside `basic-examples.md` for copy-paste templates.

---

## Why Three Pillars

Most AGENTS.md files cover *what* to build (Do/Don't, code style) but not *how to finish*. Without explicit completion criteria, agents decide for themselves when work is "done" — and they consistently skip verification, testing, or documentation updates.

The Three Pillars solve this by making **task completion** a first-class section of AGENTS.md:

| Problem | Which Pillar Prevents It |
|---------|-------------------------|
| Agent commits code that fails linting | **AUTOMATING** — mandatory post-task verification |
| Agent ships features without tests | **TESTING** — explicit test requirements per change type |
| AGENTS.md goes stale after first week | **DOCUMENTING** — change-type checklists for self-updating |
| Agent removes failing tests to "fix" the suite | **TESTING** — "never remove or weaken tests" rule |
| Agent adds dependency but Tech Stack section is wrong | **DOCUMENTING** — dependency change → update Tech Stack |
| Agent runs full build after every one-line change | **AUTOMATING** — file-scoped commands enforced |

### Why Not Two Pillars? Why Not Four?

- **Two pillars** (e.g., just Testing + Documenting) miss the verification layer — agents commit code that doesn't lint or type-check.
- **Four+ pillars** (e.g., adding Security, Performance) create cognitive overhead. Security and performance rules belong in Do/Don't/Boundaries, not in the completion criteria. The Three Pillars are *universal completion gates*, not domain-specific rules.

---

## Multi-Stack Templates

### JavaScript / TypeScript

```markdown
## Task Completion — AUTOMATING

After every code change, run these checks on the files you modified:

1. **Lint**: `npx eslint --fix path/to/changed/file.tsx`
2. **Type-check**: `npx tsc --noEmit path/to/changed/file.tsx`
3. **Format**: `npx prettier --write path/to/changed/file.tsx`

A task is not complete until all three pass. Do not commit code that fails linting or type-checking.

## Task Completion — TESTING

Every code change must include verification:

- **New features**: Write tests before or alongside the implementation
- **Bug fixes**: Add a regression test that reproduces the bug, then fix
- **Refactors**: Run existing tests to confirm no regressions

Run tests on changed files: `npx vitest run path/to/changed/file.test.tsx`

Do not remove or weaken existing tests to make the suite pass.

## Task Completion — DOCUMENTING

This AGENTS.md must stay in sync with the codebase. After completing any task, check whether your changes require updates here.

**By change type:**

| Change Type | Update These Sections |
|-------------|----------------------|
| New dependency | Tech Stack |
| New command or script | Commands |
| New directory or moved files | Project Structure |
| New pattern established | Do section |
| Anti-pattern discovered | Don't section |
| New config, CI, or tooling | Relevant sections |
| Git workflow change | Git Workflow |
| Bug fix | Don't section (if it was a recurring mistake) |
| Refactor | Project Structure, Code Examples |
| Security change | Boundaries |

**How to update:**
1. After completing your primary task, review what changed
2. Update the relevant AGENTS.md section(s) in the same commit/PR
3. Keep updates minimal and factual — match the existing style
4. If working in a subdirectory with its own AGENTS.md, update that file instead

**Do not:**
- Skip the update because "it's a small change" — small drift compounds
- Rewrite sections unrelated to your change
- Remove existing rules without explicit approval

## Three Pillars — Every Task Must Satisfy All Three

A task is **not complete** until:
1. ✅ **AUTOMATING** — Lint, type-check, and format pass on all changed files
2. ✅ **TESTING** — Tests pass, new code has tests, no tests removed
3. ✅ **DOCUMENTING** — This AGENTS.md is updated if the change affects it

Skipping any pillar = incomplete work.
```

### Python

```markdown
## Task Completion — AUTOMATING

After every code change, run these checks on the files you modified:

1. **Lint**: `ruff check --fix path/to/changed/file.py`
2. **Type-check**: `mypy path/to/changed/file.py`
3. **Format**: `ruff format path/to/changed/file.py`

A task is not complete until all three pass. Do not commit code that fails linting or type-checking.

## Task Completion — TESTING

Every code change must include verification:

- **New features**: Write tests before or alongside the implementation
- **Bug fixes**: Add a regression test that reproduces the bug, then fix
- **Refactors**: Run existing tests to confirm no regressions

Run tests on changed files: `pytest path/to/test_changed_file.py -v`

Do not remove or weaken existing tests to make the suite pass.

## Task Completion — DOCUMENTING

This AGENTS.md must stay in sync with the codebase. After completing any task, check whether your changes require updates here.

**By change type:**

| Change Type | Update These Sections |
|-------------|----------------------|
| New dependency | Tech Stack, `pyproject.toml` or `requirements.txt` |
| New command or script | Commands |
| New directory or moved files | Project Structure |
| New pattern established | Do section |
| Anti-pattern discovered | Don't section |
| New config, CI, or tooling | Relevant sections |
| Git workflow change | Git Workflow |
| Bug fix | Don't section (if it was a recurring mistake) |
| Refactor | Project Structure, Code Examples |
| Security change | Boundaries |

**How to update:**
1. After completing your primary task, review what changed
2. Update the relevant AGENTS.md section(s) in the same commit/PR
3. Keep updates minimal and factual — match the existing style

**Do not:**
- Skip the update because "it's a small change" — small drift compounds
- Rewrite sections unrelated to your change
- Remove existing rules without explicit approval

## Three Pillars — Every Task Must Satisfy All Three

A task is **not complete** until:
1. ✅ **AUTOMATING** — Lint, type-check, and format pass on all changed files
2. ✅ **TESTING** — Tests pass, new code has tests, no tests removed
3. ✅ **DOCUMENTING** — This AGENTS.md is updated if the change affects it

Skipping any pillar = incomplete work.
```

### Go

```markdown
## Task Completion — AUTOMATING

After every code change, run these checks on the files you modified:

1. **Vet**: `go vet ./path/to/changed/package/`
2. **Format**: `gofmt -w path/to/changed/file.go`
3. **Build**: `go build ./path/to/changed/package/`

A task is not complete until all three pass. Do not commit code that fails vet or build.

## Task Completion — TESTING

Every code change must include verification:

- **New features**: Write tests before or alongside the implementation
- **Bug fixes**: Add a regression test that reproduces the bug, then fix
- **Refactors**: Run existing tests to confirm no regressions

Run tests on changed packages: `go test ./path/to/changed/package/ -v -race`

Do not remove or weaken existing tests to make the suite pass.

## Task Completion — DOCUMENTING

This AGENTS.md must stay in sync with the codebase. After completing any task, check whether your changes require updates here.

**By change type:**

| Change Type | Update These Sections |
|-------------|----------------------|
| New dependency | Tech Stack, `go.mod` |
| New command or script | Commands |
| New directory or moved files | Project Structure |
| New pattern established | Do section |
| Anti-pattern discovered | Don't section |
| New config, CI, or tooling | Relevant sections |
| Git workflow change | Git Workflow |
| Bug fix | Don't section (if it was a recurring mistake) |
| Refactor | Project Structure, Code Examples |
| Security change | Boundaries |

**How to update:**
1. After completing your primary task, review what changed
2. Update the relevant AGENTS.md section(s) in the same commit/PR
3. Keep updates minimal and factual — match the existing style

**Do not:**
- Skip the update because "it's a small change" — small drift compounds
- Rewrite sections unrelated to your change
- Remove existing rules without explicit approval

## Three Pillars — Every Task Must Satisfy All Three

A task is **not complete** until:
1. ✅ **AUTOMATING** — Vet, format, and build pass on all changed packages
2. ✅ **TESTING** — Tests pass (with -race), new code has tests, no tests removed
3. ✅ **DOCUMENTING** — This AGENTS.md is updated if the change affects it

Skipping any pillar = incomplete work.
```

---

## Adaptation by Project Type

The Three Pillars apply universally, but the *specific content* varies by project type.

### Web Application (React, Next.js, Vue, etc.)

| Pillar | Adaptation |
|--------|-----------|
| **AUTOMATING** | Lint (ESLint/Biome), type-check (TypeScript), format (Prettier). Add: accessibility lint (`eslint-plugin-jsx-a11y`) if applicable |
| **TESTING** | Unit tests (Vitest/Jest), component tests (Testing Library), E2E (Playwright). New features need at minimum a unit test |
| **DOCUMENTING** | Track component library changes, route changes, state management patterns. AGENTS.md should reference design system tokens |

### REST/GraphQL API

| Pillar | Adaptation |
|--------|-----------|
| **AUTOMATING** | Lint, type-check, format. Add: OpenAPI/schema validation if applicable |
| **TESTING** | Unit tests for business logic, integration tests for endpoints, contract tests for API consumers. Every new endpoint needs a test |
| **DOCUMENTING** | Track endpoint changes, auth changes, rate limit changes. AGENTS.md should reference API docs location |

### Library / Package

| Pillar | Adaptation |
|--------|-----------|
| **AUTOMATING** | Lint, type-check, format. Add: bundle size check, backwards compatibility check |
| **TESTING** | Unit tests for all public API surfaces. Breaking changes need migration test examples |
| **DOCUMENTING** | Track public API changes, breaking changes, deprecations. AGENTS.md should reference CHANGELOG format |

### Monorepo

| Pillar | Adaptation |
|--------|-----------|
| **AUTOMATING** | Package-scoped lint/type-check/format. Use `pnpm --filter` or equivalent. Root AGENTS.md defines global rules; package AGENTS.md files override per-package |
| **TESTING** | Package-scoped tests. Cross-package changes need integration tests. Use `--affected` flags where available |
| **DOCUMENTING** | Update the *closest* AGENTS.md to the changed files. Root AGENTS.md only for cross-cutting changes |

### Documentation-Only Project (like this repo)

| Pillar | Adaptation |
|--------|-----------|
| **AUTOMATING** | No lint/type-check. Instead: validate structural rules (frontmatter format, directory conventions, file naming, line limits) |
| **TESTING** | Verify code snippets are syntactically correct, cross-references resolve to existing files, examples follow ❌/✅ format |
| **DOCUMENTING** | Update AGENTS.md when adding files/directories, changing conventions, or completing milestones. Use change-type table adapted to doc changes |

### CLI Tool

| Pillar | Adaptation |
|--------|-----------|
| **AUTOMATING** | Lint, type-check, format. Add: `--help` output validation if applicable |
| **TESTING** | Unit tests for command logic, integration tests for CLI invocation (test actual command execution with known inputs) |
| **DOCUMENTING** | Track command changes, flag changes, environment variable changes. AGENTS.md should reference man page or `--help` text |

---

## Failure Modes Per Pillar

### AUTOMATING Failures

| Failure Mode | Symptom | Prevention |
|-------------|---------|------------|
| **Missing commands** | AUTOMATING section says "run lint" but doesn't give the exact command | Always include the full command with `npx`/`go`/`ruff` prefix and file path placeholder |
| **Project-wide only** | Agent runs `npm run build` (3 min) instead of `npx tsc --noEmit file.tsx` (2 sec) | Include both file-scoped and project-wide commands; mark project-wide as "use sparingly" |
| **Wrong tool version** | Agent uses `eslint` config syntax for v8 but project uses v9 flat config | Specify tool versions in Tech Stack section |
| **Stale commands** | Team switched from Jest to Vitest but AUTOMATING still says `npx jest` | DOCUMENTING pillar catches this — dependency changes trigger Tech Stack + Commands update |

### TESTING Failures

| Failure Mode | Symptom | Prevention |
|-------------|---------|------------|
| **No test expectations** | Agent implements feature, skips tests, says "done" | Include explicit per-change-type rules: "new features require new tests" |
| **Test deletion** | Agent removes failing test instead of fixing the code | Add to Don't: "Do not remove or weaken existing tests" + Boundaries: "🚫 Never" |
| **Wrong test scope** | Agent writes E2E test for a utility function | Mention test type expectations: unit for logic, integration for endpoints, E2E for user flows |
| **No regression test** | Agent fixes bug but doesn't add test to prevent recurrence | Explicit rule: "Bug fixes require a regression test that reproduces the bug" |

### DOCUMENTING Failures

| Failure Mode | Symptom | Prevention |
|-------------|---------|------------|
| **No update triggers** | AGENTS.md says "keep this current" but doesn't say *when* | Use the change-type table — maps specific changes to specific sections |
| **Over-updating** | Agent rewrites entire AGENTS.md after adding one file | Add: "Keep updates minimal and factual — match the existing style" |
| **Wrong file updated** | Agent updates root AGENTS.md when a package-level one exists | Add: "If working in a subdirectory with its own AGENTS.md, update that file instead" |
| **Skipping small changes** | Agent adds a util directory but doesn't update Project Structure | Add: "Do not skip because it's a small change — small drift compounds" |

---

## Validation by Change Type Matrix

This matrix shows which pillar actions are required for each type of change. Include it in AGENTS.md for complex projects:

| Change Type | AUTOMATING | TESTING | DOCUMENTING |
|-------------|-----------|---------|-------------|
| **New feature** | Lint + type-check + format | New tests required | Update Structure, Do, Commands if needed |
| **Bug fix** | Lint + type-check | Regression test required | Update Don't section if recurring |
| **Refactor** | Lint + type-check + format | Run existing tests | Update Structure, Code Examples |
| **Dependency change** | Lint + type-check | Run full suite | Update Tech Stack, Commands |
| **Config change** | Lint if applicable | Smoke test | Update Commands, Boundaries |
| **Security fix** | Lint + type-check | Security-focused test | Update Boundaries, Don't section |
| **Performance optimization** | Lint + type-check + format | Benchmark test or existing tests | Update Do section if new pattern |
| **Documentation only** | N/A | N/A | Update AGENTS.md if structural |
| **CI/CD change** | N/A | Run full suite to verify | Update Commands, Boundaries |
| **Database migration** | Lint if applicable | Integration tests | Update Tech Stack, Project Structure |

---

## Integration with Six Core Areas

The Three Pillars don't replace the six core areas — they complement them. Here's how they interact:

| Core Area | Three Pillars Connection |
|-----------|------------------------|
| **Commands** | AUTOMATING pillar *uses* the commands defined here. Commands section provides the tools; AUTOMATING makes running them mandatory. |
| **Testing** | TESTING pillar *enforces* the testing expectations defined here. Testing section says *how* to test; TESTING pillar says *when* (every change, per type). |
| **Project Structure** | DOCUMENTING pillar *maintains* this section. When agents create directories or move files, the change-type table triggers an update. |
| **Code Style (Do/Don't)** | DOCUMENTING pillar *grows* these sections. When agents establish or discover patterns, the change-type table triggers additions. |
| **Git Workflow** | All three pillars feed into the commit/PR workflow. AUTOMATING runs before commit; TESTING runs before PR; DOCUMENTING updates in the same commit. |
| **Boundaries** | Three Pillars *reinforce* boundaries. The "Always" tier should include "Satisfy all Three Pillars." The "Never" tier should include "Remove tests to make suite pass." |

---

## Reinforcement Patterns

For maximum effectiveness, embed Three Pillars references in multiple AGENTS.md sections:

### In the Do Section
```markdown
- Satisfy all Three Pillars (AUTOMATING, TESTING, DOCUMENTING) before considering a task complete
- Update this AGENTS.md in the same commit when you change project structure, conventions, or dependencies
```

### In the Don't Section
```markdown
- Do not skip documentation updates because "it's a small change" — small drift compounds
- Do not remove or weaken existing tests to make the suite pass
- Do not commit code that fails linting or type-checking
```

### In the Boundaries Section
```markdown
- ✅ **Always**: Satisfy all Three Pillars before marking work complete
- 🚫 **Never**: Remove failing tests, skip lint/type-check, or leave AGENTS.md stale after structural changes
```

### In the PR Checklist (if applicable)
```markdown
## PR Checklist
- [ ] All Three Pillars satisfied:
  - [ ] AUTOMATING — lint, type-check, format pass
  - [ ] TESTING — tests pass, new code has tests
  - [ ] DOCUMENTING — AGENTS.md updated if structural changes made
```

---

## Complete AGENTS.md Template with Three Pillars

This is a complete, copy-paste-ready AGENTS.md template with all Three Pillars sections integrated:

```markdown
# AGENTS.md

## Tech Stack
- **Language**: [Language] [Version] ([mode if applicable])
- **Framework**: [Framework] [Version]
- **Package Manager**: [Manager] [Version]
- **Testing**: [Framework] [Version]
- **Linting**: [Tool] [Version]

## Commands

# Lint one file
[lint command] path/to/file.[ext]

# Type-check one file
[type-check command] path/to/file.[ext]

# Format one file
[format command] path/to/file.[ext]

# Run one test
[test command] path/to/file.test.[ext]

# Full build — use sparingly
[build command]

## Project Structure
- `src/` — Application source code
- `tests/` — Test files
- `docs/` — Documentation
- `scripts/` — Build and utility scripts

## Do
- [Project-specific do rules]
- Satisfy all Three Pillars (AUTOMATING, TESTING, DOCUMENTING) before considering a task complete
- Update this AGENTS.md in the same commit when you change project structure, conventions, or dependencies

## Don't
- [Project-specific don't rules]
- Do not skip documentation updates because "it's a small change"
- Do not remove or weaken existing tests to make the suite pass
- Do not commit code that fails linting or type-checking

## Boundaries
- ✅ **Always**: Run lint and tests on changed files, satisfy all Three Pillars, follow naming conventions
- ⚠️ **Ask first**: [Project-specific ask-first items]
- 🚫 **Never**: Commit secrets, remove tests, skip lint, leave AGENTS.md stale after structural changes

## Task Completion — AUTOMATING

After every code change, run these checks on the files you modified:

1. **Lint**: `[lint command] path/to/changed/file.[ext]`
2. **Type-check**: `[type-check command] path/to/changed/file.[ext]`
3. **Format**: `[format command] path/to/changed/file.[ext]`

A task is not complete until all pass. Do not commit code that fails linting or type-checking.

## Task Completion — TESTING

Every code change must include verification:

- **New features**: Write tests before or alongside the implementation
- **Bug fixes**: Add a regression test that reproduces the bug, then fix
- **Refactors**: Run existing tests to confirm no regressions

Run tests on changed files: `[test command] path/to/changed/file.test.[ext]`

Do not remove or weaken existing tests to make the suite pass.

## Task Completion — DOCUMENTING

This AGENTS.md must stay in sync with the codebase. After completing any task, check whether your changes require updates here.

**By change type:**

| Change Type | Update These Sections |
|-------------|----------------------|
| New dependency | Tech Stack |
| New command or script | Commands |
| New directory or moved files | Project Structure |
| New pattern established | Do section |
| Anti-pattern discovered | Don't section |
| New config, CI, or tooling | Relevant sections |
| Git workflow change | Git Workflow |
| Bug fix | Don't section (if it was a recurring mistake) |
| Refactor | Project Structure, Code Examples |
| Security change | Boundaries |

**How to update:**
1. After completing your primary task, review what changed
2. Update the relevant AGENTS.md section(s) in the same commit/PR
3. Keep updates minimal and factual — match the existing style

**Do not:**
- Skip the update because "it's a small change" — small drift compounds
- Rewrite sections unrelated to your change
- Remove existing rules without explicit approval

## Three Pillars — Every Task Must Satisfy All Three

A task is **not complete** until:
1. ✅ **AUTOMATING** — Lint, type-check, and format pass on all changed files
2. ✅ **TESTING** — Tests pass, new code has tests, no tests removed
3. ✅ **DOCUMENTING** — This AGENTS.md is updated if the change affects it

Skipping any pillar = incomplete work.
```

---

## Origin

The Three Pillars Framework is adapted from the archive's "Three Pillars" pattern (originally Scripting, Testing, Documenting) found in `_complete_archive/_templates-main/DOCUMENTATION-BLUEPRINT.tpl.md` and `_complete_archive/_templates-main/docs/universal/INTEGRATION-GUIDE.tpl.md`. The original version was tightly coupled to a specific template system with `.\scripts\ai-workflow.ps1`; this adaptation is universal and tool-agnostic.

| Original | Adapted |
|----------|---------|
| Scripting (run `ai-workflow.ps1`) | **AUTOMATING** (lint, type-check, format with project's own tools) |
| Testing (85%+ coverage threshold) | **TESTING** (per-change-type expectations, no coverage number mandated) |
| Documenting (update 20-file doc structure) | **DOCUMENTING** (change-type checklists for AGENTS.md self-updating) |
