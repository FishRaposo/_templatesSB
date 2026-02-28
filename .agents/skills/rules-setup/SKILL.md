---
name: rules-setup
description: Use this skill when creating, improving, or auditing the Rules template type for any repository — AGENTS.md (canonical), CLAUDE.md, CURSOR.md, WINDSURF.md. Includes generating AGENTS.md with Three Pillars (AUTOMATING with prefer scripts, TESTING, DOCUMENTING), Prompt Validation, four rule files in ALL CAPS, thin tool-specific entries that point to AGENTS.md, and optional .cursor/rules. Fits the seven-template-types framework (Rules, Blueprints, Tasks, Recipes, Subagents, Skills, Protocols).
---

# Rules Setup Skill

This skill creates and maintains the **Rules** template type: **AGENTS.md** (canonical) plus tool-specific rule files (**CLAUDE.md**, **CURSOR.md**, **WINDSURF.md**) so every AI tool follows the same project conventions. Rule files at project root use **ALL CAPS** filenames.

## Your Role

Help users **create** and **modify** the Rules template type through:

1. **Creating New Rules** — Generate AGENTS.md and the four rule files (AGENTS.md, CLAUDE.md, CURSOR.md, WINDSURF.md) for a project from scratch
2. **Editing Existing Rules** — Improve or update an existing AGENTS.md or rule files (add sections, refine commands, add Prompt Validation or Three Pillars)
3. **Auditing Rules** — Review rule files against the framework (six core areas, Three Pillars, Prompt Validation) and fix gaps

When invoked, analyze the codebase as needed and produce concrete, actionable rule content. Every generated AGENTS.md must include the Three Pillars (AUTOMATING with prefer scripts, TESTING, DOCUMENTING) and a Prompt Validation reference (4 checks). Do not duplicate full protocol text in AGENTS.md—link to the protocol.

**Note:** The complete **Prompt Validation Protocol** is available in `./reference/prompt-validation-protocol-reference.md` for embedding in generated AGENTS.md files. The SKILL.md includes a brief reference section (Step 9) that points to the full protocol.

# Core Approach — The Three Pillars Framework

Every effective AGENTS.md must enforce three pillars. If any pillar is missing, agents produce incomplete work:

| Pillar | What It Covers | Without It |
|--------|---------------|------------|
| **AUTOMATING** | Commands, CI, linting, formatting, build scripts; **prefer scripts over manual steps** — if a task can be done with a script (especially reusable), use it | Agent guesses how to verify work — runs wrong commands, breaks builds |
| **TESTING** | Test commands, coverage expectations, test-first rules | Agent ships untested code or skips regressions |
| **DOCUMENTING** | Self-updating AGENTS.md, change-type checklists, doc parity | AGENTS.md becomes stale within days, next agent gets wrong instructions |

**The rule**: A task is not complete until all three pillars are satisfied — code is verified (AUTOMATING), tested (TESTING), and the AGENTS.md is updated if the change affects it (DOCUMENTING).

When invoked, the skill will:
1. Analyze the project's tech stack, structure, and conventions
2. Cover the six core areas: commands, testing, project structure, code style, git workflow, and boundaries
3. Write concrete, actionable instructions — not vague descriptions
4. Set clear three-tier boundaries (always do / ask first / never do)
5. **Enforce the Three Pillars** — every generated AGENTS.md includes AUTOMATING, TESTING, and DOCUMENTING sections with explicit enforcement rules
6. **Add Prompt Validation** — every generated AGENTS.md includes a pre-task validation gate that catches vague, incomplete, or unsafe prompts before execution

# Step-by-Step Instructions

## 1. Analyze the Codebase

First, examine the project to gather the information agents need:

- **Tech stack**: Identify languages, frameworks, versions, and key dependencies
- **Project structure**: Map the directory layout, entry points, and key files
- **Commands**: Find build, lint, test, and format commands from package.json, Makefile, pyproject.toml, etc.
- **Code style**: Detect naming conventions, patterns, and formatting choices from existing code
- **Git workflow**: Check for commit conventions, PR templates, branch naming from git config and CI files
- **Boundaries**: Identify sensitive files, generated code, vendor directories, and secrets

**JavaScript/TypeScript project — discovery commands:**
```bash
# Discover commands
cat package.json | jq '.scripts'

# Detect framework and versions
cat package.json | jq '.dependencies, .devDependencies'

# Find linter/formatter configs
ls .eslintrc* .prettierrc* tsconfig.json biome.json 2>/dev/null

# Check for CI
ls .github/workflows/*.yml 2>/dev/null

# Check for existing rule files (Rules template type — use ALL CAPS names)
ls AGENTS.md CLAUDE.md CURSOR.md WINDSURF.md 2>/dev/null
ls .cursor/rules/*.md 2>/dev/null
```

**Python project — discovery commands:**
```bash
# Discover commands
cat pyproject.toml | grep -A 20 '\[tool.poetry.scripts\]'
cat Makefile 2>/dev/null

# Detect framework and versions
cat pyproject.toml | grep -A 50 '\[tool.poetry.dependencies\]'
pip list --format=json | python -c "import sys,json; [print(p['name'],p['version']) for p in json.load(sys.stdin)]"

# Find linter/formatter configs
ls pyproject.toml setup.cfg .flake8 .ruff.toml mypy.ini 2>/dev/null
```

**Go project — discovery commands:**
```bash
# Discover dependencies and Go version
cat go.mod

# Find build/test commands
cat Makefile 2>/dev/null
ls .goreleaser.yml 2>/dev/null
```

## 2. Write the AGENTS.md

Structure the file covering all six core areas. Put commands early — agents reference them constantly.

**Minimal effective structure:**

```markdown
# AGENTS.md

## Tech Stack
- **Language**: TypeScript 5.3 (strict mode)
- **Framework**: Next.js 14 (App Router)
- **Package Manager**: pnpm 9

## Commands
# Lint a single file
npx eslint --fix path/to/file.tsx

# Type-check a single file
npx tsc --noEmit path/to/file.tsx

# Run a single test
npx vitest run path/to/file.test.tsx

# Full build (use sparingly)
pnpm build

Prefer scripts over manual steps when a script exists (e.g. in scripts/).

## Testing
- Run lint and tests on changed files before considering a task complete.
- Per change type: new feature → new tests; bug fix → regression test; refactor → run existing tests.
- Do not remove or weaken existing tests.

## Project Structure
- `src/app/` — Pages and layouts
- `src/components/` — Reusable UI components
- `src/lib/` — Utilities and helpers

## Do
- Use named exports for components
- Use Zod for runtime validation
- Default to small, focused components

## Don't
- Do not use `any` type
- Do not hardcode colors — use design tokens
- Do not add dependencies without approval

## Boundaries
- ✅ **Always**: Run lint and tests on changed files, satisfy all Three Pillars
- ⚠️ **Ask first**: Schema changes, new dependencies
- 🚫 **Never**: Commit secrets, edit vendor/, remove tests

## Prompt Validation — Before Every Task

Before starting, run these 4 checks (see PROMPT-VALIDATION-PROTOCOL.md for full process):
1. **Purpose in first line** — Can you state what the prompt wants in one sentence?
2. **All variables defined** — Are all placeholders defined or defaulted?
3. **No dangerous patterns** — No eval, exec, rm -rf, DROP TABLE, sudo, secrets
4. **Output format specified** — Does the prompt say what output should look like?

If any fail, ask for clarification before proceeding.

## Three Pillars — Every Task Must Satisfy All Three

A task is **not complete** until:
1. ✅ **AUTOMATING** — Prefer scripts over manual steps; lint, type-check, and format pass on all changed files
2. ✅ **TESTING** — Tests pass, new code has tests, no tests removed
3. ✅ **DOCUMENTING** — This AGENTS.md (and other rule files if affected) is updated if the change affects it

Skipping any pillar = incomplete work.
```

**Why each section matters:**

| Section | Without It | With It |
|---------|-----------|---------|
| Tech Stack | Agent guesses versions → subtle API bugs | Correct imports and patterns |
| Commands | Agent runs full builds → minutes wasted | File-scoped checks in seconds |
| Testing | Agent ships untested code | Clear expectations per change type |
| Project Structure | Agent re-explores every chat | Starts where humans would start |
| Do / Don't | Agent uses random patterns | Mirrors your best practices |
| Boundaries | Agent touches prod configs | Safe, controlled changes |
| Prompt Validation | Agent acts on vague or unsafe prompts | 4-check gate before every task |
| Git Workflow | Inconsistent commits, stale docs | Validation before commit, CHANGELOG append-only |

**When the project uses the seven-template-types framework** (Rules, Blueprints, Tasks, Recipes, Subagents, Skills, Protocols), include: Project Overview (seven types), Tech stack, Commands (with prefer scripts), **Testing** section, Code Style, Repository Structure, **Boundaries**, **Git Workflow**, Memory System Protocol, **Prompt Validation — Before Every Task** (4 checks), Three Pillars, Workflows (adding rule file, blueprint, task, recipe, subagent, skill, protocol), Tool Selection, **Subagents for execution**, **Right tool for the job**, Key References, When Stuck. Use the project's AGENTS.md as the reference implementation (when present).

## 3. Add File-Scoped Commands

Agents that run project-wide builds on every change waste time. Prefer per-file commands:

**JavaScript/TypeScript:**
```markdown
## Commands
# Type-check one file (seconds, not minutes)
npx tsc --noEmit path/to/file.tsx

# Format one file
npx prettier --write path/to/file.tsx

# Lint one file
npx eslint --fix path/to/file.tsx

# Test one file
npx vitest run path/to/file.test.tsx

# Full build — only when explicitly requested
pnpm build

Note: Always lint, type-check, and test changed files. Use full builds sparingly.
```

**Python:**
```markdown
## Commands
# Type-check one file
mypy path/to/file.py

# Format one file
ruff format path/to/file.py

# Lint one file
ruff check --fix path/to/file.py

# Test one file
pytest path/to/test_file.py -v

# Full test suite
pytest --cov
```

**Go:**
```markdown
## Commands
# Vet one package
go vet ./path/to/package/

# Format one file
gofmt -w path/to/file.go

# Test one package
go test ./path/to/package/ -v

# Full test suite
go test ./... -race -cover
```

## 4. Write Concrete Do's and Don'ts

The most impactful section. Build this iteratively: run prompts, note mistakes, add rules.

**Effective pattern — be specific, not abstract:**

```markdown
## Do
- Use MUI v3 — ensure code is v3 compatible
- Use emotion `css={{}}` prop format for styling
- Use mobx for state management with `useLocalStore`
- Use design tokens from `src/lib/theme/tokens.ts` for all styling
- Use Apex Charts for charts — do not supply custom HTML tooltips
- Default to small components and small diffs

## Don't
- Do not hardcode colors, spacing, or breakpoints
- Do not use `div` when a semantic element or existing component fits
- Do not add new heavy dependencies without approval
- Do not use class-based components — use functional with hooks
```

**Anti-pattern — too vague to be useful:**
```markdown
## Do
- Write clean code
- Follow best practices
- Use good naming

## Don't
- Don't write bad code
```

## 5. Set Three-Tier Boundaries

Use the always / ask-first / never pattern to prevent destructive mistakes:

```markdown
## Boundaries
- ✅ **Always**: Write to `src/` and `tests/`, run tests before commits, follow naming conventions
- ⚠️ **Ask first**: Database schema changes, adding dependencies, modifying CI/CD config
- 🚫 **Never**: Commit secrets or API keys, edit `node_modules/` or `vendor/`, remove failing tests
```

**Safety and permissions (for tools that support it):**
```markdown
## Safety and Permissions
Allowed without prompt:
- Read/list files
- Single-file type-check, format, lint
- Run individual unit tests

Ask first:
- Package installs
- Git push, force operations
- File deletion
- Full build or E2E suites
```

## 6. Add Concrete Code Examples

One real snippet beats three paragraphs. Point to actual files showing your best patterns.

```markdown
## Code Examples

**Good patterns to copy:**
- Forms: see `src/components/forms/CreateUserForm.tsx`
- Tables: see `src/components/data/DataGrid.tsx`
- API calls: see `src/services/api-client.ts`

**Legacy patterns to avoid:**
- Class components like `src/legacy/Admin.tsx`
- Direct fetch in components like `src/old/Dashboard.tsx`

**Style example:**
```typescript
// ✅ Good — descriptive names, proper error handling
export async function fetchUserById(id: string): Promise<User> {
  if (!id) throw new AppError('User ID required', 'VALIDATION');
  const response = await api.get(`/users/${id}`);
  return response.data;
}

// ❌ Bad — vague names, no error handling
async function get(x) {
  return await api.get('/users/' + x).data;
}
```
```

## 7. Set Up Nested Overrides (Monorepos)

For large repos, place directory-specific `AGENTS.md` files:

```
my-monorepo/
├── AGENTS.md                        ← repo-wide defaults
├── packages/
│   ├── api/
│   │   └── AGENTS.md               ← API-specific (Express, Prisma)
│   ├── web/
│   │   └── AGENTS.md               ← Web-specific (React 18, Tailwind)
│   └── shared/
│       └── AGENTS.md               ← Shared lib rules
└── services/
    └── payments/
        └── AGENTS.override.md      ← Payments overrides (stricter security)
```

Rules cascade: the agent reads the closest file to the work it's doing. Use `AGENTS.override.md` to completely replace (not extend) parent rules for sensitive areas.

## 8. Enforce the Three Pillars

This is the most critical step. Every AGENTS.md must include a **Three Pillars** section that makes automation, testing, and documentation an inseparable part of every task — not optional extras.

### Pillar 1: AUTOMATING

The AUTOMATING pillar ensures agents verify their work with the project's actual tools and **prefer scripts over manual steps**. If a task can be done with a script (especially a reusable one in `scripts/`), use the script instead of doing it manually. This is covered by the Commands section (Step 3), but must also be reinforced as a mandatory post-task behavior:

```markdown
## Task Completion — AUTOMATING

After every code change, run these checks on the files you modified:

1. **Lint**: `npx eslint --fix path/to/changed/file.tsx`
2. **Type-check**: `npx tsc --noEmit path/to/changed/file.tsx`
3. **Format**: `npx prettier --write path/to/changed/file.tsx`

A task is not complete until all three pass. Do not commit code that fails linting or type-checking.
```

### Pillar 2: TESTING

The TESTING pillar ensures agents never ship untested code. Include explicit testing expectations:

```markdown
## Task Completion — TESTING

Every code change must include verification:

- **New features**: Write tests before or alongside the implementation
- **Bug fixes**: Add a regression test that reproduces the bug, then fix
- **Refactors**: Run existing tests to confirm no regressions

Run tests on changed files: `npx vitest run path/to/changed/file.test.tsx`

Do not remove or weaken existing tests to make the suite pass.
```

### Pillar 3: DOCUMENTING

The DOCUMENTING pillar ensures AGENTS.md stays current. It uses explicit change-type checklists so agents know exactly what to update:

```markdown
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
```

### Putting It Together: The Three Pillars Block

For maximum impact, add a single reinforcement block that ties all three pillars together:

```markdown
## Three Pillars — Every Task Must Satisfy All Three

A task is **not complete** until:
1. ✅ **AUTOMATING** — Prefer scripts over manual steps; if a script exists (especially in `scripts/`), use it. Lint, type-check, and format pass on all changed files.
2. ✅ **TESTING** — Tests pass, new code has tests, no tests removed
3. ✅ **DOCUMENTING** — This AGENTS.md (and other rule files if affected) is updated if the change affects it

Skipping any pillar = incomplete work.
```

### Three Pillars Validation by Change Type

This table shows which pillar actions are required for each type of change:

| Change Type | AUTOMATING | TESTING | DOCUMENTING |
|-------------|-----------|---------|-------------|
| **New feature** | Lint + type-check + format | New tests required | Update Structure, Do, Commands if needed |
| **Bug fix** | Lint + type-check | Regression test required | Update Don't section if recurring |
| **Refactor** | Lint + type-check + format | Run existing tests | Update Structure, Code Examples |
| **Dependency change** | Lint + type-check | Run full suite | Update Tech Stack, Commands |
| **Config change** | Lint if applicable | Smoke test | Update Commands, Boundaries |
| **Documentation only** | N/A | N/A | Update AGENTS.md if structural |

**For the agent generating the AGENTS.md:** Always include the Three Pillars section. Adapt the specific commands to the project's tech stack. This is not optional — it's the enforcement mechanism that keeps AGENTS.md alive and code quality consistent.

## 9. Add Prompt Validation Reference

Every generated AGENTS.md should reference the **Prompt Validation Protocol** to ensure agents validate what they're asked to do before executing. This prevents agents from acting on vague, incomplete, or unsafe prompts — catching problems at the input, not the output.

### Why This Matters

| Without Prompt Validation | With Prompt Validation |
|--------------------------|----------------------|
| Agent guesses intent from vague prompts | Agent confirms scope before starting |
| Unsafe operations slip through | Security scan catches dangerous patterns |
| Agent builds the wrong thing from ambiguous requests | Agent asks for clarification upfront |
| Output format undefined — agent picks randomly | Output format confirmed before execution |

### What to Include in Generated AGENTS.md

Add a brief reference section that points to the standalone protocol:

```markdown
## Prompt Validation Protocol

**All agents MUST validate user prompts before execution** using `PROMPT-VALIDATION-PROTOCOL.md`. This ensures clarity, completeness, security, and effectiveness.

### Quick Reference

Before any task, run these 4 checks:

1. **Purpose in first line** — Can you state what the prompt wants in one sentence?
2. **All variables defined** — Are all `{{`, `[`, `{` placeholders defined?
3. **No dangerous patterns** — No `eval`, `exec`, `rm -rf`, `DROP TABLE`, `sudo`, secrets
4. **Output format specified** — Does the prompt say what output should look like?

If ANY fail, ask for clarification before proceeding.

### Full Protocol

See `PROMPT-VALIDATION-PROTOCOL.md` for:
- Validation Levels (PERMISSIVE / STANDARD / STRICT)
- 27 Security Patterns (blocked injection vectors)
- 5-Dimension Scoring (Clarity, Completeness, Structure, Security, Effectiveness)
- 3-Dimension Checklist (Content, Structure, Technical)
- Type-Specific Checks (7 prompt types)
- 4-Step Validation Process
- Common Failures & Fix Patterns
- Validation Log Template
- Grade Calculation (A-F)
- Escalation Criteria
```

**Note:** The full `PROMPT-VALIDATION-PROTOCOL.md` may live at the project root or under `docs/protocols/`. When generating a new AGENTS.md, include the brief reference section above and point to the project's actual path for the full protocol.

## 10. Set Up the Four Rule Files (Rules Template Type)

**Rules** are one of seven template types. At project root, use **ALL CAPS** filenames so rule files are consistent: **AGENTS.md** (canonical), **CLAUDE.md**, **CURSOR.md**, **WINDSURF.md**. One project, one source of truth — AGENTS.md — and thin tool-specific files that point to it.

**AGENTS.md** — Contains all behavioral rules, commands, Three Pillars, Prompt Validation reference, and project-specific content. This is the only file that should hold the full rule set.

**CLAUDE.md** — Claude entry. Keep it thin: point to AGENTS.md and add any Claude-specific commands or paths.
```markdown
# CLAUDE.md
Strictly follow the rules in ./AGENTS.md. See AGENTS.md for commands, Three Pillars, and boundaries.
```

**CURSOR.md** — Cursor entry. Keep it thin: point to AGENTS.md and add Cursor-specific paths (e.g. skills in `~/.cursor/skills/` or `.cursor/skills/`).
```markdown
# CURSOR.md
Follow all instructions in ./AGENTS.md. See AGENTS.md for commands, Three Pillars, and boundaries.
```

**WINDSURF.md** — Windsurf entry. Same idea: point to AGENTS.md, add Windsurf-specific quick start if needed.
```markdown
# WINDSURF.md
Follow all instructions in ./AGENTS.md. See AGENTS.md for commands, Three Pillars, and boundaries.
```

**Optional**: `.cursor/rules/*.md` for Cursor file- or scope-specific rules; these can reference AGENTS.md for project-wide behavior.

**Do not** duplicate full content across CLAUDE.md, CURSOR.md, WINDSURF.md — keep one canonical AGENTS.md and thin pointer content in the others. Do not use symlinks if you want tool-specific bullets (e.g. Cursor paths); use real thin files.

# Best Practices

- **Put commands early** — agents reference them on every task
- **Prefer file-scoped commands** — seconds vs. minutes per check
- **Show code examples, not descriptions** — one snippet > three paragraphs
- **Be version-specific** — `React 18 with TypeScript 5.3` not `React project`
- **Start small, iterate** — add a rule the second time you see the same mistake
- **Point to real reference files** — the agent mirrors your best examples
- **Keep it scannable** — short bullet points, tables, code blocks — not walls of prose
- **Nest for monorepos** — packages evolve independently, guidance should too
- **Give an escape hatch** — "When stuck, ask" prevents dead-end loops
- **Enforce the Three Pillars** — every AGENTS.md must have AUTOMATING, TESTING, DOCUMENTING enforcement
- **Add Prompt Validation** — every AGENTS.md should validate inputs (prompts) before agents execute, not just outputs (Three Pillars)
- **Treat AGENTS.md as code** — it should be updated in the same commit as the changes it documents
- **Use change-type checklists** — different change types require different documentation updates
- **Prefer scripts over manual steps** — If a task can be done with a script (especially in `scripts/`), use it; don't do it manually.
- **Rule files in ALL CAPS** — Use AGENTS.md, CLAUDE.md, CURSOR.md, WINDSURF.md at project root (not Agents.md or Cursor.md).
- **Tie completion to all three pillars** — "task not complete until lint passes, tests pass, and docs updated"

# Validation Checklist

When reviewing an AGENTS.md, verify:
- [ ] Tech stack specified with versions
- [ ] Commands section present and uses file-scoped commands where possible; **prefer scripts** noted
- [ ] **Testing section** present — what to run per change type, do not remove tests
- [ ] Project structure mapped with key directories and files
- [ ] Do / Don't section with specific, actionable rules (not vague)
- [ ] Three-tier boundaries defined (always / ask first / never)
- [ ] **Git workflow** documented (validation before commit, CHANGELOG, branch/commit expectations)
- [ ] Code examples point to real files or show concrete patterns
- [ ] No vague instructions like "write clean code" or "follow best practices"
- [ ] Safety permissions defined (what's allowed without prompt)
- [ ] File is scannable — uses bullet points, tables, and code blocks
- [ ] Under 32 KiB (Codex default limit; split across directories if larger)
- [ ] **Rule files use ALL CAPS** — AGENTS.md, CLAUDE.md, CURSOR.md, WINDSURF.md (not Cursor.md or Windsurf.md).
- [ ] **Prompt Validation — Before Every Task** section present with 4 must-pass checks and reference to PROMPT-VALIDATION-PROTOCOL.md
- [ ] Three Pillars section present with all three pillars:
  - [ ] AUTOMATING — **prefer scripts over manual steps**; post-task lint/type-check/format commands defined
  - [ ] TESTING — test expectations per change type (new feature, bug fix, refactor)
  - [ ] DOCUMENTING — change-type checklist for when to update AGENTS.md and other rule files
- [ ] Three Pillars completion block — "task not complete until all three pass"
- [ ] Change-type documentation table — maps change types to required doc updates (optional but recommended)

# Troubleshooting

## Issue: Agent Keeps Making the Same Mistake

**Symptoms**: Agent uses wrong state library, wrong component patterns, or wrong styling approach despite having an AGENTS.md

**Solution**:
- Add a specific Don't rule: "Do not use useState — use Zustand stores"
- Add a Do rule pointing to a reference file: "Copy pattern from `src/stores/userStore.ts`"
- Check that the AGENTS.md is at the right directory level (not too far from the files being edited)

## Issue: Agent Runs Slow Full-Project Commands

**Symptoms**: Agent runs `npm run build` or `npm test` after every small change

**Solution**:
- Add file-scoped command alternatives in the Commands section
- Add note: "Use file-scoped checks. Full builds only when explicitly requested."
- Add to Safety: "Ask first before running full build or E2E suites"

## Issue: AGENTS.md Is Too Long

**Symptoms**: Agent ignores rules at the end of a very long file, or Codex truncates it

**Solution**:
- Split into nested directory-level files
- Move detailed examples to separate referenced files
- Keep the root AGENTS.md focused on global rules
- Codex has a 32 KiB default limit (`project_doc_max_bytes`)

## Issue: AGENTS.md Becomes Stale

**Symptoms**: AGENTS.md references old dependencies, missing directories, or outdated commands

**Solution**:
- Ensure the Three Pillars DOCUMENTING section is present with change-type checklists
- Make it a Do rule: "Update AGENTS.md in the same commit as structural changes"
- Add to Boundaries: "✅ Always: Update AGENTS.md when adding dependencies, directories, or patterns"
- Add the completion block: "task not complete until all three pillars pass"
- Review and prune AGENTS.md periodically (monthly)

## Issue: Agent Ships Untested Code

**Symptoms**: Agent implements features without writing tests, or removes failing tests

**Solution**:
- Ensure the Three Pillars TESTING section specifies expectations per change type
- Add explicit rules: "New features require new tests", "Bug fixes require regression tests"
- Add to Don't: "Do not remove or weaken existing tests"
- Add to Boundaries: "🚫 Never: Remove failing tests to make the suite pass"

## Issue: Cross-Tool Inconsistency

**Symptoms**: Different AI tools behave differently on the same repo

**Solution**:
- Use a single **AGENTS.md** as the source of truth (canonical Rules).
- Create thin tool-specific rule files with **ALL CAPS** names: **CLAUDE.md**, **CURSOR.md**, **WINDSURF.md**. Each should point to AGENTS.md and add only tool-specific commands or paths.
- See `AGENTIC-ASSETS-FRAMEWORK.md` → "Rules, Skills, and Subagents" and "Key Files (examples of Rules)" for the four-file convention.

# Supporting Files

- **Archive:** When the project has an archive, an archive reference doc (e.g. `docs/ARCHIVE-REFERENCE-FOR-TEMPLATE-TYPES.md`) may list Rules paths; do not modify archive files
- **Reference implementation:** The project's AGENTS.md at project root (when present) — full structure with Tech Stack, Commands, Testing, Code Style, Repository Structure, Boundaries, **Safety and Permissions**, Git Workflow, Memory System, Prompt Validation (4 checks), Three Pillars (with change-type doc table), Workflows, Tool Selection, **Subagents for execution**, **Right tool for the job**, Key References, When Stuck
- See `./_examples/basic-examples.md` for before/after AGENTS.md patterns by project type
- See `./_examples/three-pillars-reference.md` for the comprehensive Three Pillars guide
- **Framework:** The project's `AGENTIC-ASSETS-FRAMEWORK.md` at project root (when present) for the Rules template type, four rule files (AGENTS.md, CLAUDE.md, CURSOR.md, WINDSURF.md), and "Rules, Skills, and Subagents"
- **Prompt validation protocol:** The project's protocol at project root or `docs/protocols/PROMPT-VALIDATION-PROTOCOL.md` (when present). To **install** the protocol file in a new project, use the **prompt-validation-setup** skill (`.agents/skills/prompt-validation-setup/`). For the **complete protocol text** to embed in generated AGENTS.md files, see `./reference/prompt-validation-protocol-reference.md`
- **Archive (optional):** When the project has an archive, a prompt-validation or system reference doc may exist there (e.g. PROMPT-VALIDATION-SYSTEM-REFERENCE.md) for the original implementation

## Related Skills

- **prompt-validation-setup** — Installs and maintains the Prompt Validation Protocol in `docs/protocols/PROMPT-VALIDATION-PROTOCOL.md`. Use it when setting up a new project so the protocol file exists; use this skill (rules-setup) to add the "Prompt Validation — Before Every Task" reference section to AGENTS.md.
- **agents-md-setup** — Create or edit AGENTS.md as the primary rule only (canonical content and structure). Use when the user wants to focus on AGENTS.md; use this skill (rules-setup) when you need all four rule files (AGENTS.md + CLAUDE.md, CURSOR.md, WINDSURF.md).
- **skill-setup** — Create the AI agent skills that rule files and AGENTS.md reference
- **memory-system-setup** — When adding event-sourced memory (CHANGELOG, .memory/) and the Memory System Protocol section to AGENTS.md
- When the project uses other skills (e.g. for linting, code review, logging), reference them in AGENTS.md; this skill generates the rule files that point to them

Remember: The best rule sets grow through iteration — add a rule the second time you see the same mistake. Keep AGENTS.md canonical and CLAUDE.md, CURSOR.md, WINDSURF.md thin.
