# Generating AGENTS.md — Basic Examples

## Tech Stack: Be Specific

```markdown
# ❌ Too vague — agent guesses versions and makes subtle mistakes
## Tech Stack
- React
- Node.js
- PostgreSQL

# ✅ Specific — agent uses correct APIs and patterns
## Tech Stack
- **Frontend**: React 18.3, TypeScript 5.3, Vite 5, Tailwind CSS 3.4
- **Backend**: Node.js 20 LTS, Express 4.18, Prisma 5.10
- **Database**: PostgreSQL 16
- **Testing**: Vitest 1.6, Playwright 1.42
- **Package Manager**: pnpm 9
```

## Commands: File-Scoped Over Project-Wide

```markdown
# ❌ Only project-wide commands — slow, wasteful
## Commands
npm run build
npm test
npm run lint

# ✅ File-scoped commands for fast feedback loops
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

## Do / Don't: Concrete Over Abstract

```markdown
# ❌ Too abstract — agent can't act on these
## Do
- Write clean code
- Follow best practices
- Use good naming

## Don't
- Don't write bad code
- Don't make mistakes

# ✅ Specific and actionable
## Do
- Use MUI v3 — ensure code is v3 compatible
- Use emotion `css={{}}` prop format for styling
- Use mobx for state management with `useLocalStore`
- Use design tokens from `src/lib/theme/tokens.ts` — no hardcoded values
- Default to small components and small diffs

## Don't
- Do not hardcode colors, spacing, or breakpoints
- Do not use `div` when a semantic element or existing component fits
- Do not add new dependencies without approval
- Do not use class-based components — use functional with hooks
```

## Boundaries: Three-Tier System

```markdown
# ❌ No boundaries — agent may do destructive things
## Rules
- Be careful with the code

# ✅ Clear three-tier boundaries
## Boundaries
- ✅ **Always**: Run lint and tests on changed files, follow naming conventions, write to `src/` and `tests/`
- ⚠️ **Ask first**: Database schema changes, adding new dependencies, modifying CI/CD config
- 🚫 **Never**: Commit secrets or API keys, edit `node_modules/`, remove failing tests, modify `.env.production`

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

## Code Examples: Real Files Over Descriptions

```markdown
# ❌ Abstract description — agent still guesses
## Code Style
Use functional components with hooks. Follow consistent naming.
Make sure code is clean and well-organized.

# ✅ Points to real files the agent can read
## Code Examples

**Good patterns to copy:**
- Forms: `src/components/forms/CreateUserForm.tsx`
- Tables: `src/components/data/DataGrid.tsx`
- API calls: `src/services/api-client.ts`
- Stores: `src/stores/userStore.ts`

**Legacy patterns to avoid:**
- Class components: `src/legacy/Admin.tsx`
- Direct fetch in components: `src/old/Dashboard.tsx`

**Naming conventions:**
- Components: `PascalCase` (`UserProfile.tsx`)
- Utils: `camelCase` (`formatDate.ts`)
- Constants: `UPPER_SNAKE_CASE` (`MAX_RETRIES`)
```

## Project Structure: Save Discovery Time

```markdown
# ❌ No structure — agent wastes time exploring every chat
(section missing entirely)

# ✅ Key pointers so agent starts where humans would
## Project Structure
- `src/app/` — Next.js App Router pages and layouts
- `src/components/` — Reusable UI components (PascalCase files)
- `src/lib/` — Utilities, helpers, shared logic
- `src/services/` — Business logic and external API clients
- `src/stores/` — Zustand state stores
- `prisma/schema.prisma` — Database schema (ask before modifying)
- `.github/workflows/` — CI/CD pipeline
- `tests/e2e/` — Playwright E2E tests
```

## Nested Overrides: Monorepo Example

```markdown
# ❌ One giant AGENTS.md with conditionals
## Rules
- If in packages/api, use Express patterns
- If in packages/web, use React patterns
- If in packages/shared, don't add framework-specific code

# ✅ Directory-level AGENTS.md files
# Root AGENTS.md — global defaults
# AGENTS.md
## Package Manager
Use pnpm workspaces. Run commands with `pnpm --filter <package>`.

# packages/api/AGENTS.md — API-specific
## Tech Stack
- Express 4.18, Prisma 5, TypeScript strict
## Commands
pnpm --filter api test
pnpm --filter api lint

# packages/web/AGENTS.md — Web-specific
## Tech Stack
- React 18, Vite 5, Tailwind CSS 3.4
## Commands
pnpm --filter web dev
pnpm --filter web test
```

## Cross-Tool Compatibility

```markdown
# ❌ Separate files with duplicated content
# CLAUDE.md — 200 lines of rules
# .cursorrules — same 200 lines, slightly different format
# AGENTS.md — yet another copy

# ✅ Single source of truth with pointer files
# AGENTS.md — all rules live here (the source of truth)

# CLAUDE.md — one line
Strictly follow the rules in ./AGENTS.md

# .cursorrules — one line
Follow all instructions in ./AGENTS.md in this repository.

# Or just use symlinks:
# ln -s AGENTS.md CLAUDE.md
# ln -s AGENTS.md .cursorrules
```

## Three Pillars: Complete Task Enforcement

```markdown
# ❌ No completion criteria — agent decides when "done" means done
## Rules
- Try to write good code
- Test if you can

# ✅ Three Pillars — explicit completion criteria for every task
## Three Pillars — Every Task Must Satisfy All Three

A task is **not complete** until:
1. ✅ **AUTOMATING** — Lint, type-check, and format pass on all changed files
2. ✅ **TESTING** — Tests pass, new code has tests, no tests removed
3. ✅ **DOCUMENTING** — This AGENTS.md is updated if the change affects it

Skipping any pillar = incomplete work.
```

## Three Pillars: AUTOMATING Section

```markdown
# ❌ No post-task verification — agent commits unchecked code
(section missing entirely)

# ✅ Explicit verification commands for every change
## Task Completion — AUTOMATING

After every code change, run these checks on the files you modified:

1. **Lint**: `npx eslint --fix path/to/changed/file.tsx`
2. **Type-check**: `npx tsc --noEmit path/to/changed/file.tsx`
3. **Format**: `npx prettier --write path/to/changed/file.tsx`

A task is not complete until all three pass.
Do not commit code that fails linting or type-checking.
```

## Three Pillars: TESTING Section

```markdown
# ❌ Vague testing expectations — agent skips tests
## Testing
- Write tests when needed
- Run the test suite sometimes

# ✅ Explicit testing rules per change type
## Task Completion — TESTING

Every code change must include verification:

- **New features**: Write tests before or alongside the implementation
- **Bug fixes**: Add a regression test that reproduces the bug, then fix
- **Refactors**: Run existing tests to confirm no regressions

Run tests on changed files:
npx vitest run path/to/changed/file.test.tsx

Do not remove or weaken existing tests to make the suite pass.
```

## Three Pillars: DOCUMENTING Section

```markdown
# ❌ No documentation rules — AGENTS.md goes stale immediately
(section missing entirely)

# ✅ Change-type checklists for automatic documentation updates
## Task Completion — DOCUMENTING

This AGENTS.md must stay in sync with the codebase.
After completing any task, check whether your changes require updates here.

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
| Bug fix | Don't section (if recurring mistake) |
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
```

## Three Pillars: Validation by Change Type

```markdown
# ❌ Same rules for every change — overkill for docs, too lax for features
## After Changes
- Run tests
- Update docs

# ✅ Specific pillar requirements per change type
| Change Type | AUTOMATING | TESTING | DOCUMENTING |
|-------------|-----------|---------|-------------|
| New feature | Lint + type-check + format | New tests required | Update Structure, Do, Commands |
| Bug fix | Lint + type-check | Regression test required | Update Don't if recurring |
| Refactor | Lint + type-check + format | Run existing tests | Update Structure, Examples |
| Dependency change | Lint + type-check | Run full suite | Update Tech Stack, Commands |
| Config change | Lint if applicable | Smoke test | Update Commands, Boundaries |
| Documentation only | N/A | N/A | Update AGENTS.md if structural |
```

## When to Use

- "Create an AGENTS.md for this project"
- "My AI agent keeps using the wrong patterns"
- "Set up agent instructions for our monorepo"
- "Audit my AGENTS.md for missing sections"
- "Make my AGENTS.md work with Claude and Cursor"
- "My agent ships untested code"
- "My AGENTS.md keeps going stale"
