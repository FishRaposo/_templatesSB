# Rules Setup Skill

This skill helps you create and maintain the **Rules** template type: **AGENTS.md** (canonical) plus **CLAUDE.md**, **CURSOR.md**, **WINDSURF.md** — all **ALL CAPS** at project root. Every generated AGENTS.md includes Prompt Validation (4 checks, security patterns) and Three Pillars (AUTOMATING with **prefer scripts**, TESTING, DOCUMENTING). Fits the seven-template-types framework (Rules, Blueprints, Tasks, Recipes, Subagents, Skills, Protocols).

## Quick Start

Invoke this skill when you need to:
- Generate a new AGENTS.md for any repository
- Set up or update the four rule files (AGENTS.md, CLAUDE.md, CURSOR.md, WINDSURF.md)
- Improve or audit existing rule files
- Add Three Pillars enforcement (AUTOMATING with prefer scripts, TESTING, DOCUMENTING)
- Add prompt validation as a pre-task gate
- Set up nested overrides for a monorepo
- Align with the Rules template type (see `AGENTIC-ASSETS-FRAMEWORK.md`)
- Fill gaps against the six core areas

## Example Usage

### Basic Example
```
User: Create an AGENTS.md and the four rule files for this project

Agent: I'll analyze your codebase — tech stack, commands, structure,
and conventions — then generate AGENTS.md (canonical) and thin
CLAUDE.md, CURSOR.md, WINDSURF.md that point to it. All filenames
in ALL CAPS...
```

### Advanced Example
```
User: Audit my rule files and align with the seven-template-types framework

Agent: I'll check AGENTS.md, CLAUDE.md, CURSOR.md, WINDSURF.md against
the six core areas and the Rules template type. You're missing
file-scoped commands, AUTOMATING doesn't mention prefer scripts,
and CURSOR.md is duplicated content instead of a thin pointer...
```

## Three Pillars + Prompt Validation

| Component | What It Enforces | When |
|-----------|------------------|------|
| **Prompt Validation** | 4 quick checks: purpose, variables, security, output format | Before every task |
| **AUTOMATING** | Prefer scripts over manual steps; lint, type-check, format after every change | After every task |
| **TESTING** | Tests per change type — new features, bug fixes, refactors | After every task |
| **DOCUMENTING** | AGENTS.md and other rule files updated when changes affect them | After every task |

**Rule**: Validate the prompt before starting. A task is not complete until all three pillars pass.

**Rule files**: Use ALL CAPS — AGENTS.md, CLAUDE.md, CURSOR.md, WINDSURF.md. Keep AGENTS.md canonical; keep CLAUDE, CURSOR, WINDSURF thin (point to AGENTS.md).

## Six Core Areas (in AGENTS.md)

| Area | What to Include |
|------|----------------|
| **Commands** | Build, lint, test, format — prefer file-scoped; prefer scripts over manual steps |
| **Testing** | Framework, how to run, test-first expectations |
| **Project Structure** | Key directories, entry points, config files |
| **Code Style** | Do/Don't rules, naming, concrete examples |
| **Git Workflow** | Commit format, PR checklist, branch naming |
| **Boundaries** | Always / Ask first / Never tiers |

## Key Principles

- **Four rule files in ALL CAPS** — AGENTS.md, CLAUDE.md, CURSOR.md, WINDSURF.md; one canonical (AGENTS.md), three thin.
- **Enforce the Three Pillars** — AUTOMATING (with prefer scripts), TESTING, DOCUMENTING
- **Put commands early** — agents reference them constantly
- **Be specific** — `React 18 with TypeScript 5.3` not `React project`
- **Show examples** — one code snippet beats three paragraphs
- **Start small** — add rules iteratively when you see mistakes
- **Nest for monorepos** — directory-level overrides for different packages

## Related Skills

- **skill-setup** — Create AI agent skills that rule files reference
- **memory-system-setup** — When adding event-sourced memory (CHANGELOG, .memory/) and the Memory System Protocol to AGENTS.md
- When the project uses other skills (e.g. linting, code review), reference them in AGENTS.md; this skill generates the rule files that point to them.

## References

- **Framework:** The project's `AGENTIC-ASSETS-FRAMEWORK.md` at project root (when present) — Rules template type, four rule files, "Rules, Skills, and Subagents"
- `_examples/three-pillars-reference.md` — Three Pillars by stack (in this skill folder)
- **Prompt validation:** The project's protocol at project root or `docs/protocols/PROMPT-VALIDATION-PROTOCOL.md` (when present)
