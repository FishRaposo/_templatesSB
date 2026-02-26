# Agents Setup Skill

This skill helps you create effective AGENTS.md files with built-in **Prompt Validation Protocol**. Every generated AGENTS.md includes both input validation (4 must-pass checks, 27 security patterns, 5-dimension scoring) and output enforcement (Three Pillars: AUTOMATING, TESTING, DOCUMENTING).

## Quick Start

Invoke this skill when you need to:
- Generate a new AGENTS.md for any repository
- Improve or audit an existing AGENTS.md
- Add Three Pillars enforcement (AUTOMATING, TESTING, DOCUMENTING)
- Add prompt validation as a pre-task gate
- Set up nested overrides for a monorepo
- Create cross-tool compatibility (CLAUDE.md, .cursorrules pointers)
- Fill gaps in agent instructions against the six core areas

## Example Usage

### Basic Example
```
User: Create an AGENTS.md for this project

Agent: I'll analyze your codebase — tech stack, commands, structure,
and conventions — then generate a complete AGENTS.md covering all
six core areas: commands, testing, structure, code style, git
workflow, and boundaries...
```

### Advanced Example
```
User: Audit my AGENTS.md and fill in any gaps

Agent: I'll check your AGENTS.md against the six core areas.
You're missing file-scoped commands (you only have full builds),
your boundaries section has no "ask first" tier, and your code
style section is vague. Here are the specific additions...
```

## Three Pillars + Prompt Validation

Every generated AGENTS.md includes both **input validation** and **output enforcement**:

| Component | What It Enforces | When |
|-----------|------------------|------|
| **Prompt Validation** | 4 quick checks: purpose, variables, security, output format | Before every task |
| **AUTOMATING** | Lint, type-check, format after every change | After every task |
| **TESTING** | Tests per change type — new features, bug fixes, refactors | After every task |
| **DOCUMENTING** | AGENTS.md updated when changes affect it | After every task |

**Rule**: Validate the prompt before starting. A task is not complete until all three pillars pass.

**References**:
- `_examples/three-pillars-reference.md` — multi-stack templates, adaptation by project type, failure modes
- `../PROMPT-VALIDATION-PROTOCOL.md` — full 5-dimension scoring, type-specific checklists, security patterns (this skill embeds the complete protocol)

## Six Core Areas

| Area | What to Include |
|------|----------------|
| **Commands** | Build, lint, test, format — prefer file-scoped |
| **Testing** | Framework, how to run, test-first expectations |
| **Project Structure** | Key directories, entry points, config files |
| **Code Style** | Do/Don't rules, naming, concrete examples |
| **Git Workflow** | Commit format, PR checklist, branch naming |
| **Boundaries** | Always / Ask first / Never tiers |

## Key Principles

- **Enforce the Three Pillars** — every AGENTS.md must have AUTOMATING, TESTING, DOCUMENTING
- **Put commands early** — agents reference them constantly
- **Be specific** — `React 18 with TypeScript 5.3` not `React project`
- **Show examples** — one code snippet beats three paragraphs
- **Start small** — add rules iteratively when you see mistakes
- **Nest for monorepos** — directory-level overrides for different packages

## Related Skills

- **skill-builder** - Create AI agent skills that AGENTS.md references
- **code-standards** - Define linting/formatting rules for AGENTS.md
- **code-quality-review** - Set up the PR process AGENTS.md documents
