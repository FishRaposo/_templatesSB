# Contributing to _templatesSB

Thank you for contributing. This document covers how to report bugs, propose features, set up your development environment, and get your changes merged.

---

## Reporting Bugs

1. **Search existing issues** at the repository's Issues page before opening a new one.
2. Include: environment (OS, Git/Python versions), reproduction steps, expected vs. actual behavior, and relevant file paths (e.g. which skill or doc).

## Proposing Features

1. Open a **feature request** (or discussion) describing the problem and proposed solution.
2. For new template types or skills, reference `AGENTIC-ASSETS-FRAMEWORK.md` and `docs/SUGGESTIONS-FOR-NEW-TEMPLATES.md`.
3. Wait for maintainer acknowledgment before large changes.

---

## Development Setup

### Prerequisites

- Git
- Python 3 (for JSON validation and any scripts)
- Text editor or AI IDE (Cursor, VS Code, Windsurf)

### Setup

```bash
git clone <repo-url>
cd _templatesSB
# No npm/pip install required for docs and skills; optional: use scripts in docs/memory-system/scripts/ or .agents/skills/skill-setup/scripts/
```

### Verify

```bash
# Validate all skill configs
find .agents/skills -name "config.json" -exec python -m json.tool {} \; > /dev/null
```

---

## Branching and Commit Conventions

### Branches

- `main` — stable, protected
- `feature/name` — new features
- `fix/name` — bug fixes
- `docs/name` — documentation-only changes

### Commit Messages

```
type(scope): short description

types: feat | fix | docs | style | refactor | test | chore
```

Examples: `docs(skills): add protocol-setup to index` · `fix(memory): regenerate graph horizon`

---

## Pull Request Process

1. Create a branch from `main` (or the project's default branch).
2. Make your changes — satisfy all **Three Pillars** before marking ready.
3. Run JSON validation on any changed `config.json`.
4. Open a PR with a clear description and reference to CHANGELOG event if applicable.
5. After review, merge (squash or merge commit per project preference).

### Three Pillars Requirement for Contributors

Before marking your PR ready:

- **AUTOMATING** — Run structure/JSON/link checks where applicable; use scripts over manual inspection.
- **TESTING** — Examples and configs are valid; trigger keywords and paths are accurate.
- **DOCUMENTING** — README, docs/INDEX.md, AGENTS.md (or related rule files), and CHANGELOG.md updated per change type. See AGENTS.md "Three Pillars — DOCUMENTING" table.

---

## Code and Doc Style

- Follow conventions in **AGENTS.md** (Markdown, JSON, YAML).
- Skills: `SKILL.md` (frontmatter + steps + examples), `config.json` (triggers, examples), `README.md` &lt; 80 lines.
- Rule files at project root: **ALL CAPS** (AGENTS.md, CLAUDE.md, CURSOR.md, WINDSURF.md).
- No undefined `{{PLACEHOLDER}}` in committed files.

---

## Questions

Open an issue or discussion in the repository.
