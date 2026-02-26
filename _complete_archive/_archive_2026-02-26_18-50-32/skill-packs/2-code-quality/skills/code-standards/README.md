# Code Standards Skill

This skill helps you establish and enforce coding standards with linters, formatters, and CI gates.

## Quick Start

Invoke this skill when you need to:
- Set up ESLint, Prettier, or Ruff for a project
- Configure pre-commit hooks
- Set up CI quality gates
- Create a team style guide
- Enforce commit message conventions

## Example Usage

### Basic Example
```
User: Set up linting and formatting for this TypeScript project

Agent: I'll configure ESLint with strict TypeScript rules, Prettier for
formatting, and husky pre-commit hooks for automatic enforcement...
```

## Tool Stack by Language

| Language | Linter | Formatter | Commit |
|----------|--------|-----------|--------|
| JS/TS | ESLint | Prettier | commitlint |
| Python | Ruff | Ruff format | commitlint |
| Go | golangci-lint | gofmt | commitlint |

## Related Skills

- **code-metrics** - Enforce metric thresholds as linter rules
- **code-quality-review** - Standards reduce manual review burden
- **clean-code** - Standards automate clean code enforcement
