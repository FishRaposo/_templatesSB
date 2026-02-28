# Contributing to TestProject

Thank you for contributing. This document covers how to report bugs, propose features, set up your development environment, and get your changes merged.

---

## Reporting Bugs

1. **Search existing issues** at {{FILL_ME:REPO_URL}}/issues before opening a new one
2. Use the **bug report template** at `.github/ISSUE_TEMPLATE/bug_report.md`
3. Include: environment details, reproduction steps, expected vs. actual behavior, and logs

## Proposing Features

1. Open a **feature request** using `.github/ISSUE_TEMPLATE/feature_request.md`
2. Describe the problem being solved, not just the solution
3. Wait for maintainer acknowledgment before beginning implementation

---

## Development Setup

### Prerequisites

- Python — 3.11+
- pip — 23+

### Setup

```bash
# Clone the repository
git clone {{FILL_ME:REPO_URL}}
cd TestProject

# Install dependencies
pip install -r requirements.txt

# Run tests to verify setup
pytest
```

---

## Branching and Commit Conventions

### Branches

```
main          ← stable, protected
feature/name  ← feature work
fix/name      ← bug fixes
docs/name     ← documentation-only changes
```

### Commit Messages

```
type(scope): short description

types: feat | fix | docs | style | refactor | test | chore
```

Examples:
- `feat(auth): add OAuth2 login flow`
- `fix(api): handle null response from upstream`
- `docs(readme): update setup instructions`

---

## Pull Request Process

1. Create a branch from `main`
2. Make your changes — satisfy all Three Pillars before marking ready
3. Run the test suite: `pytest`
4. Open a PR using the PR template
5. At least one maintainer approval required before merge

### Three Pillars Requirement for Contributors

Before marking your PR ready for review:

- **AUTOMATING** — run placeholder scanner (`grep -r '{{' .`), link checker, and linter — all exit 0
- **TESTING** — all tests pass, new code has coverage, examples are runnable
- **DOCUMENTING** — README/docs updated if behavior changed, CHANGELOG has an entry

---

## Code Style

Follow the conventions established in `AGENTS.md`. Key rules:

- Follow PEP 8 conventions
- Use type hints for all public functions
- Write docstrings for modules, classes, and public functions

Run the linter before committing: `ruff check .`

---

## Questions?

Open a discussion at {{FILL_ME:REPO_URL}}/discussions or check existing documentation.
