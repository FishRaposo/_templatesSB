---
name: code-standards
description: Use this skill when establishing or enforcing coding standards for a team or project. This includes configuring linters, formatters, commit conventions, CI quality gates, and creating style guides that reduce bikeshedding and improve consistency.
---

# Code Standards

I'll help you establish and enforce coding standards with linters, formatters, and CI gates. When you invoke this skill, I can guide you through setting up automated enforcement so standards are followed consistently without manual effort.

# Core Approach

My approach focuses on:
1. Automating everything that can be automated (formatting, linting, commit messages)
2. Using well-established community configs as a starting point
3. Enforcing in CI so non-compliant code can't merge
4. Keeping rules practical — enforce what matters, ignore what doesn't

# Step-by-Step Instructions

## 1. Set Up Linting

Catch bugs and enforce patterns at development time:

**JavaScript/TypeScript (ESLint):**
```bash
npm init @eslint/config@latest
```

```javascript
// eslint.config.js (flat config)
import eslint from '@eslint/js';
import tseslint from 'typescript-eslint';

export default tseslint.config(
  eslint.configs.recommended,
  ...tseslint.configs.strict,
  {
    rules: {
      'no-console': 'warn',
      'no-unused-vars': 'off',
      '@typescript-eslint/no-unused-vars': ['error', { argsIgnorePattern: '^_' }],
      'complexity': ['warn', { max: 15 }],
      'max-depth': ['warn', { max: 3 }],
      'max-lines-per-function': ['warn', { max: 50 }],
      'prefer-const': 'error',
      'no-var': 'error',
    },
  },
);
```

**Python (Ruff — replaces flake8 + isort + pyupgrade):**
```toml
# pyproject.toml
[tool.ruff]
target-version = "py312"
line-length = 100

[tool.ruff.lint]
select = [
  "E",    # pycodestyle errors
  "W",    # pycodestyle warnings
  "F",    # pyflakes
  "I",    # isort
  "N",    # pep8-naming
  "UP",   # pyupgrade
  "B",    # bugbear
  "C4",   # comprehensions
  "SIM",  # simplify
]

[tool.ruff.lint.per-file-ignores]
"tests/**" = ["S101"]  # allow assert in tests
```

**Go (golangci-lint):**
```yaml
# .golangci.yml
linters:
  enable:
    - gofmt
    - goimports
    - govet
    - errcheck
    - staticcheck
    - gosimple
    - ineffassign
    - unused
    - cyclop
    - gocognit
  settings:
    cyclop:
      max-complexity: 15
    gocognit:
      min-complexity: 20
```

## 2. Set Up Formatting

End formatting debates forever — automate it:

```bash
# JavaScript/TypeScript: Prettier
npm i -D prettier
echo '{"semi": true, "singleQuote": true, "trailingComma": "all", "printWidth": 100}' > .prettierrc

# Python: already handled by Ruff
ruff format src/

# Go: built-in
gofmt -w .
goimports -w .
```

## 3. Enforce Commit Conventions

Standardize commit messages for automated changelogs:

```bash
# Install commitlint + husky
npm i -D @commitlint/{cli,config-conventional} husky

# Configure commitlint
echo 'export default { extends: ["@commitlint/config-conventional"] };' > commitlint.config.js

# Set up husky
npx husky init
echo 'npx --no -- commitlint --edit $1' > .husky/commit-msg
```

**Conventional Commits format:**
```
feat: add user registration endpoint
fix: prevent duplicate email registration
refactor: extract validation into middleware
docs: update API authentication guide
test: add integration tests for payment flow
chore: upgrade ESLint to v9
```

## 4. Enforce in CI

Make compliance mandatory — non-compliant code cannot merge:

```yaml
# .github/workflows/standards.yml
name: Code Standards
on: [pull_request]
jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { node-version: '22' }
      - run: npm ci
      - run: npx eslint . --max-warnings 0
      - run: npx prettier --check .
      - run: npx tsc --noEmit
      - run: npx commitlint --from ${{ github.event.pull_request.base.sha }}
```

## 5. Document the Standards

Create a concise style guide that covers only what automation doesn't:

```markdown
# Code Style Guide

## Automated (don't discuss — the tools handle it)
- Formatting: Prettier (runs on save and in CI)
- Linting: ESLint strict config (runs in CI)
- Commits: Conventional Commits (enforced by commitlint)

## Manual (team decisions)
- File organization: one primary export per file
- Naming: PascalCase for components, camelCase for functions, UPPER_SNAKE for constants
- Error handling: always use typed AppError subclasses (see error-handling skill)
- Comments: explain WHY, not WHAT; no commented-out code
```

# Best Practices

- Start with community configs (eslint/recommended, prettier defaults) and customize sparingly
- Automate on save (format on save in IDE) and in CI (block on violations)
- Use pre-commit hooks for fast feedback, CI for enforcement
- Don't add rules the team doesn't agree with — discuss and vote
- Grandfather existing violations — fix forward, don't block all PRs on day one
- Keep the style guide short — if it's more than 1 page, automate more

# Validation Checklist

When setting up code standards, verify:
- [ ] Linter configured with community base + team-specific rules
- [ ] Formatter runs on save and in CI
- [ ] Pre-commit hooks run linting and formatting
- [ ] CI blocks PRs that violate linting or formatting
- [ ] Commit messages follow Conventional Commits
- [ ] Style guide exists for manual decisions only
- [ ] Editor config (`.editorconfig`) ensures consistent settings

# Troubleshooting

## Issue: Too Many Linting Errors on Existing Code

**Symptoms**: Enabling linting on a legacy project produces thousands of errors

**Solution**:
- Use `eslint-config-prettier` to avoid format-vs-lint conflicts
- Add `// eslint-disable-next-line` only for justified cases
- Use `--fix` to auto-fix what can be auto-fixed
- Enable rules incrementally — start with errors, add warnings later
- Use `eslint --no-error-on-unmatched-pattern` for gradual adoption

## Issue: Team Disagrees on Rules

**Symptoms**: Endless debates about tabs vs spaces, semicolons, etc.

**Solution**:
- Use Prettier defaults — it was designed to end these debates
- For linting rules, vote and move on — consistency matters more than preference
- Document the decision and the rationale
- Remind: "We can always change it later — what matters is consistency now"

# Supporting Files

- See `./_examples/basic-examples.md` for ESLint, Ruff, Prettier, commitlint, and CI gate examples
- See `./README.md` for quick start and invocation examples

## Related Skills

- **code-metrics** - Enforce metric thresholds as linter rules
- **code-quality-review** - Standards reduce what humans need to review
- **clean-code** - Standards automate clean code enforcement
- → **12-devops-automation**: ci-cd-pipelines (for CI quality gates)
- → **31-collaboration-workflows**: git-workflow (for commit conventions)

Remember: The best code standard is one that's enforced automatically — if a human has to check it, it won't be followed!
