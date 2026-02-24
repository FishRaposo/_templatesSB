# Code Standards — Basic Examples

## ESLint Setup (JavaScript/TypeScript)

```javascript
// eslint.config.js (flat config, ESLint 9+)
import eslint from '@eslint/js';
import tseslint from 'typescript-eslint';

export default tseslint.config(
  eslint.configs.recommended,
  ...tseslint.configs.strict,
  {
    rules: {
      'no-console': 'warn',
      '@typescript-eslint/no-unused-vars': ['error', { argsIgnorePattern: '^_' }],
      'complexity': ['warn', { max: 15 }],
      'max-depth': ['warn', { max: 3 }],
      'prefer-const': 'error',
      'no-var': 'error',
    },
  },
);
```

## Ruff Setup (Python)

```toml
# pyproject.toml
[tool.ruff]
target-version = "py312"
line-length = 100

[tool.ruff.lint]
select = ["E", "W", "F", "I", "N", "UP", "B", "C4", "SIM"]

[tool.ruff.lint.per-file-ignores]
"tests/**" = ["S101"]
```

## golangci-lint Setup (Go)

```yaml
# .golangci.yml
linters:
  enable:
    - gofmt
    - govet
    - errcheck
    - staticcheck
    - cyclop
  settings:
    cyclop:
      max-complexity: 15
```

## Pre-Commit Hooks

```bash
# Install husky + lint-staged
npm i -D husky lint-staged
npx husky init
echo 'npx lint-staged' > .husky/pre-commit
```

```json
// package.json
{
  "lint-staged": {
    "*.{ts,tsx}": ["eslint --fix", "prettier --write"],
    "*.{json,md}": ["prettier --write"]
  }
}
```

## Conventional Commits

```bash
# Install commitlint
npm i -D @commitlint/{cli,config-conventional}
echo 'export default { extends: ["@commitlint/config-conventional"] };' > commitlint.config.js
echo 'npx --no -- commitlint --edit $1' > .husky/commit-msg
```

```
# Valid commit messages
feat: add user registration endpoint
fix: prevent duplicate email registration
refactor: extract validation into middleware
docs: update API authentication guide
test: add integration tests for payment flow
```

## CI Quality Gate

```yaml
# .github/workflows/quality.yml
name: Quality
on: [pull_request]
jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm ci
      - run: npx eslint . --max-warnings 0
      - run: npx prettier --check .
      - run: npx tsc --noEmit
```

## When to Use
- "Set up ESLint for this project"
- "Configure Prettier and pre-commit hooks"
- "Add commit message conventions"
- "Set up CI quality gates"
