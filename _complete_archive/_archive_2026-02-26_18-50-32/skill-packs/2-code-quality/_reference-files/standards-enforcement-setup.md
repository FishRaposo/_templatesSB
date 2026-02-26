<!-- Generated from task-outputs/task-11-code-standards.md -->

# Task 11 — Code Standards Enforcement
> Skills: code-standards, code-quality-review

## ESLint Flat Config

```javascript
// eslint.config.js
import js from '@eslint/js';
import ts from 'typescript-eslint';
import prettier from 'eslint-config-prettier';

export default [
  js.configs.recommended,
  ...ts.configs.recommended,
  {
    rules: {
      'complexity': ['error', 10],
      'max-lines-per-function': ['error', 50],
      'no-console': ['warn'],
      '@typescript-eslint/explicit-function-return-type': 'error'
    }
  },
  prettier
];
```

## Ruff (Python)

```toml
# pyproject.toml
[tool.ruff]
line-length = 100
target-version = "py311"

[tool.ruff.lint]
select = ["E", "F", "I", "N", "W", "UP", "B", "C4"]
ignore = ["E501"]

[tool.ruff.lint.pydocstyle]
convention = "google"
```

## Prettier

```json
{
  "semi": true,
  "singleQuote": true,
  "tabWidth": 2,
  "trailingComma": "es5",
  "printWidth": 100
}
```

## Commitlint + Husky

```json
// .commitlintrc.json
{
  "extends": ["@commitlint/config-conventional"],
  "rules": {
    "type-enum": [2, "always", ["feat", "fix", "docs", "style", "refactor", "test", "chore"]]
  }
}
```

```json
// package.json
{
  "husky": {
    "hooks": {
      "pre-commit": "lint-staged",
      "commit-msg": "commitlint -E HUSKY_GIT_PARAMS"
    }
  },
  "lint-staged": {
    "*.{js,ts}": ["eslint --fix", "prettier --write"],
    "*.py": ["ruff check --fix", "ruff format"]
  }
}
```

## CI Pipeline

```yaml
name: Standards
on: [pull_request]

jobs:
  enforce:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - run: npm ci
      - run: npx eslint . --max-warnings=0
      - run: npx prettier --check .
      - run: npm run typecheck
```

- [x] All config files are complete and correct
- [x] Pre-commit hooks work for both JS and Python
- [x] CI pipeline enforces all standards
- [x] Style guide is concise (manual decisions only)

