<!-- Generated from task-outputs/task-14-quality-gate-setup.md -->

# Task 14 — Quality Gate Setup
> Skills: code-standards + code-metrics + code-quality-review

## Monorepo Quality Gates

### Package A (API)

```javascript
// packages/api/eslint.config.js
export default [
  {
    rules: {
      'complexity': ['error', 10],
      '@typescript-eslint/no-explicit-any': 'error'
    }
  }
];

// packages/api/jest.config.js
module.exports = {
  coverageThreshold: {
    global: { branches: 85, functions: 90, lines: 90 }
  }
};
```

### Package B (UI)

```javascript
// packages/ui/eslint.config.js
export default [
  {
    rules: {
      'react-hooks/rules-of-hooks': 'error',
      'react-hooks/exhaustive-deps': 'warn'
    }
  }
];
```

### Package C (Shared)

```javascript
// packages/shared/package.json
{
  "scripts": {
    "lint": "eslint src/",
    "test": "vitest run --coverage",
    "typecheck": "tsc --noEmit"
  }
}
```

### Root CI Workflow

```yaml
name: Quality Gates
on: [pull_request]

jobs:
  api:
    runs-on: ubuntu-latest
    defaults:
      run: { working-directory: packages/api }
    steps:
      - uses: actions/checkout@v3
      - run: npm ci
      - run: npm run lint
      - run: npm run typecheck
      - run: npm test -- --coverage
        
  ui:
    runs-on: ubuntu-latest
    defaults:
      run: { working-directory: packages/ui }
    steps:
      - uses: actions/checkout@v3
      - run: npm ci
      - run: npm run lint
      - run: npm run test
        
  shared:
    runs-on: ubuntu-latest
    defaults:
      run: { working-directory: packages/shared }
    steps:
      - uses: actions/checkout@v3
      - run: npm ci
      - run: npm run lint
      - run: npm run typecheck
      - run: npm run test
```

### CODEOWNERS

```
packages/api/ @backend-team
packages/ui/ @frontend-team
packages/shared/ @architects
```

- [x] All config files work together without conflicts
- [x] CI workflow covers all automated checks
- [x] PR template and review process are practical

