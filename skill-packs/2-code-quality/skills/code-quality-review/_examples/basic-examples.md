# Code Quality Review — Basic Examples

## PR Review Checklist

```markdown
## Review Checklist
### Correctness
- [ ] Code does what the PR description says
- [ ] Edge cases handled (null, empty, boundary)
- [ ] Error paths are correct and tested

### Design
- [ ] Code is in the right file/layer
- [ ] No premature abstractions
- [ ] Functions are ≤50 lines, single-purpose

### Security
- [ ] User input validated and sanitized
- [ ] SQL queries parameterized
- [ ] No secrets in code

### Tests
- [ ] New paths covered by tests
- [ ] Tests verify behavior, not implementation
```

## Automated Quality Checks (CI)

**GitHub Actions:**
```yaml
name: PR Quality
on: [pull_request]
jobs:
  quality:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm ci
      - run: npx eslint . --max-warnings 0
      - run: npx prettier --check .
      - run: npx tsc --noEmit
      - run: npx jest --coverage --coverageThreshold='{"global":{"lines":80}}'
```

## Good vs Bad Review Comments

```markdown
# ✅ Good: specific, actionable, explains why
"This function validates AND saves — consider extracting `validateOrder()` 
so each function has a single responsibility. This makes testing easier too."

# ✅ Good: asks a question
"I see we skip cache for admin users — is that intentional? 
A comment explaining why would help future readers."

# ❌ Bad: vague
"This could be better."

# ❌ Bad: should be automated
"Missing semicolon on line 42."

# ❌ Bad: prescriptive without rationale
"Use a factory pattern here."
```

## Self-Review Before PR

```bash
# Check your own diff
git diff main...HEAD --stat
git diff main...HEAD -- '*.ts' | head -200

# Run all checks locally
npm run lint && npm test && npm run build

# Check PR size (aim for <400 lines)
git diff main...HEAD --stat | tail -1
```

## When to Use
- "Review this code for quality issues"
- "Create a PR review checklist for our team"
- "Set up automated quality checks in CI"
- "How should I give feedback on this PR?"
