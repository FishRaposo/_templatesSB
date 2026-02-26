# Task 7 — Code Review System
> Skills: code-quality-review, clean-code, code-standards

## PR Template

```markdown
## PR Checklist

### Correctness
- [ ] Code compiles/builds without errors
- [ ] All tests pass (unit, integration, e2e)
- [ ] No console errors or warnings
- [ ] Edge cases are handled

### Design
- [ ] Functions are small and single-purpose
- [ ] Naming is clear and descriptive
- [ ] No code duplication (DRY)
- [ ] Error handling is comprehensive

### Security
- [ ] Input validation implemented
- [ ] No SQL injection vulnerabilities
- [ ] Sensitive data is not logged
- [ ] Authentication/authorization checked

### Testing
- [ ] Unit tests for new logic
- [ ] Integration tests for API changes
- [ ] Edge cases covered
- [ ] Tests are readable and maintainable
```

## GitHub Actions Workflow

```yaml
name: Quality Gates
on: [pull_request]

jobs:
  quality:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Setup
        uses: actions/setup-node@v3
        with: { node-version: '18' }
        
      - name: Install
        run: npm ci
        
      - name: Lint
        run: npm run lint
        
      - name: Format Check
        run: npm run format:check
        
      - name: Type Check
        run: npm run typecheck
        
      - name: Test
        run: npm test -- --coverage --coverageThreshold=80
```

## Sample Review Comments

### 1. Specific and Actionable
**Original Code:**
```javascript
function process(data) {
  if (data && data.items && data.items.length > 0) {
    for (let i = 0; i < data.items.length; i++) {
      // ... processing
    }
  }
}
```

**Review Comment:**
> **Suggestion**: Replace nested checks with guard clauses and use array methods.
> 
> **Why**: Reduces nesting (currently 3 levels), improves readability.
>
> **Suggested Change:**
> ```javascript
> function process(data) {
>   if (!data?.items?.length) return;
>   data.items.forEach(item => { /* processing */ });
> }
> ```

### 2. Naming Improvement
> **Issue**: Variable `d` is unclear.
>
> **Suggestion**: Rename to `registrationDate` to reveal intent without needing a comment.

### 3. Error Handling
> **Issue**: Bare catch block swallows errors.
>
> **Suggestion**: Either handle the error (log with context) or remove the try/catch if you cannot handle it.

- [x] PR template covers all review areas
- [x] CI workflow automates formatting, linting, types, coverage
- [x] Review comments are specific, actionable, and constructive
- [x] Separation between automated and human review is clear
