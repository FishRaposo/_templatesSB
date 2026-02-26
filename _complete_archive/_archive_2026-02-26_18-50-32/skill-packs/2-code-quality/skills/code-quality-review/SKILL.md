---
name: code-quality-review
description: Use this skill when conducting code reviews, assessing code quality, or building review processes. This includes review checklists, automated analysis, PR review workflows, and measuring code health through structured review.
---

# Code Quality Review

I'll help you measure and improve code through structured review checklists and automated analysis. When you invoke this skill, I can guide you through building review processes, conducting thorough reviews, and automating quality checks.

# Core Approach

My approach focuses on:
1. Using consistent checklists to catch common issues
2. Automating what can be automated (lint, format, coverage)
3. Focusing human review on design, logic, and maintainability
4. Giving constructive, actionable feedback

# Step-by-Step Instructions

## 1. Review Checklist

Use a structured checklist for every code review:

### Correctness
- Does the code do what it claims to do?
- Are edge cases handled (null, empty, boundary values)?
- Are error paths correct and tested?
- Does it handle concurrency safely (if applicable)?

### Design
- Is the code in the right place (right file, right layer)?
- Are responsibilities clearly separated?
- Could any part be simplified without losing functionality?
- Are there any premature abstractions?

### Quality
- Are names descriptive and consistent?
- Are functions small and single-purpose?
- Is there duplicated logic that should be extracted?
- Are magic numbers/strings extracted to constants?

### Security
- Is user input validated and sanitized?
- Are SQL queries parameterized?
- Are secrets/tokens kept out of code?
- Are permissions checked before sensitive operations?

### Testing
- Are new code paths covered by tests?
- Do tests verify behavior, not implementation?
- Are edge cases tested?
- Are tests readable and maintainable?

## 2. Automate the Mechanical Checks

Free up human reviewers for design and logic by automating:

```yaml
# .github/workflows/pr-quality.yml
name: PR Quality Check
on: [pull_request]
jobs:
  automated-review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm ci

      # Formatting — no debate needed
      - run: npx prettier --check .

      # Linting — catches common bugs
      - run: npx eslint . --max-warnings 0

      # Type checking
      - run: npx tsc --noEmit

      # Tests with coverage threshold
      - run: npx jest --coverage --coverageThreshold='{"global":{"lines":80}}'

      # Dependency audit
      - run: npm audit --audit-level=high

      # Bundle size check (for frontend)
      - run: npx size-limit
```

```bash
# Pre-commit hook for instant feedback
npx husky add .husky/pre-commit "npx lint-staged"

# lint-staged config in package.json
# "lint-staged": {
#   "*.{ts,tsx}": ["eslint --fix", "prettier --write"],
#   "*.{json,md}": ["prettier --write"]
# }
```

## 3. Give Constructive Feedback

**Good review comments:**
```markdown
# ✅ Specific and actionable
"This function does both validation and persistence — consider extracting
`validateOrder()` so each function has a single responsibility."

# ✅ Explains WHY
"Using `any` here loses type safety. Consider defining an interface for
the API response so downstream code gets autocomplete and type checks."

# ✅ Asks questions when unsure
"I notice this skips the cache for admin users — is that intentional?
If so, a comment explaining why would help future readers."
```

**Bad review comments:**
```markdown
# ❌ Vague
"This could be better."

# ❌ Nitpicking (should be automated)
"Missing semicolon on line 42."

# ❌ Prescriptive without context
"Use a factory pattern here."
```

## 4. Self-Review Before Requesting Review

Before opening a PR:

```bash
# Check your own diff
git diff main...HEAD --stat           # Files changed
git diff main...HEAD -- '*.ts'        # Actual changes

# Run all automated checks locally
npm run lint && npm run test && npm run build

# Check PR size — ideally <400 lines changed
git diff main...HEAD --stat | tail -1
```

# Best Practices

- Keep PRs small (≤400 lines changed) for effective review
- Review your own code first before requesting others
- Automate formatting and style checks — don't waste human time on them
- Focus human review on: correctness, design, security, and readability
- Respond to every comment — even if just "Done" or "Won't fix because..."
- Use PR templates to ensure consistency
- Praise good code too, not just criticize

# Validation Checklist

When setting up a review process, verify:
- [ ] PR template exists with checklist items
- [ ] Automated checks run on every PR (lint, test, format)
- [ ] Coverage thresholds enforce minimum test coverage
- [ ] Review is required before merging (branch protection)
- [ ] Human review focuses on design and logic, not style
- [ ] Reviewers provide specific, actionable feedback
- [ ] PR size guidelines are communicated to the team

# Troubleshooting

## Issue: Reviews Take Too Long

**Symptoms**: PRs sit for days without review, blocking progress

**Solution**:
- Set team SLA for first review (e.g., 4 hours)
- Keep PRs small — large PRs get deprioritized
- Use CODEOWNERS to auto-assign reviewers
- Automate mechanical checks so humans only review design

## Issue: Review Comments Cause Conflict

**Symptoms**: Defensive reactions, arguments in PR comments

**Solution**:
- Frame as questions, not demands ("What do you think about...?")
- Use "we" language ("Could we simplify this?")
- Separate style preferences from correctness issues
- If unresolved, discuss synchronously then document the decision

# Supporting Files

- See `./_examples/basic-examples.md` for PR checklists, CI setup, and review comment examples
- See `./README.md` for quick start and invocation examples

## Related Skills

- **clean-code** - The standards being checked during review
- **code-metrics** - Quantitative quality data to inform reviews
- **code-standards** - The automated rules that reduce review burden
- **code-refactoring** - The tool for addressing review feedback
- → **31-collaboration-workflows**: pull-requests, code-review (for team workflow aspects)

Remember: The goal of code review is to improve the code AND the team — not to prove who's right!
