# Code Quality — Skill Verification Tasks

> **Pack**: 2-code-quality
> **Skills Count**: 12
> **Generated from**: `skill-packs/TASKS-TEMPLATE.md`

These tasks are used to generate the reference files in `_reference-files/`. Each task names the **primary skill** and the **related skills** the agent should invoke. Use these tasks to verify skills produce correct, useful guidance.

**Pack location**: `skill-packs/2-code-quality/`

---

## A. Individual Skill Tasks

### Task 1 — clean-code

**Invoke**: `clean-code`, `simplify-complexity`

**Prompt**:
> Take this 80-line Express route handler that processes user registration (inline validation, database calls, email sending, analytics tracking, nested conditionals) and rewrite it following clean code principles. Show the before and after in JavaScript, then rewrite the "after" in Python (Flask) and Go (net/http). For each change, name the clean code principle applied (naming, SRP, guard clauses, no magic numbers, etc.).

**Output**: `task-01-clean-code.md`

**Evaluation criteria**:
- [ ] Applies naming, SRP, guard clauses, constants extraction
- [ ] Multi-language output (JS, Python, Go)
- [ ] Each change is labeled with the principle applied
- [ ] Result passes the clean-code validation checklist

---

### Task 2 — code-refactoring

**Invoke**: `code-refactoring`, `clean-code`, `code-deduplication`

**Prompt**:
> Given a 200-line `OrderProcessor` class that handles validation, pricing, inventory, payment, and notification, apply at least 5 distinct refactoring patterns to improve its design. Show each refactoring step separately with before/after code in JavaScript. Name each pattern (Extract Method, Introduce Parameter Object, Replace Conditional with Polymorphism, etc.). After all refactorings, show the final class decomposition diagram.

**Output**: `task-02-code-refactoring.md`

**Evaluation criteria**:
- [ ] At least 5 distinct refactoring patterns applied and named
- [ ] Each step shown incrementally (before → after)
- [ ] Behavior preservation discussed
- [ ] Final decomposition is clear and testable

---

### Task 3 — code-deduplication

**Invoke**: `code-deduplication`, `code-refactoring`, `code-metrics`

**Prompt**:
> Analyze a Node.js project with 3 service files (UserService, OrderService, ProductService) that each contain duplicated fetch-retry-error logic, duplicated validation patterns, and duplicated response formatting. Classify each duplication type (exact, near, structural, coincidental), extract shared utilities, and show the before/after with duplication percentage reduction. Use jscpd output format for detection results.

**Output**: `task-03-code-deduplication.md`

**Evaluation criteria**:
- [ ] Duplication correctly classified by type
- [ ] Shared utilities are well-named and focused
- [ ] Rule of Three respected (no premature abstraction)
- [ ] Duplication percentage quantified before and after

---

### Task 4 — error-handling

**Invoke**: `error-handling`, `input-validation`, `logging-strategies`

**Prompt**:
> Design and implement a complete error handling strategy for a REST API payment service. Include: (1) typed error hierarchy with at least 5 error classes, (2) error boundary middleware that converts errors to HTTP responses, (3) retry logic with exponential backoff for transient failures, (4) error wrapping that preserves the original cause chain. Show in JavaScript (Express) and Python (FastAPI). Include a test that verifies error propagation through all layers.

**Output**: `task-04-error-handling.md`

**Evaluation criteria**:
- [ ] Error hierarchy distinguishes operational vs programmer errors
- [ ] Retry logic handles transient vs permanent failures
- [ ] Error context preserved through wrapping
- [ ] HTTP boundary converts errors to proper responses
- [ ] Multi-language output (JS, Python)

---

### Task 5 — input-validation

**Invoke**: `input-validation`, `error-handling`

**Prompt**:
> Build a complete input validation layer for an e-commerce API with these endpoints: POST /users (registration), POST /orders (checkout), PUT /users/:id (profile update), POST /uploads (file upload). For each endpoint: create a Zod schema (JS) and Pydantic model (Python), handle validation errors with field-level messages, and demonstrate XSS sanitization, SQL injection prevention, and path traversal protection. Show the validation middleware that ties it all together.

**Output**: `task-05-input-validation.md`

**Evaluation criteria**:
- [ ] Schema validation for all 4 endpoints
- [ ] Field-level error messages
- [ ] Security sanitization (XSS, SQLi, path traversal)
- [ ] Multi-language (Zod + Pydantic)
- [ ] File upload validation (type, size, content)

---

### Task 6 — logging-strategies

**Invoke**: `logging-strategies`, `error-handling`

**Prompt**:
> Implement structured logging for a microservice that processes orders. Include: (1) pino setup with JSON output in JS, structlog in Python, slog in Go, (2) correlation ID middleware that propagates across HTTP calls, (3) correct log level usage for 10 different events (order created, payment failed, retry, cache miss, etc.), (4) sensitive data redaction (credit card, password fields). Show a sample log output for a complete order flow from request to completion.

**Output**: `task-06-logging-strategies.md`

**Evaluation criteria**:
- [ ] Structured JSON output in all 3 languages
- [ ] Correlation IDs propagate correctly
- [ ] Log levels are appropriate for each event
- [ ] Sensitive data is redacted
- [ ] Sample log output shows a complete flow

---

### Task 7 — code-quality-review

**Invoke**: `code-quality-review`, `clean-code`, `code-standards`

**Prompt**:
> Create a complete code review system for a TypeScript project: (1) PR template with structured checklist (correctness, design, security, tests), (2) GitHub Actions workflow that automates mechanical checks (lint, format, type-check, coverage), (3) review a sample 100-line PR diff and write 5 review comments demonstrating good review practices (specific, actionable, explains why). Show both the automation setup and the human review process.

**Output**: `task-07-code-quality-review.md`

**Evaluation criteria**:
- [ ] PR template covers all review areas
- [ ] CI workflow automates formatting, linting, types, coverage
- [ ] Review comments are specific, actionable, and constructive
- [ ] Separation between automated and human review is clear

---

### Task 8 — technical-debt

**Invoke**: `technical-debt`, `code-metrics`, `code-refactoring`

**Prompt**:
> Analyze a mature Node.js codebase and create a technical debt payoff plan. Include: (1) automated debt inventory using grep, madge, jscpd, and git log analysis, (2) scoring 8 debt items by impact × churn / effort, (3) a quarterly payoff plan allocating 20% sprint capacity, (4) guardrails (linter rules, coverage thresholds) to prevent new debt. Show all CLI commands, the scoring spreadsheet, and the sprint-by-sprint plan.

**Output**: `task-08-technical-debt.md`

**Evaluation criteria**:
- [ ] Multiple detection methods used (TODO grep, circular deps, duplication, churn)
- [ ] Scoring formula applied consistently
- [ ] Payoff plan is realistic and time-boxed
- [ ] Prevention guardrails included

---

### Task 9 — code-metrics

**Invoke**: `code-metrics`, `technical-debt`

**Prompt**:
> Set up a complete code quality metrics pipeline for a TypeScript project. Measure: (1) cyclomatic complexity with ESLint, (2) test coverage with Jest, (3) code duplication with jscpd, (4) churn hotspots with git log analysis. Create a CI job that collects all metrics, stores them in a JSON file, and fails the build if any metric regresses. Show the exact CLI commands, CI config, and a sample metrics dashboard output.

**Output**: `task-09-code-metrics.md`

**Evaluation criteria**:
- [ ] All 4 metric types measured with working commands
- [ ] CI pipeline collects and stores metrics
- [ ] Regression detection implemented
- [ ] Sample output shows realistic data

---

### Task 10 — simplify-complexity

**Invoke**: `simplify-complexity`, `clean-code`, `code-refactoring`

**Prompt**:
> Take 5 code snippets with different complexity problems and simplify each using a different technique: (1) deep nesting → guard clauses, (2) long switch → lookup table, (3) boolean flags → state machine, (4) god function → orchestrator + helpers, (5) clever one-liner → clear multi-line. Show before/after in JavaScript, with cyclomatic complexity scores for each. Then show the guard clause example in Python and Go as well.

**Output**: `task-10-simplify-complexity.md`

**Evaluation criteria**:
- [ ] 5 distinct techniques demonstrated
- [ ] Before/after for each with complexity scores
- [ ] Behavior preserved in all simplifications
- [ ] Multi-language for guard clause example

---

### Task 11 — code-standards

**Invoke**: `code-standards`, `code-quality-review`

**Prompt**:
> Set up a complete code standards enforcement system for a new TypeScript + Python monorepo. Include: (1) ESLint flat config with strict TypeScript rules, (2) Ruff config for Python, (3) Prettier for formatting, (4) commitlint for conventional commits, (5) husky pre-commit hooks with lint-staged, (6) CI pipeline that blocks non-compliant PRs, (7) a 1-page style guide covering only manual decisions. Show all config files and the CI workflow.

**Output**: `task-11-code-standards.md`

**Evaluation criteria**:
- [ ] All config files are complete and correct
- [ ] Pre-commit hooks work for both JS and Python
- [ ] CI pipeline enforces all standards
- [ ] Style guide is concise (manual decisions only)

---

### Task 12 — legacy-code-migration

**Invoke**: `legacy-code-migration`, `code-refactoring`, `technical-debt`

**Prompt**:
> Plan and begin executing a strangler fig migration for a legacy Express.js order management module (no tests, 500 lines, tightly coupled to a MySQL database). Include: (1) characterization tests capturing current behavior, (2) new TypeScript interface definition, (3) legacy adapter wrapping old code behind new interface, (4) shadow mode comparing old and new results, (5) feature flag configuration for phased cutover, (6) rollback plan. Show the complete migration code for one method (calculateTotal) through all 6 phases.

**Output**: `task-12-legacy-code-migration.md`

**Evaluation criteria**:
- [ ] Characterization tests capture actual behavior including quirks
- [ ] Interface defined before implementation
- [ ] Shadow mode compares results and logs mismatches
- [ ] Feature flag controls traffic, not deploys
- [ ] Rollback plan is documented and tested

---

## B. Combined Skill Tasks

### Task 13 — Production Hardening

**Invoke**: `error-handling` + `input-validation` + `logging-strategies` + `clean-code`

**Prompt**:
> Take a raw, unhardened Express API endpoint that accepts user registration (name, email, password, avatar upload) and make it production-ready:
> 1. **input-validation**: Add Zod schema validation with field-level errors
> 2. **error-handling**: Add typed errors, retry for email service, global error boundary
> 3. **logging-strategies**: Add structured pino logging with correlation ID
> 4. **clean-code**: Ensure the final code is clean, well-named, and well-structured
> Show the complete before and after, with all middleware, error classes, and logging.

**Output**: `task-13-production-hardening.md`

**Evaluation criteria**:
- [ ] All 4 skills visibly applied
- [ ] Skills integrated naturally (not applied in isolation)
- [ ] Result is genuinely production-ready

---

### Task 14 — Quality Gate Setup

**Invoke**: `code-standards` + `code-metrics` + `code-quality-review`

**Prompt**:
> Set up a complete quality gate system for a TypeScript monorepo with 3 packages:
> 1. **code-standards**: ESLint, Prettier, commitlint, pre-commit hooks
> 2. **code-metrics**: Complexity limits, coverage thresholds, duplication detection
> 3. **code-quality-review**: PR template, automated checks, CODEOWNERS
> Show all configuration files, the CI workflow, and a sample PR review process.

**Output**: `task-14-quality-gate-setup.md`

**Evaluation criteria**:
- [ ] All config files work together without conflicts
- [ ] CI workflow covers all automated checks
- [ ] PR template and review process are practical

---

### Task 15 — Debt Reduction Sprint

**Invoke**: `technical-debt` + `code-metrics` + `code-refactoring` + `code-deduplication`

**Prompt**:
> Execute a focused debt reduction sprint on a codebase with these problems: (1) a 400-line UserService god class, (2) duplicated validation across 4 controllers, (3) 12 TODO/FIXME markers, (4) no complexity limits enforced.
> 1. **code-metrics**: Measure current state (complexity, duplication, coverage)
> 2. **technical-debt**: Score and prioritize all debt items
> 3. **code-refactoring**: Decompose the god class into 3 focused services
> 4. **code-deduplication**: Extract shared validation utilities
> Show before/after metrics proving improvement.

**Output**: `task-15-debt-reduction-sprint.md`

**Evaluation criteria**:
- [ ] Metrics measured before and after
- [ ] Debt items scored and prioritized correctly
- [ ] God class successfully decomposed
- [ ] Duplication reduced with shared utilities

---

### Task 16 — Legacy Modernization

**Invoke**: `legacy-code-migration` + `error-handling` + `code-refactoring` + `logging-strategies`

**Prompt**:
> Modernize a legacy Python 2 payment processor module:
> 1. **legacy-code-migration**: Write characterization tests, create new interface, build adapter
> 2. **code-refactoring**: Decompose the monolithic process_payment() function
> 3. **error-handling**: Replace bare except/print with typed errors and proper handling
> 4. **logging-strategies**: Replace print statements with structured logging
> Show the migration through all phases including shadow mode comparison.

**Output**: `task-16-legacy-modernization.md`

**Evaluation criteria**:
- [ ] Characterization tests capture legacy quirks
- [ ] Strangler fig pattern applied correctly
- [ ] Error handling and logging are modern and structured
- [ ] Shadow mode validates behavioral equivalence

---

### Task 17 — Clean Codebase Audit

**Invoke**: `clean-code` + `simplify-complexity` + `code-metrics` + `code-quality-review`

**Prompt**:
> Perform a comprehensive code quality audit on a 2000-line TypeScript Express application:
> 1. **code-metrics**: Run complexity, coverage, and duplication analysis
> 2. **clean-code**: Identify naming, SRP, and formatting violations
> 3. **simplify-complexity**: Find and fix the 3 most complex functions
> 4. **code-quality-review**: Write a structured audit report with prioritized findings
> Produce a final audit report with scores, findings, and an action plan.

**Output**: `task-17-clean-codebase-audit.md`

**Evaluation criteria**:
- [ ] Quantitative metrics support qualitative findings
- [ ] Findings are specific and actionable
- [ ] Complexity reductions shown with before/after
- [ ] Action plan is prioritized by impact

---

## C. Capstone Task

### Task 18 — Full Stack (All 12 Skills)

**Invoke**: `clean-code`, `code-refactoring`, `code-deduplication`, `error-handling`, `input-validation`, `logging-strategies`, `code-quality-review`, `technical-debt`, `code-metrics`, `simplify-complexity`, `code-standards`, `legacy-code-migration`

**Prompt**:
> You're taking over a legacy Node.js e-commerce API (Express, MongoDB, no tests, 3000 lines across 8 files). The previous developer left and there's no documentation. Your mission:
> 1. **code-metrics**: Measure current quality (complexity, coverage, duplication, churn)
> 2. **technical-debt**: Create a scored debt inventory from the measurements
> 3. **clean-code**: Identify the top 10 cleanliness violations
> 4. **code-standards**: Set up ESLint, Prettier, and pre-commit hooks
> 5. **simplify-complexity**: Refactor the 3 most complex functions using guard clauses and decomposition
> 6. **code-refactoring**: Decompose the largest god class into focused services
> 7. **code-deduplication**: Extract shared utilities from duplicated patterns
> 8. **error-handling**: Replace try/catch with typed error hierarchy
> 9. **input-validation**: Add Zod schemas to all API endpoints
> 10. **logging-strategies**: Replace console.log with structured pino logging
> 11. **legacy-code-migration**: Use strangler fig to migrate the payment module
> 12. **code-quality-review**: Write a final audit report with before/after metrics
>
> Show your work for each step with before/after code. Produce a final quality scorecard.

**Output**: `task-18-full-stack.md`

**Evaluation criteria**:
- [ ] All 12 skills visibly applied
- [ ] Each step builds on previous steps
- [ ] Before/after metrics show measurable improvement
- [ ] Final codebase is production-ready
- [ ] Quality scorecard summarizes all improvements

---

## D. Execution Notes

- **Run each task as a fresh conversation** with the agent, explicitly invoking the named skills
- **Save the agent's full response** as a raw output file in `_reference-files/task-outputs/`
- **Evaluate** whether the agent correctly applied each skill's principles (check against the SKILL.md validation checklists)
- **Estimated time**: Individual tasks 10–20 min; combined tasks 20–40 min; capstone ~1.5 hours
- **Do not skip the capstone** — it validates that all 12 skills integrate correctly

## E. Reference File Generation

After running all tasks, convert raw outputs into standalone reference files. This is a three-phase process:

### Phase 1: Run tasks and save raw outputs

Save every raw agent response to `_reference-files/task-outputs/`:

```
_reference-files/
└── task-outputs/
    ├── task-01-clean-code.md
    ├── task-02-code-refactoring.md
    ├── ...
    ├── task-17-clean-codebase-audit.md
    └── task-18-full-stack.md         ← capstone
```

**Keep raw outputs permanently** — they serve as history and can be re-processed.

### Phase 2: Convert each output into a standalone reference file

For **every** task output, create a corresponding reference file at the `_reference-files/` level:

1. **Copy** the task output content
2. **Remove** all "task", "prompt", and "exercise" language
3. **Rename** to a descriptive standalone filename (see Expected Reference Files table below)
4. **Rewrite the title and intro** so it reads as a self-contained guide, not a task response
5. **Preserve** all code snippets, examples, and technical content
6. **Add** a header comment: `<!-- Generated from task-outputs/task-NN-name.md -->`
7. **Save** to `_reference-files/` (alongside TASKS.md and INDEX.md)

Result:

```
_reference-files/
├── INDEX.md                              ← categorized index
├── TASKS.md                              ← this file
├── clean-code-patterns.md                ← standalone reference (from task-01)
├── refactoring-catalog.md                ← standalone reference (from task-02)
├── ...                                   ← one reference file per task
├── complete-quality-overhaul.md          ← capstone reference (from task-18)
└── task-outputs/                         ← raw outputs (kept for history)
    ├── task-01-clean-code.md
    ├── task-02-code-refactoring.md
    └── ...
```

### Phase 3: Create INDEX.md and cross-link

1. **Create `INDEX.md`** in `_reference-files/` with:
   - Table of all reference files organized by category
   - Quick reference by topic section
   - Usage guidance

2. **Update pack files** to cross-reference:
   - Add Reference Files table to `PACK.md`
   - Add Reference links to scenarios in `QUICK_REFERENCE.md`

### Expected Reference Files

| Task Output | Expected Reference File |
|-------------|------------------------|
| `task-01-clean-code.md` | `clean-code-patterns.md` |
| `task-02-code-refactoring.md` | `refactoring-catalog.md` |
| `task-03-code-deduplication.md` | `deduplication-strategies.md` |
| `task-04-error-handling.md` | `error-handling-patterns.md` |
| `task-05-input-validation.md` | `validation-schemas.md` |
| `task-06-logging-strategies.md` | `structured-logging-guide.md` |
| `task-07-code-quality-review.md` | `review-process-guide.md` |
| `task-08-technical-debt.md` | `debt-management-playbook.md` |
| `task-09-code-metrics.md` | `metrics-pipeline-setup.md` |
| `task-10-simplify-complexity.md` | `complexity-reduction-techniques.md` |
| `task-11-code-standards.md` | `standards-enforcement-setup.md` |
| `task-12-legacy-code-migration.md` | `strangler-fig-migration.md` |
| `task-13-production-hardening.md` | `production-hardening-guide.md` |
| `task-14-quality-gate-setup.md` | `quality-gate-configuration.md` |
| `task-15-debt-reduction-sprint.md` | `debt-reduction-playbook.md` |
| `task-16-legacy-modernization.md` | `legacy-modernization-guide.md` |
| `task-17-clean-codebase-audit.md` | `codebase-audit-template.md` |
| `task-18-full-stack.md` | `complete-quality-overhaul.md` |

## F. Results Summary

After running all tasks, fill in this table:

| Task | Primary Skill(s) | Pass/Fail | Reference File | Notes |
|------|-------------------|-----------|----------------|-------|
| 1 | clean-code | Pass | clean-code-patterns.md | Multi-language (JS/Python/Go), all 6 principles applied |
| 2 | code-refactoring | Pass | refactoring-catalog.md | 5 patterns: Extract Method, Parameter Object, Polymorphism, Extract Class, Move Method |
| 3 | code-deduplication | Pass | deduplication-strategies.md | 76% → 0% duplication, shared utilities extracted |
| 4 | error-handling | Pass | error-handling-patterns.md | 5 error classes, retry logic, JS + Python implementations |
| 5 | input-validation | Pass | validation-schemas.md | Zod + Pydantic, XSS/SQL injection prevention, file upload |
| 6 | logging-strategies | Pass | structured-logging-guide.md | Pino/Structlog/Slog, correlation IDs, 10 events demonstrated |
| 7 | code-quality-review | Pass | review-process-guide.md | PR template, GitHub Actions, 5 review comments with examples |
| 8 | technical-debt | Pass | debt-management-playbook.md | CLI inventory, scoring formula (impact×churn/effort), quarterly plan |
| 9 | code-metrics | Pass | metrics-pipeline-setup.md | ESLint complexity, Jest coverage, jscpd, churn analysis |
| 10 | simplify-complexity | Pass | complexity-reduction-techniques.md | 5 techniques, CC reduced 60-80% per function |
| 11 | code-standards | Pass | standards-enforcement-setup.md | ESLint flat config, Ruff, Prettier, commitlint, husky, CI |
| 12 | legacy-code-migration | Pass | strangler-fig-migration.md | 6-phase migration: tests → interface → adapter → shadow → flags → rollback |
| 13 | error-handling + validation + logging + clean-code | Pass | production-hardening-guide.md | End-to-end hardening, all 4 skills integrated |
| 14 | standards + metrics + review | Pass | quality-gate-configuration.md | Monorepo quality gates for 3 packages |
| 15 | debt + metrics + refactoring + dedup | Pass | debt-reduction-playbook.md | Sprint execution, 48% LOC reduction |
| 16 | migration + error + refactoring + logging | Pass | legacy-modernization-guide.md | Python 2→3 modernization, all 4 skills applied |
| 17 | clean + complexity + metrics + review | Pass | codebase-audit-template.md | Full audit with grades, findings prioritized, action plan |
| 18 | all 12 skills | Pass | complete-quality-overhaul.md | Full transformation: F → A-, 87% coverage, 74% complexity reduction |
