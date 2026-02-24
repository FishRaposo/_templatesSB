# Code Quality — Reference Files Index

> **Pack**: 2-code-quality  
> **Reference Files**: 18  
> **Generated from**: [TASKS.md](TASKS.md)

A comprehensive collection of code quality guides covering clean code, refactoring, error handling, testing, and migration strategies.

---

## Core Code Quality

| File | Topics Covered |
|------|----------------|
| [clean-code-patterns.md](clean-code-patterns.md) | Naming, SRP, guard clauses, constants extraction in JS/Python/Go |
| [refactoring-catalog.md](refactoring-catalog.md) | 5 refactoring patterns: Extract Method, Parameter Object, Polymorphism, Extract Class, Move Method |
| [deduplication-strategies.md](deduplication-strategies.md) | Classification (exact/near/structural), extraction techniques, Rule of Three |
| [complexity-reduction-techniques.md](complexity-reduction-techniques.md) | Guard clauses, lookup tables, state machines, function decomposition |

---

## Production Readiness

| File | Topics Covered |
|------|----------------|
| [error-handling-patterns.md](error-handling-patterns.md) | Typed error hierarchy, error boundary middleware, retry logic, error wrapping |
| [validation-schemas.md](validation-schemas.md) | Zod/Pydantic schemas, field-level errors, XSS/SQL injection prevention |
| [structured-logging-guide.md](structured-logging-guide.md) | Pino/Structlog/Slog setup, correlation IDs, log levels, sensitive data redaction |

---

## Process & Standards

| File | Topics Covered |
|------|----------------|
| [review-process-guide.md](review-process-guide.md) | PR templates, GitHub Actions workflows, review comment best practices |
| [standards-enforcement-setup.md](standards-enforcement-setup.md) | ESLint, Ruff, Prettier, commitlint, husky, CI pipeline |
| [quality-gate-configuration.md](quality-gate-configuration.md) | Monorepo quality gates, complexity limits, coverage thresholds |

---

## Measurement & Improvement

| File | Topics Covered |
|------|----------------|
| [metrics-pipeline-setup.md](metrics-pipeline-setup.md) | ESLint complexity, Jest coverage, jscpd duplication, churn analysis |
| [debt-management-playbook.md](debt-management-playbook.md) | Automated inventory, scoring formula, payoff planning, guardrails |
| [debt-reduction-playbook.md](debt-reduction-playbook.md) | Sprint planning, god class decomposition, duplication reduction |
| [codebase-audit-template.md](codebase-audit-template.md) | Structured audit process, findings prioritization, action planning |

---

## Migration & Modernization

| File | Topics Covered |
|------|----------------|
| [strangler-fig-migration.md](strangler-fig-migration.md) | Characterization tests, adapters, shadow mode, feature flags, rollback |
| [legacy-modernization-guide.md](legacy-modernization-guide.md) | Python 2→3 migration, error handling, structured logging, decomposition |
| [production-hardening-guide.md](production-hardening-guide.md) | Input validation, error boundaries, retry logic, structured logging |
| [complete-quality-overhaul.md](complete-quality-overhaul.md) | Full stack transformation: metrics → migration → review |

---

## Quick Reference by Topic

### Error Handling
- [error-handling-patterns.md](error-handling-patterns.md) — Complete error hierarchy and boundary setup
- [validation-schemas.md](validation-schemas.md) — Input validation with security

### Code Organization
- [refactoring-catalog.md](refactoring-catalog.md) — Code restructuring patterns
- [deduplication-strategies.md](deduplication-strategies.md) — Eliminating duplication
- [complexity-reduction-techniques.md](complexity-reduction-techniques.md) — Simplifying complex code

### Quality Assurance
- [review-process-guide.md](review-process-guide.md) — Code review system
- [metrics-pipeline-setup.md](metrics-pipeline-setup.md) — Automated quality measurement
- [standards-enforcement-setup.md](standards-enforcement-setup.md) — Pre-commit and CI

### Technical Debt
- [debt-management-playbook.md](debt-management-playbook.md) — Inventory and scoring
- [debt-reduction-playbook.md](debt-reduction-playbook.md) — Sprint execution
- [codebase-audit-template.md](codebase-audit-template.md) — Comprehensive auditing

### Migration
- [strangler-fig-migration.md](strangler-fig-migration.md) — Safe legacy migration
- [legacy-modernization-guide.md](legacy-modernization-guide.md) — Language modernization
- [complete-quality-overhaul.md](complete-quality-overhaul.md) — End-to-end transformation

---

## Usage

1. **AI Agents**: Include relevant files as context when invoking skills
2. **Developers**: Quick reference for implementing patterns
3. **Code Review**: Verify implementations against reference patterns

## Expected Reference Files

Once tasks are executed and outputs reworked, this index will contain:

### Individual Skill References

| Skill(s) | Expected Reference File | What It Will Cover |
|----------|------------------------|-------------------|
| clean-code | `clean-code-patterns.md` | Naming, SRP, guard clauses, multi-language before/after |
| code-refactoring | `refactoring-catalog.md` | Extract Method, Parameter Object, Polymorphism catalog |
| code-deduplication | `deduplication-strategies.md` | Detection, classification, extraction patterns |
| error-handling | `error-handling-patterns.md` | Typed hierarchy, retry, circuit breaker, error boundary |
| input-validation | `validation-schemas.md` | Zod, Pydantic, validator schemas, sanitization |
| logging-strategies | `structured-logging-guide.md` | pino/structlog/slog setup, correlation IDs, levels |
| code-quality-review | `review-process-guide.md` | PR templates, CI automation, review comment examples |
| technical-debt | `debt-management-playbook.md` | Inventory, scoring, payoff plans, guardrails |
| code-metrics | `metrics-pipeline-setup.md` | Complexity, coverage, duplication, churn pipeline |
| simplify-complexity | `complexity-reduction-techniques.md` | Guard clauses, lookup tables, state machines, decomposition |
| code-standards | `standards-enforcement-setup.md` | ESLint, Ruff, Prettier, commitlint, CI gates |
| legacy-code-migration | `strangler-fig-migration.md` | Characterization tests, adapter, shadow mode, cutover |

### Combined Skill References

| Skills Combined | Expected Reference File | What It Will Cover |
|----------------|------------------------|-------------------|
| error-handling + validation + logging + clean-code | `production-hardening-guide.md` | End-to-end endpoint hardening |
| standards + metrics + review | `quality-gate-configuration.md` | Complete CI quality gate setup |
| debt + metrics + refactoring + dedup | `debt-reduction-playbook.md` | Sprint-based debt payoff execution |
| migration + error + refactoring + logging | `legacy-modernization-guide.md` | Full legacy module modernization |
| clean + complexity + metrics + review | `codebase-audit-template.md` | Structured code quality audit |

### Capstone Reference

| Skills | Expected Reference File | What It Will Cover |
|--------|------------------------|-------------------|
| **all 12 skills** | `complete-quality-overhaul.md` | Full codebase quality transformation |

## How to Generate

1. Run each task from [`TASKS.md`](TASKS.md) as a fresh agent conversation
2. Save raw outputs to `task-outputs/`
3. Rework each into a standalone reference file (remove task language, give descriptive name)
4. Update this INDEX.md with actual file links
5. Add Reference Files table to [`../PACK.md`](../PACK.md)
6. Add Reference links to scenarios in [`../QUICK_REFERENCE.md`](../QUICK_REFERENCE.md)

> **See also**: [`TASKS.md`](TASKS.md) for the full task list and execution instructions.
