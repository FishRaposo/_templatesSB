# Evaluation Criteria — {{PROJECT_NAME}}

_Quality benchmarks and acceptance criteria for agents and human reviewers_

---

## Output Quality Standards

| Criterion | Minimum | Target | How to Measure |
|-----------|---------|--------|----------------|
| Test coverage | {{MIN_COVERAGE}}% | {{TARGET_COVERAGE}}% | `{{COVERAGE_COMMAND}}` |
| Build success | 100% | 100% | `{{BUILD_COMMAND}}` |
| Lint errors | 0 | 0 | `{{LINT_COMMAND}}` |
| Documentation parity | All changes covered | All changes covered | Three Pillars checklist |
| Broken links | 0 | 0 | Manual or link checker |

---

## Task Completion Criteria

A task is complete when **all** of the following are true:

### Functional Criteria

- [ ] The stated goal is achieved
- [ ] All acceptance criteria in the task description are met
- [ ] No regressions introduced (existing tests still pass)
- [ ] Edge cases identified in the task description are handled

### Three Pillars Criteria

- [ ] **AUTOMATING** — structure validator, placeholder scanner, link checker, and linter all run and exited with 0 errors
- [ ] **TESTING** — test suite passes, new behavior has coverage, examples are runnable
- [ ] **DOCUMENTING** — CHANGELOG has event, affected docs updated, memory layers regenerated

### Agent-Specific Criteria

- [ ] Boot sequence followed (AGENTS.md read before starting)
- [ ] All decisions appended to CHANGELOG.md before shutdown
- [ ] No forbidden memory carried across task boundaries
- [ ] context.md regenerated if stale at session start

---

## Evaluation Rubric

Use this rubric when reviewing agent or human output:

| Dimension | 4 — Excellent | 3 — Good | 2 — Needs Work | 1 — Failing |
|-----------|--------------|----------|----------------|-------------|
| **Correctness** | Fully correct, no bugs | Minor issues, all fixable | Significant issues | Incorrect output |
| **Completeness** | All requirements met | Most requirements met | Key requirements missing | Barely started |
| **Documentation** | Fully documented, parity maintained | Minor gaps | Significant gaps | No documentation |
| **Code quality** | Clean, idiomatic, follows conventions | Minor deviations | Multiple style issues | Poor quality throughout |
| **Test coverage** | Target % reached | Near target | Below minimum | No tests |

**Minimum acceptable score**: 3 in Correctness and Completeness, 2 in all others.

---

## Benchmark Tasks

Tasks used to verify the system is working correctly:

| Benchmark | Description | Expected Result | Last Run |
|-----------|-------------|-----------------|----------|
| {{BENCHMARK_1}} | {{BENCHMARK_1_DESCRIPTION}} | {{BENCHMARK_1_EXPECTED}} | {{DATE}} |
| {{BENCHMARK_2}} | {{BENCHMARK_2_DESCRIPTION}} | {{BENCHMARK_2_EXPECTED}} | {{DATE}} |

---

## Regression Baselines

Key metrics tracked over time. Update after each release.

| Metric | Baseline | Current | Delta |
|--------|----------|---------|-------|
| Test count | {{BASELINE_TEST_COUNT}} | — | — |
| Coverage % | {{BASELINE_COVERAGE}} | — | — |
| Build time | {{BASELINE_BUILD_TIME}} | — | — |

---

_Record evaluation results as `test` events in CHANGELOG.md with tag `evaluation`._
