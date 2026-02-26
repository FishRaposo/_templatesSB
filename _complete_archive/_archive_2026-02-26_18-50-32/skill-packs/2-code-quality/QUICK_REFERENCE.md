# Code Quality — Quick Reference

This guide helps you quickly find the right skill for your code quality needs.

> **Navigation**: [`PACK.md`](PACK.md) for full pack overview | `skills/<skill>/SKILL.md` for skill details | [`_reference-files/INDEX.md`](_reference-files/INDEX.md) for all reference implementations

## Decision Tree

```
What do you need?
│
├─ Improve existing code
│  ├─ Make it more readable? → clean-code
│  ├─ Restructure without breaking? → code-refactoring
│  ├─ Remove duplication? → code-deduplication
│  └─ Reduce complexity? → simplify-complexity
│
├─ Harden & protect
│  ├─ Handle errors gracefully? → error-handling
│  ├─ Validate user/API input? → input-validation
│  └─ Add logging/observability? → logging-strategies
│
├─ Measure & enforce
│  ├─ Set up linters/formatters? → code-standards
│  ├─ Measure quality metrics? → code-metrics
│  └─ Conduct a code review? → code-quality-review
│
└─ Plan & migrate
   ├─ Prioritize tech debt? → technical-debt
   └─ Modernize legacy code? → legacy-code-migration
```

## Common Scenarios

### "This code is hard to read"
→ **clean-code** for naming, formatting, function size  
→ **simplify-complexity** if deeply nested or convoluted  
→ **code-deduplication** if patterns repeat across files

### "I need to refactor safely"
→ **code-refactoring** for extract/inline/rename patterns  
→ **code-quality-review** to verify before merging  
→ **3-testing-mastery**: unit-testing to add safety net first

### "Our team needs consistent style"
→ **code-standards** for linter/formatter setup and CI gates  
→ **code-metrics** for objective quality thresholds  
→ **code-quality-review** for review checklists

### "This endpoint keeps crashing"
→ **error-handling** for try/catch, typed errors, recovery  
→ **input-validation** for boundary checks and sanitization  
→ **logging-strategies** for tracing the failure path

### "We have too much tech debt"
→ **technical-debt** for inventory, prioritization, payoff plans  
→ **code-metrics** for measuring debt quantitatively  
→ **code-refactoring** for executing the improvements

### "We need to migrate off this legacy system"
→ **legacy-code-migration** for strangler fig, incremental rewrite  
→ **technical-debt** for prioritizing what to migrate first  
→ **code-deduplication** for consolidating during migration

### "Preparing code for production"
→ **error-handling** + **input-validation** for robustness  
→ **logging-strategies** for production observability  
→ **code-quality-review** for final checklist pass

## Skill Relationships

```
                    code-standards
                         │
                    code-metrics
                         │
                  code-quality-review
                   ╱            ╲
          clean-code          error-handling
           │     │               │      │
   code-refactoring  code-deduplication  input-validation
           │                                │
   simplify-complexity              logging-strategies
           │
   technical-debt ──── legacy-code-migration
```

## Quick Tips

| Situation | Do This | Don't Do This |
|-----------|---------|---------------|
| Long function | Extract helper functions | Add comments explaining each section |
| Repeated code | Extract shared utility | Copy-paste with minor tweaks |
| Unclear naming | Rename to reveal intent | Add comment explaining the name |
| Deep nesting | Use early returns / guard clauses | Add more indentation |
| No error handling | Add typed errors + recovery | Catch-all with empty handler |
| No logging | Add structured JSON logs | Sprinkle `console.log` everywhere |
| Legacy rewrite | Strangler fig pattern | Big bang rewrite |

## Cross-Pack References

| Need | Pack | Skill |
|------|------|-------|
| Write tests before refactoring | **3-testing-mastery** | unit-testing |
| Profile before optimizing | **4-performance-optimization** | profiling |
| Set up CI quality gates | **12-devops-automation** | ci-cd-pipelines |
| Document APIs during cleanup | **33-documentation-mastery** | code-documentation |
| Review architecture during migration | **5-architecture-fundamentals** | architecture-patterns |
