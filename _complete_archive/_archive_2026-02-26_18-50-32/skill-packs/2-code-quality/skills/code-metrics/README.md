# Code Metrics Skill

This skill helps you measure code quality with cyclomatic complexity, coverage, coupling, and churn analysis.

## Quick Start

Invoke this skill when you need to:
- Measure cyclomatic complexity of functions/modules
- Check test coverage and set thresholds
- Find code duplication percentages
- Identify hotspots (high churn + high complexity)
- Track quality trends over time

## Example Usage

### Basic Example
```
User: What's the complexity of this module?

Agent: I'll run cyclomatic complexity analysis and show which functions
exceed recommended thresholds, with specific refactoring suggestions...
```

## Key Metrics

| Metric | Tool (JS) | Tool (Python) | Tool (Go) |
|--------|-----------|---------------|-----------|
| Complexity | eslint complexity | radon | gocyclo |
| Coverage | jest --coverage | pytest-cov | go test -cover |
| Duplication | jscpd | pylint | PMD CPD |
| Churn | git log analysis | git log analysis | git log analysis |

## Related Skills

- **technical-debt** - Use metrics to quantify debt
- **code-standards** - Enforce thresholds via linter rules
- **simplify-complexity** - Reduce flagged complexity
