# Technical Debt Skill

This skill helps you identify, prioritize, and systematically reduce technical debt.

## Quick Start

Invoke this skill when you need to:
- Inventory technical debt in a codebase
- Prioritize debt items by impact and effort
- Create a debt payoff plan
- Set up guards to prevent new debt
- Track debt reduction over time

## Example Usage

### Basic Example
```
User: What technical debt do we have in this project?

Agent: I'll scan for TODO/FIXME markers, long files, circular dependencies,
code duplication, and high-churn files to build a debt inventory...
```

## Priority Formula

**Score = (Impact × Churn) / Effort**

| Factor | Measures |
|--------|----------|
| Impact (1-10) | How much it slows the team |
| Churn (frequency) | How often the affected code changes |
| Effort (1-10) | How hard it is to fix |

## Related Skills

- **code-metrics** - Quantify debt with objective measurements
- **code-refactoring** - Execute debt payoff safely
- **legacy-code-migration** - For large-scale migration debt
