# Simplify Complexity Skill

This skill helps you reduce unnecessary complexity through extraction, flattening, and decomposition.

## Quick Start

Invoke this skill when you need to:
- Flatten deeply nested conditionals with guard clauses
- Decompose large functions into focused helpers
- Replace clever one-liners with clear code
- Convert boolean flags to state machines
- Replace long switch/if chains with lookup tables

## Example Usage

### Basic Example
```
User: This function has 5 levels of nesting, simplify it

Agent: I'll apply guard clauses for error cases and early returns to
flatten the nesting to 1-2 levels while preserving all behavior...
```

## Key Techniques

| Technique | When to Use |
|-----------|-------------|
| Guard clauses | Deep nesting from validation/error checks |
| Lookup tables | Long if/else or switch chains on values |
| Decompose function | Function does multiple things |
| State machine | Multiple boolean flags tracking state |
| Clear over clever | One-liners that need comments to explain |

## Related Skills

- **clean-code** - Simplification is a core clean code practice
- **code-refactoring** - Extract Method and guard clauses are refactoring patterns
- **code-metrics** - Cyclomatic complexity quantifies what needs simplification
