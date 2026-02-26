# Code Refactoring Skill

This skill helps you improve code structure without changing its external behavior using proven refactoring patterns.

## Quick Start

Invoke this skill when you need to:
- Extract long functions into smaller ones
- Rename variables, functions, or classes for clarity
- Replace conditionals with polymorphism
- Decompose large classes into focused ones
- Remove code smells

## Example Usage

### Basic Example
```
User: This function is 150 lines long, help me break it up

Agent: I'll identify natural groupings in the function and extract each
into a named helper, preserving the original behavior...
```

### Advanced Example
```
User: This class has too many responsibilities, how should I split it?

Agent: I'll analyze the class methods and fields, identify clusters of
related functionality, and guide you through extracting focused classes...
```

## Key Refactoring Patterns

| Pattern | When to Use |
|---------|-------------|
| Extract Method | Long function with identifiable blocks |
| Rename | Name doesn't reveal intent |
| Introduce Parameter Object | Function has >3 parameters |
| Replace Conditional with Polymorphism | Switch/if on type field |
| Move Method | Method uses another class's data more |
| Inline | Abstraction adds no value |

## Related Skills

- **clean-code** - Identify what needs refactoring
- **code-deduplication** - Eliminate duplication found during refactoring
- **technical-debt** - Prioritize which refactorings matter most
