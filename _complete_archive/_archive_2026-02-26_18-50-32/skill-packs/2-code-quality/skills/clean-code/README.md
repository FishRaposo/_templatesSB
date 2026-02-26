# Clean Code Skill

This skill helps you write readable, maintainable code with clear naming, small functions, and consistent formatting.

## Quick Start

Invoke this skill when you need to:
- Improve variable, function, or class naming
- Break up long functions into smaller ones
- Make code self-documenting
- Remove unnecessary comments
- Apply consistent formatting

## Example Usage

### Basic Example
```
User: This function is hard to read, can you clean it up?

Agent: I'll improve readability by renaming variables to reveal intent,
extracting helper functions, and removing unnecessary comments...
```

### Advanced Example
```
User: Review this module for clean code violations

Agent: I'll scan for naming issues, long functions, deep nesting,
magic numbers, and commented-out code, then suggest specific fixes...
```

## Key Principles

| Principle | Guideline |
|-----------|-----------|
| Naming | Names should reveal intent without a comment |
| Function size | ≤20 lines ideal, ≤50 hard limit |
| Parameters | ≤3 per function, use options object for more |
| Nesting | ≤3 levels deep, use guard clauses |
| Comments | Explain WHY, not WHAT |
| Constants | No magic numbers or strings |

## Languages

Examples provided in JavaScript, Python, and Go. See `../PACK.md` for the **Language Adaptation Guide** to map concepts to other languages.

## Related Skills

- **code-refactoring** - Restructure code after identifying issues
- **simplify-complexity** - Reduce deep nesting and convoluted logic
- **code-standards** - Automate enforcement with linters
