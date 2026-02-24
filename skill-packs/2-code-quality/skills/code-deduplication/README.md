# Code Deduplication Skill

This skill helps you eliminate duplicate code through abstraction, extraction, and shared utilities.

## Quick Start

Invoke this skill when you need to:
- Find and remove copy-pasted code
- Extract shared utilities from repeated patterns
- Consolidate near-duplicate functions
- Decide whether duplication is worth removing

## Example Usage

### Basic Example
```
User: These two functions are almost identical, help me consolidate

Agent: I'll compare the functions, identify the differences, and extract
a parameterized shared version that serves both use cases...
```

### Advanced Example
```
User: Scan this project for code duplication

Agent: I'll run copy-paste detection, classify the duplicates by type,
and create a prioritized deduplication plan...
```

## The Rule of Three

Don't abstract until you see the pattern three times:
1. First time — just write it
2. Second time — note the duplication
3. Third time — extract and share

## Related Skills

- **code-refactoring** - Extract Method is the primary deduplication tool
- **clean-code** - Spot duplication during code review
- **code-metrics** - Measure duplication percentage
