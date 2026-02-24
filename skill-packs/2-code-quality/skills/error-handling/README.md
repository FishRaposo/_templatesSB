# Error Handling Skill

This skill helps you implement robust error management with typed errors, recovery strategies, and fail-safe patterns.

## Quick Start

Invoke this skill when you need to:
- Design custom error types and hierarchies
- Add try/catch with proper recovery logic
- Implement retry, fallback, or circuit breaker patterns
- Fix empty catch blocks or swallowed errors
- Build global error boundaries

## Example Usage

### Basic Example
```
User: Add proper error handling to this API endpoint

Agent: I'll create typed error classes, add try/catch at the handler level,
and ensure all error paths return appropriate HTTP responses...
```

### Advanced Example
```
User: Design an error handling strategy for our microservice

Agent: I'll design a layered approach — typed errors at domain level,
wrapping at service level, and conversion to HTTP at the boundary...
```

## Error Categories

| Category | Example | Recovery |
|----------|---------|----------|
| Validation | Bad input format | Return 400 with field details |
| Not Found | Missing resource | Return 404 |
| Transient | Network timeout | Retry with backoff |
| Permanent | Invalid credentials | Fail fast, notify user |
| Programmer | Null reference | Log, return 500, fix in code |

## Related Skills

- **input-validation** - Prevent errors before they happen
- **logging-strategies** - Make errors observable in production
- **clean-code** - Write readable error handling code
