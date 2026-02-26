# Logging Strategies Skill

This skill helps you implement structured, leveled logging with correlation IDs and observability.

## Quick Start

Invoke this skill when you need to:
- Replace console.log with structured logging
- Choose correct log levels for events
- Add correlation IDs for request tracing
- Set up log aggregation
- Reduce log noise while keeping actionable data

## Example Usage

### Basic Example
```
User: Replace console.log with proper logging in this Express app

Agent: I'll set up pino for structured JSON logging, add request correlation
middleware, and replace all console.log calls with leveled log statements...
```

## Key Libraries

| Language | Library | Features |
|----------|---------|----------|
| JavaScript | pino | Fast JSON logging, child loggers |
| Python | structlog | Structured processors, JSON output |
| Go | slog (stdlib) | Built-in structured logging |

## Related Skills

- **error-handling** - Log errors with context and severity
- **input-validation** - Log validation failures for abuse detection
