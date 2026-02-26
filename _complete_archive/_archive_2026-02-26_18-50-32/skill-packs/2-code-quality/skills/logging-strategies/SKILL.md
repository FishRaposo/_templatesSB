---
name: logging-strategies
description: Use this skill when implementing logging in applications. This includes structured logging, log levels, correlation IDs, log aggregation, and building observable systems with meaningful log output.
---

# Logging Strategies

I'll help you implement effective, structured logging that makes systems observable and debuggable. When you invoke this skill, I can guide you through log levels, structured formats, correlation, and aggregation patterns.

# Core Approach

My approach focuses on:
1. Using structured JSON logs with consistent fields
2. Choosing appropriate log levels for each event
3. Adding correlation IDs to trace requests across services
4. Making logs searchable and actionable, not noisy

# Step-by-Step Instructions

## 1. Set Up Structured Logging

Replace `console.log` and `print` with structured loggers:

**JavaScript (pino):**
```javascript
import pino from 'pino';

const logger = pino({
  level: process.env.LOG_LEVEL || 'info',
  formatters: {
    level: (label) => ({ level: label }),
  },
  timestamp: pino.stdTimeFunctions.isoTime,
});

// Usage: structured fields, not string interpolation
logger.info({ userId: user.id, action: 'login' }, 'User logged in');
// Output: {"level":"info","time":"2026-02-07T...","userId":"u123","action":"login","msg":"User logged in"}
```

**Python (structlog):**
```python
import structlog

structlog.configure(
    processors=[
        structlog.stdlib.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.JSONRenderer(),
    ],
)
logger = structlog.get_logger()

# Usage
logger.info("user.login", user_id=user.id, ip=request.remote_addr)
# Output: {"event":"user.login","user_id":"u123","ip":"10.0.0.1","level":"info","timestamp":"2026-02-07T..."}
```

**Go (slog — stdlib):**
```go
import "log/slog"

logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
    Level: slog.LevelInfo,
}))

// Usage
logger.Info("user login", "user_id", userID, "action", "login")
// Output: {"time":"2026-02-07T...","level":"INFO","msg":"user login","user_id":"u123","action":"login"}
```

## 2. Choose Log Levels Correctly

| Level | When to Use | Example |
|-------|-------------|---------|
| **ERROR** | Operation failed, needs attention | Database connection lost, payment failed |
| **WARN** | Unexpected but handled, may need attention | Retry succeeded after 2 attempts, rate limit approaching |
| **INFO** | Normal business events worth recording | User created, order placed, deploy completed |
| **DEBUG** | Detailed diagnostic information | SQL query executed, cache hit/miss, request/response bodies |
| **TRACE** | Very verbose, step-by-step flow | Function entry/exit, loop iterations |

```javascript
// ❌ Bad: wrong levels
logger.error('User not found');       // Not an error — it's expected behavior
logger.info({ query: sql, params });  // Too verbose for production — use debug
logger.debug('Server started');       // Important event — use info

// ✅ Good: correct levels
logger.info({ userId }, 'User not found — returning 404');
logger.debug({ query: sql, params }, 'Executing query');
logger.info({ port: 3000 }, 'Server started');
```

## 3. Add Correlation IDs

Trace requests across services with a correlation ID:

**JavaScript (Express + pino):**
```javascript
import { randomUUID } from 'crypto';
import { AsyncLocalStorage } from 'async_hooks';

const requestContext = new AsyncLocalStorage();

// Middleware: create or propagate correlation ID
app.use((req, res, next) => {
  const correlationId = req.headers['x-correlation-id'] || randomUUID();
  res.setHeader('x-correlation-id', correlationId);
  requestContext.run({ correlationId }, next);
});

// Logger: automatically include correlation ID
function getLogger() {
  const ctx = requestContext.getStore();
  return logger.child({ correlationId: ctx?.correlationId });
}

// Usage: every log line includes the correlation ID
app.get('/orders/:id', async (req, res) => {
  const log = getLogger();
  log.info({ orderId: req.params.id }, 'Fetching order');
});
```

**Python (FastAPI + structlog):**
```python
import uuid
import contextvars
import structlog

correlation_id_var: contextvars.ContextVar[str] = contextvars.ContextVar("correlation_id", default="")

def add_correlation_id(logger, method_name, event_dict):
    cid = correlation_id_var.get("")
    if cid:
        event_dict["correlation_id"] = cid
    return event_dict

structlog.configure(processors=[
    add_correlation_id,
    structlog.stdlib.add_log_level,
    structlog.processors.JSONRenderer(),
])

# FastAPI middleware
@app.middleware("http")
async def correlation_middleware(request, call_next):
    cid = request.headers.get("x-correlation-id", str(uuid.uuid4()))
    correlation_id_var.set(cid)
    response = await call_next(request)
    response.headers["x-correlation-id"] = cid
    return response

# Usage: correlation ID is automatically added to every log
logger = structlog.get_logger()
logger.info("order.fetch", order_id=order_id)
```

**Go (net/http + slog):**
```go
func correlationMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        cid := r.Header.Get("X-Correlation-ID")
        if cid == "" {
            cid = uuid.NewString()
        }
        w.Header().Set("X-Correlation-ID", cid)
        ctx := context.WithValue(r.Context(), correlationKey, cid)
        next.ServeHTTP(w, r.WithContext(ctx))
    })
}

func getLogger(ctx context.Context) *slog.Logger {
    cid, _ := ctx.Value(correlationKey).(string)
    return slog.Default().With("correlation_id", cid)
}

// Usage
func handleGetOrder(w http.ResponseWriter, r *http.Request) {
    log := getLogger(r.Context())
    log.Info("order.fetch", "order_id", orderID)
}
```

## 4. Log Actionable Events, Not Noise

```javascript
// ❌ Noise: too frequent, no actionable info
logger.info('Entering function processOrder');
logger.info('Loop iteration 1 of 100');
logger.debug('Variable x = 42');

// ✅ Actionable: business events with context
logger.info({ orderId, items: items.length, total }, 'Order created');
logger.warn({ orderId, attempt: 3, maxAttempts: 5 }, 'Payment retry');
logger.error({ orderId, error: err.message, provider: 'stripe' }, 'Payment failed');
```

# Best Practices

- Use structured JSON format — never unstructured text in production
- Log at service boundaries (request in, response out, external calls)
- Include enough context to debug without reproducing (IDs, counts, durations)
- Use consistent field names across services (`userId`, not sometimes `user_id`)
- Set log level via environment variable, not code changes
- Never log sensitive data (passwords, tokens, PII, credit cards)
- Add request duration to all HTTP handler logs

# Validation Checklist

When implementing logging, verify:
- [ ] All logs are structured JSON (not `console.log` strings)
- [ ] Log levels are used correctly (ERROR for failures, INFO for events)
- [ ] Correlation IDs propagate across service boundaries
- [ ] No sensitive data in logs (passwords, tokens, PII)
- [ ] Log level is configurable via environment variable
- [ ] Request duration is logged for HTTP handlers
- [ ] Business-critical events have INFO-level logs

# Troubleshooting

## Issue: Logs Are Too Noisy

**Symptoms**: Thousands of log lines per second, can't find relevant entries

**Solution**:
- Move high-frequency logs from INFO to DEBUG
- Use sampling for high-volume events (log 1 in 100)
- Add rate limiting to error logs (same error → log once per minute)
- Review what's at INFO level — only business events belong there

## Issue: Can't Trace a Request Across Services

**Symptoms**: Logs from different services can't be correlated

**Solution**:
- Implement correlation ID middleware at every service
- Propagate via `x-correlation-id` header on all inter-service calls
- Use OpenTelemetry for distributed tracing alongside logs

# Supporting Files

- See `./_examples/basic-examples.md` for structured logging, log levels, and correlation ID examples
- See `./README.md` for quick start and invocation examples

## Related Skills

- **error-handling** - Log errors with appropriate context and severity
- **input-validation** - Log validation failures for abuse detection
- **code-standards** - Enforce logging conventions across the team
- → **24-monitoring-observability**: distributed-tracing, log-analysis (for production observability)

Remember: The best log is one that lets you debug a production issue without reproducing it!
