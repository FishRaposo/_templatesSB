# Logging Strategies — Basic Examples

## Structured JSON Logging

**JavaScript (pino):**
```javascript
import pino from 'pino';

const logger = pino({ level: process.env.LOG_LEVEL || 'info' });

// ❌ Unstructured
console.log(`User ${userId} placed order ${orderId} for $${total}`);

// ✅ Structured
logger.info({ userId, orderId, total, itemCount: items.length }, 'Order placed');
// {"level":"info","userId":"u_123","orderId":"ord_456","total":99.99,"itemCount":3,"msg":"Order placed"}
```

**Python (structlog):**
```python
import structlog
logger = structlog.get_logger()

# ❌ Unstructured
print(f"User {user_id} logged in from {ip}")

# ✅ Structured
logger.info("user.login", user_id=user_id, ip=ip, method="password")
# {"event":"user.login","user_id":"u_123","ip":"10.0.0.1","method":"password","level":"info"}
```

**Go (slog):**
```go
logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

// ❌ Unstructured
log.Printf("User %s logged in from %s", userID, ip)

// ✅ Structured
logger.Info("user login", "user_id", userID, "ip", ip, "method", "password")
```

## Correct Log Levels

```javascript
// ❌ Wrong levels
logger.error('User not found');          // Expected behavior, not an error
logger.info({ sql, params }, 'Query');   // Too verbose for INFO
logger.debug('Server started on :3000'); // Important event, not debug

// ✅ Correct levels
logger.info({ userId }, 'User not found, returning 404');
logger.debug({ sql, params }, 'Executing query');
logger.info({ port: 3000 }, 'Server started');
logger.error({ err: err.message, orderId }, 'Payment processing failed');
logger.warn({ attempt: 3, maxAttempts: 5 }, 'Retry after transient failure');
```

## Correlation IDs

```javascript
import { AsyncLocalStorage } from 'async_hooks';
const ctx = new AsyncLocalStorage();

// Middleware: attach correlation ID to every request
app.use((req, res, next) => {
  const correlationId = req.headers['x-correlation-id'] || crypto.randomUUID();
  res.setHeader('x-correlation-id', correlationId);
  ctx.run({ correlationId }, next);
});

// Helper: get logger with correlation ID
function getLogger() {
  return logger.child({ correlationId: ctx.getStore()?.correlationId });
}

// Usage: all logs in this request share the correlation ID
app.get('/orders/:id', async (req, res) => {
  const log = getLogger();
  log.info({ orderId: req.params.id }, 'Fetching order');
});
```

## When to Use
- "Replace console.log with proper logging"
- "Add structured logging to this service"
- "What log level should I use for this?"
- "Add correlation IDs for request tracing"
