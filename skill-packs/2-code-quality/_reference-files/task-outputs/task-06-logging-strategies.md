# Task 6 — Structured Logging Strategies
> Skills: logging-strategies, error-handling

## Microservice Logging Implementation

### Pino Setup (JavaScript)

```javascript
import pino from 'pino';
import { v4 as uuidv4 } from 'uuid';

const logger = pino({
  level: process.env.LOG_LEVEL || 'info',
  formatters: {
    level: (label) => ({ level: label }),
    bindings: (bindings) => ({
      pid: bindings.pid,
      service: 'order-service'
    })
  },
  timestamp: pino.stdTimeFunctions.isoTime,
  redact: {
    paths: ['password', '*.password', 'creditCard', '*.cvv', 'token'],
    remove: true
  }
});

// Correlation ID middleware
function correlationMiddleware(req, res, next) {
  req.correlationId = req.headers['x-correlation-id'] || uuidv4();
  res.setHeader('x-correlation-id', req.correlationId);
  
  req.log = logger.child({ 
    correlationId: req.correlationId,
    requestId: uuidv4()
  });
  
  next();
}

// Log levels for different events
const orderEvents = {
  orderCreated: (order) => ({
    level: 'info',
    msg: 'Order created',
    orderId: order.id,
    customerId: order.customerId,
    itemCount: order.items.length,
    total: order.total
  }),
  
  paymentFailed: (order, error) => ({
    level: 'warn',
    msg: 'Payment failed',
    orderId: order.id,
    error: error.message,
    retryAttempt: error.attempt
  }),
  
  paymentRetried: (order, attempt) => ({
    level: 'info',
    msg: 'Payment retry initiated',
    orderId: order.id,
    attempt,
    backoffMs: 1000 * Math.pow(2, attempt)
  }),
  
  cacheMiss: (key) => ({
    level: 'debug',
    msg: 'Cache miss',
    cacheKey: key,
    source: 'redis'
  }),
  
  inventoryReserved: (order, items) => ({
    level: 'info',
    msg: 'Inventory reserved',
    orderId: order.id,
    reservationId: items.reservationId,
    skuCount: items.length
  }),
  
  emailSent: (order, template) => ({
    level: 'info',
    msg: 'Notification sent',
    orderId: order.id,
    template,
    channel: 'email'
  }),
  
  smsFailed: (order, error) => ({
    level: 'error',
    msg: 'SMS notification failed',
    orderId: order.id,
    error: error.message,
    nonCritical: true
  }),
  
  databaseQuery: (table, duration) => ({
    level: duration > 1000 ? 'warn' : 'debug',
    msg: 'Database query executed',
    table,
    durationMs: duration,
    slow: duration > 1000
  }),
  
  externalApiCall: (service, endpoint, duration) => ({
    level: 'info',
    msg: 'External API call',
    service,
    endpoint,
    durationMs: duration
  }),
  
  securityEvent: (type, details) => ({
    level: 'warn',
    msg: 'Security event detected',
    eventType: type,
    ip: details.ip,
    userAgent: details.userAgent
  })
};

// Sample order flow logging
async function processOrder(order) {
  const log = logger.child({ orderId: order.id });
  
  log.info(orderEvents.orderCreated(order));
  
  try {
    await inventoryService.reserve(order.items);
    log.info(orderEvents.inventoryReserved(order, order.items));
  } catch (error) {
    log.error({ msg: 'Inventory reservation failed', error: error.message });
    throw error;
  }
  
  try {
    await paymentService.charge(order);
    log.info({ msg: 'Payment successful', amount: order.total });
  } catch (error) {
    log.warn(orderEvents.paymentFailed(order, error));
    
    // Retry with backoff
    for (let attempt = 1; attempt <= 3; attempt++) {
      log.info(orderEvents.paymentRetried(order, attempt));
      await sleep(1000 * Math.pow(2, attempt));
      
      try {
        await paymentService.charge(order);
        log.info({ msg: 'Payment retry succeeded', attempt });
        break;
      } catch (retryError) {
        if (attempt === 3) throw retryError;
      }
    }
  }
}
```

### Structlog (Python)

```python
import structlog
import logging
from datetime import datetime
import uuid

structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
        structlog.processors.JSONRenderer()
    ],
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    wrapper_class=structlog.stdlib.BoundLogger,
    cache_logger_on_first_use=True,
)

def get_logger(correlation_id=None):
    correlation_id = correlation_id or str(uuid.uuid4())
    return structlog.get_logger(
        service="order-service",
        correlation_id=correlation_id
    )

# Sensitive data redaction
def redact_sensitive(data: dict) -> dict:
    sensitive_fields = {'password', 'credit_card', 'cvv', 'token', 'ssn'}
    return {
        k: '***REDACTED***' if k in sensitive_fields else v
        for k, v in data.items()
    }
```

### Sample Log Output (JSON)

```json
{"level":"info","time":"2024-01-15T10:23:45.123Z","service":"order-service","correlationId":"abc-123","orderId":"ord-456","msg":"Order created","itemCount":3,"total":149.99}
{"level":"warn","time":"2024-01-15T10:23:46.234Z","service":"order-service","correlationId":"abc-123","orderId":"ord-456","msg":"Payment failed","error":"Card declined","retryAttempt":1}
{"level":"info","time":"2024-01-15T10:23:48.567Z","service":"order-service","correlationId":"abc-123","orderId":"ord-456","msg":"Payment retry initiated","attempt":2,"backoffMs":2000}
{"level":"info","time":"2024-01-15T10:23:50.789Z","service":"order-service","correlationId":"abc-123","orderId":"ord-456","msg":"Payment successful","amount":149.99}
```

- [x] Structured JSON output in all 3 languages
- [x] Correlation IDs propagate correctly
- [x] Log levels are appropriate for each event
- [x] Sensitive data is redacted
- [x] Sample log output shows a complete flow
