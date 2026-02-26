---
name: error-handling
description: Use this skill when implementing error management in applications. This includes designing error hierarchies, choosing recovery strategies, implementing try/catch patterns, creating custom error types, and building fail-safe systems.
---

# Error Handling

I'll help you implement robust error management that makes failures predictable, debuggable, and recoverable. When you invoke this skill, I can guide you through designing error types, choosing recovery strategies, and building resilient code.

# Core Approach

My approach focuses on:
1. Designing typed error hierarchies that distinguish operational from programmer errors
2. Failing fast and explicitly at system boundaries
3. Recovering gracefully with retries, fallbacks, and circuit breakers
4. Making errors observable with context, stack traces, and correlation

# Step-by-Step Instructions

## 1. Design Error Types

Create a typed error hierarchy that distinguishes error categories:

**JavaScript:**
```javascript
class AppError extends Error {
  constructor(message, code, statusCode = 500, isOperational = true) {
    super(message);
    this.code = code;
    this.statusCode = statusCode;
    this.isOperational = isOperational;
    Error.captureStackTrace(this, this.constructor);
  }
}

class ValidationError extends AppError {
  constructor(message, field) {
    super(message, 'VALIDATION_ERROR', 400);
    this.field = field;
  }
}

class NotFoundError extends AppError {
  constructor(resource, id) {
    super(`${resource} '${id}' not found`, 'NOT_FOUND', 404);
    this.resource = resource;
    this.resourceId = id;
  }
}

class ExternalServiceError extends AppError {
  constructor(service, cause) {
    super(`${service} failed: ${cause.message}`, 'EXTERNAL_ERROR', 502);
    this.service = service;
    this.cause = cause;
  }
}
```

**Python:**
```python
class AppError(Exception):
    def __init__(self, message: str, code: str, status: int = 500):
        super().__init__(message)
        self.code = code
        self.status = status

class ValidationError(AppError):
    def __init__(self, message: str, field: str = None):
        super().__init__(message, "VALIDATION_ERROR", 400)
        self.field = field

class NotFoundError(AppError):
    def __init__(self, resource: str, resource_id: str):
        super().__init__(f"{resource} '{resource_id}' not found", "NOT_FOUND", 404)
```

**Go:**
```go
type AppError struct {
    Message string `json:"message"`
    Code    string `json:"code"`
    Status  int    `json:"-"`
    Cause   error  `json:"-"`
}

func (e *AppError) Error() string { return e.Message }
func (e *AppError) Unwrap() error { return e.Cause }

func NewNotFound(resource, id string) *AppError {
    return &AppError{
        Message: fmt.Sprintf("%s '%s' not found", resource, id),
        Code:    "NOT_FOUND",
        Status:  404,
    }
}

func NewValidation(msg string) *AppError {
    return &AppError{Message: msg, Code: "VALIDATION_ERROR", Status: 400}
}
```

## 2. Handle Errors at the Right Level

- **Boundary layer** (HTTP handlers, CLI): Convert errors to user-facing responses
- **Service layer**: Wrap and add context, decide on recovery
- **Data layer**: Wrap database/IO errors with domain context

```javascript
// Boundary: convert to HTTP response
app.use((err, req, res, next) => {
  if (err instanceof AppError && err.isOperational) {
    return res.status(err.statusCode).json({
      error: { code: err.code, message: err.message }
    });
  }
  // Programmer error — log and return generic 500
  logger.error('Unhandled error', { error: err, stack: err.stack });
  res.status(500).json({ error: { code: 'INTERNAL', message: 'Something went wrong' } });
});

// Service: add context, decide recovery
async function getUser(id) {
  try {
    const user = await userRepo.findById(id);
    if (!user) throw new NotFoundError('User', id);
    return user;
  } catch (err) {
    if (err instanceof NotFoundError) throw err;
    throw new ExternalServiceError('UserDatabase', err);
  }
}
```

## 3. Recovery Strategies

Choose the right recovery pattern:

**JavaScript:**
```javascript
// Retry with exponential backoff
async function withRetry(fn, { maxAttempts = 3, baseDelay = 1000 } = {}) {
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      return await fn();
    } catch (err) {
      if (attempt === maxAttempts) throw err;
      if (!isTransient(err)) throw err;
      const delay = baseDelay * Math.pow(2, attempt - 1);
      await new Promise(r => setTimeout(r, delay));
    }
  }
}

// Fallback
async function getUserAvatar(userId) {
  try {
    return await avatarService.fetch(userId);
  } catch {
    return DEFAULT_AVATAR_URL; // graceful degradation
  }
}
```

**Python:**
```python
import time

def with_retry(fn, max_attempts=3, base_delay=1.0):
    """Retry with exponential backoff for transient failures."""
    for attempt in range(1, max_attempts + 1):
        try:
            return fn()
        except TransientError:
            if attempt == max_attempts:
                raise
            delay = base_delay * (2 ** (attempt - 1))
            time.sleep(delay)

# Fallback
def get_user_avatar(user_id: str) -> str:
    try:
        return avatar_service.fetch(user_id)
    except ExternalServiceError:
        return DEFAULT_AVATAR_URL  # graceful degradation
```

**Go:**
```go
func withRetry(fn func() error, maxAttempts int) error {
    for attempt := 1; attempt <= maxAttempts; attempt++ {
        err := fn()
        if err == nil {
            return nil
        }
        if attempt == maxAttempts || !isTransient(err) {
            return fmt.Errorf("after %d attempts: %w", attempt, err)
        }
        time.Sleep(time.Duration(1<<attempt) * time.Second)
    }
    return nil
}

// Fallback
func getUserAvatar(userID string) string {
    avatar, err := avatarService.Fetch(userID)
    if err != nil {
        return defaultAvatarURL // graceful degradation
    }
    return avatar
}
```

## 4. Never Do This

```javascript
// ❌ Empty catch — hides failures
try { riskyOperation(); } catch (e) {}

// ❌ Catch-all with generic message
try { /* ... */ } catch { throw new Error('Something went wrong'); }

// ❌ Using errors for control flow
try {
  const user = getUser(id); // throws if not found
} catch { /* expected — means user is new */ }

// ✅ Instead, return null/undefined for expected "not found"
const user = findUser(id); // returns null if not found
if (!user) { /* handle new user */ }
```

# Best Practices

- Distinguish operational errors (expected) from programmer errors (bugs)
- Never catch an error you can't handle — let it propagate
- Always preserve the original error as a cause/chain
- Include context: what operation, what input, what was expected
- Use error codes (not just messages) for programmatic handling
- Log at the boundary, not at every catch

# Validation Checklist

When implementing error handling, verify:
- [ ] All error types extend a base error class with code and status
- [ ] No empty catch blocks anywhere
- [ ] Original errors are preserved (wrapped, not swallowed)
- [ ] Boundary layer converts errors to appropriate responses
- [ ] Transient errors have retry logic
- [ ] Non-transient errors fail fast with clear messages
- [ ] Errors include enough context for debugging

# Troubleshooting

## Issue: "Error: Something went wrong" with no context

**Symptoms**: Generic error messages in production logs

**Solution**:
- Add error codes and structured fields to every error type
- Wrap lower-level errors with domain context at each layer
- Include the operation name, input parameters, and expected outcome

## Issue: Unhandled promise rejections crashing the process

**Symptoms**: `UnhandledPromiseRejection` in Node.js logs

**Solution**:
- Add `.catch()` to every promise chain or use `async/await` with `try/catch`
- Register global `process.on('unhandledRejection', handler)`
- Use ESLint rule `no-floating-promises` to catch at lint time

# Supporting Files

- See `./_examples/basic-examples.md` for typed errors, retry with backoff, and error boundary examples
- See `./README.md` for quick start and invocation examples

## Related Skills

- **input-validation** - Prevent errors by validating inputs before processing
- **logging-strategies** - Log errors with structured context for debugging
- **clean-code** - Write error handling that's readable and maintainable
- → **3-testing-mastery**: unit-testing (for testing error paths)
- → **24-monitoring-observability**: incident-response (for production error handling)

Remember: Every catch block should either handle the error, wrap it with context, or let it propagate — never swallow it!
