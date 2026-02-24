# Error Handling — Basic Examples

## Typed Error Hierarchy

**JavaScript:**
```javascript
class AppError extends Error {
  constructor(message, code, statusCode = 500) {
    super(message);
    this.code = code;
    this.statusCode = statusCode;
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
  }
}

// Usage
throw new ValidationError('Email is required', 'email');
throw new NotFoundError('User', 'usr_123');
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
}

func (e *AppError) Error() string { return e.Message }

func NewNotFound(resource, id string) *AppError {
    return &AppError{
        Message: fmt.Sprintf("%s '%s' not found", resource, id),
        Code:    "NOT_FOUND",
        Status:  404,
    }
}
```

## Retry with Backoff

**JavaScript:**
```javascript
async function withRetry(fn, maxAttempts = 3) {
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      return await fn();
    } catch (err) {
      if (attempt === maxAttempts) throw err;
      await new Promise(r => setTimeout(r, 1000 * Math.pow(2, attempt)));
    }
  }
}

// Usage
const data = await withRetry(() => fetch('https://api.example.com/data'));
```

## Error Boundary (HTTP)

**JavaScript:**
```javascript
// Express global error handler
app.use((err, req, res, next) => {
  if (err instanceof AppError) {
    return res.status(err.statusCode).json({
      error: { code: err.code, message: err.message },
    });
  }
  console.error('Unhandled:', err);
  res.status(500).json({ error: { code: 'INTERNAL', message: 'Something went wrong' } });
});
```

## When to Use
- "Add error handling to this endpoint"
- "Create custom error types for this service"
- "This catch block is empty, fix it"
- "Add retry logic to this API call"
