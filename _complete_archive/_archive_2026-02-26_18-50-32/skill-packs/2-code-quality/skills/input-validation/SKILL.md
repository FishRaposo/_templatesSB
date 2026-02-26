---
name: input-validation
description: Use this skill when validating and sanitizing user input, API payloads, form data, or any external data entering a system. This includes schema validation, type checking, sanitization, and securing system boundaries against malformed or malicious input.
---

# Input Validation

I'll help you validate and sanitize inputs securely at every system boundary. When you invoke this skill, I can guide you through schema validation, type coercion, sanitization, and building defense-in-depth against bad data.

# Core Approach

My approach focuses on:
1. Validating at every trust boundary (API, form, file upload, queue)
2. Using schema-based validation over ad-hoc checks
3. Sanitizing to prevent injection attacks (XSS, SQL injection, command injection)
4. Failing fast with clear, specific error messages

# Step-by-Step Instructions

## 1. Define Validation Schemas

Use schema libraries instead of hand-written if/else chains:

**JavaScript (Zod):**
```javascript
import { z } from 'zod';

const CreateUserSchema = z.object({
  name: z.string().min(1).max(100).trim(),
  email: z.string().email(),
  age: z.number().int().min(13).max(150),
  role: z.enum(['user', 'admin', 'moderator']),
  bio: z.string().max(500).optional(),
});

// Usage
function createUser(req, res, next) {
  const result = CreateUserSchema.safeParse(req.body);
  if (!result.success) {
    return res.status(400).json({
      error: 'VALIDATION_ERROR',
      details: result.error.issues.map(i => ({
        field: i.path.join('.'),
        message: i.message,
      })),
    });
  }
  // result.data is typed and validated
  return userService.create(result.data);
}
```

**Python (Pydantic):**
```python
from pydantic import BaseModel, EmailStr, Field, field_validator

class CreateUserRequest(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    email: EmailStr
    age: int = Field(ge=13, le=150)
    role: Literal["user", "admin", "moderator"]
    bio: str | None = Field(default=None, max_length=500)

    @field_validator("name")
    @classmethod
    def strip_name(cls, v: str) -> str:
        return v.strip()

# Usage — raises ValidationError automatically
user = CreateUserRequest(**request_data)
```

**Go (go-playground/validator):**
```go
type CreateUserRequest struct {
    Name  string `json:"name" validate:"required,min=1,max=100"`
    Email string `json:"email" validate:"required,email"`
    Age   int    `json:"age" validate:"required,min=13,max=150"`
    Role  string `json:"role" validate:"required,oneof=user admin moderator"`
    Bio   string `json:"bio" validate:"max=500"`
}

func (h *Handler) CreateUser(w http.ResponseWriter, r *http.Request) {
    var req CreateUserRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        http.Error(w, "Invalid JSON", http.StatusBadRequest)
        return
    }
    if err := h.validate.Struct(req); err != nil {
        respondValidationErrors(w, err)
        return
    }
    // req is validated
}
```

## 2. Sanitize for Security

Prevent injection attacks by sanitizing dangerous content:

```javascript
import createDOMPurify from 'dompurify';
import { JSDOM } from 'jsdom';
const DOMPurify = createDOMPurify(new JSDOM('').window);

// XSS prevention: sanitize HTML input
function sanitizeHTML(dirty) {
  return DOMPurify.sanitize(dirty, { ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'a'] });
}

// SQL injection: always use parameterized queries
// ❌ Never interpolate user input into SQL
const bad = `SELECT * FROM users WHERE name = '${name}'`;
// ✅ Parameterized query
const [rows] = await db.query('SELECT * FROM users WHERE name = ?', [name]);

// Path traversal: validate file paths
function safeFilePath(userPath) {
  const resolved = path.resolve(UPLOAD_DIR, userPath);
  if (!resolved.startsWith(UPLOAD_DIR)) {
    throw new ValidationError('Invalid file path');
  }
  return resolved;
}
```

## 3. Validate at Every Boundary

Don't trust any external input, even from your own services:

```
Client → [API Gateway: validate headers, auth tokens]
       → [Controller: validate request schema]
       → [Service: validate business rules]
       → [Repository: validate data constraints]
       → [Database: enforce schema constraints]
```

## 4. Handle Validation Errors Well

Return specific, actionable error messages:

```json
{
  "error": "VALIDATION_ERROR",
  "message": "Request validation failed",
  "details": [
    { "field": "email", "message": "Must be a valid email address" },
    { "field": "age", "message": "Must be at least 13" }
  ]
}
```

# Best Practices

- Validate early, fail fast — don't process invalid data
- Use allowlists over denylists (accept known-good, not reject known-bad)
- Never trust client-side validation alone — always re-validate server-side
- Sanitize output too (HTML encoding, JSON escaping)
- Use schema libraries — they're tested, maintained, and declarative
- Validate file uploads: check MIME type, size, extension, and content

# Validation Checklist

When implementing input validation, verify:
- [ ] All API endpoints validate request bodies with schemas
- [ ] All user inputs are sanitized for HTML/SQL/command injection
- [ ] File uploads check type, size, and content (not just extension)
- [ ] Validation errors return specific field-level messages
- [ ] Server-side validation exists even when client-side does too
- [ ] Numeric inputs have min/max bounds
- [ ] String inputs have length limits

# Troubleshooting

## Issue: Validation Too Strict — Rejects Valid Input

**Symptoms**: Users report valid data being rejected (e.g., accented names)

**Solution**:
- Use Unicode-aware validation for names (not just `[a-zA-Z]`)
- Test with international data: accents, CJK characters, RTL text
- Use `\p{L}` Unicode letter class in regexes instead of `[a-z]`

## Issue: Validation Bypassed via API

**Symptoms**: Invalid data appears in database despite frontend validation

**Solution**:
- Add server-side validation middleware (never rely on client only)
- Add database-level constraints as final safety net
- Audit all endpoints to ensure schema validation middleware is applied

# Supporting Files

- See `./_examples/basic-examples.md` for Zod, Pydantic, validator schemas, and sanitization examples
- See `./README.md` for quick start and invocation examples

## Related Skills

- **error-handling** - Return proper error responses for validation failures
- **logging-strategies** - Log validation failures for abuse detection
- **code-standards** - Enforce validation conventions across the team
- → **11-security-implementation**: xss-prevention, sql-injection-prevention (for deep security)

Remember: Never trust input — validate everything, sanitize everything, at every boundary!
