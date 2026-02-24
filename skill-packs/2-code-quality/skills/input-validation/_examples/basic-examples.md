# Input Validation — Basic Examples

## Schema Validation

**JavaScript (Zod):**
```javascript
import { z } from 'zod';

const CreateOrderSchema = z.object({
  customerId: z.string().uuid(),
  items: z.array(z.object({
    productId: z.string(),
    quantity: z.number().int().positive().max(100),
    price: z.number().positive(),
  })).min(1, 'Order must have at least one item'),
  couponCode: z.string().regex(/^[A-Z0-9]{6,10}$/).optional(),
});

// Usage in Express handler
app.post('/orders', (req, res) => {
  const result = CreateOrderSchema.safeParse(req.body);
  if (!result.success) {
    return res.status(400).json({
      error: 'VALIDATION_ERROR',
      details: result.error.issues.map(i => ({
        field: i.path.join('.'),
        message: i.message,
      })),
    });
  }
  // result.data is typed and safe
  orderService.create(result.data);
});
```

**Python (Pydantic):**
```python
from pydantic import BaseModel, Field, EmailStr, field_validator
from typing import Literal

class ContactForm(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    email: EmailStr
    subject: Literal["support", "sales", "feedback"]
    message: str = Field(min_length=10, max_length=5000)

    @field_validator("name")
    @classmethod
    def clean_name(cls, v: str) -> str:
        return v.strip()

# Usage — raises ValidationError with field details
form = ContactForm(**request.json())
```

**Go (validator):**
```go
type SignupRequest struct {
    Username string `json:"username" validate:"required,min=3,max=30,alphanum"`
    Email    string `json:"email" validate:"required,email"`
    Password string `json:"password" validate:"required,min=8"`
    Age      int    `json:"age" validate:"required,min=13,max=150"`
}

validate := validator.New()
if err := validate.Struct(req); err != nil {
    // Convert validation errors to API response
}
```

## Sanitize Against Injection

```javascript
// ❌ SQL injection vulnerable
const query = `SELECT * FROM users WHERE email = '${email}'`;

// ✅ Parameterized query
const [rows] = await db.query('SELECT * FROM users WHERE email = ?', [email]);

// ❌ XSS vulnerable
element.innerHTML = userInput;

// ✅ Text content (no HTML parsing)
element.textContent = userInput;

// ✅ Or sanitize HTML
import DOMPurify from 'dompurify';
element.innerHTML = DOMPurify.sanitize(userInput);
```

## File Upload Validation

```javascript
function validateUpload(file) {
  const ALLOWED_TYPES = ['image/jpeg', 'image/png', 'image/webp'];
  const MAX_SIZE = 5 * 1024 * 1024; // 5MB

  if (!ALLOWED_TYPES.includes(file.mimetype)) {
    throw new ValidationError(`File type ${file.mimetype} not allowed`);
  }
  if (file.size > MAX_SIZE) {
    throw new ValidationError(`File exceeds ${MAX_SIZE / 1024 / 1024}MB limit`);
  }
}
```

## When to Use
- "Add validation to this API endpoint"
- "Sanitize user input in this form"
- "Create a validation schema for this request"
- "Check this code for injection vulnerabilities"
