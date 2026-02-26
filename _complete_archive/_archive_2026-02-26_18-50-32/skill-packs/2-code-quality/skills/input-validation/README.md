# Input Validation Skill

This skill helps you validate and sanitize inputs securely at every system boundary.

## Quick Start

Invoke this skill when you need to:
- Add schema validation to API endpoints
- Sanitize user input against XSS/SQL injection
- Create Zod, Pydantic, or validator schemas
- Validate file uploads safely
- Return clear, field-level validation errors

## Example Usage

### Basic Example
```
User: Add validation to this POST /users endpoint

Agent: I'll create a Zod schema for the request body, add validation
middleware, and return structured error messages for invalid fields...
```

## Key Libraries

| Language | Library | Usage |
|----------|---------|-------|
| JavaScript | Zod, Joi, Yup | Schema validation |
| Python | Pydantic, marshmallow | Model validation |
| Go | go-playground/validator | Struct tag validation |

## Related Skills

- **error-handling** - Return proper responses for validation failures
- **logging-strategies** - Log validation failures for abuse detection
