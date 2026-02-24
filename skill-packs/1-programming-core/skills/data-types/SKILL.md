---
name: data-types
description: Use this skill when working with different data types, type systems, type conversions, or designing type-safe code. This includes primitive types, complex types, type checking, type coercion, custom types, type guards, and implementing type-safe patterns.
---

# Data Types

I'll help you work effectively with different data types, implement type-safe code, handle type conversions properly, and design robust type systems. When you invoke this skill, I can guide you through understanding and using types correctly in your programs.

# Core Approach

My approach to data types focuses on:
1. Understanding type systems and their importance
2. Choosing appropriate types for your data
3. Implementing proper type checking and validation
4. Handling type conversions safely
5. Creating type-safe abstractions

# Step-by-Step Instructions

## 1. Understand Type Systems

I'll help you master type systems across languages:

**JavaScript (dynamic, weak typing):**
```javascript
typeof 'hello'    // 'string'   — 7 primitives + object
typeof 42         // 'number'   — no int/float distinction
typeof null       // 'object'   — legacy bug
Array.isArray([]) // true       — arrays need special check
```

**Python (dynamic, strong typing):**
```python
type('hello')     # <class 'str'>
type(42)          # <class 'int'>    — int/float are distinct
type(3.14)        # <class 'float'>
isinstance([], list)  # True
isinstance(42, (int, float))  # Union check
```

**TypeScript (static, structural typing):**
```typescript
const name: string = 'hello';
const age: number = 42;
type User = { name: string; age: number; email?: string };
function greet(user: User): string { return `Hi ${user.name}`; }
```

**Go (static, strong typing):**
```go
var name string = "hello"
var age int = 42          // int, int8, int16, int32, int64
var pi float64 = 3.14     // float32, float64
type User struct { Name string; Age int }
```

**Rust (static, strong, ownership-aware):**
```rust
let name: &str = "hello";   // string slice (borrowed)
let owned: String = String::from("hello"); // owned string
let age: i32 = 42;          // i8, i16, i32, i64, i128, usize
let pi: f64 = 3.14;         // f32, f64
```

## 2. Handle Type Conversions Safely

**JavaScript — explicit conversion (avoid coercion):**
```javascript
Number('42')       // 42 — safe
Number('hello')    // NaN — check with isNaN()
String(42)         // '42'
Boolean(0)         // false — falsy: 0, '', null, undefined, NaN
// Pitfall: '5' + 5 = '55' but '5' - 5 = 0
```

**Python — strict (no implicit coercion):**
```python
int('42')          # 42
int('hello')       # ValueError — must handle
str(42)            # '42'
bool(0)            # False — falsy: 0, '', None, [], {}
# '5' + 5 → TypeError (Python refuses implicit coercion)
```

**Go — explicit casting required:**
```go
strconv.Atoi("42")          // 42, nil
strconv.ParseFloat("3.14", 64) // 3.14, nil
fmt.Sprintf("%d", 42)       // "42"
// Go never converts implicitly between types
```

**Rust — explicit with Result:**
```rust
"42".parse::<i32>()     // Ok(42)
"hello".parse::<i32>()  // Err(ParseIntError)
42.to_string()          // "42"
// Rust requires explicit conversion; no implicit coercion ever
```

## 3. Runtime Validation

**JavaScript — Zod (schema validation):**
```javascript
import { z } from 'zod';
const UserSchema = z.object({
    id: z.number(),
    name: z.string().min(1),
    email: z.string().email(),
    age: z.number().optional(),
});
const result = UserSchema.safeParse(data); // { success, data/error }
```

**Python — Pydantic (runtime + type hints):**
```python
from pydantic import BaseModel, EmailStr
class User(BaseModel):
    id: int
    name: str
    email: EmailStr
    age: int | None = None

user = User.model_validate(data)  # Raises ValidationError if invalid
```

**TypeScript — type guards:**
```typescript
function isUser(value: unknown): value is User {
    return typeof value === 'object' && value !== null
        && 'id' in value && typeof (value as any).id === 'number';
}
```

**Go — struct tags + validator:**
```go
type User struct {
    ID    int    `json:"id" validate:"required"`
    Name  string `json:"name" validate:"required,min=1"`
    Email string `json:"email" validate:"required,email"`
}
err := validate.Struct(user) // github.com/go-playground/validator
```

## 4. Design Custom Types

**JavaScript — Value Objects:**
```javascript
class Email {
    #value;
    constructor(value) {
        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value))
            throw new TypeError(`Invalid email: ${value}`);
        this.#value = value;
    }
    toString() { return this.#value; }
    equals(other) { return other instanceof Email && this.#value === other.#value; }
}
```

**Python — dataclasses + __post_init__:**
```python
from dataclasses import dataclass
import re

@dataclass(frozen=True)  # Immutable value object
class Email:
    value: str
    def __post_init__(self):
        if not re.match(r'^[^\s@]+@[^\s@]+\.[^\s@]+$', self.value):
            raise ValueError(f'Invalid email: {self.value}')
```

**Rust — newtype pattern:**
```rust
struct Email(String);
impl Email {
    fn new(value: &str) -> Result<Self, String> {
        if value.contains('@') { Ok(Email(value.to_string())) }
        else { Err(format!("Invalid email: {}", value)) }
    }
}
```

**Go — custom types with methods:**
```go
type Email string
func NewEmail(v string) (Email, error) {
    if !strings.Contains(v, "@") { return "", errors.New("invalid email") }
    return Email(v), nil
}
```

# Examples

## Example 1: Type-Safe API Response

**User Query**: "Create type-safe handlers for API responses"

**Approach**:
1. Define response schemas
2. Create type guards
3. Validate responses at runtime
4. Handle type errors gracefully

**Complete Commands:**
```bash
# Test type-safe API
node type-safe-api.js

# Test with invalid data
node type-safe-api.js --invalid-data
```

## Example 2: Data Validation Pipeline

**User Query**: "Build a validation pipeline for user input"

**Approach**:
1. Create validation schemas
2. Chain validators
3. Collect all errors
4. Return typed result

# CLI Tools to Leverage

**Language-Specific Type Tools:**
- **JavaScript**: `typescript` / `zod` / `io-ts` for runtime validation
- **Python**: `mypy` / `pyright` (static) / `pydantic` (runtime)
- **Go**: Built-in static typing / `go vet` for type checks
- **Rust**: Built-in static typing / `clippy` for lint

# Language Patterns

See `./_examples/type-safe-patterns.md` for advanced patterns including:
- Type-Safe Builder Pattern
- Runtime Type System with typed functions

> **Other languages?** Examples use JS/Python/Go/Rust, but all concepts apply universally. See the **Language Adaptation Guide** in `../PACK.md` for C#, Java, Kotlin, Swift, Elixir, Haskell equivalents.

# Best Practices

- Always validate external data
- Use strict equality (===) instead of loose equality (==)
- Be explicit with type conversions
- Create custom types for domain concepts
- Use type guards for runtime validation
- Document type contracts
- Consider TypeScript for static typing
- Handle null and undefined explicitly

# Type System Concepts

| Axis | Languages |
|------|-----------|
| Static typing | TypeScript, Go, Rust, Java |
| Dynamic typing | JavaScript, Python, Ruby |
| Strong typing | Python, Go, Rust |
| Weak typing | JavaScript, C |
| Structural typing | TypeScript, Go |
| Nominal typing | Java, Rust |

# Validation Checklist

When working with types, verify:
- [ ] All external data is validated
- [ ] Type conversions are explicit
- [ ] Edge cases (null, undefined) handled
- [ ] Type errors are caught early
- [ ] Custom types are well-defined
- [ ] Type contracts are documented
- [ ] Equality checks are strict

# Troubleshooting

## Issue: Type Coercion Bugs

**Symptoms**: Unexpected behavior with + operator

**Solution**:
```javascript
// JS: Always be explicit
const add = (a, b) => Number(a) + Number(b);
```
```python
# Python: No coercion — but validate input types
def add(a, b): return int(a) + int(b)  # Raises ValueError if invalid
```

## Issue: Undefined Property Access

**Symptoms**: Cannot read property of undefined

**Solution**:
```javascript
const value = obj?.prop?.subProp ?? defaultValue;  // JS: optional chaining + nullish coalescing
```
```python
value = obj.get('prop', {}).get('subProp', default)  # Python: dict.get() chains
```
```go
// Go: No optional chaining — check explicitly
if obj != nil && obj.Prop != nil { value = obj.Prop.SubProp }
```

# Supporting Files

- See `./_examples/type-safe-patterns.md` for advanced type patterns
- See `./_examples/type-system-examples.md` for type system examples
- See `./_examples/basic-examples.md` for fundamental usage

## Related Skills

- **data-structures** - Choose appropriate types for data structures
- **abstraction** - Types help create effective abstractions
- **control-flow** - Type checking affects control flow
- **functional-paradigm** - Type safety in functional programming
- **algorithms** - Algorithm efficiency depends on type choices
- → **2-code-quality**: error-handling (for type errors)
- → **35-development-environment**: debugging-skills (for debugging type issues)

Remember: Types are a tool for writing correct code - use them to make your intentions clear and catch errors early!
