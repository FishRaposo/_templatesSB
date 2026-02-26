---
name: abstraction
description: Use this skill when simplifying complex systems, hiding implementation details, creating reusable components, or designing interfaces. This includes data abstraction, procedural abstraction, control abstraction, abstraction layers, interface design, and creating clean abstractions.
---

# Abstraction

I'll help you simplify complex systems through abstraction, hide implementation details, create reusable components, and design clean interfaces. When you invoke this skill, I can guide you through creating effective abstractions that make your code more maintainable and understandable.

# Core Approach

My approach to abstraction focuses on:
1. Identifying what to hide and what to expose
2. Creating clear boundaries between components
3. Designing intuitive interfaces
4. Building reusable, composable abstractions
5. Maintaining the right level of abstraction

# Step-by-Step Instructions

## 1. Identify Abstraction Opportunities

I'll help you find where abstraction can help:

```javascript
// Before abstraction - complex, tightly coupled code
function processUsers(users) {
    for (let i = 0; i < users.length; i++) {
        if (users[i].age >= 18 && users[i].active) {
            users[i].verified = true;
            users[i].notifications.push({
                type: 'welcome',
                message: 'Welcome to our platform!'
            });
            sendEmail(users[i].email, 'Welcome!', '...');
        }
    }
}

// After abstraction - clean, reusable components
class UserProcessor {
    constructor(notificationService, emailService) {
        this.notificationService = notificationService;
        this.emailService = emailService;
    }
    
    process(users) {
        return users
            .filter(user => this.isEligible(user))
            .map(user => this.activateUser(user));
    }
    
    isEligible(user) {
        return user.age >= 18 && user.active;
    }
    
    activateUser(user) {
        user.verified = true;
        this.notificationService.sendWelcome(user);
        this.emailService.sendWelcome(user);
        return user;
    }
}
```

## 2. Design Abstract Interfaces

I'll help you create clean interfaces:

**JavaScript — class-based (no enforced interfaces):**
```javascript
class DataSource {
    async getData(id) { throw new Error('Not implemented'); }
    async saveData(id, data) { throw new Error('Not implemented'); }
}
class DatabaseSource extends DataSource {
    async getData(id) { return this.db.find({ id }); }
}
```

**Python — ABC (Abstract Base Class):**
```python
from abc import ABC, abstractmethod

class DataSource(ABC):
    @abstractmethod
    async def get_data(self, id): ...
    @abstractmethod
    async def save_data(self, id, data): ...

class DatabaseSource(DataSource):
    async def get_data(self, id):
        return await self.db.find_one({'id': id})
    async def save_data(self, id, data):
        await self.db.update_one({'id': id}, {'$set': data}, upsert=True)
```

**Go — interfaces (implicit, structural):**
```go
type DataSource interface {
    GetData(id string) ([]byte, error)
    SaveData(id string, data []byte) error
}
// Any struct with these methods automatically implements DataSource
type DatabaseSource struct { db *sql.DB }
func (d *DatabaseSource) GetData(id string) ([]byte, error) { /* ... */ }
func (d *DatabaseSource) SaveData(id string, data []byte) error { /* ... */ }
```

**Rust — traits (explicit, enforced):**
```rust
trait DataSource {
    async fn get_data(&self, id: &str) -> Result<Vec<u8>, Error>;
    async fn save_data(&self, id: &str, data: &[u8]) -> Result<(), Error>;
}
impl DataSource for DatabaseSource {
    async fn get_data(&self, id: &str) -> Result<Vec<u8>, Error> { /* ... */ }
    async fn save_data(&self, id: &str, data: &[u8]) -> Result<(), Error> { /* ... */ }
}
```

## 3. Create Abstraction Layers

I'll help you build layered abstractions:

```javascript
// Layer 1: Low-level database operations
class DatabaseConnection {
    async query(sql, params) {
        // Direct database query implementation
    }
    
    async transaction(queries) {
        // Transaction implementation
    }
}

// Layer 2: Data access abstraction
class UserRepository {
    constructor(db) {
        this.db = db;
    }
    
    async findById(id) {
        return await this.db.query('SELECT * FROM users WHERE id = ?', [id]);
    }
    
    async save(user) {
        return await this.db.query('INSERT INTO users SET ?', user);
    }
}

// Layer 3: Business logic abstraction
class UserService {
    constructor(userRepo) {
        this.userRepo = userRepo;
    }
    
    async createUser(userData) {
        // Business logic here
        const user = this.validateAndPrepare(userData);
        return await this.userRepo.save(user);
    }
    
    async getUserProfile(id) {
        const user = await this.userRepo.findById(id);
        return this.formatProfile(user);
    }
}

// Layer 4: API interface abstraction
class UserController {
    constructor(userService) {
        this.userService = userService;
    }
    
    async createUser(req, res) {
        try {
            const user = await this.userService.createUser(req.body);
            res.json({ success: true, user });
        } catch (error) {
            res.status(500).json({ error: error.message });
        }
    }
}
```

## 4. Build Reusable Components

I'll help you create composable abstractions:

```javascript
// Reusable validation abstraction
class Validator {
    constructor(rules) {
        this.rules = rules;
    }
    
    validate(data) {
        const errors = [];
        
        for (const [field, rule] of Object.entries(this.rules)) {
            const value = data[field];
            const result = rule(value);
            
            if (!result.valid) {
                errors.push({ field, message: result.message });
            }
        }
        
        return {
            valid: errors.length === 0,
            errors
        };
    }
}

// Composable rules
const Rules = {
    required: value => ({
        valid: value != null && value !== '',
        message: 'This field is required'
    }),
    
    email: value => ({
        valid: /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value),
        message: 'Must be a valid email'
    }),
    
    minLength: min => value => ({
        valid: value && value.length >= min,
        message: `Must be at least ${min} characters`
    }),
    
    combine: (...rules) => value => {
        for (const rule of rules) {
            const result = rule(value);
            if (!result.valid) return result;
        }
        return { valid: true };
    }
};

// Usage
const userValidator = new Validator({
    name: Rules.combine(
        Rules.required,
        Rules.minLength(2)
    ),
    email: Rules.combine(
        Rules.required,
        Rules.email
    )
});
```

# Examples

## Example 1: Abstracting File Operations

**User Query**: "I need to work with different file formats (JSON, CSV, XML) but want a simple interface"

**Approach**:
1. Create abstract FileReader interface
2. Implement concrete readers for each format
3. Use factory pattern to create appropriate reader
4. Hide format-specific details

**Complete Commands:**
```bash
# Test with different file formats
echo '{"name": "John", "age": 30}' > test.json
echo 'name,age\nJohn,30' > test.csv

# Use abstract interface
node file-processor.js test.json
node file-processor.js test.csv
```

## Example 2: Creating API Abstraction

**User Query**: "I need to switch between different payment providers without changing my code"

**Approach**:
1. Define PaymentProcessor interface
2. Implement for Stripe, PayPal, etc.
3. Use dependency injection
4. Switch providers with configuration

# CLI Tools to Leverage

**Language-Specific Abstraction Tools:**
- **JavaScript/TypeScript**: `typescript` for interface definitions
- **Python**: `abc` module (stdlib) / `zope.interface` / `mypy` for protocol checks
- **Go**: Interfaces are built-in and implicit; `go vet` checks
- **Rust**: Traits are built-in; `clippy` for trait best practices

# Language Patterns

See `./_examples/abstraction-node-patterns.md` for advanced patterns including:
- Abstract Factory pattern
- Higher-order functions for abstraction (withErrorHandling, withLogging)
- Module pattern for abstraction

> **Other languages?** Examples use JS/Python/Go/Rust, but all concepts apply universally. See the **Language Adaptation Guide** in `../PACK.md` for C#, Java, Kotlin, Swift, Elixir, Haskell equivalents.

# Best Practices

- Hide complexity, not important details
- Keep abstractions simple and intuitive
- Follow the principle of least astonishment
- Make abstractions composable, not monolithic
- Document the abstraction's purpose and usage
- Test abstractions independently
- Don't over-abstract (YAGNI principle)
- Ensure abstractions are leak-free

# Types of Abstraction

## 1. Data Abstraction
- Hide data representation
- Expose only necessary operations
- Example: Stack hides array implementation

## 2. Procedural Abstraction
- Group related operations
- Hide implementation details
- Example: Sort function hides algorithm

## 3. Control Abstraction
- Abstract control flow patterns
- Hide iteration/recursion details
- Example: Map, filter, reduce functions

## 4. Abstraction Layers
- Organize code by abstraction level
- Clear boundaries between layers
- Example: OSI model layers

# Validation Checklist

When creating abstractions, verify:
- [ ] Abstraction hides the right details
- [ ] Interface is intuitive and clear
- [ ] Implementation is properly encapsulated
- [ ] Abstraction is reusable
- [ ] Dependencies are minimal
- [ ] Abstraction is well-tested
- [ ] Documentation is complete

# Troubleshooting

## Issue: Abstraction is Too Complex

**Symptoms**: Hard to understand or use

**Solution**:
- Simplify the interface
- Remove unnecessary methods
- Better naming and documentation
- Split into smaller abstractions

## Issue: Leaky Abstraction

**Symptoms**: Implementation details leak through

**Solution**:
- Review interface boundaries
- Handle all cases internally
- Provide consistent behavior
- Add proper error handling

## Issue: Over-Abstraction

**Symptoms**: Too many layers, indirection

**Solution**:
- Remove unnecessary abstractions
- Combine related abstractions
- Follow YAGNI principle
- Simplify the architecture

# Supporting Files

- See `./_examples/abstraction-node-patterns.md` for advanced patterns
- See `./_examples/basic-examples.md` for fundamental usage

## Related Skills

- **modularity** - Abstraction enables modular design
- **functional-paradigm** - Functional programming relies on abstraction
- **data-structures** - Data structures are abstractions for data organization
- **algorithms** - Algorithms abstract away implementation details
- **control-flow** - Abstract complex control flows into simple patterns
- → **35-development-environment**: debugging-skills (for debugging abstraction layers)
- → **2-code-quality**: error-handling (for handling abstraction errors)

Remember: Good abstraction makes complex things simple, bad abstraction makes simple things complex!
