---
name: modularity
description: Use this skill when designing modular systems, creating reusable components, organizing code structure, or managing dependencies. This includes module design, interface definition, dependency management, module composition, loose coupling, and creating maintainable modular architectures.
---

# Modularity

I'll help you design modular systems with reusable components, organize code structure effectively, manage dependencies, and create maintainable modular architectures. When you invoke this skill, I can guide you through building systems that are flexible, testable, and easy to maintain.

# Core Approach

My approach to modularity focuses on:
1. Identifying natural module boundaries
2. Designing clear interfaces between modules
3. Managing dependencies effectively
4. Creating composable, reusable modules
5. Ensuring loose coupling and high cohesion

# Step-by-Step Instructions

## 1. Identify Module Boundaries

I'll help you find natural separation points:

```javascript
// Monolithic approach - everything mixed together
function processOrder(order) {
    // Validation
    if (!order.customerId) throw new Error('No customer');
    if (!order.items.length) throw new Error('No items');
    
    // Pricing
    let total = 0;
    for (const item of order.items) {
        total += item.price * item.quantity;
    }
    
    // Inventory
    for (const item of order.items) {
        const stock = getInventory(item.productId);
        if (stock < item.quantity) {
            throw new Error('Out of stock');
        }
        updateInventory(item.productId, stock - item.quantity);
    }
    
    // Payment
    const payment = processPayment(order.customerId, total);
    
    // Shipping
    const shipment = createShipment(order);
    
    // Notification
    sendEmail(order.customerEmail, 'Order confirmed');
    
    return { orderId: order.id, payment, shipment };
}

// Modular approach - separate concerns
const OrderProcessor = {
    validate: (order) => ValidationModule.validate(order),
    calculate: (order) => PricingModule.calculate(order),
    reserve: (order) => InventoryModule.reserve(order),
    charge: (order, amount) => PaymentModule.charge(order, amount),
    ship: (order) => ShippingModule.create(order),
    notify: (order) => NotificationModule.send(order)
};

async function processOrder(order) {
    OrderProcessor.validate(order);
    const total = OrderProcessor.calculate(order);
    OrderProcessor.reserve(order);
    const payment = OrderProcessor.charge(order, total);
    const shipment = OrderProcessor.ship(order);
    OrderProcessor.notify(order);
    
    return { orderId: order.id, payment, shipment };
}
```

## 2. Design Module Interfaces

I'll help you create clean module interfaces:

```javascript
// Module interface definition
const createModule = (name, dependencies = {}) => {
    return {
        name,
        
        // Public interface
        api: {},
        
        // Private implementation
        private: {},
        
        // Dependencies
        dependencies,
        
        // Initialize module
        init() {
            this.setupDependencies();
            this.registerApi();
        },
        
        // Setup dependency injection
        setupDependencies() {
            for (const [name, dep] of Object.entries(this.dependencies)) {
                this.private[name] = dep;
            }
        },
        
        // Register public API
        registerApi() {
            // Override in implementation
        }
    };
};

// Example: User module
const UserModule = createModule('user', {
    database: null,
    emailService: null
});

UserModule.registerApi = function() {
    this.api = {
        // Public methods
        create: async (userData) => {
            const validated = this.validateUser(userData);
            const user = await this.private.database.save(validated);
            await this.private.emailService.sendWelcome(user);
            return this.sanitizeUser(user);
        },
        
        findById: async (id) => {
            const user = await this.private.database.findById(id);
            return user ? this.sanitizeUser(user) : null;
        },
        
        update: async (id, updates) => {
            const user = await this.private.database.findById(id);
            if (!user) throw new Error('User not found');
            
            const updated = await this.private.database.update(id, updates);
            return this.sanitizeUser(updated);
        }
    };
    
    // Private methods
    this.validateUser = (userData) => {
        if (!userData.email || !userData.name) {
            throw new Error('Invalid user data');
        }
        return userData;
    };
    
    this.sanitizeUser = (user) => {
        const { password, ...sanitized } = user;
        return sanitized;
    };
};
```

## 3. Manage Dependencies

I'll help you handle module dependencies:

```javascript
// Dependency injection container
class DIContainer {
    constructor() {
        this.services = new Map();
        this.singletons = new Map();
    }
    
    // Register a service
    register(name, factory, options = {}) {
        this.services.set(name, {
            factory,
            singleton: options.singleton || false,
            dependencies: options.dependencies || []
        });
    }
    
    // Resolve a service
    resolve(name) {
        const service = this.services.get(name);
        if (!service) {
            throw new Error(`Service ${name} not found`);
        }
        
        // Check if singleton already created
        if (service.singleton && this.singletons.has(name)) {
            return this.singletons.get(name);
        }
        
        // Resolve dependencies
        const deps = service.dependencies.map(dep => this.resolve(dep));
        
        // Create instance
        const instance = service.factory(...deps);
        
        // Store singleton
        if (service.singleton) {
            this.singletons.set(name, instance);
        }
        
        return instance;
    }
}

// Usage
const container = new DIContainer();

// Register services
container.register('database', () => new Database(), { singleton: true });
container.register('emailService', (db) => new EmailService(db), {
    dependencies: ['database']
});
container.register('userService', (email, db) => new UserService(email, db), {
    dependencies: ['emailService', 'database'],
    singleton: true
});

// Resolve services
const userService = container.resolve('userService');
```

## 4. Create Composable Modules

I'll help you build modules that work together:

```javascript
// Module composition pattern
class ModuleComposer {
    static compose(...modules) {
        const composed = {
            modules: new Map(),
            
            // Add module
            use(module) {
                this.modules.set(module.name, module);
                return this;
            },
            
            // Get module API
            get(name) {
                const module = this.modules.get(name);
                return module ? module.api : null;
            },
            
            // Initialize all modules
            async init() {
                for (const module of this.modules.values()) {
                    if (module.init) {
                        await module.init();
                    }
                }
            },
            
            // Create module pipeline
            pipeline(...moduleNames) {
                const modules = moduleNames.map(name => this.get(name));
                return new ModulePipeline(modules);
            }
        };
        
        // Add all modules
        modules.forEach(module => composed.use(module));
        
        return composed;
    }
}

// Pipeline for chaining module operations
class ModulePipeline {
    constructor(modules) {
        this.modules = modules;
    }
    
    async execute(data) {
        let result = data;
        
        for (const module of this.modules) {
            if (module.process) {
                result = await module.process(result);
            }
        }
        
        return result;
    }
}
```

# Examples

## Example 1: Modular E-Commerce System

**User Query**: "I need to build an e-commerce system that's easy to extend with new features"

**Approach**:
1. Create core modules: Products, Orders, Payments, Shipping
2. Define clear interfaces between modules
3. Use dependency injection for loose coupling
4. Create plugin system for extensions

**Complete Commands:**
```bash
# Create module structure
mkdir -p modules/{products,orders,payments,shipping,plugins}

# Initialize modules
node init-modules.js

# Test module integration
node test-integration.js
```

## Example 2: Refactoring to Modules

**User Query**: "My monolithic app is hard to maintain, how can I modularize it?"

**Approach**:
1. Identify cohesive code groups
2. Extract into separate modules
3. Define interfaces
4. Gradually migrate usage

# CLI Tools to Leverage

**Essential tools for modular development:**
- `tree src/` - Visualize module structure
- `madge --circular src/` - Find circular dependencies

**Language-Specific Tools:**
- **JavaScript**: `madge` / `dependency-cruiser` / `npm ls`
- **Python**: `pipdeptree` / `import-linter` / `pydeps`
- **Go**: `go mod graph` / `go mod why` (built-in)
- **Rust**: `cargo tree` / `cargo-udeps` (unused deps)

# Language Patterns

**JavaScript — ES Modules:**
```javascript
// user.service.js
export class UserService {
    constructor(db) { this.db = db; }
    async findById(id) { return this.db.find(id); }
}
// main.js
import { UserService } from './user.service.js';
```

**Python — packages:**
```python
# users/__init__.py
from .service import UserService
from .repository import UserRepository
__all__ = ['UserService', 'UserRepository']

# main.py
from users import UserService
```

**Go — packages (enforced by compiler):**
```go
// users/service.go
package users
type Service struct { db *Database }
func (s *Service) FindByID(id int) (*User, error) { /* ... */ }

// main.go
import "myapp/users"
svc := &users.Service{}
```

**Rust — modules + crates:**
```rust
// src/users/mod.rs
pub mod service;
pub mod repository;

// src/main.rs
mod users;
use users::service::UserService;
```

See `./_examples/modularity-node-patterns.md` for additional patterns.

> **Other languages?** Examples use JS/Python/Go/Rust, but all concepts apply universally. See the **Language Adaptation Guide** in `../PACK.md` for C#, Java, Kotlin, Swift, Elixir, Haskell equivalents.

# Best Practices

- Keep modules small and focused (Single Responsibility Principle)
- Design stable interfaces that don't change often
- Minimize dependencies between modules
- Use dependency injection instead of direct imports
- Make modules testable in isolation
- Document module contracts and interfaces
- Avoid circular dependencies
- Consider module lifecycle (init, start, stop, destroy)

# Module Design Principles

## 1. High Cohesion
- Module should have a single, well-defined purpose
- Related functionality should be grouped together
- Minimal unrelated code in each module

## 2. Low Coupling
- Modules should know little about each other
- Communicate through well-defined interfaces
- Avoid direct dependencies on implementation details

## 3. Encapsulation
- Hide internal implementation
- Expose only necessary API
- Protect internal state

## 4. Reusability
- Design modules to be used in different contexts
- Avoid hardcoded dependencies
- Make configuration injectable

# Validation Checklist

When designing modules, verify:
- [ ] Module has a single responsibility
- [ ] Interface is clear and stable
- [ ] Dependencies are minimal and explicit
- [ ] Module can be tested independently
- [ ] No circular dependencies
- [ ] Documentation is complete
- [ ] Error handling is proper
- [ ] Module is configurable

# Troubleshooting

## Issue: Circular Dependencies

**Symptoms**: Modules depend on each other in a cycle

**Solution**:
- Extract common dependency to a third module
- Use dependency injection
- Merge tightly coupled modules
- Use events or pub/sub pattern

## Issue: Too Many Dependencies

**Symptoms**: Module requires many other modules

**Solution**:
- Split module into smaller modules
- Create facade for common operations
- Use dependency injection container
- Review if all dependencies are necessary

## Issue: Module is Too Large

**Symptoms**: Module does too many things

**Solution**:
- Identify separate responsibilities
- Extract sub-modules
- Apply Single Responsibility Principle
- Consider module composition

# Supporting Files

- See `./_examples/modularity-node-patterns.md` for module patterns
- See `./_examples/basic-examples.md` for fundamental usage

## Related Skills

- **abstraction** - Modularity uses abstraction
- **data-structures** - Design modular data structures
- **functional-paradigm** - Functional programming promotes modularity
- **metaprogramming** - Generate modular code programmatically
- **control-flow** - Modular control flow design

- → **5-architecture-fundamentals**: modular-monolith (for modular architecture)
- → **2-code-quality**: code-refactoring (for improving modularity)

Remember: Good modularity makes systems easier to understand, test, and maintain!
