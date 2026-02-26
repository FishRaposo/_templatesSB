# Advanced Type System Examples

## Custom Type System Implementation

```javascript
// Type system for runtime type checking
class TypeSystem {
    static types = new Map();
    
    static defineType(name, validator) {
        this.types.set(name, {
            name,
            validate: validator,
            toString: () => name
        });
    }
    
    static validate(value, type) {
        const typeDef = this.types.get(type);
        if (!typeDef) {
            throw new Error(`Unknown type: ${type}`);
        }
        return typeDef.validate(value);
    }
    
    static createTypeGuard(type) {
        return (value) => this.validate(value, type);
    }
}

// Define custom types
TypeSystem.defineType('PositiveNumber', (value) => {
    return typeof value === 'number' && value > 0;
});

TypeSystem.defineType('Email', (value) => {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return typeof value === 'string' && emailRegex.test(value);
});

TypeSystem.defineType('NonEmptyString', (value) => {
    return typeof value === 'string' && value.trim().length > 0;
});

// Usage
const isPositiveNumber = TypeSystem.createTypeGuard('PositiveNumber');
const isEmail = TypeSystem.createTypeGuard('Email');

function processOrder(order) {
    if (!isPositiveNumber(order.amount)) {
        throw new Error('Amount must be positive');
    }
    if (!isEmail(order.customerEmail)) {
        throw new Error('Invalid email address');
    }
    // Process order...
}
```

## Type Composition

```javascript
// Compose types for complex validation
class ComposedType {
    constructor(...types) {
        this.types = types;
    }
    
    validate(value) {
        return this.types.every(type => type.validate(value));
    }
    
    toString() {
        return this.types.map(t => t.toString()).join(' & ');
    }
}

// Create composed types
const PositiveInteger = new ComposedType(
    { validate: v => typeof v === 'number', toString: () => 'Number' },
    { validate: v => Number.isInteger(v), toString: () => 'Integer' },
    { validate: v => v > 0, toString: () => 'Positive' }
);

// Usage with function overloading
function process(value) {
    if (PositiveInteger.validate(value)) {
        return value * 2; // Double positive integers
    }
    if (typeof value === 'string') {
        return value.toUpperCase(); // Uppercase strings
    }
    throw new Error('Unsupported type');
}
```

## Type-Safe Builder Pattern

```javascript
// Type-safe builder for object construction
class TypeSafeBuilder {
    constructor(schema) {
        this.schema = schema;
        this.data = {};
        this.errors = [];
    }
    
    set(field, value) {
        const fieldType = this.schema[field];
        if (!fieldType) {
            this.errors.push(`Unknown field: ${field}`);
            return this;
        }
        
        if (!fieldType.validate(value)) {
            this.errors.push(`Invalid type for ${field}: expected ${fieldType}`);
            return this;
        }
        
        this.data[field] = value;
        return this;
    }
    
    build() {
        if (this.errors.length > 0) {
            throw new Error(`Validation errors: ${this.errors.join(', ')}`);
        }
        
        // Check required fields
        const required = Object.keys(this.schema);
        const missing = required.filter(field => !(field in this.data));
        if (missing.length > 0) {
            throw new Error(`Missing required fields: ${missing.join(', ')}`);
        }
        
        return { ...this.data };
    }
}

// Define schema
const userSchema = {
    name: { validate: v => typeof v === 'string' && v.length > 0 },
    age: { validate: v => typeof v === 'number' && v >= 0 },
    email: { validate: v => typeof v === 'string' && v.includes('@') }
};

// Usage
const user = new TypeSafeBuilder(userSchema)
    .set('name', 'John Doe')
    .set('age', 30)
    .set('email', 'john@example.com')
    .build();
```

## Runtime Type Information

```javascript
// Rich type information system
class TypeInfo {
    constructor(name, constraints = {}) {
        this.name = name;
        this.constraints = constraints;
    }
    
    validate(value) {
        // Check type
        if (this.name === 'string' && typeof value !== 'string') return false;
        if (this.name === 'number' && typeof value !== 'number') return false;
        if (this.name === 'boolean' && typeof value !== 'boolean') return false;
        
        // Check constraints
        if (this.constraints.min !== undefined && value < this.constraints.min) return false;
        if (this.constraints.max !== undefined && value > this.constraints.max) return false;
        if (this.constraints.pattern && !this.constraints.pattern.test(value)) return false;
        
        return true;
    }
    
    getErrorMessage(value) {
        if (this.validate(value)) return null;
        
        const errors = [];
        if (typeof value !== this.name) {
            errors.push(`expected ${this.name}`);
        }
        
        for (const [key, constraint] of Object.entries(this.constraints)) {
            if (key === 'min' && value < constraint) {
                errors.push(`must be >= ${constraint}`);
            }
            if (key === 'max' && value > constraint) {
                errors.push(`must be <= ${constraint}`);
            }
            if (key === 'pattern' && !constraint.test(value)) {
                errors.push('invalid format');
            }
        }
        
        return errors.join(', ');
    }
}

// Create type definitions
const AgeType = new TypeInfo('number', { min: 0, max: 150 });
const NameType = new TypeInfo('string', { min: 1, pattern: /^[A-Za-z\s]+$/ });
const EmailType = new TypeInfo('string', { pattern: /^[^\s@]+@[^\s@]+\.[^\s@]+$/ });

// Validate with detailed errors
function validatePerson(person) {
    const errors = {};
    
    if (!AgeType.validate(person.age)) {
        errors.age = AgeType.getErrorMessage(person.age);
    }
    if (!NameType.validate(person.name)) {
        errors.name = NameType.getErrorMessage(person.name);
    }
    if (!EmailType.validate(person.email)) {
        errors.email = EmailType.getErrorMessage(person.email);
    }
    
    return Object.keys(errors).length === 0 ? null : errors;
}
```

## When to Use

- Implement custom type systems for domain-specific validation
- Create type-safe APIs that validate inputs
- Build form validation systems
- Design configuration validation
- Create runtime type checking for JavaScript projects
