# Type-Safe Patterns

Advanced type-safety patterns for JavaScript/Node.js.

## Type-Safe Builder Pattern

```javascript
#!/usr/bin/env node
class TypeSafeBuilder {
    constructor(schema) {
        this.schema = schema;
        this.data = {};
        this.errors = [];
    }
    
    set(key, value) {
        const fieldSchema = this.schema[key];
        
        if (!fieldSchema) {
            this.errors.push(`Unknown field: ${key}`);
            return this;
        }
        
        if (!TypeGuard.validate(value, fieldSchema)) {
            this.errors.push(`Invalid type for ${key}: expected ${fieldSchema}`);
            return this;
        }
        
        this.data[key] = value;
        return this;
    }
    
    build() {
        if (this.errors.length > 0) {
            throw new Error(`Validation errors: ${this.errors.join(', ')}`);
        }
        return this.data;
    }
}

// Usage
const userSchema = { name: 'string', age: 'number', email: 'string' };
const user = new TypeSafeBuilder(userSchema)
    .set('name', 'John')
    .set('age', 30)
    .set('email', 'john@example.com')
    .build();
```

## Runtime Type System

```javascript
#!/usr/bin/env node
class RuntimeTypeSystem {
    constructor() {
        this.types = new Map();
        this.validators = new Map();
    }
    
    define(name, schema) {
        this.types.set(name, schema);
        this.validators.set(name, TypeGuard.create(schema));
    }
    
    validate(typeName, value) {
        const validator = this.validators.get(typeName);
        if (!validator) throw new Error(`Unknown type: ${typeName}`);
        return validator(value);
    }
    
    typed(fn, paramTypes, returnType) {
        const self = this;
        return function(...args) {
            paramTypes.forEach((type, index) => {
                if (!self.validate(type, args[index])) {
                    throw new TypeError(`Parameter ${index} must be of type ${type}`);
                }
            });
            const result = fn.apply(this, args);
            if (!self.validate(returnType, result)) {
                throw new TypeError(`Return value must be of type ${returnType}`);
            }
            return result;
        };
    }
}

// Usage
const types = new RuntimeTypeSystem();
types.define('User', { id: 'number', name: 'string', email: 'string' });
types.define('Product', { id: 'number', name: 'string', price: 'number' });
```
