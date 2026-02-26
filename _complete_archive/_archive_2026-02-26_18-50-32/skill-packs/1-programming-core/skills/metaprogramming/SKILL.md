---
name: metaprogramming
description: Use this skill when writing code that writes or manipulates other code, generating code programmatically, creating templates, scaffolding projects, or implementing advanced language features. This includes reflection, proxies, decorators, code generation, template engines, AST manipulation, and creating dynamic or self-modifying programs.
---

# Metaprogramming

I'll help you write code that can write, modify, or analyze other code, generate code programmatically, create reusable templates, and implement advanced metaprogramming techniques. When you invoke this skill, I can guide you through reflection, proxies, decorators, code generation, and template systems.

# Core Approach

My approach to metaprogramming focuses on:
1. Identifying when metaprogramming or code generation is appropriate
2. Using reflection to inspect and modify code at runtime
3. Implementing proxies for interception and modification
4. Creating decorators for cross-cutting concerns
5. Building template systems and code generators

# Step-by-Step Instructions

## 1. Use Reflection Effectively

I'll help you inspect and modify code at runtime:

**JavaScript — Reflect API:**
```javascript
Reflect.ownKeys(obj);                    // All own keys (incl. symbols)
Object.getPrototypeOf(obj);              // Prototype chain
typeof obj.method === 'function';        // Method check
```

**Python — inspect module (rich reflection):**
```python
import inspect
inspect.getmembers(obj, predicate=inspect.ismethod)  # All methods
inspect.signature(fn)           # Function signature with params
inspect.getsource(fn)           # Actual source code!
hasattr(obj, 'method')          # Attribute check
getattr(obj, 'method', default) # Safe attribute access
```

**Go — reflect package:**
```go
import "reflect"
t := reflect.TypeOf(obj)        // Type info
v := reflect.ValueOf(obj)       // Value info
for i := 0; i < t.NumMethod(); i++ {
    fmt.Println(t.Method(i).Name) // List methods
}
```

**Rust — limited runtime reflection (use macros instead):**
```rust
// Rust favors compile-time metaprogramming via macros
std::any::type_name::<T>()  // Type name at runtime
// For rich reflection, use `serde` derive macros
#[derive(Debug, Serialize, Deserialize)]
struct User { name: String, age: u32 }
```

## 2. Implement Proxies for Interception

I'll help you create powerful proxy patterns:

```javascript
// Logging proxy
function createLoggingProxy(target) {
    return new Proxy(target, {
        get(target, prop, receiver) {
            const value = Reflect.get(target, prop, receiver);
            if (typeof value === 'function') {
                return function(...args) {
                    console.log(`Calling ${prop} with:`, args);
                    const result = value.apply(this, args);
                    console.log(`${prop} returned:`, result);
                    return result;
                };
            }
            return value;
        },
        set(target, prop, value, receiver) {
            console.log(`Setting ${prop} to:`, value);
            return Reflect.set(target, prop, value, receiver);
        }
    });
}

// Validation proxy
function createValidationProxy(target, schema) {
    return new Proxy(target, {
        set(target, prop, value) {
            if (schema[prop] && !schema[prop](value)) {
                throw new Error(`Invalid value for ${prop}: ${value}`);
            }
            return Reflect.set(target, prop, value);
        }
    });
}

// Caching proxy
function createCachingProxy(fn) {
    const cache = new Map();
    return new Proxy(fn, {
        apply(target, thisArg, args) {
            const key = JSON.stringify(args);
            if (cache.has(key)) return cache.get(key);
            const result = Reflect.apply(target, thisArg, args);
            cache.set(key, result);
            return result;
        }
    });
}
```

## 3. Create Decorators

**JavaScript — higher-order functions:**
```javascript
const timed = fn => (...args) => {
    const start = performance.now();
    const result = fn(...args);
    console.log(`${fn.name}: ${performance.now() - start}ms`);
    return result;
};
const retry = (fn, n = 3) => (...args) => {
    for (let i = 0; i < n; i++) { try { return fn(...args); } catch(e) { if (i === n-1) throw e; } }
};
```

**Python — first-class decorators (language feature):**
```python
import functools, time

def timed(fn):
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        start = time.perf_counter()
        result = fn(*args, **kwargs)
        print(f"{fn.__name__}: {time.perf_counter() - start:.3f}s")
        return result
    return wrapper

@timed
def slow_function(): time.sleep(1)
```

**Rust — proc macros (compile-time decorators):**
```rust
// Derive macros are Rust's equivalent of decorators
#[derive(Debug, Clone, Serialize)]  // Auto-generate trait implementations
struct User { name: String }

// Custom attribute macros can transform code at compile time
#[tokio::main]  // Transforms main() into async runtime
async fn main() { /* ... */ }
```

## 4. Build Template Systems and Code Generators

I'll help you generate code programmatically:

```javascript
// Simple template engine
class TemplateEngine {
    render(template, data) {
        return template.replace(/\{\{(\w+(?:\.\w+)*)\}\}/g, (match, key) => {
            const value = key.split('.').reduce(
                (obj, k) => obj && obj[k], data
            );
            return value !== undefined ? value : match;
        });
    }
}

// Class generator
class ClassGenerator {
    generate(config) {
        const { name, properties = [], methods = [] } = config;
        
        const props = properties.map(p => `        this.${p} = ${p};`).join('\n');
        const params = properties.join(', ');
        const meths = methods.map(m => 
            `    ${m.name}(${(m.params || []).join(', ')}) {\n        // Implementation\n    }`
        ).join('\n\n');
        
        return `class ${name} {\n    constructor(${params}) {\n${props}\n    }\n\n${meths}\n}`;
    }
}

// Usage
const gen = new ClassGenerator();
console.log(gen.generate({
    name: 'User',
    properties: ['name', 'email'],
    methods: [{ name: 'validate', params: [] }, { name: 'save', params: [] }]
}));
```

# Examples

## Example 1: Creating an ORM with Proxies

**User Query**: "Build a simple ORM using proxies and metaprogramming"

**Approach**:
1. Use proxies for lazy loading and dirty tracking
2. Add validation with property setters
3. Add method chaining

## Example 2: Component Scaffolder

**User Query**: "Create a React component generator with tests"

**Approach**:
1. Define component template
2. Add test template
3. Generate with props interface

**Complete Commands:**
```bash
node component-gen.js --name UserProfile --props "name:string,email:string"
```

# CLI Tools to Leverage

**Language-Specific Metaprogramming Tools:**
- **JavaScript**: `babel` (AST transform) / `plop` / `hygen` (code gen)
- **Python**: `ast` module (stdlib) / `jinja2` (templates) / `cookiecutter` (scaffolding)
- **Go**: `go generate` / `text/template` (stdlib) / `jennifer` (code gen)
- **Rust**: `proc-macro2` / `syn` / `quote` (compile-time macros)

> **Other languages?** Examples use JS/Python/Go/Rust, but all concepts apply universally. See the **Language Adaptation Guide** in `../PACK.md` for C#, Java, Kotlin, Swift, Elixir, Haskell equivalents.

# Best Practices

- Use metaprogramming sparingly — when it adds real value
- Document dynamic behavior clearly
- Prefer explicit code over clever metaprogramming
- Be careful with `eval` and code injection risks
- Consider performance implications of proxies
- Test metaprogramming behavior thoroughly
- Keep debugging in mind — dynamic code is harder to trace

# Validation Checklist

When using metaprogramming, verify:
- [ ] Metaprogramming adds clear value over explicit code
- [ ] Code is still maintainable and debuggable
- [ ] Security risks are considered (no uncontrolled eval)
- [ ] Performance is acceptable
- [ ] Behavior is well-documented
- [ ] Tests cover dynamic behavior
- [ ] Generated code is syntactically correct

# Troubleshooting

## Issue: Proxy Performance

**Symptoms**: Proxy operations are slow in hot paths

**Solution**:
- Cache proxy handlers
- Minimize trap overhead
- Use proxies only where interception is needed
- Consider direct property access for performance-critical code

## Issue: Generated Code Has Syntax Errors

**Symptoms**: Parser fails on generated code

**Solution**:
```javascript
import { parse } from '@babel/parser';

function validateCode(code) {
    try {
        parse(code, { sourceType: 'module' });
        return true;
    } catch (error) {
        console.error('Generated code error:', error.message);
        return false;
    }
}
```

## Issue: Decorator Order

**Symptoms**: Decorators not applying in expected order

**Solution**: Decorators apply bottom-to-top. Use `compose()` for explicit ordering.

# Supporting Files

- See `./_examples/basic-examples.md` for metaprogramming examples

## Related Skills

- **abstraction** - Metaprogramming creates abstractions
- **functional-paradigm** - Metaprogramming in functional style
- **data-types** - Metaprogramming can create new types
- **algorithms** - Metaprogramming can generate algorithm implementations
- **modularity** - Generate and compose modular components
- → **35-development-environment**: debugging-skills (for debugging metaprogramming)
- → **5-architecture-fundamentals**: design-patterns (many patterns use metaprogramming)

Remember: Metaprogramming is powerful but can make code hard to understand - use it judiciously and document well!
