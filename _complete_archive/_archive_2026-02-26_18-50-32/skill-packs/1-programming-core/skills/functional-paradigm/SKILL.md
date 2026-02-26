---
name: functional-paradigm
description: Use this skill when writing clean, predictable functional code, applying functional programming concepts, or refactoring imperative code to functional style. This includes pure functions, immutability, higher-order functions, function composition, monads, functors, and applying functional programming patterns.
---

# Functional Paradigm

I'll help you write clean, predictable functional code, apply functional programming concepts effectively, and refactor imperative code to functional style. When you invoke this skill, I can guide you through functional programming principles, patterns, and best practices.

# Core Approach

My approach to functional programming focuses on:
1. Writing pure functions without side effects
2. Embracing immutability for predictable code
3. Using higher-order functions for abstraction
4. Composing functions for complex operations
5. Applying functional patterns for common problems

# Step-by-Step Instructions

## 1. Write Pure Functions

I'll help you create pure, predictable functions:

**JavaScript:**
```javascript
// Pure: only depends on inputs, no side effects
const add = (a, b) => a + b;
const updateUser = (user, updates) => ({ ...user, ...updates });
```

**Python:**
```python
# Pure functions are natural in Python
def add(a, b): return a + b
def update_user(user, updates): return {**user, **updates}
```

**Rust (pure by default — ownership enforces no side effects):**
```rust
fn add(a: i32, b: i32) -> i32 { a + b }  // No mutation possible without &mut
```

## 2. Embrace Immutability

I'll help you work with immutable data:

**JavaScript — spread operator:**
```javascript
const addItem = (cart, item) => ({
    ...cart,
    items: [...cart.items, item],
    total: cart.total + item.price
});
```

**Python — frozen dataclasses / tuples:**
```python
from dataclasses import dataclass, replace

@dataclass(frozen=True)
class Cart:
    items: tuple
    total: float

def add_item(cart, item):
    return replace(cart, items=(*cart.items, item), total=cart.total + item.price)
```

**Rust (immutable by default):**
```rust
let v = vec![1, 2, 3];
let v2: Vec<_> = v.iter().chain(&[4]).copied().collect(); // New vec, v unchanged
```

## 3. Use Higher-Order Functions

I'll help you create and use higher-order functions:

**JavaScript:**
```javascript
const createMultiplier = factor => number => number * factor;
const double = createMultiplier(2);
const withLogging = fn => (...args) => {
    console.log(`Calling with:`, args);
    return fn(...args);
};
```

**Python — closures + functools:**
```python
from functools import partial, reduce

def create_multiplier(factor):
    return lambda n: n * factor

double = create_multiplier(2)
add5 = partial(lambda a, b: a + b, 5)  # Partial application
```

**Rust — closures:**
```rust
let double = |x| x * 2;
let add = |a, b| a + b;
let nums: Vec<_> = (1..=5).map(|x| x * 2).collect(); // [2, 4, 6, 8, 10]
```

## 4. Compose Functions

I'll help you create function compositions:

**JavaScript:**
```javascript
const pipe = (...fns) => x => fns.reduce((acc, fn) => fn(acc), x);
const processUser = pipe(
    user => ({ ...user, name: user.name.trim() }),
    user => ({ ...user, email: user.email.toLowerCase() }),
);
```

**Python — functools.reduce or toolz:**
```python
from functools import reduce

def pipe(*fns):
    return lambda x: reduce(lambda acc, fn: fn(acc), fns, x)

process_user = pipe(
    lambda u: {**u, 'name': u['name'].strip()},
    lambda u: {**u, 'email': u['email'].lower()},
)
```

**Rust — iterator chaining (built-in composition):**
```rust
let result: Vec<String> = users.iter()
    .filter(|u| u.active)
    .map(|u| u.name.trim().to_lowercase())
    .collect();
// Rust iterators are lazy and compose naturally
```

# Examples

## Example 1: Refactoring to Functional Style

**User Query**: "Convert this imperative code to functional style"

**Before (Imperative JS):**
```javascript
function processUsers(users) {
    const result = [];
    for (let i = 0; i < users.length; i++) {
        if (users[i].active) result.push({ ...users[i], processed: true });
    }
    return result;
}
```

**After (Functional JS):**
```javascript
const processUsers = users =>
    users.filter(u => u.active).map(u => ({ ...u, processed: true }));
```

**Python equivalent:**
```python
process_users = lambda users: [
    {**u, 'processed': True} for u in users if u['active']
]
```

## Example 2: Creating a Functional Data Pipeline

**User Query**: "Create a data processing pipeline using functional composition"

**Complete Commands:**
```bash
# Test the functional pipeline
echo '[{"name": "John", "age": 25}, {"name": "Jane", "age": 30}]' | node functional-pipeline.js

# Compare with imperative version
time node imperative-version.js
time node functional-version.js
```

# CLI Tools to Leverage

**Language-Specific FP Libraries:**
- **JavaScript**: `ramda` / `lodash-fp` / `sanctuary` / `fp-ts`
- **Python**: `toolz` / `fn.py` / `returns` (monads)
- **Rust**: Built-in iterators + `itertools` crate
- **Go**: `lo` (samber/lo) for generic functional utilities

# Language Patterns

See `./_examples/functional-data-structures.md` for advanced patterns including:
- Immutable List implementation
- Maybe monad for null handling
- Either monad for error handling
- Functional utilities (compose, pipe, curry, partial, memoize)

> **Other languages?** Examples use JS/Python/Go/Rust, but all concepts apply universally. See the **Language Adaptation Guide** in `../PACK.md` for C#, Java, Kotlin, Swift, Elixir, Haskell equivalents.

# Best Practices

- Write small, pure functions that do one thing
- Avoid side effects and mutations
- Use function composition over inheritance
- Prefer point-free style when it improves readability
- Handle errors with monads (Maybe, Either)
- Use currying for creating specialized functions
- Test functions easily with pure inputs/outputs
- Document function contracts and types

# Functional Programming Concepts

## 1. Pure Functions
- No side effects
- Same input always produces same output
- Easy to test and reason about

## 2. Immutability
- Data never changes after creation
- Create new data instead of modifying
- Prevents unexpected mutations

## 3. Higher-Order Functions
- Functions that take or return functions
- Enable abstraction and reuse
- Examples: map, filter, reduce

## 4. Function Composition
- Combine simple functions into complex ones
- Build pipelines for data transformation
- Point-free style when appropriate

## 5. Functors and Monads
- Container types for values
- Handle null/errors functionally
- Examples: Maybe, Either, Promise

# Validation Checklist

When writing functional code, verify:
- [ ] Functions are pure (no side effects)
- [ ] Data is immutable
- [ ] Functions are small and focused
- [ ] Composition is clear and readable
- [ ] Error handling is functional
- [ ] Code is testable
- [ ] Types are consistent

# Troubleshooting

## Issue: Performance with Immutable Updates

**Symptoms**: Creating many objects is slow

**Solution**:
```javascript
// Use immutable libraries for better performance
import { Map, List } from 'immutable';

const data = Map({ users: List([]) });
const updated = data.set('users', data.get('users').push(newUser));

// Or use structural sharing
const updateImmutable = (obj, path, value) => {
    const [head, ...tail] = path;
    if (tail.length === 0) {
        return { ...obj, [head]: value };
    }
    return {
        ...obj,
        [head]: updateImmutable(obj[head] || {}, tail, value)
    };
};
```

## Issue: Complex Function Composition

**Symptoms**: Composed functions are hard to read

**Solution**:
```javascript
// Add intermediate variables
const processedData = pipe(
    data => validate(data),
    validated => transform(validated),
    transformed => filter(transformed),
    filtered => sort(filtered)
);

// Or name compositions
const validateAndTransform = pipe(validate, transform);
const filterAndSort = pipe(filter, sort);
const process = pipe(validateAndTransform, filterAndSort);
```

## Issue: Debugging Functional Code

**Symptoms**: Hard to trace execution flow

**Solution**:
```javascript
// Add trace function
const trace = label => value => {
    console.log(`${label}:`, value);
    return value;
};

// Insert in pipeline
const result = pipe(
    data,
    trace('After validation'),
    transform,
    trace('After transform'),
    filter
)(input);
```

# Supporting Files

- See `./_examples/functional-data-structures.md` for advanced FP patterns
- See `./_examples/basic-examples.md` for fundamental usage

## Related Skills

- **abstraction** - Functional programming relies heavily on abstraction
- **modularity** - Pure functions are naturally modular
- **data-types** - Type safety in functional programming
- **algorithms** - Functional algorithms and patterns
- **recursion** - Preferred over loops in FP
- **iteration-patterns** - Alternative approach to functional iteration
- → **35-development-environment**: debugging-skills (for debugging functional code)
- → **2-code-quality**: code-refactoring (for refactoring to functional style)

Remember: Functional programming is about writing predictable, testable code - focus on purity and immutability!
