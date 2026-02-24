# Functional Programming Examples

## Pure Functions

**JavaScript:**
```javascript
// Pure (no side effects, same input → same output)
function add(a, b) { return a + b; }

function updateUser(user, updates) {
    return { ...user, ...updates, updatedAt: new Date().toISOString() };
}
```

**Python:**
```python
def add(a, b): return a + b

def update_user(user, updates):
    return {**user, **updates, "updated_at": datetime.now().isoformat()}
```

## Higher-Order Functions

**JavaScript:**
```javascript
function createMultiplier(factor) {
    return (number) => number * factor;
}
const double = createMultiplier(2);
const triple = createMultiplier(3);
console.log(double(5)); // 10
```

**Python:**
```python
def create_multiplier(factor):
    return lambda n: n * factor

double = create_multiplier(2)
triple = create_multiplier(3)
print(double(5))  # 10
```

## Function Composition

**JavaScript:**
```javascript
const compose = (f, g) => (x) => f(g(x));
const addOneThenDouble = compose(x => x * 2, x => x + 1);
console.log(addOneThenDouble(3)); // 8
```

**Python:**
```python
from functools import reduce

def compose(*fns):
    return reduce(lambda f, g: lambda x: f(g(x)), fns)

add_one_then_double = compose(lambda x: x * 2, lambda x: x + 1)
print(add_one_then_double(3))  # 8
```

## When to Use
- Write this code using functional patterns
- Make this function pure
- Compose functions for data transformation