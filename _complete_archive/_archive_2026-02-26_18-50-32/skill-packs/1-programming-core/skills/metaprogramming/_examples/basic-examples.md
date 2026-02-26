# Metaprogramming Examples

## Proxy / Attribute Interception

**JavaScript:**
```javascript
function createLoggingProxy(target) {
    return new Proxy(target, {
        get(obj, prop) { console.log(`Get: ${prop}`); return obj[prop]; },
        set(obj, prop, val) { console.log(`Set: ${prop}=${val}`); obj[prop] = val; return true; }
    });
}
const user = createLoggingProxy({ name: 'John' });
user.name; // Logs: Get: name
```

**Python:**
```python
class LoggingProxy:
    def __init__(self, target):
        object.__setattr__(self, '_target', target)
    def __getattr__(self, name):
        print(f"Get: {name}")
        return getattr(self._target, name)
    def __setattr__(self, name, value):
        print(f"Set: {name}={value}")
        setattr(self._target, name, value)
```

## Reflection / Introspection

**JavaScript:**
```javascript
function getMethodNames(obj) {
    return Object.getOwnPropertyNames(Object.getPrototypeOf(obj))
        .filter(name => typeof obj[name] === 'function' && name !== 'constructor');
}
```

**Python:**
```python
import inspect

def get_method_names(obj):
    return [name for name, _ in inspect.getmembers(obj, predicate=inspect.ismethod)]
```

## Decorator Pattern

**JavaScript:**
```javascript
function timed(fn) {
    return function(...args) {
        const start = performance.now();
        const result = fn.apply(this, args);
        console.log(`${fn.name} took ${performance.now() - start}ms`);
        return result;
    };
}
```

**Python:**
```python
import time
from functools import wraps

def timed(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        start = time.perf_counter()
        result = fn(*args, **kwargs)
        print(f"{fn.__name__} took {time.perf_counter() - start:.4f}s")
        return result
    return wrapper

@timed
def process(data):
    return [x * 2 for x in data]
```

## When to Use
- Intercept property access with proxies
- Inspect objects at runtime
- Add behavior to existing functions