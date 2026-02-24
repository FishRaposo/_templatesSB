# Data Types Examples

## Type Checking

**JavaScript:**
```javascript
function getType(value) {
    if (value === null) return 'null';
    if (Array.isArray(value)) return 'array';
    return typeof value;
}

function toNumber(value, defaultValue = 0) {
    const num = Number(value);
    return isNaN(num) ? defaultValue : num;
}
```

**Python:**
```python
def get_type(value):
    return type(value).__name__  # 'int', 'str', 'list', 'NoneType', etc.

def to_number(value, default=0):
    try:
        return float(value)
    except (ValueError, TypeError):
        return default
```

## Custom Types (Value Objects)

**JavaScript:**
```javascript
class Email {
    constructor(value) {
        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value))
            throw new Error('Invalid email');
        this.value = value.toLowerCase();
    }
    toString() { return this.value; }
}
```

**Python:**
```python
import re
from dataclasses import dataclass

@dataclass(frozen=True)
class Email:
    value: str
    def __post_init__(self):
        if not re.match(r'^[^\s@]+@[^\s@]+\.[^\s@]+$', self.value):
            raise ValueError('Invalid email')
        object.__setattr__(self, 'value', self.value.lower())
```

## Type Guards / Dispatch

**JavaScript:**
```javascript
function processValue(value) {
    if (typeof value === 'string') return value.toUpperCase();
    if (typeof value === 'number') return value.toFixed(2);
    return String(value);
}
```

**Python:**
```python
from functools import singledispatch

@singledispatch
def process_value(value):
    return str(value)

@process_value.register(str)
def _(value): return value.upper()

@process_value.register(int)
@process_value.register(float)
def _(value): return f"{value:.2f}"
```

## When to Use
- Choose the right data type for this value
- Convert between types safely
- Validate input types