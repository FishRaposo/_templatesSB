# Modularity Examples

## ES Modules / Python Packages

**JavaScript (ES Modules):**
```javascript
// math.js
export const PI = 3.14159;
export function add(a, b) { return a + b; }
export function multiply(a, b) { return a * b; }

// main.js
import { PI, add, multiply } from './math.js';
console.log(add(5, 3)); // 8
```

**Python:**
```python
# math_utils.py
PI = 3.14159
def add(a, b): return a + b
def multiply(a, b): return a * b

# main.py
from math_utils import PI, add, multiply
print(add(5, 3))  # 8
```

## Encapsulation

**JavaScript:**
```javascript
// user-service.js
const users = [];  // private to module
export function addUser(user) { users.push(user); }
export function getUser(id) { return users.find(u => u.id === id); }
export function getAllUsers() { return [...users]; }
```

**Python:**
```python
# user_service.py
_users = []  # convention: underscore = private

def add_user(user): _users.append(user)
def get_user(id): return next((u for u in _users if u["id"] == id), None)
def get_all_users(): return list(_users)
```

## When to Use
- Modularize this large code file
- Create reusable components
- Organize code into logical modules