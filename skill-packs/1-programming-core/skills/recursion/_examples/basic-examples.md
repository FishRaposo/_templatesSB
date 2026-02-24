# Recursion Examples

## Factorial

**JavaScript:**
```javascript
function factorial(n) {
    if (n <= 1) return 1;
    return n * factorial(n - 1);
}
console.log(factorial(5)); // 120
```

**Python:**
```python
def factorial(n):
    if n <= 1: return 1
    return n * factorial(n - 1)

print(factorial(5))  # 120
```

## Fibonacci (with Memoization)

**JavaScript:**
```javascript
function fibonacci(n, memo = {}) {
    if (n in memo) return memo[n];
    if (n <= 1) return n;
    memo[n] = fibonacci(n - 1, memo) + fibonacci(n - 2, memo);
    return memo[n];
}
console.log(fibonacci(10)); // 55
```

**Python:**
```python
from functools import lru_cache

@lru_cache(maxsize=None)
def fibonacci(n):
    if n <= 1: return n
    return fibonacci(n - 1) + fibonacci(n - 2)

print(fibonacci(10))  # 55
```

## Tree Traversal

**JavaScript:**
```javascript
function traverse(node) {
    if (!node) return;
    console.log(node.value);
    traverse(node.left);
    traverse(node.right);
}
```

**Python:**
```python
def traverse(node):
    if not node: return
    print(node.value)
    traverse(node.left)
    traverse(node.right)

# Generator variant (lazy):
def traverse_gen(node):
    if not node: return
    yield node.value
    yield from traverse_gen(node.left)
    yield from traverse_gen(node.right)
```

## When to Use
- Implement this recursively for cleaner code
- Convert this iterative solution to recursion
- Design a recursive algorithm for tree structures