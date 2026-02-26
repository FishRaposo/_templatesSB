---
name: recursion
description: Use this skill when solving problems using recursive approaches, implementing divide-and-conquer algorithms, working with tree/graph structures, or converting between recursive and iterative solutions. This includes recursive problem-solving, tail recursion, memoization, recursion optimization, and understanding recursion depth and stack limits.
---

# Recursion

I'll help you solve problems using recursive approaches, implement divide-and-conquer algorithms, work with tree and graph structures recursively, and optimize recursive solutions. When you invoke this skill, I can guide you through designing efficient recursive algorithms and understanding when and how to use recursion effectively.

# Core Approach

My approach to recursion focuses on:
1. Identifying problems suitable for recursive solutions
2. Designing recursive algorithms with proper base cases
3. Optimizing recursion with memoization and tail recursion
4. Converting between recursive and iterative solutions
5. Managing stack depth and performance considerations

# Step-by-Step Instructions

## 1. Identify Recursive Patterns

I'll help you recognize when recursion is appropriate:

**JavaScript — tree traversal:**
```javascript
function traverse(node) {
    if (!node) return;
    console.log(node.value);
    traverse(node.left);
    traverse(node.right);
}
```

**Python — tree traversal:**
```python
def traverse(node):
    if not node: return
    print(node.value)
    traverse(node.left)
    traverse(node.right)
```

**Rust — tree traversal (with ownership):**
```rust
fn traverse(node: &Option<Box<TreeNode>>) {
    if let Some(n) = node {
        println!("{}", n.value);
        traverse(&n.left);
        traverse(&n.right);
    }
}
```

## 2. Design Recursive Solutions

I'll help you structure recursive algorithms:

**JavaScript:**
```javascript
const factorial = n => n <= 1 ? 1 : n * factorial(n - 1);
const fibonacci = n => n <= 1 ? n : fibonacci(n - 1) + fibonacci(n - 2);
```

**Python:**
```python
def factorial(n): return 1 if n <= 1 else n * factorial(n - 1)
def fibonacci(n): return n if n <= 1 else fibonacci(n - 1) + fibonacci(n - 2)
```

**Go:**
```go
func factorial(n int) int {
    if n <= 1 { return 1 }
    return n * factorial(n-1)
}
```

**Rust:**
```rust
fn factorial(n: u64) -> u64 {
    if n <= 1 { 1 } else { n * factorial(n - 1) }
}
```

## 3. Optimize Recursive Solutions

I'll help you optimize recursive algorithms:

**JavaScript — memoization:**
```javascript
const memo = new Map();
function fib(n) {
    if (memo.has(n)) return memo.get(n);
    if (n <= 1) return n;
    const result = fib(n - 1) + fib(n - 2);
    memo.set(n, result);
    return result;
}
```

**Python — built-in memoization:**
```python
from functools import lru_cache

@lru_cache(maxsize=None)
def fib(n): return n if n <= 1 else fib(n - 1) + fib(n - 2)
```

**Tail recursion (languages that optimize it):**
```python
# Python doesn't optimize tail calls, but the pattern is universal
def factorial_tail(n, acc=1):
    if n <= 1: return acc
    return factorial_tail(n - 1, n * acc)
```
```rust
// Rust: use iterative for guaranteed no stack overflow
fn factorial(n: u64) -> u64 { (1..=n).product() }
```

## 4. Handle Complex Recursive Scenarios

I'll help with advanced recursive patterns:

```javascript
// Backtracking template
function backtrack(solution, partial = []) {
    // Check if solution is complete
    if (isComplete(partial)) {
        solutions.push([...partial]);
        return;
    }
    
    // Try all possible next steps
    for (const option of getOptions(partial)) {
        if (isValid(option, partial)) {
            partial.push(option);
            backtrack(solution, partial);
            partial.pop(); // Backtrack
        }
    }
}

// Example: Generate all permutations
function permutations(arr) {
    const results = [];
    
    function backtrack(current, remaining) {
        if (remaining.length === 0) {
            results.push([...current]);
            return;
        }
        
        for (let i = 0; i < remaining.length; i++) {
            current.push(remaining[i]);
            const newRemaining = [
                ...remaining.slice(0, i),
                ...remaining.slice(i + 1)
            ];
            backtrack(current, newRemaining);
            current.pop();
        }
    }
    
    backtrack([], arr);
    return results;
}

// Tree recursion with accumulation
function collectPaths(node, path = [], paths = []) {
    if (!node) return paths;
    
    path.push(node.value);
    
    // Leaf node - save path
    if (!node.left && !node.right) {
        paths.push([...path]);
    } else {
        collectPaths(node.left, path, paths);
        collectPaths(node.right, path, paths);
    }
    
    path.pop(); // Backtrack
    return paths;
}
```

# Examples

## Example 1: Solving the Tower of Hanoi

**User Query**: "Implement Tower of Hanoi solution using recursion"

**Approach**:
1. Identify base case (single disk)
2. Recursive step: move n-1 disks, move largest, move n-1 disks
3. Track source, destination, auxiliary pegs

**Complete Commands:**
```bash
# Test with different disk counts
node hanoi.js 3
node hanoi.js 4

# Measure recursion depth
node --stack-size=10000 hanoi.js 20
```

## Example 2: Optimizing Recursive Tree Operations

**User Query**: "My recursive tree traversal is slow for deep trees"

**Approach**:
1. Add memoization for repeated subproblems
2. Convert to tail recursion where possible
3. Consider iterative approach for very deep trees

# CLI Tools to Leverage

**Essential tools for recursion work:**
- `ulimit -s` - Check/set system stack limits
- `time` / `hyperfine` - Measure execution time

**Language-Specific Tools:**
- **JavaScript**: `node --stack-size=10000` to increase stack
- **Python**: `sys.setrecursionlimit(10000)` (default 1000)
- **Go**: Goroutines have growable stacks (no fixed limit)
- **Rust**: Stack size configurable via `std::thread::Builder`

# Language Patterns

**Tree max depth — JavaScript:**
```javascript
function maxDepth(node) {
    if (!node) return 0;
    return Math.max(maxDepth(node.left), maxDepth(node.right)) + 1;
}
```

**Tree max depth — Python:**
```python
def max_depth(node):
    if not node: return 0
    return max(max_depth(node.left), max_depth(node.right)) + 1
```

**Recursive generators — JavaScript:**
```javascript
function* traverse(node) {
    if (!node) return;
    yield node.value;
    yield* traverse(node.left);
    yield* traverse(node.right);
}
```

**Recursive generators — Python:**
```python
def traverse(node):
    if not node: return
    yield node.value
    yield from traverse(node.left)
    yield from traverse(node.right)
```

> **Other languages?** Examples use JS/Python/Go/Rust, but all concepts apply universally. See the **Language Adaptation Guide** in `../PACK.md` for C#, Java, Kotlin, Swift, Elixir, Haskell equivalents.

# Best Practices

- Always have a clear base case to prevent infinite recursion
- Consider stack depth for large inputs
- Use memoization for overlapping subproblems
- Prefer tail recursion when possible
- Test with edge cases (empty, single item)
- Consider iterative alternatives for performance-critical code
- Document the recursive logic clearly
- Use recursion for clarity, not just for the sake of it

# Common Recursive Patterns

## 1. Linear Recursion
- Single recursive call
- Example: Factorial, sum of array

## 2. Binary Recursion
- Two recursive calls
- Example: Fibonacci, tree traversal

## 3. N-ary Recursion
- Multiple recursive calls
- Example: N-ary tree traversal

## 4. Mutual Recursion
- Functions call each other
- Example: Even/odd checking

## 5. Nested Recursion
- Recursive call as parameter
- Example: Ackermann function

# Validation Checklist

When implementing recursive solutions, verify:
- [ ] Base case is clearly defined and reachable
- [ ] Recursive calls progress toward base case
- [ ] Stack depth is reasonable for input size
- [ ] No duplicate work (consider memoization)
- [ ] Edge cases are handled
- [ ] Performance is acceptable
- [ ] Alternative iterative solution considered

# Troubleshooting

## Issue: Stack Overflow

**Symptoms**: "Maximum call stack size exceeded"

**Solution**:
```bash
node --stack-size=10000 script.js  # JS: increase stack
```
```python
import sys; sys.setrecursionlimit(10000)  # Python: increase limit
```

Or convert to iterative:
```javascript
function factorial(n) { let r = 1; while (n > 1) r *= n--; return r; }
```
```python
import math; math.factorial(n)  # Python stdlib handles it
```

## Issue: Exponential Time Complexity

**Symptoms**: Very slow for larger inputs

**Solution**:
```javascript
// JS: bottom-up DP
function fibDP(n) { const dp = [0, 1]; for (let i = 2; i <= n; i++) dp[i] = dp[i-1] + dp[i-2]; return dp[n]; }
```
```python
# Python: built-in memoization
from functools import lru_cache
@lru_cache(maxsize=None)
def fib(n): return n if n <= 1 else fib(n-1) + fib(n-2)
```

## Issue: Incorrect Base Case

**Symptoms**: Wrong results or infinite recursion

**Solution**:
- Carefully consider smallest valid input
- Test with base case inputs
- Ensure recursive calls move toward base case

# Supporting Files

- See `./_examples/basic-examples.md` for common recursive patterns

## Related Skills

- **iteration-patterns** - Alternative approach to recursion
- **algorithms** - Many algorithms use recursion
- **data-structures** - Trees and graphs naturally use recursion
- **problem-solving** - Recursive problem-solving strategies
- **functional-paradigm** - Functional languages favor recursion
- **control-flow** - Managing recursion flow and termination
- → **35-development-environment**: debugging-skills (for debugging recursion)
- → **4-performance-optimization**: performance-analysis (for analyzing recursive performance)

Remember: Recursion should make code clearer, not more complex - use it when it naturally fits the problem!
