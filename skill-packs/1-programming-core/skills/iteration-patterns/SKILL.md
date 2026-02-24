---
name: iteration-patterns
description: Use this skill when implementing efficient iteration techniques, optimizing loops, processing collections, or converting between iteration methods. This includes loop optimization, iterator patterns, collection processing, performance tuning, and choosing the right iteration approach for specific scenarios.
---

# Iteration Patterns

I'll help you implement efficient iteration techniques, optimize loops, process collections effectively, and choose the right iteration approach for your specific needs. When you invoke this skill, I can guide you through various iteration patterns and help you write performant, readable iteration code.

# Core Approach

My approach to iteration focuses on:
1. Selecting the appropriate iteration pattern for the problem
2. Optimizing loop performance and readability
3. Using modern iteration methods and patterns
4. Handling edge cases and error conditions
5. Balancing performance with code clarity

# Step-by-Step Instructions

## 1. Choose the Right Iteration Pattern

I'll help you select the best iteration approach:

**JavaScript:**
```javascript
nums.map(n => n * 2);              // Transform
nums.filter(n => n % 2 === 0);     // Select
nums.reduce((acc, n) => acc + n, 0); // Aggregate
nums.find(n => n > 10);            // First match
nums.some(n => n > 10);            // Any match?
```

**Python — comprehensions (idiomatic):**
```python
[n * 2 for n in nums]              # Transform (map)
[n for n in nums if n % 2 == 0]    # Select (filter)
sum(nums)                           # Aggregate
next((n for n in nums if n > 10), None)  # First match
any(n > 10 for n in nums)          # Any match?
```

**Rust — iterator chains (lazy, zero-cost):**
```rust
nums.iter().map(|n| n * 2).collect::<Vec<_>>();  // Transform
nums.iter().filter(|n| *n % 2 == 0).collect::<Vec<_>>(); // Select
nums.iter().sum::<i32>();            // Aggregate
nums.iter().find(|&&n| n > 10);     // First match
```

**Go — explicit loops (no built-in map/filter):**
```go
// Go uses explicit for loops for everything
var doubled []int
for _, n := range nums {
    doubled = append(doubled, n*2)
}
// With generics (Go 1.18+): use samber/lo library
import "github.com/samber/lo"
doubled := lo.Map(nums, func(n int, _ int) int { return n * 2 })
```

## 2. Optimize Loop Performance

I'll help you write efficient loops:

**JavaScript — cache + destructure:**
```javascript
const len = items.length;
for (let i = 0; i < len; i++) {
    const { active, verified } = items[i];
    if (active && verified) processItem(items[i]);
}
```

**Python — generators for memory efficiency:**
```python
# Process 10M items without loading all into memory
def process_large(filepath):
    with open(filepath) as f:
        for line in f:           # Lazy line-by-line
            yield process(line)
```

**Rust — iterators are zero-cost abstractions:**
```rust
// This compiles to the same machine code as a manual loop
items.iter()
    .filter(|i| i.active && i.verified)
    .for_each(|i| process_item(i));
```

## 3. Advanced Iteration Patterns

I'll help you implement sophisticated iteration techniques:

```javascript
// Nested iteration with early exit
function findIntersection(arr1, arr2) {
    for (let i = 0; i < arr1.length; i++) {
        for (let j = 0; j < arr2.length; j++) {
            if (arr1[i] === arr2[j]) {
                return arr1[i]; // Early exit
            }
        }
    }
    return null;
}

// Optimized with Set for O(1) lookup
function findIntersectionOptimized(arr1, arr2) {
    const set2 = new Set(arr2);
    for (const item of arr1) {
        if (set2.has(item)) {
            return item;
        }
    }
    return null;
}

// Sliding window pattern
function maxSubarraySum(arr, k) {
    if (arr.length < k) return null;
    
    let maxSum = 0;
    let windowSum = 0;
    
    // Initialize first window
    for (let i = 0; i < k; i++) {
        windowSum += arr[i];
    }
    maxSum = windowSum;
    
    // Slide window
    for (let i = k; i < arr.length; i++) {
        windowSum = windowSum - arr[i - k] + arr[i];
        maxSum = Math.max(maxSum, windowSum);
    }
    
    return maxSum;
}

// Two pointers pattern
function twoSum(arr, target) {
    let left = 0;
    let right = arr.length - 1;
    
    while (left < right) {
        const sum = arr[left] + arr[right];
        
        if (sum === target) {
            return [arr[left], arr[right]];
        } else if (sum < target) {
            left++;
        } else {
            right--;
        }
    }
    
    return null;
}
```

## 4. Iterator and Generator Patterns

I'll help you use advanced iteration features:

**JavaScript — generators:**
```javascript
function* fibonacci() {
    let [a, b] = [0, 1];
    while (true) { yield a; [a, b] = [b, a + b]; }
}
const fib10 = [...take(fibonacci(), 10)];
```

**Python — generators (first-class):**
```python
def fibonacci():
    a, b = 0, 1
    while True:
        yield a
        a, b = b, a + b

from itertools import islice
fib10 = list(islice(fibonacci(), 10))
```

**Rust — iterator trait:**
```rust
struct Fibonacci { a: u64, b: u64 }
impl Iterator for Fibonacci {
    type Item = u64;
    fn next(&mut self) -> Option<u64> {
        let val = self.a;
        (self.a, self.b) = (self.b, self.a + self.b);
        Some(val)
    }
}
let fib10: Vec<_> = Fibonacci { a: 0, b: 1 }.take(10).collect();
```

**Go — channels as generators:**
```go
func fibonacci(n int) <-chan int {
    ch := make(chan int)
    go func() {
        a, b := 0, 1
        for i := 0; i < n; i++ { ch <- a; a, b = b, a+b }
        close(ch)
    }()
    return ch
}
for num := range fibonacci(10) { fmt.Println(num) }
```

# Examples

## Example 1: Optimizing Data Processing

**User Query**: "My array processing is slow, how can I optimize it?"

**Approach**:
1. Analyze current iteration pattern
2. Identify bottlenecks (property access, method calls)
3. Apply appropriate optimizations
4. Test performance improvements

**Complete Commands:**
```bash
# Create test data
node -e "console.log(Array.from({length: 1000000}, (_, i) => ({id: i, value: Math.random()})).join('\n'))" > data.json

# Test performance
time node slow-iteration.js
time node fast-iteration.js

# Profile with Node.js
node --prof fast-iteration.js
node --prof-process isolate-*.log > analysis.txt
```

## Example 2: Processing Nested Data Structures

**User Query**: "I need to flatten a nested array efficiently"

**Approach**:
1. Choose appropriate iteration pattern
2. Handle variable nesting depth
3. Consider using generators for memory efficiency

# CLI Tools to Leverage

**Essential tools for iteration work:**
- `time` / `hyperfine` - Measure and compare iteration performance
- `perf` - System-level performance analysis

**Language-Specific Tools:**
- **JavaScript**: `benchmark` / `lodash` for iteration utilities
- **Python**: `itertools` (stdlib) / `more-itertools` / `toolz`
- **Go**: `samber/lo` for generic map/filter/reduce
- **Rust**: `itertools` crate / `rayon` for parallel iteration

# Language Patterns

See `./_examples/advanced-iteration-utilities.md` for production-ready utilities including:
- CollectionProcessor (batch, parallel processing)
- Lazy evaluation with generators (filterMap)
- Custom iteration tools (zip, chunks, take, skip)

> **Other languages?** Examples use JS/Python/Go/Rust, but all concepts apply universally. See the **Language Adaptation Guide** in `../PACK.md` for C#, Java, Kotlin, Swift, Elixir, Haskell equivalents.

# Best Practices

- Choose the clearest iteration pattern for the problem
- Consider performance for large datasets
- Use built-in methods when they match your needs
- Avoid unnecessary intermediate arrays
- Use generators for memory efficiency with large data
- Profile before optimizing
- Consider readability over micro-optimizations
- Use appropriate data structures for lookup operations

# Iteration Pattern Selection Guide

## Use for loop when:
- You need the index
- You need to break or continue early
- Performance is critical and you need optimization

## Use for...of when:
- Simple iteration is needed
- You're working with iterables
- Code clarity is important

## Use forEach when:
- You need to execute side effects
- You don't need to break or continue
- Functional style is preferred

## Use map when:
- Transforming each element
- Creating a new array
- No side effects

## Use filter when:
- Selecting elements
- Creating a subset
- Conditions are complex

## Use reduce when:
- Aggregating values
- Building complex objects
- Multiple operations in one pass

# Validation Checklist

When implementing iteration, verify:
- [ ] Chose appropriate iteration pattern
- [ ] Handled empty collections
- [ ] Considered performance implications
- [ ] No off-by-one errors
- [ ] Proper error handling
- [ ] Memory usage is reasonable
- [ ] Code is readable and maintainable

# Troubleshooting

## Issue: Slow Loop Performance

**Symptoms**: Iteration takes too long

**Solution**:
```javascript
// Cache property access
const len = array.length;

// Use Set for O(1) lookup
const lookup = new Set(array);

// Process in batches
for (let i = 0; i < array.length; i += 1000) {
    const batch = array.slice(i, i + 1000);
    processBatch(batch);
}
```

## Issue: Memory Issues with Large Arrays

**Symptoms**: Out of memory errors

**Solution**:
```javascript
// Use generators for lazy evaluation
function* processLarge(data) {
    for (const item of data) {
        yield transform(item);
    }
}

// Process in streams
for (const result of processLarge(largeArray)) {
    handleResult(result);
}
```

## Issue: Infinite Loop

**Symptoms**: Program never terminates

**Solution**:
- Add loop condition checks
- Use break conditions
- Add iteration limits for debugging
- Log iteration progress

# Supporting Files

- See `./_examples/advanced-iteration-utilities.md` for production-ready utilities
- See `./_examples/basic-examples.md` for fundamental patterns

## Related Skills

- **algorithms** - Many algorithms use iteration
- **recursion** - Alternative to iteration
- **control-flow** - Iteration is control flow
- **data-structures** - Iterate over data structures
- **functional-paradigm** - Functional iteration patterns

- → **4-performance-optimization**: performance-analysis (for optimizing iterations)
- → **35-development-environment**: debugging-skills (for debugging loops)

Remember: Choose the iteration pattern that makes your code most readable and maintainable, then optimize if needed!
