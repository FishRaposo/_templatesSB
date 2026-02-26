---
name: complexity-analysis
description: Use this skill when analyzing algorithm efficiency, comparing different approaches, or optimizing code performance. This includes calculating time and space complexity, identifying bottlenecks, Big O notation analysis, amortized analysis, and performance optimization strategies.
---

# Complexity Analysis

I'll help you analyze algorithm efficiency, calculate time and space complexity, identify performance bottlenecks, and optimize code for better performance. When you invoke this skill, I can provide comprehensive analysis of your code's efficiency.

# Core Approach

My approach focuses on:
1. Analyzing algorithmic complexity using Big O notation
2. Identifying performance bottlenecks in code
3. Comparing different algorithmic approaches
4. Providing optimization strategies and techniques

# Step-by-Step Instructions

## 1. Code Analysis

First, I'll analyze your code structure:

- Identify loops and nested loops
- Analyze recursive calls and base cases
- Count basic operations
- Identify data structure operations

**CLI Tools for Analysis:**
- `grep -rn "for\|while" src/` - Find all loops
- `grep -rn "def \|func \|fn " src/` - Find function definitions
- `wc -l src/**` - Count lines of code

## 2. Time Complexity Calculation

I'll calculate time complexity:

**JavaScript:**
```javascript
// O(n) - single loop
for (let i = 0; i < n; i++) { /* ... */ }
// O(n²) - nested loops
for (let i = 0; i < n; i++)
    for (let j = 0; j < n; j++) { /* ... */ }
// O(log n) - halving
for (let i = 1; i < n; i *= 2) { /* ... */ }
```

**Python:**
```python
# O(n) - single loop
for i in range(n): ...
# O(n²) - nested loops
for i in range(n):
    for j in range(n): ...
# O(log n) - halving
i = 1
while i < n:
    i *= 2
```

## 3. Space Complexity Analysis

I'll analyze memory usage:

**JavaScript:**
```javascript
const x = 42;                                    // O(1)
const arr = new Array(n);                         // O(n)
const matrix = Array(n).fill().map(() => Array(n)); // O(n²)
```

**Python:**
```python
import sys
x = 42                        # O(1)
arr = [0] * n                 # O(n)
matrix = [[0]*n for _ in range(n)]  # O(n²)
print(sys.getsizeof(arr))     # Check actual memory
```

**Rust (zero-cost abstractions):**
```rust
let v: Vec<i32> = Vec::with_capacity(n);  // O(n), pre-allocated
let matrix: Vec<Vec<i32>> = vec![vec![0; n]; n]; // O(n²)
// Rust's ownership model prevents hidden memory allocations
```

## 4. Performance Profiling

I'll help profile your code:

**JavaScript:**
```javascript
const start = performance.now();
expensiveOperation();
console.log(`${performance.now() - start}ms`);
```

**Python:**
```python
import time
start = time.perf_counter()
expensive_operation()
print(f"{time.perf_counter() - start:.3f}s")
```

**Go:**
```go
start := time.Now()
expensiveOperation()
fmt.Printf("%v\n", time.Since(start))
```

# Examples

## Example 1: Analyzing a Sorting Algorithm

**User Query**: "What's the time complexity of this bubble sort implementation?"

**Approach**:
1. Identify nested loops
2. Count operations in worst case
3. Determine Big O notation
4. Compare with other sorting algorithms

**Complete Commands:**
```bash
# Create test data
node -e "console.log(Array.from({length: 1000}, () => Math.random()).join(','))" > test.csv

# Time the algorithm
time node bubble-sort.js test.csv

# Profile with different input sizes
for n in 100 1000 10000; do
    echo "Testing with n=$n"
    time node bubble-sort.js <(head -n $n test.csv)
done
```

## Example 2: Optimizing a Database Query

**User Query**: "My database query is slow, how can I analyze and optimize it?"

**Approach**:
1. Analyze query execution plan
2. Identify missing indexes
3. Calculate complexity of joins
4. Suggest optimization strategies

# CLI Tools to Leverage

**Essential tools for complexity analysis:**
- `time` / `hyperfine` - Measure and compare execution time
- `perf` - Linux performance analyzer
- `valgrind` - Memory profiling (C/C++/Rust)
- `git bisect` - Find performance regressions

**Language-Specific Tools:**
- **JavaScript**: `clinic` / `0x` (flame graphs) / `node --prof`
- **Python**: `cProfile` / `line_profiler` / `memory_profiler` / `py-spy`
- **Go**: `go tool pprof` / `go test -bench` (built-in)
- **Rust**: `cargo flamegraph` / `criterion` crate

# Language Patterns

**Empirical Complexity Testing — JavaScript:**
```javascript
function plotComplexity(sizes, testFn) {
    for (const n of sizes) {
        const start = performance.now();
        for (let i = 0; i < 100; i++) testFn(n);
        console.log(`n=${n}, avg=${((performance.now() - start) / 100).toFixed(2)}ms`);
    }
}
plotComplexity([100, 1000, 10000], n => {
    const arr = Array.from({length: n}, (_, i) => i);
    arr.sort(() => Math.random() - 0.5);
});
```

**Empirical Complexity Testing — Python:**
```python
import timeit

def plot_complexity(sizes, test_fn):
    for n in sizes:
        t = timeit.timeit(lambda: test_fn(n), number=100)
        print(f"n={n}, avg={t/100*1000:.2f}ms")

plot_complexity([100, 1000, 10000], lambda n: sorted(range(n), reverse=True))
```

**Benchmarking — Go:**
```go
func BenchmarkSort(b *testing.B) {
    for _, size := range []int{100, 1000, 10000} {
        b.Run(fmt.Sprintf("size=%d", size), func(b *testing.B) {
            for i := 0; i < b.N; i++ {
                data := rand.Perm(size)
                sort.Ints(data)
            }
        })
    }
}
```

> **Other languages?** Examples use JS/Python/Go/Rust, but all concepts apply universally. See the **Language Adaptation Guide** in `../PACK.md` for C#, Java, Kotlin, Swift, Elixir, Haskell equivalents.

# Best Practices

- Always consider worst-case, best-case, and average-case complexity
- Focus on the dominant term in complexity expressions
- Use amortized analysis for data structures with expensive operations
- Consider both time and space complexity
- Profile real code, not just theoretical analysis
- Use appropriate data structures for your complexity needs
- Remember that constants matter for small inputs

# Validation Checklist

When analyzing complexity, verify:
- [ ] Identified all loops and recursive calls
- [ ] Calculated both time and space complexity
- [ ] Considered best, average, and worst cases
- [ ] Verified with actual performance measurements
- [ ] Compared alternative approaches
- [ ] Provided optimization recommendations

# Troubleshooting

## Issue: Theoretical Analysis Doesn't Match Reality

**Symptoms**: Code should be O(n) but performs like O(n²)

**Investigation**:
```bash
# Profile with detailed timing
node --prof slow-code.js
node --prof-process isolate-*.log > analysis.txt

# Check for hidden loops
grep -r "for\|while\|map\|filter\|reduce" src/
```

**Solution**:
- Look for hidden O(n) operations inside loops
- Check library function complexities
- Consider cache effects and constant factors
- Profile with realistic data

## Issue: Memory Usage Higher Than Expected

**Symptoms**: Space complexity seems correct but memory usage is high

**Investigation**:
```bash
# Monitor memory in detail
node --trace-gc --trace-mem memory-test.js

# Check for memory leaks
node --inspect heap-analysis.js
```

**Solution**:
- Account for JavaScript object overhead
- Check for memory leaks in closures
- Consider garbage collection pauses
- Use more memory-efficient data structures

# Common Complexity Patterns

**O(1) - Constant Time:**
- Array access by index
- Hash table lookup (average case)
- Stack push/pop

**O(log n) - Logarithmic:**
- Binary search
- Balanced tree operations
- Divide and conquer algorithms

**O(n) - Linear:**
- Single loop through array
- Linked list traversal
- Hash table collision resolution

**O(n log n) - Linearithmic:**
- Efficient sorting algorithms (merge sort, quick sort)
- Many divide and conquer algorithms

**O(n²) - Quadratic:**
- Nested loops
- Bubble sort, insertion sort
- Naive string matching

**O(2^n) - Exponential:**
- Recursive Fibonacci
- Power set generation
- Brute force password cracking

# Supporting Files

- See `./_examples/basic-examples.md` for complexity analysis examples

## Related Skills

- **algorithms** - Analyze algorithm complexity
- **data-structures** - Analyze data structure efficiency
- **problem-solving** - Consider complexity in solutions
- **iteration-patterns** - Optimize loop complexity
- **recursion** - Analyze recursive complexity
- → **4-performance-optimization**: performance-analysis (for detailed analysis)
- → **35-development-environment**: debugging-skills (for performance debugging)

Remember: Premature optimization is the root of all evil, but understanding complexity is essential for good design!
