---
name: algorithms
description: Use this skill when designing, analyzing, implementing, or optimizing algorithms for any programming problem. This includes selecting appropriate algorithms, understanding their trade-offs, implementing them efficiently, and optimizing for specific constraints.
---

# Algorithms

I'll help you design, analyze, implement, and optimize algorithms for any programming problem. When you invoke this skill, I can guide you through the entire algorithm development process.

# Core Approach

My approach focuses on:
1. Understanding the problem constraints and requirements
2. Selecting the most suitable algorithmic paradigm
3. Implementing clean, efficient solutions
4. Analyzing and optimizing performance

# Step-by-Step Instructions

## 1. Problem Analysis

First, I'll help you thoroughly understand the problem:

- Identify input/output formats and constraints
- Determine edge cases and boundary conditions
- Analyze time and space complexity requirements
- Consider any special properties of the data

**CLI Tools for Analysis:**
- `wc -l` - Count lines to understand input size
- `head -n 10` - Preview first 10 lines of input
- `sort | uniq` - Identify unique values in data

## 2. Algorithm Selection

Based on the problem characteristics, I'll recommend the best approach:

- **Sorting algorithms** for ordering problems
- **Search algorithms** for finding elements
- **Graph algorithms** for network/relationship problems
- **Dynamic programming** for optimization with overlapping subproblems
- **Greedy algorithms** for optimization with local optimal choices
- **Divide and conquer** for problems that can be broken down

## 3. Implementation

I'll help you implement the algorithm with best practices:

**JavaScript:**
```javascript
function quickSort(arr) {
    if (arr.length <= 1) return arr;
    const pivot = arr[Math.floor(arr.length / 2)];
    const left = arr.filter(x => x < pivot);
    const middle = arr.filter(x => x === pivot);
    const right = arr.filter(x => x > pivot);
    return [...quickSort(left), ...middle, ...quickSort(right)];
}
```

**Python:**
```python
def quick_sort(arr):
    if len(arr) <= 1:
        return arr
    pivot = arr[len(arr) // 2]
    left = [x for x in arr if x < pivot]
    middle = [x for x in arr if x == pivot]
    right = [x for x in arr if x > pivot]
    return quick_sort(left) + middle + quick_sort(right)
```

**Go:**
```go
func quickSort(arr []int) []int {
    if len(arr) <= 1 { return arr }
    pivot := arr[len(arr)/2]
    var left, middle, right []int
    for _, v := range arr {
        switch {
        case v < pivot:  left = append(left, v)
        case v == pivot: middle = append(middle, v)
        default:         right = append(right, v)
        }
    }
    return append(append(quickSort(left), middle...), quickSort(right)...)
}
```

## 4. Optimization

I'll help optimize your algorithm:

- Profile with time measurements
- Identify bottlenecks using profiling tools
- Apply memoization for repeated calculations
- Use appropriate data structures
- Consider parallel processing for large datasets

```bash
# Time your algorithm (any language)
time node algorithm.js
time python algorithm.py
time go run algorithm.go

# Profile
node --prof algorithm.js           # JavaScript
python -m cProfile algorithm.py    # Python
go tool pprof cpu.prof             # Go
```

# Examples

## Example 1: Finding the Kth Largest Element

**User Query**: "Find the 3rd largest number in this array without sorting the entire array"

**Approach**:
1. Use Quickselect algorithm (O(n) average case)
2. Implement partition-based selection
3. Handle edge cases and duplicates

**Complete Commands:**
```bash
# Create test data
echo -e "5\n3\n8\n1\n9\n2" > numbers.txt

# Run Quickselect solution
node kth-largest.js numbers.txt 3
```

**Expected Output**: `5` (3rd largest is 5)

## Example 2: Optimizing a Slow Solution

**User Query**: "My solution is timing out for large inputs, how can I optimize it?"

**Approach**:
1. Analyze current algorithm complexity
2. Identify redundant computations
3. Apply memoization or better data structures
4. Test with larger datasets

# CLI Tools to Leverage

**Essential tools for algorithm development:**
- `time` - Measure execution time
- `git` - Version control for algorithm iterations
- `jq` - Process JSON test data
- `awk` - Process text-based inputs
- `sort` - Test sorting implementations
- `hyperfine` - Benchmark comparison across implementations

**Language-Specific Tools:**
- **JavaScript**: `npm install -g benchmark` / `clinic` for profiling
- **Python**: `pip install pytest-benchmark` / `memory-profiler`
- **Go**: `go test -bench` / `go tool pprof` (built-in)
- **Rust**: `cargo bench` / `criterion` crate

# Language Patterns

**Memoization — JavaScript:**
```javascript
const memo = new Map();
function fibonacci(n) {
    if (memo.has(n)) return memo.get(n);
    if (n <= 1) return n;
    const result = fibonacci(n - 1) + fibonacci(n - 2);
    memo.set(n, result);
    return result;
}
```

**Memoization — Python:**
```python
from functools import lru_cache

@lru_cache(maxsize=None)
def fibonacci(n):
    if n <= 1: return n
    return fibonacci(n - 1) + fibonacci(n - 2)
```

**Memoization — Rust:**
```rust
use std::collections::HashMap;
fn fibonacci(n: u64, memo: &mut HashMap<u64, u64>) -> u64 {
    if let Some(&v) = memo.get(&n) { return v; }
    let result = if n <= 1 { n } else {
        fibonacci(n - 1, memo) + fibonacci(n - 2, memo)
    };
    memo.insert(n, result);
    result
}
```

> **Other languages?** Examples use JS/Python/Go/Rust, but all concepts apply universally. See the **Language Adaptation Guide** in `../PACK.md` for C#, Java, Kotlin, Swift, Elixir, Haskell equivalents.

# Best Practices

- Always analyze time and space complexity before coding
- Write clean, readable code with meaningful variable names
- Test with edge cases (empty input, single element, duplicates)
- Use appropriate data structures for the problem
- Profile before optimizing to find actual bottlenecks
- Consider trade-offs between time and space complexity
- Document your algorithm's approach and complexity

# Validation Checklist

When completing an algorithm task, verify:
- [ ] Correctly handles all test cases
- [ ] Time complexity meets requirements
- [ ] Space complexity is acceptable
- [ ] Edge cases are handled properly
- [ ] Code is readable and well-documented
- [ ] Performance tested with large inputs

# Troubleshooting

## Issue: Time Limit Exceeded

**Symptoms**: Algorithm works but is too slow

**Investigation**:
```bash
# Check time complexity with large input
time node algorithm.js < large-input.txt
time python algorithm.py < large-input.txt

# Profile to find bottlenecks
node --prof algorithm.js < large-input.txt    # JS
python -m cProfile -s cumtime algorithm.py     # Python
```

**Solution**: 
- Optimize inner loops
- Use more efficient data structures
- Apply dynamic programming or memoization
- Consider a different algorithmic approach

## Issue: Memory Limit Exceeded

**Symptoms**: Program crashes with with large inputs

**Investigation**:
```bash
# Monitor memory usage
node --trace-gc algorithm.js < large-input.txt     # JS
python -m memory_profiler algorithm.py              # Python
```

**Solution**:
- Process data in chunks
- Use streaming for large files
- Avoid storing unnecessary data
- Use more memory-efficient data structures

# Supporting Files

- See `./_examples/basic-examples.md` for common algorithm patterns
- See `./_examples/sorting-examples.md` for sorting algorithm comparisons
- See `./_examples/advanced-examples.md` for advanced techniques

## Related Skills

- **data-structures** - Algorithms often depend on appropriate data structures
- **complexity-analysis** - Essential for evaluating algorithm efficiency
- **problem-solving** - Provides framework for algorithmic thinking
- **recursion** - Many algorithms use recursive approaches
- **iteration-patterns** - Alternative to recursion for many algorithms
- **functional-paradigm** - Functional programming patterns for algorithms
- → **35-development-environment**: debugging-skills (for debugging algorithms)
- → **4-performance-optimization**: algorithm-optimization (for advanced optimization)

Remember: Always choose the right algorithm for the job, not just the first one that comes to mind!
