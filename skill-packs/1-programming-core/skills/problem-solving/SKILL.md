---
name: problem-solving
description: Use this skill when approaching programming challenges systematically, breaking down complex problems, designing solutions, applying computational thinking, or troubleshooting issues. This includes problem decomposition, pattern recognition, abstraction, algorithmic thinking, solution design, debugging strategies, and systematic problem-solving methodologies.
---

# Problem Solving

I'll help you approach programming challenges systematically using computational thinking, break down complex problems, design effective solutions, and troubleshoot issues. When you invoke this skill, I can guide you through a structured problem-solving process.

# Core Approach

My approach combines computational thinking with practical methodology:
1. **Decomposition** - Break complex problems into smaller parts
2. **Pattern Recognition** - Identify similarities with known solutions
3. **Abstraction** - Focus on important details, hide complexity
4. **Algorithmic Thinking** - Design step-by-step solutions
5. **Iterative Refinement** - Test, validate, and improve

# Step-by-Step Instructions

## 1. Problem Understanding

First, I'll help you thoroughly understand the problem:

- Clarify requirements and constraints
- Identify inputs, outputs, and edge cases
- Ask clarifying questions to fill gaps
- Define success criteria

**CLI Tools for Problem Analysis:**
- `cat problem.txt | grep -E "(input|output|constraint)"` - Extract key requirements
- `wc -l data.txt` - Understand input size

## 2. Problem Decomposition

I'll help break down the problem into manageable pieces:

**JavaScript — pipeline decomposition:**
```javascript
function solve(input) {
    const parsed = parseInput(input);
    const processed = preprocess(parsed);
    return formatOutput(applyAlgorithm(processed));
}
```

**Python — pipeline decomposition:**
```python
def solve(input_data):
    parsed = parse_input(input_data)
    processed = preprocess(parsed)
    return format_output(apply_algorithm(processed))
```

**Go — error-aware pipeline:**
```go
func solve(input []byte) ([]byte, error) {
    parsed, err := parseInput(input)
    if err != nil { return nil, err }
    processed := preprocess(parsed)
    result := applyAlgorithm(processed)
    return formatOutput(result), nil
}
```

**Decomposition Techniques:**
- **Top-Down**: Start with the big picture, break down
- **Bottom-Up**: Start with details, build up
- **Functional**: Decompose by functions/features
- **Data-Driven**: Decompose by data structures

## 3. Pattern Recognition

I'll help identify known solution patterns:

```javascript
// Common problem patterns and their approaches
const problemPatterns = {
    'process-all-items':    'iteration / map / forEach',
    'find-matching-items':  'filter / find / search',
    'combine-values':       'reduce / accumulator',
    'overlapping-subproblems': 'dynamic programming / memoization',
    'locally-optimal':      'greedy algorithm',
    'can-be-split':         'divide and conquer',
    'explore-all-paths':    'backtracking / DFS',
    'shortest-path':        'BFS / Dijkstra',
    'sliding-range':        'sliding window',
    'sorted-traversal':     'two pointers'
};
```

## 4. Solution Design

I'll help design the solution:

```javascript
// Problem-solving template
class ProblemSolver {
    constructor(problem) {
        this.problem = problem;
    }
    
    understand() {
        return {
            input: this.analyzeInput(),
            output: this.analyzeOutput(),
            constraints: this.identifyConstraints(),
            examples: this.extractExamples()
        };
    }
    
    design() {
        const approach = this.selectApproach();
        const algorithm = this.designAlgorithm();
        const complexity = this.analyzeComplexity();
        return { approach, algorithm, complexity };
    }
}
```

## 5. Implementation and Testing

I'll guide test-driven implementation:

```javascript
// Test-driven problem solving
function solveWithTests(solution, testCases) {
    let passed = 0;
    
    testCases.forEach((test, index) => {
        const result = solution(test.input);
        const ok = JSON.stringify(result) === JSON.stringify(test.expected);
        
        console.log(`Test ${index + 1}: ${ok ? 'PASS' : 'FAIL'}`);
        if (!ok) {
            console.log(`  Expected: ${JSON.stringify(test.expected)}`);
            console.log(`  Got:      ${JSON.stringify(result)}`);
        } else {
            passed++;
        }
    });
    
    console.log(`\n${passed}/${testCases.length} passed`);
}
```

# Examples

## Example 1: Maximum Subarray Sum

**User Query**: "Given an array of integers, find the maximum sum of a contiguous subarray"

**Approach**:
1. **Decompose**: Track current sum and max sum while iterating
2. **Pattern**: Dynamic programming / greedy (Kadane's algorithm)
3. **Design**: O(n) time, O(1) space

**JavaScript:**
```javascript
function maxSubarraySum(arr) {
    let max = arr[0], cur = arr[0];
    for (let i = 1; i < arr.length; i++) {
        cur = Math.max(arr[i], cur + arr[i]);
        max = Math.max(max, cur);
    }
    return max;
}
```

**Python:**
```python
def max_subarray_sum(arr):
    max_sum = cur = arr[0]
    for n in arr[1:]:
        cur = max(n, cur + n)
        max_sum = max(max_sum, cur)
    return max_sum
```

**Rust:**
```rust
fn max_subarray_sum(arr: &[i32]) -> i32 {
    let (mut max, mut cur) = (arr[0], arr[0]);
    for &n in &arr[1..] {
        cur = n.max(cur + n);
        max = max.max(cur);
    }
    max
}
```

## Example 2: Debugging a Failing Solution

**User Query**: "My solution works for small inputs but fails for large ones"

**Approach**:
1. Check for integer overflow or precision issues
2. Analyze time complexity — look for hidden O(n²)
3. Profile with realistic data sizes
4. Look for edge cases not handled

# CLI Tools to Leverage

**Essential tools for problem solving:**
- `git` - Version control for solution iterations
- `jq` - Process JSON test data
- `diff` - Compare expected vs actual output
- `time` / `hyperfine` - Measure execution time

**Language-Specific Testing:**
- **JavaScript**: `node --test` (built-in) / `jest` / `vitest`
- **Python**: `pytest` / `unittest` / `doctest`
- **Go**: `go test` (built-in)
- **Rust**: `cargo test` (built-in)

> **Other languages?** Examples use JS/Python/Go/Rust, but all concepts apply universally. See the **Language Adaptation Guide** in `../PACK.md` for C#, Java, Kotlin, Swift, Elixir, Haskell equivalents.

# Best Practices

- Always start by understanding the problem completely
- Break complex problems into smaller, manageable pieces
- Look for patterns in similar problems you've solved
- Write test cases before implementing (TDD approach)
- Start with a simple solution, then optimize if needed
- Consider multiple approaches before committing
- Document your thought process and approach

See `./_examples/problem-solving-strategies.md` for detailed strategy reference.
See `./_examples/computational-thinking-framework.md` for the four pillars framework.

# Validation Checklist

When solving a problem, verify:
- [ ] Fully understand requirements and constraints
- [ ] Problem is properly decomposed
- [ ] Relevant patterns are identified
- [ ] Considered multiple approaches
- [ ] Implemented the most suitable solution
- [ ] Tested with various inputs and edge cases
- [ ] Analyzed time and space complexity

# Troubleshooting

## Issue: Solution Doesn't Handle Edge Cases

**Symptoms**: Works for normal cases but fails on extremes

**Solution**:
- Test with empty input, single element, maximum values
- Consider boundary conditions
- Add explicit checks for edge cases

## Issue: Performance Issues

**Symptoms**: Solution is correct but too slow

**Solution**:
- Analyze time complexity
- Look for redundant computations (add memoization)
- Consider more efficient algorithms or data structures
- Optimize inner loops

## Issue: Can't Break Down the Problem

**Symptoms**: Problem feels overwhelming, no clear starting point

**Solution**:
- Try explaining the problem to someone else
- Look for natural divisions or phases
- Start with the simplest version
- Work backwards from the goal

# Supporting Files

- See `./_examples/problem-solving-strategies.md` for strategy reference (brute force, greedy, D&C, DP, etc.)
- See `./_examples/computational-thinking-framework.md` for the four pillars in detail
- See `./_examples/basic-examples.md` for fundamental problem-solving examples

## Related Skills

- **algorithms** - Many problems require algorithmic solutions
- **data-structures** - Choose appropriate structures for problems
- **complexity-analysis** - Evaluate solution efficiency
- **abstraction** - Simplify complex problems through abstraction
- **recursion** - Recursive problem-solving strategies
- **control-flow** - Implement solution logic effectively
- → **35-development-environment**: debugging-skills (for debugging solutions)
- → **3-testing-mastery**: test-strategy (for testing problem solutions)

Remember: Every problem has a solution - decompose, find patterns, abstract, and think algorithmically!
