# Programming Core - Quick Reference Guide

This guide helps you quickly find the right skill for your programming needs.

> **Navigation**: [`PACK.md`](PACK.md) for full pack overview | `skills/<skill>/SKILL.md` for skill details | [`_reference-files/INDEX.md`](_reference-files/INDEX.md) for all reference implementations

## Decision Tree

```
Need to solve a problem?
├─ Is it about data organization?
│  ├─ Choosing how to store data → data-structures
│  └─ Working with specific data types → data-types
├─ Is it about processing data?
│  ├─ Need loops/iteration → iteration-patterns
│  ├─ Problem seems recursive → recursion
│  └─ Want functional approach → functional-paradigm
├─ Is it about performance?
│  ├─ Need to analyze efficiency → complexity-analysis
│  └─ Need specific algorithm → algorithms
├─ Is it about code structure?
│  ├─ Simplifying complexity → abstraction
│  └─ Organizing into modules → modularity
├─ Is it about automation?
│  └─ Generating or manipulating code → metaprogramming
└─ Is it about program flow?
   └─ Managing execution paths → control-flow
```

## Common Scenarios

### "I need to sort a list"
1. **Primary**: algorithms (for sorting algorithms)
2. **Supporting**: data-structures (choose appropriate structure)
3. **Optimization**: complexity-analysis (analyze O(n log n) vs O(n²))
- **Reference**: [`sorting-algorithms.md`](_reference-files/sorting-algorithms.md)

### "My code is too slow"
1. **Analyze**: complexity-analysis (find bottlenecks)
2. **Optimize**: algorithms (choose better algorithm)
3. **Improve**: iteration-patterns (optimize loops)
4. **Structure**: data-structures (use efficient structures)
- **Reference**: [`algorithm-optimization-patterns.md`](_reference-files/algorithm-optimization-patterns.md), [`topk-optimization.md`](_reference-files/topk-optimization.md)

### "I need to process a large dataset"
1. **Approach**: problem-solving (decompose the problem)
2. **Iteration**: iteration-patterns (efficient processing)
3. **Functional**: functional-paradigm (immutable processing)
4. **Types**: data-types (ensure type safety)
- **Reference**: [`data-pipeline-architecture.md`](_reference-files/data-pipeline-architecture.md), [`iteration-patterns.md`](_reference-files/iteration-patterns.md)

### "I want to build a reusable component"
1. **Design**: abstraction (create clean interface)
2. **Structure**: modularity (make it modular)
3. **Flow**: control-flow (manage internal logic)
4. **Types**: data-types (type-safe interface)
- **Reference**: [`payment-gateway-abstraction.md`](_reference-files/payment-gateway-abstraction.md), [`plugin-system-architecture.md`](_reference-files/plugin-system-architecture.md)

### "I keep writing similar code"
1. **Meta**: metaprogramming (generate code, write code that writes code)
2. **Abstract**: abstraction (find common patterns)
3. **Modular**: modularity (extract reusable components)
- **Reference**: [`code-generation-patterns.md`](_reference-files/code-generation-patterns.md), [`python-decorator-patterns.md`](_reference-files/python-decorator-patterns.md)

## Skill Relationships Map

```
problem-solving
    ↓
algorithms ← → data-structures
    ↓              ↓
complexity-analysis ← → iteration-patterns ← → recursion
    ↓
functional-paradigm
    ↓
abstraction ← → modularity
    ↓
metaprogramming
    ↓
control-flow
    ↓
data-types
```

## Quick Tips

### Algorithms
- Start with brute force, then optimize
- Consider time vs space trade-offs
- Use built-in methods when possible

### Data Structures
- Array for random access
- Linked list for frequent insertions
- Hash map for fast lookups
- Tree for hierarchical data

### Complexity Analysis
- O(1) is constant time
- O(n) scales linearly
- O(n²) gets slow quickly
- O(log n) is very efficient

### Functional Programming
- Avoid side effects
- Use pure functions
- Compose small functions
- Prefer map/filter/reduce

### Recursion
- Always have a base case
- Each call must progress toward base
- Consider stack depth
- Memoize expensive computations

## Cross-Reference to Other Packs

When you need:

| Need | This Pack | Related Pack |
|------|-----------|-------------|
| Debug code | Any skill | 35-development-environment: debugging-skills |
| Handle errors | Any skill | 2-code-quality: error-handling |
| Write tests | algorithms, data-structures | 3-testing-mastery |
| Optimize performance | complexity-analysis | 4-performance-optimization |
| Design architecture | abstraction, modularity | 5-architecture-fundamentals |
| Write clean code | Any skill | 2-code-quality: clean-code |

## Example Workflows

### Workflow 1: Implementing a Feature
1. **problem-solving** - Understand requirements
2. **abstraction** - Design interface
3. **data-types** - Define types
4. **algorithms** - Implement logic
5. **control-flow** - Handle edge cases
6. **testing** - (Pack 3) Write tests

### Workflow 2: Optimizing Code
1. **complexity-analysis** - Find bottlenecks
2. **algorithms** - Choose better algorithm
3. **data-structures** - Optimize data access
4. **iteration-patterns** - Improve loops
5. **profiling** - (Pack 4) Measure improvements

### Workflow 3: Building a Tool
1. **metaprogramming** - Design dynamic behavior and generate code
2. **modularity** - Create reusable parts
3. **functional-paradigm** - Ensure predictability
4. **documentation** - (Pack 2) Document usage

## Cheat Sheet

| Concept | Skill | Key Idea |
|---------|-------|----------|
| Big O | complexity-analysis | O(1) < O(log n) < O(n) < O(n log n) < O(n²) |
| Map/Filter/Reduce | functional-paradigm | Transform arrays without loops |
| Stack/Queue | data-structures | LIFO vs FIFO |
| Binary Search | algorithms | O(log n) search in sorted data |
| Memoization | recursion | Cache recursive results |
| Higher-Order Function | functional-paradigm | Function that takes/returns functions |
| Proxy | metaprogramming | Intercept object operations |
| Early Return | control-flow | Exit early for clarity |
| Interface | abstraction | Hide implementation details |

## Reference Files by Skill

For worked implementations demonstrating each skill, see the `_reference-files/` directory:

| Skill | Reference File(s) |
|-------|-------------------|
| **algorithms** | [`sorting-algorithms.md`](_reference-files/sorting-algorithms.md), [`algorithm-optimization-patterns.md`](_reference-files/algorithm-optimization-patterns.md) |
| **data-structures** | [`hashmap-implementation.md`](_reference-files/hashmap-implementation.md), [`lru-cache-implementation.md`](_reference-files/lru-cache-implementation.md) |
| **complexity-analysis** | [`algorithm-optimization-patterns.md`](_reference-files/algorithm-optimization-patterns.md), [`topk-optimization.md`](_reference-files/topk-optimization.md) |
| **problem-solving** | [`dynamic-programming-lis.md`](_reference-files/dynamic-programming-lis.md) |
| **abstraction** | [`payment-gateway-abstraction.md`](_reference-files/payment-gateway-abstraction.md), [`plugin-system-architecture.md`](_reference-files/plugin-system-architecture.md) |
| **modularity** | [`modular-architecture-guide.md`](_reference-files/modular-architecture-guide.md), [`code-generation-patterns.md`](_reference-files/code-generation-patterns.md) |
| **recursion** | [`recursion-patterns.md`](_reference-files/recursion-patterns.md), [`json-query-engine.md`](_reference-files/json-query-engine.md) |
| **iteration-patterns** | [`iteration-patterns.md`](_reference-files/iteration-patterns.md), [`data-pipeline-architecture.md`](_reference-files/data-pipeline-architecture.md) |
| **functional-paradigm** | [`functional-programming-patterns.md`](_reference-files/functional-programming-patterns.md), [`data-pipeline-architecture.md`](_reference-files/data-pipeline-architecture.md) |
| **data-types** | [`runtime-type-validation.md`](_reference-files/runtime-type-validation.md) |
| **control-flow** | [`state-machine-pattern.md`](_reference-files/state-machine-pattern.md) |
| **metaprogramming** | [`python-decorator-patterns.md`](_reference-files/python-decorator-patterns.md), [`code-generation-patterns.md`](_reference-files/code-generation-patterns.md) |
| **all skills combined** | [`in-memory-database-engine.md`](_reference-files/in-memory-database-engine.md) |

> Full index: [`_reference-files/INDEX.md`](_reference-files/INDEX.md)

Remember: These skills are tools in your toolbox. The best solution often combines multiple skills!
