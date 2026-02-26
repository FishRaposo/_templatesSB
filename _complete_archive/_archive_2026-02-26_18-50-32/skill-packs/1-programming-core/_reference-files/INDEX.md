# Programming Core — Reference Files Index

> **Pack**: 1-programming-core
> **Reference Files**: 19
> **Generated from**: [`TASKS.md`](TASKS.md)

A comprehensive collection of programming reference guides covering algorithms, data structures, design patterns, and system architecture.

---

## Core Algorithms & Data Structures

| File | Topics Covered |
|------|----------------|
| [`sorting-algorithms.md`](sorting-algorithms.md) | Merge Sort, Heap Sort, Binary Search implementations with complexity analysis and comparison guidelines |
| [`hashmap-implementation.md`](hashmap-implementation.md) | HashMap with separate chaining, abstract storage interfaces, TreeMap comparison |
| [`algorithm-optimization-patterns.md`](algorithm-optimization-patterns.md) | Complexity analysis, hash set optimizations, memoization patterns |
| [`dynamic-programming-lis.md`](dynamic-programming-lis.md) | Longest Increasing Subsequence with brute force → DP → binary search optimization |

---

## Design Patterns & Architecture

| File | Topics Covered |
|------|----------------|
| [`payment-gateway-abstraction.md`](payment-gateway-abstraction.md) | Dependency Inversion Principle with abstract PaymentGateway interface, swappable backends |
| [`modular-architecture-guide.md`](modular-architecture-guide.md) | Refactoring monolithic apps, module structures for Python/JS, circular import prevention |
| [`plugin-system-architecture.md`](plugin-system-architecture.md) | Plugin interfaces, dependency resolution with topological sort, event bus pattern |
| [`state-machine-pattern.md`](state-machine-pattern.md) | Order lifecycle state machine with guard clauses, async event processing |

---

## Programming Paradigms

| File | Topics Covered |
|------|----------------|
| [`recursion-patterns.md`](recursion-patterns.md) | Flattening, Tower of Hanoi, permutations with memoization and iterative alternatives |
| [`iteration-patterns.md`](iteration-patterns.md) | Sliding window, lazy generators, chunked processing with memory comparisons |
| [`functional-programming-patterns.md`](functional-programming-patterns.md) | Pure functions, immutability, function composition, currying |
| [`python-decorator-patterns.md`](python-decorator-patterns.md) | @timed, @retry, @validate, @memoize decorators, metaclasses, JavaScript Proxy |

---

## Data Processing & Validation

| File | Topics Covered |
|------|----------------|
| [`runtime-type-validation.md`](runtime-type-validation.md) | Schema validation library for JavaScript/Python with primitives, arrays, nested objects |
| [`lru-cache-implementation.md`](lru-cache-implementation.md) | LRU Cache with HashMap + Doubly Linked List, O(1) operations |
| [`data-pipeline-architecture.md`](data-pipeline-architecture.md) | Lazy streaming, functional transforms, top-K selection algorithms |
| [`topk-optimization.md`](topk-optimization.md) | Performance optimization from O(n log n) to O(n) with heap and bucket sort |

---

## Advanced Systems

| File | Topics Covered |
|------|----------------|
| [`code-generation-patterns.md`](code-generation-patterns.md) | CRUD scaffolding with decorators, topological sort, module generation |
| [`json-query-engine.md`](json-query-engine.md) | Recursive query parser, tree traversal, filter evaluation, error handling |
| [`in-memory-database-engine.md`](in-memory-database-engine.md) | Complete DB engine with B-tree/Hash indexes, SQL parser, query planner, transactions |

---

## Quick Reference by Topic

### Algorithms
- **Sorting**: See [`sorting-algorithms.md`](sorting-algorithms.md)
- **Searching**: See [`sorting-algorithms.md`](sorting-algorithms.md) (Binary Search)
- **Optimization**: See [`algorithm-optimization-patterns.md`](algorithm-optimization-patterns.md)
- **Dynamic Programming**: See [`dynamic-programming-lis.md`](dynamic-programming-lis.md)
- **Top-K**: See [`topk-optimization.md`](topk-optimization.md)

### Data Structures
- **HashMap**: See [`hashmap-implementation.md`](hashmap-implementation.md)
- **LRU Cache**: See [`lru-cache-implementation.md`](lru-cache-implementation.md)
- **B-Tree**: See [`in-memory-database-engine.md`](in-memory-database-engine.md)
- **Query Trees**: See [`json-query-engine.md`](json-query-engine.md)

### Design Patterns
- **Abstraction**: See [`payment-gateway-abstraction.md`](payment-gateway-abstraction.md)
- **Modularity**: See [`modular-architecture-guide.md`](modular-architecture-guide.md)
- **State Machine**: See [`state-machine-pattern.md`](state-machine-pattern.md)
- **Plugin System**: See [`plugin-system-architecture.md`](plugin-system-architecture.md)

### Programming Paradigms
- **Functional**: See [`functional-programming-patterns.md`](functional-programming-patterns.md)
- **Recursion**: See [`recursion-patterns.md`](recursion-patterns.md)
- **Iteration**: See [`iteration-patterns.md`](iteration-patterns.md)
- **Metaprogramming**: See [`python-decorator-patterns.md`](python-decorator-patterns.md)

### System Architecture
- **Database Engine**: See [`in-memory-database-engine.md`](in-memory-database-engine.md)
- **Query Engine**: See [`json-query-engine.md`](json-query-engine.md)
- **Code Generation**: See [`code-generation-patterns.md`](code-generation-patterns.md)
- **Data Pipeline**: See [`data-pipeline-architecture.md`](data-pipeline-architecture.md)

---

## Usage

These reference materials are designed for:

1. **AI Agents**: Include relevant files as context when invoking skills for code generation tasks
2. **Developers**: Quick reference for implementing common patterns
3. **Code Review**: Verify implementations against reference patterns

