# Programming Core

**Pack ID**: 1-programming-core  
**Category**: Programming Fundamentals  
**Skills Count**: 12  

## Overview
This pack provides the fundamental programming concepts that apply across all languages and paradigms. All skills include examples in **JavaScript**, **Python**, **Go**, and **Rust** (with TypeScript where relevant), showing how each concept manifests differently across language families. A **Language Adaptation Guide** is included to help map concepts to any other language (C#, Java, Kotlin, Swift, Elixir, Haskell, etc.).

## Skills Included

1. **algorithms** - Design, analyze, implement, and optimize algorithms
2. **data-structures** - Select, implement, and analyze data structures
3. **complexity-analysis** - Analyze algorithm efficiency and optimize performance
4. **problem-solving** - Approach challenges systematically using computational thinking
5. **abstraction** - Simplify complex systems through abstraction
6. **modularity** - Design modular systems with reusable components
7. **recursion** - Solve problems using recursive approaches
8. **iteration-patterns** - Implement efficient iteration techniques
9. **functional-paradigm** - Write clean, predictable functional code
10. **data-types** - Choose and use appropriate data types
11. **control-flow** - Implement effective control flow patterns
12. **metaprogramming** - Write code that manipulates or generates other code

## When to Use This Pack

Invoke skills from this pack when you need to:
- Solve algorithmic problems
- Choose appropriate data structures
- Analyze code efficiency
- Design modular systems
- Implement recursive or iterative solutions
- Write functional code
- Generate or manipulate code programmatically

## Skill Relationships & Workflows

### Progression:
- **data-types** → **data-structures** → **algorithms**
- **problem-solving** → All other skills
- **iteration-patterns** ↔ **recursion** (alternative approaches)

### By Task:

| Task | Primary Skills | Supporting Skills |
|------|----------------|-------------------|
| **Solve algorithmic problem** | problem-solving, algorithms, data-structures | complexity-analysis |
| **Design system / API** | abstraction, modularity, control-flow | data-types |
| **Process data pipeline** | functional-paradigm, iteration-patterns | data-structures, algorithms |
| **Optimize performance** | complexity-analysis, algorithms | iteration-patterns, data-structures |
| **Automate / generate code** | metaprogramming, abstraction | modularity |
| **Write functional code** | functional-paradigm, recursion | abstraction, iteration-patterns |

### Cross-Pack References:
- → **2-code-quality**: clean-code, code-refactoring
- → **3-testing-mastery**: test-driven-development
- → **5-architecture-fundamentals**: design-patterns

## Pack Structure

```
1-programming-core/
├── PACK.md                  ← You are here
├── QUICK_REFERENCE.md       ← Decision tree and scenario lookup
├── _examples/               ← Pack-level examples (e.g. skill-integrations)
├── skills/                  ← 12 skill directories
│   └── <skill>/
│       ├── SKILL.md         ← Skill definition, instructions, multi-language examples
│       ├── config.json      ← Cross-platform config and trigger keywords
│       ├── README.md        ← Quick start guide
│       └── _examples/       ← Skill-specific examples
├── _reference-files/        ← Worked reference implementations
│   ├── INDEX.md             ← Full index of all reference files
│   ├── TASKS.md             ← Verification tasks
│   └── *.md                 ← 19 standalone reference guides
```

## Reference Files

The `_reference-files/` directory contains **19 standalone implementation guides** demonstrating each skill in practice. Use these as context when working on real problems.

### By Skill Area

| Skill(s) | Reference File | What It Covers |
|----------|----------------|----------------|
| algorithms | [`sorting-algorithms.md`](_reference-files/sorting-algorithms.md) | Merge Sort, Heap Sort, Binary Search with complexity comparison |
| algorithms, complexity-analysis | [`algorithm-optimization-patterns.md`](_reference-files/algorithm-optimization-patterns.md) | Hash set optimization, memoization, space-time tradeoffs |
| data-structures | [`hashmap-implementation.md`](_reference-files/hashmap-implementation.md) | HashMap from scratch with separate chaining, abstract storage |
| problem-solving, algorithms | [`dynamic-programming-lis.md`](_reference-files/dynamic-programming-lis.md) | LIS problem: brute force → DP → binary search optimization |
| abstraction | [`payment-gateway-abstraction.md`](_reference-files/payment-gateway-abstraction.md) | Dependency Inversion with swappable payment backends |
| modularity | [`modular-architecture-guide.md`](_reference-files/modular-architecture-guide.md) | Refactoring monolith to modules in Python and JavaScript |
| recursion | [`recursion-patterns.md`](_reference-files/recursion-patterns.md) | Flatten, Tower of Hanoi, permutations with iterative equivalents |
| iteration-patterns | [`iteration-patterns.md`](_reference-files/iteration-patterns.md) | Sliding window, lazy generators, chunked processing |
| functional-paradigm | [`functional-programming-patterns.md`](_reference-files/functional-programming-patterns.md) | Pure functions, composition, pipe/compose utilities |
| data-types | [`runtime-type-validation.md`](_reference-files/runtime-type-validation.md) | Schema validation library for JS and Python |
| control-flow | [`state-machine-pattern.md`](_reference-files/state-machine-pattern.md) | Order lifecycle state machine with guard clauses |
| metaprogramming | [`python-decorator-patterns.md`](_reference-files/python-decorator-patterns.md) | @timed, @retry, @validate, @memoize, metaclasses, JS Proxy |
| algorithms + data-structures | [`lru-cache-implementation.md`](_reference-files/lru-cache-implementation.md) | LRU Cache with HashMap + Doubly Linked List, O(1) operations |
| abstraction + modularity | [`plugin-system-architecture.md`](_reference-files/plugin-system-architecture.md) | Plugin interface, dependency resolution, event bus |
| functional-paradigm + iteration | [`data-pipeline-architecture.md`](_reference-files/data-pipeline-architecture.md) | Lazy streaming, functional transforms, top-K selection |
| complexity-analysis + algorithms | [`topk-optimization.md`](_reference-files/topk-optimization.md) | Top-K from O(n log n) to O(n) with heap and bucket sort |
| metaprogramming + modularity | [`code-generation-patterns.md`](_reference-files/code-generation-patterns.md) | CRUD scaffolding with decorators and topological sort |
| recursion + data-structures | [`json-query-engine.md`](_reference-files/json-query-engine.md) | Recursive descent parser, JSON traversal, filter evaluation |
| **all 12 skills** | [`in-memory-database-engine.md`](_reference-files/in-memory-database-engine.md) | Complete DB engine: B-tree, SQL parser, query planner, transactions |

## Language Adaptation Guide

> **See also**: [`QUICK_REFERENCE.md`](QUICK_REFERENCE.md) for scenario-based skill lookup and [`_reference-files/INDEX.md`](_reference-files/INDEX.md) for the full reference file index.

Skills show examples in JavaScript, Python, Go, and Rust, but all concepts apply to **any language**. Use the tables below to map to your stack.

### Concept Mapping

| Concept | C# | Java | Kotlin | Swift | Elixir | Haskell |
|---------|-----|------|--------|-------|--------|---------|
| **Module** | `namespace`/`using` | `package`/`import` | `package`/`import` | `import` module | `defmodule`/`alias` | `module`/`import` |
| **Error handling** | `try/catch/finally` | `try/catch/finally` | `try/catch` + `Result` | `do/try/catch` | `{:ok}`/`{:error}` tuples | `Either`/`Maybe` monad |
| **Collections** | `List<T>`/`Dictionary` | `ArrayList`/`HashMap` | `List`/`Map`/`MutableList` | `Array`/`Dictionary`/`Set` | `list`/`map`/`MapSet` | `[]`/`Map`/`Set` |
| **Generics** | `<T>` | `<T>` | `<T>` (reified) | `<T>` (associated types) | `@spec`/behaviours | type classes |
| **Pattern match** | `switch` expressions (C# 8+) | `switch` (21+) / sealed | `when` expression | `switch`/`case let` | `case`/`cond`/guards | `case`/guards |
| **Null safety** | `T?` nullable | `Optional<T>` | `T?` built-in | `T?` optionals | no null (atoms) | `Maybe a` |
| **Interfaces** | `interface` | `interface` | `interface` | `protocol` | `@behaviour` | type class |
| **Immutability** | `readonly`/records | `final`/records | `val`/data class | `let`/`struct` | default immutable | default immutable |

### Tool Mapping

| Purpose | C# / .NET | Java / JVM | Kotlin | Swift | Elixir | Haskell |
|---------|-----------|------------|--------|-------|--------|---------|
| **Package mgr** | `dotnet`/NuGet | Maven/Gradle | Gradle | SPM | Mix/Hex | Cabal/Stack |
| **Test runner** | `dotnet test`/xUnit | JUnit/TestNG | JUnit/kotest | XCTest | ExUnit | HSpec/QuickCheck |
| **Profiler** | dotTrace/PerfView | JProfiler/VisualVM | same as Java | Instruments | `:observer` | `+RTS -s` |
| **Linter** | Roslyn analyzers | SpotBugs/PMD | detekt/ktlint | SwiftLint | Credo | HLint |
| **Formatter** | `dotnet format` | google-java-format | ktfmt | swift-format | `mix format` | Ormolu/fourmolu |
| **Benchmark** | BenchmarkDotNet | JMH | kotlinx-benchmark | XCTest measures | Benchee | Criterion |

### Adaptation Tips

- **Focus on the concept, not the syntax** — e.g., "memoization" exists in every language, the cache mechanism differs
- **Find idiomatic equivalents** — don't transliterate JS to C#; use C# patterns (LINQ, async/await, records)
- **Map paradigms**: functional concepts (map/filter/reduce) → LINQ (C#), Streams (Java), Sequences (Kotlin), Enum (Elixir)
- **Use your language's strengths**: pattern matching (Elixir/Haskell), null safety (Kotlin/Swift), type inference (Rust/Go)
- **When examples show `console.log`**: adapt to your language's debug output (`Debug.WriteLine`, `System.out.println`, `println!`, `IO.inspect`)
