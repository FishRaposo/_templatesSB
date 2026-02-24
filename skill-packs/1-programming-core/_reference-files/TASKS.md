# Pack 1 — Skill Verification Tasks

These tasks were used to generate the reference files in this directory. Each task names the **primary skill** and the **related skills** the agent should invoke. Use these tasks to verify skills produce correct, useful guidance.

**Pack location**: `skill-packs/1-programming-core/`

---

## Individual Skill Tasks

### Task 1 — algorithms

**Invoke**: `algorithms`, `data-structures`, `complexity-analysis`, `recursion`, `iteration-patterns`

**Prompt**:
> Implement a merge sort and a heap sort in Python. Compare their time and space complexity. Explain when you'd choose one over the other. Then implement a binary search that works on the sorted output.

**Output**: `task-01-algorithms.md`

---

### Task 2 — data-structures

**Invoke**: `data-structures`, `algorithms`, `complexity-analysis`, `abstraction`, `modularity`, `data-types`

**Prompt**:
> Design and implement a HashMap from scratch in Python with separate chaining for collision handling. Include `put`, `get`, `delete`, and `resize` methods. Analyze the time complexity of each operation. Then wrap it in a clean abstract interface so the backing storage could be swapped.

**Output**: `task-02-data-structures.md`

---

### Task 3 — complexity-analysis

**Invoke**: `complexity-analysis`, `algorithms`, `data-structures`, `iteration-patterns`, `recursion`

**Prompt**:
> Given these three functions, analyze the time and space complexity of each. Identify the bottleneck in each and propose an optimized version. Show the before/after complexity.
>
> Function A: Find all pairs in an array that sum to a target (nested loop).
> Function B: Recursive Fibonacci without memoization.
> Function C: Find duplicates in a list using a set.

**Output**: `task-03-complexity-analysis.md`

---

### Task 4 — problem-solving

**Invoke**: `problem-solving`, `algorithms`, `data-structures`, `complexity-analysis`, `abstraction`, `recursion`, `control-flow`

**Prompt**:
> Solve the "Longest Increasing Subsequence" problem. Walk through the full problem-solving process: understand the problem, explore brute force, identify patterns, design an optimal solution, implement it in JavaScript and Python, then verify with test cases. Use computational thinking (decomposition, pattern recognition, abstraction, algorithm design).

**Output**: `task-04-problem-solving.md`

---

### Task 5 — abstraction

**Invoke**: `abstraction`, `data-structures`, `modularity`, `control-flow`, `data-types`

**Prompt**:
> Design a payment processing system with three backends: Stripe, PayPal, and a mock test provider. Create an abstract PaymentGateway interface, implement it for each backend in Python, and show how the calling code never needs to know which provider is active. Demonstrate the Dependency Inversion Principle.

**Output**: `task-05-abstraction.md`

---

### Task 6 — modularity

**Invoke**: `modularity`, `abstraction`, `data-structures`, `functional-paradigm`, `metaprogramming`, `control-flow`

**Prompt**:
> Take this monolithic 300-line pseudocode (a TODO app with auth, storage, and rendering mixed together) and refactor it into clean modules. Show the module structure for both Python (packages) and JavaScript (ES Modules). Define clear public interfaces, manage dependencies, and explain how you'd prevent circular imports.

**Output**: `task-06-modularity.md`

---

### Task 7 — recursion

**Invoke**: `recursion`, `iteration-patterns`, `algorithms`, `data-structures`, `problem-solving`, `control-flow`

**Prompt**:
> Implement these three recursive solutions in JavaScript and Python:
> 1. Flatten a deeply nested object/dict into a flat dict with dot-notation keys
> 2. Solve the Tower of Hanoi for n disks, printing each move
> 3. Find all permutations of a string
>
> For each, add memoization where applicable, analyze the stack depth, and provide an iterative equivalent.

**Output**: `task-07-recursion.md`

---

### Task 8 — iteration-patterns

**Invoke**: `iteration-patterns`, `algorithms`, `recursion`, `control-flow`, `data-structures`, `functional-paradigm`

**Prompt**:
> Implement these patterns in both JavaScript and Python:
> 1. A sliding window that finds the maximum sum subarray of size k
> 2. A custom generator/iterator that yields Fibonacci numbers lazily
> 3. A chunked file processor that reads a large list in batches of n
>
> Compare the memory usage of eager vs lazy approaches. Show how map/filter/reduce can replace explicit loops for each case.

**Output**: `task-08-iteration-patterns.md`

---

### Task 9 — functional-paradigm

**Invoke**: `functional-paradigm`, `abstraction`, `recursion`, `data-types`, `iteration-patterns`, `modularity`

**Prompt**:
> Refactor this imperative data processing pipeline into purely functional style:
>
> Given a list of user records `[{name, age, orders: [{amount, date}]}]`:
> 1. Filter users over 18
> 2. Calculate total spending per user
> 3. Sort by spending descending
> 4. Return top 5 with formatted output
>
> Implement in both JavaScript and Python using only pure functions, immutability, and composition. No mutations, no loops — only map/filter/reduce and function composition.

**Output**: `task-09-functional-paradigm.md`

---

### Task 10 — data-types

**Invoke**: `data-types`, `data-structures`, `abstraction`, `control-flow`, `functional-paradigm`, `algorithms`

**Prompt**:
> Build a runtime type validation library in both JavaScript and Python:
> 1. Define a `Schema` type that validates objects against a spec
> 2. Support primitives (string, number, boolean), arrays, nested objects, and optional fields
> 3. Return structured error messages on validation failure
> 4. Show how TypeScript types / Python type hints complement the runtime checks
>
> Demonstrate with an API request body validation example.

**Output**: `task-10-data-types.md`

---

### Task 11 — control-flow

**Invoke**: `control-flow`, `iteration-patterns`, `recursion`, `data-types`, `algorithms`, `problem-solving`

**Prompt**:
> Implement a state machine for an order lifecycle (created → paid → shipped → delivered, with cancellation possible from created/paid). Show:
> 1. Guard clauses to replace nested if/else
> 2. Error handling with try/catch (JS) and try/except (Python)
> 3. The state machine with transition validation
> 4. An async version that processes order events from a queue
>
> Ensure invalid transitions raise clear errors.

**Output**: `task-11-control-flow.md`

---

### Task 12 — metaprogramming

**Invoke**: `metaprogramming`, `abstraction`, `functional-paradigm`, `data-types`, `algorithms`, `modularity`

**Prompt**:
> Build a decorator/annotation system in both JavaScript and Python:
> 1. `@timed` — logs execution time of any function
> 2. `@retry(n)` — retries a function up to n times on failure
> 3. `@validate` — auto-validates function arguments against type hints
> 4. `@memoize` — caches results by arguments
>
> In JavaScript, also show a Proxy-based approach that intercepts all method calls on a class. In Python, show a metaclass that auto-registers all subclasses.

**Output**: `task-12-metaprogramming.md`

---

## Combined Skill Tasks

### Task 13 — Algorithm Development Pipeline

**Invoke**: `problem-solving` + `algorithms` + `data-structures` + `complexity-analysis`

**Prompt**:
> Design and implement an LRU Cache from scratch. Walk through the full pipeline:
> 1. **problem-solving**: Decompose the requirements (O(1) get, O(1) put, eviction)
> 2. **data-structures**: Choose and implement the right combination (HashMap + Doubly Linked List)
> 3. **algorithms**: Implement the get/put/evict logic
> 4. **complexity-analysis**: Prove all operations are O(1) time, O(n) space
>
> Implement in JavaScript and Python with full test cases.

**Output**: `task-13-algorithm-pipeline.md`

---

### Task 14 — System Architecture

**Invoke**: `abstraction` + `modularity` + `control-flow` + `data-types`

**Prompt**:
> Design a plugin system for a text editor:
> 1. **abstraction**: Define a Plugin interface with lifecycle hooks (init, execute, destroy)
> 2. **modularity**: Design the module loading system and dependency resolution
> 3. **control-flow**: Implement the event bus and plugin execution pipeline
> 4. **data-types**: Define typed configuration schemas for plugins
>
> Show the full architecture in Python with at least 3 example plugins (word count, auto-save, syntax highlight stub).

**Output**: `task-14-system-architecture.md`

---

### Task 15 — Functional Data Pipeline

**Invoke**: `functional-paradigm` + `iteration-patterns` + `data-structures` + `algorithms`

**Prompt**:
> Build a data transformation pipeline that processes a CSV of 10,000 sales records:
> 1. **iteration-patterns**: Stream/generate records lazily (don't load all into memory)
> 2. **functional-paradigm**: Transform using pure function composition (parse → filter → aggregate → format)
> 3. **data-structures**: Choose appropriate structures for aggregation (maps, sorted sets)
> 4. **algorithms**: Implement top-K selection without full sort
>
> Implement in Python with generators and in JavaScript with async iterators.

**Output**: `task-15-functional-pipeline.md`

---

### Task 16 — Performance Optimization

**Invoke**: `complexity-analysis` + `algorithms` + `iteration-patterns` + `data-structures`

**Prompt**:
> You have a slow function that finds the k most frequent words in a large text. The naive version is O(n log n). Optimize it:
> 1. **complexity-analysis**: Profile the naive version and identify bottlenecks
> 2. **data-structures**: Use a min-heap / priority queue for top-K
> 3. **algorithms**: Implement a bucket sort approach for O(n) solution
> 4. **iteration-patterns**: Stream the text to avoid loading it all at once
>
> Show the naive → optimized progression with complexity analysis at each step. Implement in both languages.

**Output**: `task-16-performance-optimization.md`

---

### Task 17 — Code Automation & Generation

**Invoke**: `metaprogramming` + `abstraction` + `modularity` + `algorithms`

**Prompt**:
> Build a code scaffolding tool that generates CRUD boilerplate:
> 1. **metaprogramming**: Use decorators/metaclasses to define model schemas
> 2. **abstraction**: Abstract the storage layer (memory, file, database stub)
> 3. **modularity**: Generate separate modules for models, routes, and storage
> 4. **algorithms**: Implement a topological sort for dependency ordering between models
>
> Given a model definition like `User(name: str, email: str, orders: List[Order])`, generate the full CRUD code. Implement in Python.

**Output**: `task-17-code-automation.md`

---

### Task 18 — Recursive System Design

**Invoke**: `recursion` + `data-structures` + `problem-solving` + `functional-paradigm` + `control-flow`

**Prompt**:
> Build a JSON query engine (like a mini jq):
> 1. **problem-solving**: Decompose the query language (field access, array indexing, filters, wildcards)
> 2. **recursion**: Recursively traverse nested JSON structures
> 3. **data-structures**: Build a tree representation of the query path
> 4. **functional-paradigm**: Compose query operations as pure functions
> 5. **control-flow**: Handle errors gracefully (missing keys, type mismatches, circular refs)
>
> Support queries like `users[*].orders[0].amount` and `users[?age>18].name`. Implement in Python.

**Output**: `task-18-recursive-system.md`

---

### Task 19 — Full Stack (All 12 Skills)

**Invoke**: `problem-solving` + `algorithms` + `data-structures` + `complexity-analysis` + `abstraction` + `modularity` + `recursion` + `iteration-patterns` + `functional-paradigm` + `data-types` + `control-flow` + `metaprogramming`

**Prompt**:
> Build a complete in-memory database engine with:
> 1. **data-types**: Typed column definitions (string, int, float, bool, date)
> 2. **data-structures**: B-tree index for fast lookups, hash index for equality
> 3. **algorithms**: Query planner that chooses index scan vs full scan
> 4. **complexity-analysis**: Document the complexity of each operation
> 5. **abstraction**: Storage engine interface (pluggable backends)
> 6. **modularity**: Separate modules for parser, planner, executor, storage
> 7. **control-flow**: Transaction state machine (begin → query → commit/rollback)
> 8. **iteration-patterns**: Lazy row iteration for large result sets
> 9. **recursion**: Recursive descent parser for SQL-like queries
> 10. **functional-paradigm**: Pure function query transforms and pipeline composition
> 11. **metaprogramming**: Decorator-based table/column definitions
> 12. **problem-solving**: Full decomposition of the design from requirements to implementation
>
> Implement the core in Python. This is a design + architecture exercise — a working prototype with `CREATE TABLE`, `INSERT`, `SELECT ... WHERE`, and `ORDER BY` is sufficient.

**Output**: `task-19-full-stack.md`

---

## D. Execution Notes

- **Run each task as a fresh conversation** with the agent, explicitly invoking the named skills
- **Save the agent's full response** as a raw output file in `_reference-files/task-outputs/`
- **Evaluate** whether the agent correctly applied each skill's principles (check against the SKILL.md validation checklists)
- **Estimated time**: Individual tasks 5–15 min; combined tasks 15–30 min; capstone ~1 hour
- **Do not skip the capstone** — it validates that all 12 skills integrate correctly

## E. Reference File Generation

After running all tasks, convert raw outputs into standalone reference files. This is a three-phase process:

### Phase 1: Run tasks and save raw outputs

Save every raw agent response to `_reference-files/task-outputs/`:

```
_reference-files/
└── task-outputs/
    ├── task-01-algorithms.md
    ├── task-02-data-structures.md
    ├── ...
    ├── task-18-recursive-system.md
    └── task-19-full-stack.md         ← capstone
```

**Keep raw outputs permanently** — they serve as history and can be re-processed.

### Phase 2: Convert each output into a standalone reference file

For **every** task output, create a corresponding reference file at the `_reference-files/` level:

1. **Copy** the task output content
2. **Remove** all "task", "prompt", and "exercise" language
3. **Rename** to a descriptive standalone filename (see Expected Reference Files table below)
4. **Rewrite the title and intro** so it reads as a self-contained guide, not a task response
5. **Preserve** all code snippets, examples, and technical content
6. **Add** a header comment: `<!-- Generated from task-outputs/task-NN-name.md -->`
7. **Save** to `_reference-files/` (alongside TASKS.md and INDEX.md)

Result:

```
_reference-files/
├── INDEX.md                              ← categorized index
├── TASKS.md                              ← this file
├── sorting-algorithms.md                 ← standalone reference (from task-01)
├── hashmap-implementation.md             ← standalone reference (from task-02)
├── ...                                   ← one reference file per task
├── in-memory-database-engine.md          ← capstone reference (from task-19)
└── task-outputs/                         ← raw outputs (kept for history)
    ├── task-01-algorithms.md
    ├── task-02-data-structures.md
    └── ...
```

### Phase 3: Create INDEX.md and cross-link

1. **Create `INDEX.md`** in `_reference-files/` with:
   - Table of all reference files organized by category
   - Quick reference by topic section
   - Usage guidance

2. **Update pack files** to cross-reference:
   - Add Reference Files table to `PACK.md`
   - Add Reference links to scenarios in `QUICK_REFERENCE.md`

### Expected Reference Files

| Task Output | Expected Reference File | Primary Skill(s) |
|-------------|------------------------|-------------------|
| `task-01-algorithms.md` | `sorting-algorithms.md` | algorithms |
| `task-02-data-structures.md` | `hashmap-implementation.md` | data-structures |
| `task-03-complexity-analysis.md` | `algorithm-optimization-patterns.md` | complexity-analysis |
| `task-04-problem-solving.md` | `dynamic-programming-lis.md` | problem-solving |
| `task-05-abstraction.md` | `payment-gateway-abstraction.md` | abstraction |
| `task-06-modularity.md` | `modular-architecture-guide.md` | modularity |
| `task-07-recursion.md` | `recursion-patterns.md` | recursion |
| `task-08-iteration-patterns.md` | `iteration-patterns.md` | iteration-patterns |
| `task-09-functional-paradigm.md` | `functional-programming-patterns.md` | functional-paradigm |
| `task-10-data-types.md` | `runtime-type-validation.md` | data-types |
| `task-11-control-flow.md` | `state-machine-pattern.md` | control-flow |
| `task-12-metaprogramming.md` | `python-decorator-patterns.md` | metaprogramming |
| `task-13-algorithm-pipeline.md` | `lru-cache-implementation.md` | algorithms + data-structures |
| `task-14-system-architecture.md` | `plugin-system-architecture.md` | abstraction + modularity |
| `task-15-functional-pipeline.md` | `data-pipeline-architecture.md` | functional + iteration |
| `task-16-performance-optimization.md` | `topk-optimization.md` | complexity + algorithms |
| `task-17-code-automation.md` | `code-generation-patterns.md` | metaprogramming + modularity |
| `task-18-recursive-system.md` | `json-query-engine.md` | recursion + data-structures |
| `task-19-full-stack.md` | `in-memory-database-engine.md` | all 12 skills |

## F. Results Summary

| Task | Primary Skill(s) | Pass/Fail | Reference File | Notes |
|------|-------------------|-----------|----------------|-------|
| 1 | algorithms | ✅ | sorting-algorithms.md | |
| 2 | data-structures | ✅ | hashmap-implementation.md | |
| 3 | complexity-analysis | ✅ | algorithm-optimization-patterns.md | |
| 4 | problem-solving | ✅ | dynamic-programming-lis.md | |
| 5 | abstraction | ✅ | payment-gateway-abstraction.md | |
| 6 | modularity | ✅ | modular-architecture-guide.md | |
| 7 | recursion | ✅ | recursion-patterns.md | |
| 8 | iteration-patterns | ✅ | iteration-patterns.md | |
| 9 | functional-paradigm | ✅ | functional-programming-patterns.md | |
| 10 | data-types | ✅ | runtime-type-validation.md | |
| 11 | control-flow | ✅ | state-machine-pattern.md | |
| 12 | metaprogramming | ✅ | python-decorator-patterns.md | |
| 13 | algorithms + data-structures | ✅ | lru-cache-implementation.md | |
| 14 | abstraction + modularity | ✅ | plugin-system-architecture.md | |
| 15 | functional + iteration | ✅ | data-pipeline-architecture.md | |
| 16 | complexity + algorithms | ✅ | topk-optimization.md | |
| 17 | metaprogramming + modularity | ✅ | code-generation-patterns.md | |
| 18 | recursion + data-structures | ✅ | json-query-engine.md | |
| 19 | all 12 skills | ✅ | in-memory-database-engine.md | |
