---
name: data-structures
description: Use this skill when selecting, implementing, analyzing, or optimizing data structures for any programming problem. This includes choosing the right data structure for specific use cases, implementing custom data structures, analyzing their performance, and optimizing for memory and speed.
---

# Data Structures

I'll help you select, implement, analyze, and optimize data structures for any programming problem. When you invoke this skill, I can guide you through choosing and implementing the most appropriate data structure for your needs.

# Core Approach

My approach focuses on:
1. Understanding data access patterns and requirements
2. Selecting the optimal data structure for the use case
3. Implementing efficient, clean data structure code
4. Analyzing and optimizing performance characteristics

# Step-by-Step Instructions

## 1. Requirements Analysis

First, I'll help you analyze your data needs:

- Identify data access patterns (read, write, update, delete)
- Determine memory constraints
- Analyze required operations and their frequency
- Consider ordering and uniqueness requirements

**CLI Tools for Analysis:**
- `du -sh` - Check memory usage of data
- `head -n 1000` - Sample data to understand patterns
- `sort | uniq -c` - Count frequency of values

## 2. Data Structure Selection

Based on your requirements, I'll recommend the best data structure:

- **Arrays/Lists** for sequential access
- **Hash Maps/Objects** for O(1) lookups
- **Sets** for unique value storage
- **Stacks** for LIFO operations
- **Queues** for FIFO operations
- **Trees** for hierarchical data
- **Graphs** for network data
- **Heaps** for priority queues

## 3. Implementation

I'll help you implement the data structure:

**JavaScript — Map/Set:**
```javascript
const map = new Map();          // Hash map: O(1) get/set
map.set('name', 'John');
const set = new Set([1, 2, 3]); // Unique values: O(1) has/add
```

**Python — dict/set/deque:**
```python
from collections import deque, defaultdict, OrderedDict

d = defaultdict(list)     # Auto-initializing dict
d['users'].append('John') # No KeyError

q = deque([1, 2, 3])     # Double-ended queue: O(1) append/pop both ends
q.appendleft(0)          # [0, 1, 2, 3]

cache = OrderedDict()     # Remembers insertion order (LRU basis)
```

**Go — slices/maps:**
```go
m := make(map[string]int)      // Hash map
m["age"] = 30

stack := []int{1, 2, 3}       // Slice as stack
stack = append(stack, 4)      // Push
top := stack[len(stack)-1]    // Peek
stack = stack[:len(stack)-1]  // Pop
```

**Rust — ownership-aware collections:**
```rust
use std::collections::{HashMap, BTreeMap, VecDeque};
let mut map = HashMap::new();   // Hash map
let mut tree = BTreeMap::new(); // Sorted map (B-tree)
let mut deque = VecDeque::new();// Double-ended queue
```

## 4. Performance Analysis

I'll help analyze and optimize performance:

**JavaScript:**
```javascript
const data = Array.from({length: 100000}, (_, i) => i);
console.time('Array'); data.includes(99999); console.timeEnd('Array');
const set = new Set(data);
console.time('Set');   set.has(99999);       console.timeEnd('Set');
```

**Python:**
```python
import timeit
data_list = list(range(100000))
data_set = set(data_list)
print(timeit.timeit(lambda: 99999 in data_list, number=100))  # ~slow
print(timeit.timeit(lambda: 99999 in data_set, number=100))   # ~fast
```

# Examples

## Example 1: Choosing Between Array and Set

**User Query**: "I need to store user IDs and frequently check if a user exists. Should I use an array or a set?"

**Approach**:
1. Analyze operation requirements
2. Compare time complexities
3. Implement both solutions
4. Benchmark performance

**Complete Commands:**
```bash
# Create test data
node -e "console.log(Array.from({length: 100000}, (_, i) => i).join('\n'))" > user-ids.txt

# Test array performance
time node array-lookup.js

# Test set performance
time node set-lookup.js
```

**Expected Result**: Set lookup is O(1) vs Array O(n)

## Example 2: Implementing a Custom Cache

**User Query**: "I need to implement a cache that removes the least recently used item when full"

**Approach**:
1. Use HashMap + Doubly Linked List
2. Implement LRU eviction logic
3. Add O(1) get and put operations

# CLI Tools to Leverage

**Essential tools for data structure work:**
- `time` / `hyperfine` - Measure operation performance
- `jq` - Process JSON data structures
- `wc -l` - Count elements in data files

**Language-Specific Tools:**
- **JavaScript**: `npm install -g benchmark` - Performance testing
- **Python**: `pip install sortedcontainers` - Fast sorted collections
- **Go**: Built-in `testing` package with `go test -bench`
- **Rust**: `cargo add indexmap` - Insertion-order preserving map

# Language Patterns

**Stack — JavaScript:**
```javascript
class Stack {
    #items = [];
    push(el) { this.#items.push(el); }
    pop()    { return this.#items.pop(); }
    peek()   { return this.#items.at(-1); }
    get size() { return this.#items.length; }
}
```

**Stack — Python:**
```python
from collections import deque
stack = deque()          # Preferred over list for stack
stack.append(1)          # push
stack.pop()              # pop
stack[-1]                # peek
```

**BST — Python (compact):**
```python
class TreeNode:
    def __init__(self, val, left=None, right=None):
        self.val, self.left, self.right = val, left, right

class BST:
    def __init__(self):
        self.root = None

    def insert(self, val):
        if not self.root:
            self.root = TreeNode(val); return
        node = self.root
        while node:
            if val < node.val:
                if not node.left: node.left = TreeNode(val); return
                node = node.left
            else:
                if not node.right: node.right = TreeNode(val); return
                node = node.right

    def search(self, val):
        node = self.root
        while node:
            if val == node.val: return True
            node = node.left if val < node.val else node.right
        return False
```

See `./_examples/basic-examples.md` for full JavaScript BST implementation.

> **Other languages?** Examples use JS/Python/Go/Rust, but all concepts apply universally. See the **Language Adaptation Guide** in `../PACK.md` for C#, Java, Kotlin, Swift, Elixir, Haskell equivalents.

# Best Practices

- Choose data structures based on your most frequent operations
- Consider space-time tradeoffs
- Use built-in data structures when available
- Implement custom data structures only when necessary
- Document time complexity of all operations
- Test with realistic data sizes
- Consider memory layout for performance-critical applications

# Validation Checklist

When implementing a data structure, verify:
- [ ] All required operations are implemented
- [ ] Time complexity meets requirements
- [ ] Space complexity is acceptable
- [ ] Edge cases are handled (empty, single item, full)
- [ ] Error handling is robust
- [ ] Performance tested with realistic data

# Troubleshooting

## Issue: Performance Degradation

**Symptoms**: Operations become slow as data grows

**Investigation**:
```bash
# Profile memory usage
node --inspect heap-analysis.js

# Check time complexity
time node performance-test.js
```

**Solution**:
- Choose a more efficient data structure
- Implement indexing or caching
- Use lazy loading for large datasets
- Consider specialized data structures

## Issue: Memory Leaks

**Symptoms**: Memory usage increases over time

**Investigation**:
```bash
# Monitor memory
node --trace-gc memory-test.js
```

**Solution**:
- Properly clean up references
- Use weak references where appropriate
- Implement object pooling
- Consider streaming for large datasets

# Supporting Files

- See `./_examples/basic-examples.md` for common data structure implementations

## Related Skills

- **algorithms** - Data structures enable efficient algorithms
- **complexity-analysis** - Understanding DS performance characteristics
- **abstraction** - Data structures are abstractions for data organization
- **modularity** - Well-designed DS are modular and reusable
- **data-types** - Foundation for understanding complex structures
- **functional-paradigm** - Immutable data structures in FP
- → **35-development-environment**: debugging-skills (for debugging data structures)
- → **4-performance-optimization**: memory-optimization (for memory efficiency)

Remember: The right data structure can make or break your algorithm's performance!
