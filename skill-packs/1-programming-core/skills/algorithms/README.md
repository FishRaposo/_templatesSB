# Algorithms Skill

This skill helps you design, analyze, implement, and optimize algorithms for any programming problem.

## Quick Start

Invoke this skill when you need to:
- Design an algorithm for a specific problem
- Choose between different algorithmic approaches
- Optimize an existing algorithm
- Analyze time and space complexity
- Implement common algorithm patterns

## Example Usage

### Basic Example
```
User: I need to sort an array of numbers efficiently

Agent: I'll help you implement an efficient sorting algorithm. Based on your requirements, I recommend using quicksort for average-case O(n log n) performance...
```

### Advanced Example
```
User: My current solution is O(n²) and too slow for large inputs

Agent: Let's analyze your algorithm and optimize it. I'll help you identify bottlenecks and implement a more efficient solution...
```

## Common Algorithm Categories

### Sorting Algorithms
- Quick Sort
- Merge Sort
- Heap Sort
- Radix Sort

### Search Algorithms
- Binary Search
- Depth-First Search (DFS)
- Breadth-First Search (BFS)
- A* Search

### Dynamic Programming
- Memoization
- Bottom-up DP
- Knapsack Problem
- Longest Common Subsequence

### Graph Algorithms
- Dijkstra's Algorithm
- Floyd-Warshall
- Minimum Spanning Tree
- Topological Sort

## Performance Guidelines

| Input Size | Recommended Approach |
|------------|---------------------|
| n < 100    | Simple O(n²) algorithms |
| n < 10⁴   | O(n log n) algorithms |
| n < 10⁶   | O(n) algorithms with care |
| n > 10⁶   | O(n) or O(log n) essential |

## Languages

Examples provided in JavaScript, Python, Go, and Rust. See `../PACK.md` for the **Language Adaptation Guide** to map concepts to C#, Java, Kotlin, Swift, and others.

## Resources

- See `./_examples/basic-examples.md` for common algorithm patterns
- See `./_examples/sorting-examples.md` for sorting comparisons
- See `./_examples/advanced-examples.md` for advanced techniques

## Related Skills

- **data-structures** - Choose appropriate structures for your algorithms
- **complexity-analysis** - Analyze algorithm efficiency
- **problem-solving** - Systematic approach to algorithm design
