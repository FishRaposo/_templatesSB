# Problem-Solving Strategies Reference

## 1. Brute Force
- Try all possible solutions
- Good for understanding the problem
- Often too slow for final solution
- Use as a baseline to verify optimized solutions

## 2. Greedy Approach
- Make locally optimal choices at each step
- Doesn't always produce global optimum
- Common in optimization problems (scheduling, coin change)
- Prove greedy choice property before relying on it

## 3. Divide and Conquer
- Break problem into smaller subproblems
- Solve subproblems recursively
- Combine solutions
- Examples: merge sort, quick sort, binary search

## 4. Dynamic Programming
- Solve overlapping subproblems
- Store results to avoid recomputation (memoization)
- Bottom-up (tabulation) or top-down (memoization)
- Examples: Fibonacci, knapsack, longest common subsequence

## 5. Two Pointers / Sliding Window
- Use two indices to traverse data
- Common in array/string problems
- Often reduces O(n²) to O(n)
- Examples: two sum (sorted), max subarray, substring problems

## 6. Backtracking
- Explore all possible paths systematically
- Prune invalid paths early
- Common in constraint satisfaction problems
- Examples: N-queens, sudoku, permutations

## 7. Graph Traversal
- BFS for shortest path (unweighted)
- DFS for exhaustive exploration
- Dijkstra for weighted shortest path
- Examples: maze solving, connected components, topological sort
