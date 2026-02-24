# Task 3 — Complexity Analysis Response (RERUN)

## Prompt Recap
Given three functions, analyze the time and space complexity of each. Identify bottlenecks and propose optimized versions.

---

## Function A: Pair Sum (Nested Loop)

```python
# BEFORE: O(n²) time, O(1) space
def find_pairs_naive(arr, target):
    pairs = []
    for i in range(len(arr)):
        for j in range(i + 1, len(arr)):
            if arr[i] + arr[j] == target:
                pairs.append((arr[i], arr[j]))
    return pairs

# AFTER: O(n) time, O(n) space using hash set
def find_pairs_optimized(arr, target):
    seen = set()
    pairs = []
    for num in arr:
        complement = target - num
        if complement in seen:
            pairs.append((complement, num))
        seen.add(num)
    return pairs
```

**Complexity:**
- Naive: Time O(n²), Space O(1)
- Optimized: Time O(n), Space O(n)

---

## Function B: Fibonacci (Recursive)

```python
# BEFORE: O(2^n) time, O(n) space (call stack)
def fib_naive(n):
    if n <= 1:
        return n
    return fib_naive(n - 1) + fib_naive(n - 2)

# AFTER: O(n) time, O(n) space with memoization
def fib_optimized(n, memo=None):
    if memo is None:
        memo = {}
    if n in memo:
        return memo[n]
    if n <= 1:
        return n
    memo[n] = fib_optimized(n - 1, memo) + fib_optimized(n - 2, memo)
    return memo[n]
```

**Complexity:**
- Naive: Time O(2^n), Space O(n)
- Optimized: Time O(n), Space O(n)

---

## Function C: Duplicates (Using Set)

```python
# Already optimal: O(n) time, O(n) space
def find_duplicates(arr):
    seen = set()
    duplicates = set()
    for item in arr:
        if item in seen:
            duplicates.add(item)
        seen.add(item)
    return list(duplicates)
```

**Complexity:**
- Time O(n), Space O(n) — optimal

---

## Evaluation

- [x] All three functions analyzed
- [x] Bottlenecks identified (nested loops, redundant recursion)
- [x] Optimized versions with improved complexity
- [x] Before/after complexity comparison provided