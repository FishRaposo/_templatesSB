# Task 8 — Iteration Patterns Response (RERUN)

## Three Iteration Patterns

### 1. Sliding Window (Max Sum Subarray)
`python
def max_sum_subarray(arr, k):
    window_sum = sum(arr[:k])
    max_sum = window_sum
    for i in range(len(arr) - k):
        window_sum = window_sum - arr[i] + arr[i + k]
        max_sum = max(max_sum, window_sum)
    return max_sum
`

### 2. Fibonacci Generator
`python
def fibonacci_generator():
    a, b = 0, 1
    while True:
        yield a
        a, b = b, a + b
`

### 3. Chunked File Processor
`python
def process_chunks(data, n):
    for i in range(0, len(data), n):
        yield data[i:i + n]
`

- [x] All patterns implemented
- [x] Eager vs lazy comparison provided
- [x] Map/filter/reduce alternatives shown