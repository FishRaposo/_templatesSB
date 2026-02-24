# Iteration Patterns Examples

## Map / Filter / Reduce

**JavaScript:**
```javascript
const nums = [1, 2, 3, 4, 5];
const doubled = nums.map(x => x * 2);          // [2, 4, 6, 8, 10]
const evens = nums.filter(x => x % 2 === 0);   // [2, 4]
const sum = nums.reduce((a, b) => a + b, 0);   // 15
```

**Python:**
```python
nums = [1, 2, 3, 4, 5]
doubled = [x * 2 for x in nums]                # [2, 4, 6, 8, 10]
evens = [x for x in nums if x % 2 == 0]        # [2, 4]
total = sum(nums)                                # 15
```

## Iterator / Generator

**JavaScript:**
```javascript
function* range(start, end) {
    for (let i = start; i < end; i++) yield i;
}
for (const n of range(0, 5)) console.log(n); // 0, 1, 2, 3, 4
```

**Python:**
```python
def chunked(iterable, size):
    """Yield successive chunks of given size."""
    for i in range(0, len(iterable), size):
        yield iterable[i:i + size]

for chunk in chunked(range(10), 3):
    print(list(chunk))  # [0,1,2], [3,4,5], [6,7,8], [9]
```

## Loop Patterns

**JavaScript:**
```javascript
// Early exit
function findFirst(arr, predicate) {
    for (const item of arr) {
        if (predicate(item)) return item;
    }
    return null;
}
```

**Python:**
```python
# next() with generator expression (early exit built-in)
def find_first(arr, predicate):
    return next((x for x in arr if predicate(x)), None)
```

## When to Use
- Optimize this loop for better performance
- Implement an iterator for custom data structure
- Choose the right iteration pattern for this case