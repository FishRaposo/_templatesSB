# Complexity Analysis Examples

## O(1) — Constant Time

**JavaScript:**
```javascript
function getFirstElement(arr) { return arr[0]; }
function accessProperty(obj, key) { return obj[key]; }
```

**Python:**
```python
def get_first(arr): return arr[0]
def access_property(obj, key): return obj[key]  # dict lookup is O(1) avg
```

## O(n) — Linear Time

**JavaScript:**
```javascript
function findMax(arr) {
    let max = arr[0];
    for (let i = 1; i < arr.length; i++) {
        if (arr[i] > max) max = arr[i];
    }
    return max;
}
```

**Python:**
```python
def find_max(arr):
    return max(arr)  # Built-in max() is O(n)

# Manual equivalent:
def find_max_manual(arr):
    m = arr[0]
    for x in arr[1:]:
        if x > m: m = x
    return m
```

## O(n²) — Quadratic Time

**JavaScript:**
```javascript
function findDuplicates(arr) {
    const duplicates = [];
    for (let i = 0; i < arr.length; i++) {
        for (let j = i + 1; j < arr.length; j++) {
            if (arr[i] === arr[j]) duplicates.push(arr[i]);
        }
    }
    return duplicates;
}
```

**Python — O(n) improvement using a set:**
```python
def find_duplicates(arr):
    seen, dupes = set(), set()
    for x in arr:
        if x in seen: dupes.add(x)  # set lookup is O(1)
        seen.add(x)
    return list(dupes)
```

## When to Use
- Analyze the time complexity of this algorithm
- Optimize this O(n²) solution
- Compare performance of different approaches