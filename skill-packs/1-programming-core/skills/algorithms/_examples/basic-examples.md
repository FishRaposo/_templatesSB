# Algorithm Examples

## Sorting — Quick Sort

**JavaScript:**
```javascript
function quickSort(arr) {
    if (arr.length <= 1) return arr;
    const pivot = arr[Math.floor(arr.length / 2)];
    const left = arr.filter(x => x < pivot);
    const middle = arr.filter(x => x === pivot);
    const right = arr.filter(x => x > pivot);
    return [...quickSort(left), ...middle, ...quickSort(right)];
}
console.log(quickSort([5, 2, 9, 1, 5, 6])); // [1, 2, 5, 5, 6, 9]
```

**Python:**
```python
def quick_sort(arr):
    if len(arr) <= 1:
        return arr
    pivot = arr[len(arr) // 2]
    left = [x for x in arr if x < pivot]
    middle = [x for x in arr if x == pivot]
    right = [x for x in arr if x > pivot]
    return quick_sort(left) + middle + quick_sort(right)

print(quick_sort([5, 2, 9, 1, 5, 6]))  # [1, 2, 5, 5, 6, 9]
```

## Search — Binary Search

**JavaScript:**
```javascript
function binarySearch(arr, target) {
    let left = 0, right = arr.length - 1;
    while (left <= right) {
        const mid = Math.floor((left + right) / 2);
        if (arr[mid] === target) return mid;
        if (arr[mid] < target) left = mid + 1;
        else right = mid - 1;
    }
    return -1;
}
console.log(binarySearch([1, 2, 3, 4, 5, 6, 7, 8, 9], 5)); // 4
```

**Python:**
```python
import bisect

def binary_search(arr, target):
    lo, hi = 0, len(arr) - 1
    while lo <= hi:
        mid = (lo + hi) // 2
        if arr[mid] == target: return mid
        elif arr[mid] < target: lo = mid + 1
        else: hi = mid - 1
    return -1

# Or use stdlib: bisect.bisect_left(arr, target)
print(binary_search([1, 2, 3, 4, 5, 6, 7, 8, 9], 5))  # 4
```

## When to Use
- Sort this array of numbers efficiently
- Find an element in a sorted array
- Implement an efficient search algorithm