# Task 1 — Algorithms Response (RERUN)

## Prompt Recap
Implement a merge sort and a heap sort in Python. Compare their time and space complexity. Explain when you'd choose one over the other. Then implement a binary search that works on the sorted output.

---

## Merge Sort Implementation

```python
def merge_sort(arr):
    """
    Merge Sort: Divide-and-conquer algorithm.
    Time: O(n log n), Space: O(n)
    """
    if len(arr) <= 1:
        return arr
    
    # Divide
    mid = len(arr) // 2
    left = merge_sort(arr[:mid])
    right = merge_sort(arr[mid:])
    
    # Conquer (merge)
    return merge(left, right)

def merge(left, right):
    """Merge two sorted arrays into one sorted array."""
    result = []
    i = j = 0
    
    while i < len(left) and j < len(right):
        if left[i] <= right[j]:
            result.append(left[i])
            i += 1
        else:
            result.append(right[j])
            j += 1
    
    result.extend(left[i:])
    result.extend(right[j:])
    return result
```

---

## Heap Sort Implementation

```python
def heap_sort(arr):
    """
    Heap Sort: Build max heap, then repeatedly extract max.
    Time: O(n log n), Space: O(1) - in-place
    """
    n = len(arr)
    
    # Build max heap
    for i in range(n // 2 - 1, -1, -1):
        heapify(arr, n, i)
    
    # Extract elements
    for i in range(n - 1, 0, -1):
        arr[0], arr[i] = arr[i], arr[0]
        heapify(arr, i, 0)
    
    return arr

def heapify(arr, heap_size, root_idx):
    """Maintain max heap property."""
    largest = root_idx
    left = 2 * root_idx + 1
    right = 2 * root_idx + 2
    
    if left < heap_size and arr[left] > arr[largest]:
        largest = left
    
    if right < heap_size and arr[right] > arr[largest]:
        largest = right
    
    if largest != root_idx:
        arr[root_idx], arr[largest] = arr[largest], arr[root_idx]
        heapify(arr, heap_size, largest)
```

---

## Binary Search Implementation

```python
def binary_search(arr, target):
    """
    Binary Search on sorted array.
    Time: O(log n), Space: O(1)
    """
    left, right = 0, len(arr) - 1
    
    while left <= right:
        mid = (left + right) // 2
        
        if arr[mid] == target:
            return mid
        elif arr[mid] < target:
            left = mid + 1
        else:
            right = mid - 1
    
    return -1
```

---

## Complexity Comparison

| Algorithm | Time | Space | Stable |
|-----------|------|-------|--------|
| Merge Sort | O(n log n) | O(n) | Yes |
| Heap Sort | O(n log n) | O(1) | No |
| Binary Search | O(log n) | O(1) | N/A |

### When to Choose:
- **Merge Sort**: Need stability, external sorting, or linked lists
- **Heap Sort**: Memory constrained, don''t need stability
- **Binary Search**: Fast lookup on static sorted data

---

## Evaluation

- [x] Merge sort implemented with O(n log n) time, O(n) space
- [x] Heap sort implemented with O(n log n) time, O(1) space  
- [x] Binary search implemented with O(log n) time
- [x] Complexity comparison table provided
- [x] Selection guidance provided