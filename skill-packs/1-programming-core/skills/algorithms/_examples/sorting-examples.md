# Sorting Algorithm Examples

## Quick Sort Implementation

```javascript
function quickSort(arr) {
    if (arr.length <= 1) return arr;
    
    const pivot = arr[Math.floor(arr.length / 2)];
    const left = arr.filter(x => x < pivot);
    const middle = arr.filter(x => x === pivot);
    const right = arr.filter(x => x > pivot);
    
    return [...quickSort(left), ...middle, ...quickSort(right)];
}

// Usage
const numbers = [5, 2, 9, 1, 5, 6];
const sorted = quickSort(numbers);
console.log(sorted); // [1, 2, 5, 5, 6, 9]
```

## Merge Sort Implementation

```javascript
function mergeSort(arr) {
    if (arr.length <= 1) return arr;
    
    const mid = Math.floor(arr.length / 2);
    const left = mergeSort(arr.slice(0, mid));
    const right = mergeSort(arr.slice(mid));
    
    return merge(left, right);
}

function merge(left, right) {
    const result = [];
    let leftIndex = 0;
    let rightIndex = 0;
    
    while (leftIndex < left.length && rightIndex < right.length) {
        if (left[leftIndex] < right[rightIndex]) {
            result.push(left[leftIndex]);
            leftIndex++;
        } else {
            result.push(right[rightIndex]);
            rightIndex++;
        }
    }
    
    return result.concat(left.slice(leftIndex)).concat(right.slice(rightIndex));
}
```

## Performance Comparison

```javascript
// Test data
const testArray = Array.from({length: 10000}, () => Math.random() * 1000);

// Time quick sort
console.time('Quick Sort');
quickSort([...testArray]);
console.timeEnd('Quick Sort');

// Time merge sort
console.time('Merge Sort');
mergeSort([...testArray]);
console.timeEnd('Merge Sort');

// Time built-in sort
console.time('Built-in Sort');
[...testArray].sort((a, b) => a - b);
console.timeEnd('Built-in Sort');
```

## When to Use Each Algorithm

| Algorithm | Best Case | Average Case | Worst Case | Space | When to Use |
|-----------|-----------|--------------|------------|-------|-------------|
| Quick Sort | O(n log n) | O(n log n) | O(n²) | O(log n) | General purpose, in-place |
| Merge Sort | O(n log n) | O(n log n) | O(n log n) | O(n) | Stable sort needed |
| Heap Sort | O(n log n) | O(n log n) | O(n log n) | O(1) | Guaranteed O(n log n) |
| Radix Sort | O(nk) | O(nk) | O(nk) | O(n+k) | Integers, fixed length |
