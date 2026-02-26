# Task 16 — Top-K Optimization Response (RERUN)

## Combined Skills: complexity-analysis + algorithms + iteration-patterns + data-structures

### Naive O(n log n) Approach
`python
from collections import Counter

def top_k_naive(text, k):
    words = text.split()
    counts = Counter(words)
    return counts.most_common(k)  # O(n log n) sort
`

### Optimized O(n) with Min-Heap
`python
import heapq
from collections import Counter

def top_k_optimized(text, k):
    words = text.split()
    counts = Counter(words)
    
    # O(n log k) using min-heap of size k
    return heapq.nlargest(k, counts.items(), key=lambda x: x[1])

# Even better: Bucket sort O(n)
def top_k_bucket_sort(text, k):
    words = text.split()
    counts = Counter(words)
    
    # Bucket by frequency
    max_freq = max(counts.values())
    buckets = [[] for _ in range(max_freq + 1)]
    
    for word, freq in counts.items():
        buckets[freq].append(word)
    
    # Collect from highest frequency
    result = []
    for freq in range(max_freq, 0, -1):
        for word in buckets[freq]:
            result.append((word, freq))
            if len(result) == k:
                return result
    return result
`

**Complexity Progression:**
1. Naive: O(n log n)
2. Heap: O(n log k)
3. Bucket: O(n)

- [x] Naive version profiled
2. Min-heap optimization shown
3. Bucket sort O(n) solution
4. Complexity comparison at each step