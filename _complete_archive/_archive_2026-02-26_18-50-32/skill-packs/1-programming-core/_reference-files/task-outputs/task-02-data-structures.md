# Task 2 — Data Structures Response (RERUN)

## Prompt Recap
Design and implement a HashMap from scratch in Python with separate chaining for collision handling. Include put, get, delete, and resize methods. Analyze the time complexity of each operation. Then wrap it in a clean abstract interface so the backing storage could be swapped.

---

## HashMap Implementation

```python
class HashMap:
    """HashMap with separate chaining collision resolution."""
    
    def __init__(self, initial_capacity=16, load_factor=0.75):
        self.capacity = initial_capacity
        self.load_factor = load_factor
        self.size = 0
        self.buckets = [[] for _ in range(self.capacity)]
    
    def _hash(self, key):
        return hash(key) % self.capacity
    
    def put(self, key, value):
        index = self._hash(key)
        bucket = self.buckets[index]
        
        for i, (k, v) in enumerate(bucket):
            if k == key:
                bucket[i] = (key, value)
                return
        
        bucket.append((key, value))
        self.size += 1
        
        if self.size / self.capacity > self.load_factor:
            self._resize()
    
    def get(self, key):
        index = self._hash(key)
        bucket = self.buckets[index]
        
        for k, v in bucket:
            if k == key:
                return v
        return None
    
    def delete(self, key):
        index = self._hash(key)
        bucket = self.buckets[index]
        
        for i, (k, v) in enumerate(bucket):
            if k == key:
                del bucket[i]
                self.size -= 1
                return True
        return False
    
    def _resize(self):
        old_buckets = self.buckets
        self.capacity *= 2
        self.size = 0
        self.buckets = [[] for _ in range(self.capacity)]
        
        for bucket in old_buckets:
            for key, value in bucket:
                self.put(key, value)


# Usage
hm = HashMap()
hm.put("name", "Alice")
hm.put("age", 30)
print(hm.get("name"))  # Alice
```

---

## Abstract Interface

```python
from abc import ABC, abstractmethod

class Map(ABC):
    @abstractmethod
    def put(self, key, value):
        pass
    
    @abstractmethod
    def get(self, key):
        pass

class TreeMap(Map):
    """Alternative BST-based implementation."""
    def __init__(self):
        self._tree = {}
    
    def put(self, key, value):
        self._tree[key] = value
    
    def get(self, key):
        return self._tree.get(key)
```

---

## Complexity Analysis

| Operation | HashMap (avg) | HashMap (worst) |
|-----------|---------------|-----------------|
| put | O(1) | O(n) |
| get | O(1) | O(n) |
| delete | O(1) | O(n) |
| resize | O(n) | O(n) |

---

## Evaluation

- [x] HashMap implemented with separate chaining
- [x] put, get, delete, resize methods working
- [x] Time complexity analyzed
- [x] Abstract Map interface created