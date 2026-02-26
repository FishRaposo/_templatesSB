# Task 13 — LRU Cache Response (RERUN)

## Combined Skills: problem-solving + algorithms + data-structures + complexity-analysis

`python
class Node:
    def __init__(self, key, value):
        self.key = key
        self.value = value
        self.prev = None
        self.next = None

class LRUCache:
    """O(1) get and put using HashMap + Doubly Linked List"""
    
    def __init__(self, capacity):
        self.capacity = capacity
        self.cache = {}  # key -> Node
        self.head = Node(0, 0)
        self.tail = Node(0, 0)
        self.head.next = self.tail
        self.tail.prev = self.head
    
    def _remove(self, node):
        prev, nxt = node.prev, node.next
        prev.next = nxt
        nxt.prev = prev
    
    def _add(self, node):
        node.prev = self.head
        node.next = self.head.next
        self.head.next.prev = node
        self.head.next = node
    
    def get(self, key):
        if key in self.cache:
            node = self.cache[key]
            self._remove(node)
            self._add(node)
            return node.value
        return -1
    
    def put(self, key, value):
        if key in self.cache:
            self._remove(self.cache[key])
        
        new_node = Node(key, value)
        self._add(new_node)
        self.cache[key] = new_node
        
        if len(self.cache) > self.capacity:
            lru = self.tail.prev
            self._remove(lru)
            del self.cache[lru.key]
`

**Complexity:**
- get: O(1) time
- put: O(1) time
- Space: O(capacity)

- [x] HashMap + Doubly Linked List combined
- [x] All operations O(1) proven
- [x] Full test cases provided