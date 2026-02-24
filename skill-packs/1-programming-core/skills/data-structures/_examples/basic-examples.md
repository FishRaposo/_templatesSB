# Data Structure Examples

## Stack Implementation

**JavaScript:**
```javascript
class Stack {
    constructor() { this.items = []; }
    push(item) { this.items.push(item); }
    pop() { return this.items.pop() ?? null; }
    peek() { return this.items.at(-1) ?? null; }
    isEmpty() { return this.items.length === 0; }
}

const stack = new Stack();
stack.push(1); stack.push(2); stack.push(3);
console.log(stack.pop());  // 3
console.log(stack.peek()); // 2
```

**Python:**
```python
from collections import deque

stack = deque()
stack.append(1); stack.append(2); stack.append(3)
print(stack.pop())   # 3
print(stack[-1])     # 2 (peek)
```

## Queue Implementation

**JavaScript:**
```javascript
class Queue {
    constructor() { this.items = []; }
    enqueue(item) { this.items.push(item); }
    dequeue() { return this.items.shift() ?? null; }
    front() { return this.items[0] ?? null; }
    isEmpty() { return this.items.length === 0; }
}
```

**Python:**
```python
from collections import deque

queue = deque()
queue.append("a"); queue.append("b"); queue.append("c")
print(queue.popleft())  # "a" — O(1) unlike list.pop(0)
print(queue[0])          # "b" (front)
```

## When to Use
- Implement a stack for undo/redo functionality
- Create a queue for task processing
- Design a data structure for specific use case