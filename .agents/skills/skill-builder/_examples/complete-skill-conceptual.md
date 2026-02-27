# Complete Example: Conceptual/Knowledge Skill

This is a complete, production-ready example of a conceptual skill — one focused on knowledge and methodology rather than CLI tooling. Modeled after Pack 1 programming-core skills.

## Directory Structure

```
design-patterns/
├── SKILL.md
├── README.md
├── config.json
└── _examples/
    ├── basic-examples.md
    └── advanced-examples.md
```

## SKILL.md

```markdown
---
name: design-patterns
description: Use this skill when selecting, implementing, or refactoring code using design patterns. This includes choosing appropriate creational, structural, or behavioral patterns, recognizing when a pattern applies, implementing patterns correctly, and refactoring existing code to use patterns for better maintainability.
---

# Design Patterns

I'll help you select, implement, and apply design patterns to write more maintainable, flexible, and well-structured code.

# Core Approach

My approach focuses on:
1. Understanding the problem context and constraints
2. Identifying which pattern (if any) fits the situation
3. Implementing the pattern with clean, idiomatic code
4. Validating the pattern improves the design

# Step-by-Step Instructions

## 1. Identify the Problem

First, I'll help you understand what design challenge you're facing:

- What varies in your design? (behavior, creation, structure)
- What coupling exists that shouldn't?
- What's hard to change or extend?
- Are there repeated conditional logic patterns?

**Key Questions:**
- "Do I need to create objects without specifying exact classes?" → Creational patterns
- "Do I need to compose objects into larger structures?" → Structural patterns
- "Do I need to define how objects communicate?" → Behavioral patterns

## 2. Select the Right Pattern

### Creational Patterns
- **Factory Method** - Create objects without specifying exact class
- **Abstract Factory** - Create families of related objects
- **Builder** - Construct complex objects step by step
- **Singleton** - Ensure only one instance exists
- **Prototype** - Clone existing objects

### Structural Patterns
- **Adapter** - Make incompatible interfaces work together
- **Decorator** - Add behavior dynamically without subclassing
- **Facade** - Simplify complex subsystem interfaces
- **Composite** - Treat individual objects and compositions uniformly
- **Proxy** - Control access to another object

### Behavioral Patterns
- **Strategy** - Define interchangeable algorithms
- **Observer** - Notify dependents of state changes
- **Command** - Encapsulate requests as objects
- **State** - Alter behavior when internal state changes
- **Iterator** - Access elements sequentially without exposing internals

## 3. Implement the Pattern

**Strategy Pattern Example (JavaScript):**

```javascript
// Define strategies
class ShippingStrategy {
  calculate(order) { throw new Error('Must implement calculate'); }
}

class StandardShipping extends ShippingStrategy {
  calculate(order) { return order.weight * 1.5; }
}

class ExpressShipping extends ShippingStrategy {
  calculate(order) { return order.weight * 3.0 + 10; }
}

class FreeShipping extends ShippingStrategy {
  calculate(order) { return 0; }
}

// Context uses strategy
class OrderProcessor {
  constructor(shippingStrategy) {
    this.shipping = shippingStrategy;
  }

  processOrder(order) {
    const shippingCost = this.shipping.calculate(order);
    return { ...order, shippingCost, total: order.subtotal + shippingCost };
  }
}

// Usage — strategy is interchangeable
const processor = new OrderProcessor(new ExpressShipping());
const result = processor.processOrder({ weight: 5, subtotal: 100 });
```

**Observer Pattern Example (JavaScript):**

```javascript
class EventEmitter {
  #listeners = new Map();

  on(event, callback) {
    if (!this.#listeners.has(event)) {
      this.#listeners.set(event, []);
    }
    this.#listeners.get(event).push(callback);
    return () => this.off(event, callback); // return unsubscribe function
  }

  off(event, callback) {
    const callbacks = this.#listeners.get(event);
    if (callbacks) {
      this.#listeners.set(event, callbacks.filter(cb => cb !== callback));
    }
  }

  emit(event, data) {
    const callbacks = this.#listeners.get(event) || [];
    callbacks.forEach(cb => cb(data));
  }
}

// Usage
const store = new EventEmitter();
const unsubscribe = store.on('itemAdded', (item) => {
  console.log(`New item: ${item.name}`);
});

store.emit('itemAdded', { name: 'Widget', price: 9.99 });
unsubscribe(); // clean up
```

## 4. Validate the Design

After implementing, verify the pattern actually helps:

- Does it reduce coupling between components?
- Is the code easier to extend with new variants?
- Can you add new behavior without modifying existing code?
- Is the pattern's intent clear to other developers?

# Best Practices

- Don't force patterns — use them when they solve a real problem
- Prefer composition over inheritance
- Keep patterns simple; avoid over-engineering
- Name classes and methods to reveal the pattern's intent
- Start without patterns; refactor to patterns when complexity demands it
- One pattern per problem — don't stack patterns unnecessarily

# Validation Checklist

When applying a design pattern, verify:
- [ ] The pattern solves an actual design problem (not used for its own sake)
- [ ] The implementation follows the pattern's core intent
- [ ] New variants can be added without modifying existing code
- [ ] The code is more readable than the non-pattern alternative
- [ ] Tests cover the pattern's key behaviors
- [ ] Other developers can understand the pattern from the code

# Troubleshooting

## Issue: Pattern adds complexity without clear benefit

**Symptoms**: Code is harder to follow after applying the pattern; team asks "why?"

**Solution**:
- Re-evaluate if the pattern is needed at the current scale
- Consider if a simpler approach (plain functions, simple conditionals) suffices
- Apply YAGNI — add patterns when complexity demands it, not preemptively

## Issue: Wrong pattern chosen

**Symptoms**: The implementation feels forced; lots of workarounds needed

**Solution**:
- Revisit the problem — what exactly varies?
- Compare against similar patterns (Strategy vs State, Decorator vs Proxy)
- Consider combining patterns or using a simpler alternative

## Issue: Pattern breaks when requirements change

**Symptoms**: A new requirement doesn't fit the pattern's structure

**Solution**:
- Patterns aren't permanent — refactor when they no longer serve the design
- Check if the pattern needs to be composed with another pattern
- Consider if the abstraction boundary is in the wrong place

# Supporting Files

- See `./_examples/basic-examples.md` for single-pattern implementations
- See `./_examples/advanced-examples.md` for pattern combinations and refactoring

## Related Skills

- **abstraction** - Core abstraction principles that patterns build upon
- **modularity** - Organizing pattern implementations into clean modules
- **algorithms** - Algorithmic patterns vs design patterns
- → **Code quality / structure**: e.g. a code-organization skill in the project when available (for structuring pattern-heavy codebases)

Remember: Patterns are tools, not goals — use them when they genuinely simplify your design!
```

## README.md

```markdown
# Design Patterns

Select, implement, and refactor code using proven design patterns.

## Quick Start

1. Identify the design problem (what varies? what's coupled?)
2. Choose the right pattern category (creational, structural, behavioral)
3. Implement with clean, idiomatic code
4. Validate it actually improves the design

## When This Skill Activates

- "Which design pattern should I use here?"
- "Refactor this code to use the strategy pattern"
- "How do I implement the observer pattern?"
- "This code has too many conditionals, what pattern helps?"
- "Should I use a factory or builder here?"

## Pattern Quick Reference

| Problem | Pattern | Category |
|---------|---------|----------|
| Create objects without specifying class | Factory Method | Creational |
| Build complex objects step by step | Builder | Creational |
| Make incompatible interfaces work | Adapter | Structural |
| Add behavior without subclassing | Decorator | Structural |
| Interchangeable algorithms | Strategy | Behavioral |
| Notify on state changes | Observer | Behavioral |
| Encapsulate requests as objects | Command | Behavioral |
```

## config.json

```json
{
  "agent_support": {
    "claude": true,
    "roo": true,
    "generic": true
  },
  "triggers": {
    "keywords": [
      "design pattern",
      "factory",
      "singleton",
      "observer",
      "strategy",
      "decorator",
      "adapter",
      "builder",
      "refactor to pattern"
    ],
    "patterns": [
      "which pattern should I use",
      "implement pattern",
      "refactor using pattern",
      "too many conditionals"
    ],
    "file_types": []
  },
  "requirements": {
    "tools": [],
    "permissions": [
      "file_read",
      "file_write"
    ],
    "memory": false
  },
  "examples": {
    "simple": [
      {
        "query": "Implement the strategy pattern for payment processing",
        "description": "Create interchangeable payment strategies"
      },
      {
        "query": "Which pattern helps reduce these if/else chains?",
        "description": "Pattern selection guidance"
      }
    ],
    "complex": [
      {
        "query": "Refactor this notification system to use observer pattern and allow plugins",
        "context": "Existing tightly-coupled notification code with direct method calls",
        "expected_behavior": "Decouple publishers from subscribers using observer, add plugin support"
      }
    ]
  }
}
```
