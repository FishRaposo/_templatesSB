---
name: control-flow
description: Use this skill when designing program flow, implementing conditional logic, managing execution paths, or optimizing control structures. This includes conditional statements, loops, switch cases, error handling, async flow control, state machines, and designing clean control flow patterns.
---

# Control Flow

I'll help you design clean and efficient program flow, implement conditional logic effectively, manage execution paths, and optimize control structures. When you invoke this skill, I can guide you through creating readable, maintainable control flow patterns.

# Core Approach

My approach to control flow focuses on:
1. Designing clear execution paths
2. Choosing appropriate control structures
3. Reducing complexity and nesting
4. Handling edge cases and errors
5. Creating predictable and testable flow

# Step-by-Step Instructions

## 1. Design Clear Conditional Logic

I'll help you write clean conditional statements:

**JavaScript — Early returns + object lookups:**
```javascript
function processUser(user) {
    if (!user) return { error: 'User is required' };
    if (!user.email) return { error: 'Email is required' };
    if (!user.isActive) return { error: 'User is not active' };
    return { success: true, processedUser: { ...user, processedAt: new Date() } };
}

const permissions = { admin: 100, moderator: 50, user: 10, guest: 1 };
const getPermissionLevel = role => permissions[role] || 0;
```

**Python — Guard clauses + match (3.10+):**
```python
def process_user(user):
    if not user: return {"error": "User is required"}
    if not user.get("email"): return {"error": "Email is required"}
    if not user.get("is_active"): return {"error": "User is not active"}
    return {"success": True, "user": {**user, "processed_at": datetime.now()}}

def get_permission(role):
    match role:
        case "admin": return 100
        case "moderator": return 50
        case "user": return 10
        case _: return 0
```

**Rust — Pattern matching (exhaustive):**
```rust
enum Role { Admin, Moderator, User, Guest }
fn get_permission(role: &Role) -> u32 {
    match role {
        Role::Admin => 100,
        Role::Moderator => 50,
        Role::User => 10,
        Role::Guest => 1,
    } // Compiler ensures all variants handled
}
```

## 2. Optimize Loop Structures

I'll help you write efficient loops:

```javascript
// Choose the right loop for the job
function processCollection(items) {
    // For...of when you need values
    for (const item of items) {
        console.log(item);
    }
    
    // For...in for object properties
    for (const key in object) {
        if (object.hasOwnProperty(key)) {
            console.log(key, object[key]);
        }
    }
    
    // Traditional for when you need index
    for (let i = 0; i < items.length; i++) {
        if (items[i] === target) {
            return i; // Early exit
        }
    }
    
    // While for unknown iterations
    while (hasMoreData()) {
        const chunk = readChunk();
        processChunk(chunk);
    }
}

// Loop optimization patterns
function optimizedSearch(items, target) {
    // Cache length
    const len = items.length;
    
    // Use appropriate data structure
    if (len > 1000) {
        const set = new Set(items);
        return set.has(target);
    }
    
    // Simple loop for small arrays
    for (let i = 0; i < len; i++) {
        if (items[i] === target) return true;
    }
    
    return false;
}
```

## 3. Implement Error Handling Flow

I'll help you design robust error handling:

**JavaScript — try/catch:**
```javascript
try {
    const response = await fetch(url);
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    return await response.json();
} catch (error) {
    if (error instanceof TypeError) return { error: 'Network error' };
    return { error: error.message };
}
```

**Python — try/except with specific types:**
```python
try:
    response = requests.get(url)
    response.raise_for_status()
    return response.json()
except requests.ConnectionError:
    return {"error": "Network error"}
except requests.HTTPError as e:
    return {"error": f"HTTP {e.response.status_code}"}
except ValueError:
    return {"error": "Invalid JSON"}
```

**Go — Explicit error returns (no exceptions):**
```go
func fetchData(url string) ([]byte, error) {
    resp, err := http.Get(url)
    if err != nil {
        return nil, fmt.Errorf("fetch failed: %w", err)
    }
    defer resp.Body.Close()
    if resp.StatusCode != 200 {
        return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
    }
    return io.ReadAll(resp.Body)
}
```

**Rust — Result type (compile-time error handling):**
```rust
fn parse_config(path: &str) -> Result<Config, Box<dyn Error>> {
    let content = fs::read_to_string(path)?;  // ? propagates errors
    let config: Config = serde_json::from_str(&content)?;
    Ok(config)
}
```

## 4. Create State Machines

I'll help you implement state machines for complex flow:

```javascript
// Simple state machine
class StateMachine {
    constructor(initialState, transitions) {
        this.state = initialState;
        this.transitions = transitions;
    }
    
    transition(event, data) {
        const currentStateTransitions = this.transitions[this.state];
        
        if (!currentStateTransitions || !currentStateTransitions[event]) {
            throw new Error(`Invalid transition: ${this.state} -> ${event}`);
        }
        
        const nextState = currentStateTransitions[event];
        
        if (typeof nextState === 'function') {
            this.state = nextState(this.state, data);
        } else {
            this.state = nextState;
        }
        
        return this.state;
    }
    
    canTransition(event) {
        const currentStateTransitions = this.transitions[this.state];
        return currentStateTransitions && currentStateTransitions[event];
    }
}

// Example: Order processing state machine
const orderStateMachine = new StateMachine('pending', {
    pending: {
        confirm: 'confirmed',
        cancel: 'cancelled'
    },
    confirmed: {
        process: 'processing',
        cancel: 'cancelled'
    },
    processing: {
        complete: 'completed',
        fail: 'failed'
    },
    completed: {
        refund: 'refunded'
    },
    cancelled: {},
    failed: {
        retry: 'processing'
    },
    refunded: {}
});

// More advanced state machine with guards and actions
class AdvancedStateMachine {
    constructor(config) {
        this.state = config.initial;
        this.states = config.states;
        this.context = config.context || {};
    }
    
    transition(event, payload = {}) {
        const currentStateConfig = this.states[this.state];
        const transition = currentStateConfig.on?.[event];
        
        if (!transition) {
            throw new Error(`No transition for ${event} from ${this.state}`);
        }
        
        // Check guard
        if (transition.guard && !transition.guard(this.context, payload)) {
            throw new Error(`Guard failed for ${event} from ${this.state}`);
        }
        
        // Execute action
        if (transition.action) {
            transition.action(this.context, payload);
        }
        
        // Change state
        this.state = transition.target;
        
        // Execute entry action
        const newStateConfig = this.states[this.state];
        if (newStateConfig.entry) {
            newStateConfig.entry(this.context);
        }
        
        return this.state;
    }
}
```

# Examples

## Example 1: Refactoring Nested Conditions

**User Query**: "This code has too many nested ifs, how can I simplify it?"

**Before:**
```javascript
function validateUser(user) {
    if (user) {
        if (user.email) {
            if (user.email.includes('@')) {
                if (user.age >= 18) {
                    return true;
                } else {
                    return false;
                }
            } else {
                return false;
            }
        } else {
            return false;
        }
    } else {
        return false;
    }
}
```

**After:**
```javascript
function validateUser(user) {
    const validations = [
        () => user !== null,
        () => user.email && user.email.includes('@'),
        () => user.age >= 18
    ];
    
    return validations.every(validate => validate());
}
```

## Example 2: Async Flow Control

**User Query**: "I need to process multiple async operations in order with error handling"

**Complete Commands:**
```bash
# Test the async flow
node async-flow.js

# Test error scenarios
node async-flow.js --simulate-error
```

# CLI Tools to Leverage

**Essential tools for control flow analysis:**
- `eslint` / `pylint` / `clippy` - Lint for complex control flow
- `complexity-report` - Measure cyclomatic complexity

**Language-Specific Tools:**
- **JavaScript**: `xstate` (state machines) / `rxjs` (reactive)
- **Python**: `transitions` (state machines) / `asyncio` (async flow)
- **Go**: Built-in `goroutines` + `channels` for concurrent flow
- **Rust**: `tokio` (async) / `sm` crate (state machines)

# Language Patterns

See `./_examples/flow-control-utilities.md` for production-ready utilities including:
- Retry with exponential backoff
- Timeout wrapper
- Circuit breaker pattern
- Batch processing with concurrency control

> **Other languages?** Examples use JS/Python/Go/Rust, but all concepts apply universally. See the **Language Adaptation Guide** in `../PACK.md` for C#, Java, Kotlin, Swift, Elixir, Haskell equivalents.

# Best Practices

- Use early returns to reduce nesting
- Extract complex conditions to well-named functions
- Handle errors at appropriate levels
- Use appropriate data structures for lookup
- Keep control flow simple and readable
- Avoid deep nesting (>3 levels)
- Use pattern matching for complex conditions
- Document complex flow decisions

# Control Flow Patterns

## 1. Guard Clauses
- Check conditions at function start
- Return early for invalid cases
- Reduces nesting

## 2. Strategy Pattern
- Encapsulate algorithms
- Select strategy based on conditions
- Easy to extend

## 3. Chain of Responsibility
- Pass request through handlers
- Each handler decides to process or pass
- Decouples sender and receiver

## 4. State Machine
- Model state transitions
- Clear state definitions
- Prevents invalid states

# Validation Checklist

When designing control flow, verify:
- [ ] All paths are handled
- [ ] Error conditions are covered
- [ ] Nesting is minimal
- [ ] Logic is clear and readable
- [ ] Edge cases are considered
- [ ] Performance is acceptable
- [ ] Tests cover all branches

# Troubleshooting

## Issue: Too Much Nesting

**Symptoms**: Code is hard to read with many nested ifs

**Solution**:
```javascript
// Use guard clauses
function process(data) {
    if (!data) return null;
    if (!data.isValid) return null;
    if (data.isExpired) return null;
    
    // Main logic here
    return processData(data);
}

// Or extract to functions
const validations = [
    d => d !== null,
    d => d.isValid,
    d => !d.isExpired
];

if (validations.every(v => v(data))) {
    return processData(data);
}
```

## Issue: Complex State Management

**Symptoms**: State changes are unpredictable

**Solution**:
```javascript
// Use state machine
const stateMachine = {
    idle: { start: 'running' },
    running: { pause: 'paused', stop: 'idle' },
    paused: { resume: 'running', stop: 'idle' }
};

function transition(currentState, event) {
    const nextState = stateMachine[currentState]?.[event];
    if (!nextState) {
        throw new Error(`Invalid transition: ${currentState} -> ${event}`);
    }
    return nextState;
}
```

# Supporting Files

- See `./_examples/flow-control-utilities.md` for production-ready utilities
- See `./_examples/async-control-flow.md` for async flow examples
- See `./_examples/basic-examples.md` for fundamental patterns

## Related Skills

- **iteration-patterns** - Control flow includes iteration
- **recursion** - Alternative control flow approach
- **data-types** - Type checking affects control flow
- **algorithms** - Algorithms require proper control flow
- **problem-solving** - Control flow is key to problem solutions
- → **35-development-environment**: debugging-skills (for debugging flow issues)
- → **2-code-quality**: error-handling (for flow control errors)

Remember: Good control flow makes code predictable and maintainable - design it carefully!
