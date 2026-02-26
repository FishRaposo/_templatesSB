# Programming Core — Skill Integrations

Practical examples showing how multiple skills from this pack work together on real tasks.

---

## 1. Building a High-Performance Data Pipeline (functional-paradigm + iteration-patterns + data-structures + complexity-analysis)

Processing large datasets efficiently requires combining multiple skills:

```python
from typing import Iterator, TypeVar, Callable, List
from functools import reduce
from collections import deque

T = TypeVar('T')
U = TypeVar('U')

# functional-paradigm: pure functions, immutability, higher-order functions
def map_filter_reduce(
    data: Iterator[T],
    transform: Callable[[T], U],
    predicate: Callable[[U], bool],
    reducer: Callable[[U, U], U]
) -> U:
    """Pure functional pipeline: transform → filter → reduce."""
    transformed = map(transform, data)
    filtered = filter(predicate, transformed)
    return reduce(reducer, filtered)

# iteration-patterns: lazy evaluation with generators
def chunked_iterator(data: Iterator[T], chunk_size: int) -> Iterator[List[T]]:
    """Memory-efficient chunking using lazy iteration."""
    chunk = []
    for item in data:
        chunk.append(item)
        if len(chunk) == chunk_size:
            yield chunk
            chunk = []
    if chunk:
        yield chunk

# data-structures: choosing the right structure for the task
from collections import defaultdict

def build_inverted_index(records: Iterator[dict]) -> dict:
    """Build search index using hashmap (O(1) lookup) instead of list scan (O(n))."""
    index = defaultdict(set)  # HashMap: term -> set of record IDs
    
    for record in records:
        record_id = record['id']
        # Tokenize and index
        for term in record['text'].lower().split():
            index[term].add(record_id)
    
    return dict(index)

# complexity-analysis: optimize from O(n²) to O(n log n)
def find_top_k(items: List[T], key: Callable[[T], float], k: int) -> List[T]:
    """Find top k items using heap (O(n log k)) vs sorting (O(n log n))."""
    import heapq
    return heapq.nlargest(k, items, key=key)
```

**Skills used**: functional-paradigm (pure functions), iteration-patterns (generators), data-structures (hashmap selection), complexity-analysis (heap optimization)

---

## 2. Designing a Plugin System (abstraction + modularity + control-flow + metaprogramming)

Creating an extensible architecture with clean boundaries:

```typescript
// abstraction: define clean interfaces hiding implementation details
interface Plugin {
  readonly name: string;
  readonly version: string;
  initialize(context: PluginContext): Promise<void>;
  execute(input: unknown): Promise<unknown>;
  shutdown(): Promise<void>;
}

interface PluginContext {
  logger: Logger;
  config: Record<string, unknown>;
  registerHook(event: string, handler: Function): void;
}

// modularity: each plugin is an isolated module with explicit dependencies
class PluginLoader {
  private plugins = new Map<string, Plugin>();
  private hooks = new Map<string, Function[]>();

  async load(pluginPath: string): Promise<void> {
    // Dynamic import with error boundary
    const module = await import(pluginPath);
    const plugin = this.validatePlugin(module.default);
    
    const context: PluginContext = {
      logger: this.createLogger(plugin.name),
      config: this.loadConfig(plugin.name),
      registerHook: (event, handler) => this.registerHook(event, handler)
    };
    
    await plugin.initialize(context);
    this.plugins.set(plugin.name, plugin);
  }

  // control-flow: structured error handling with early returns
  private validatePlugin(module: unknown): Plugin {
    if (!module || typeof module !== 'object') {
      throw new PluginError('Module must export an object');
    }
    
    const plugin = module as Partial<Plugin>;
    
    if (!plugin.name || typeof plugin.name !== 'string') {
      throw new PluginError('Plugin must have a string name');
    }
    
    if (this.plugins.has(plugin.name)) {
      throw new PluginError(`Plugin '${plugin.name}' already loaded`);
    }
    
    return plugin as Plugin;
  }

  // metaprogramming: introspection and dynamic dispatch
  async executeHook(event: string, data: unknown): Promise<unknown[]> {
    const handlers = this.hooks.get(event) || [];
    
    // Execute all handlers, collect results
    return Promise.all(
      handlers.map(async handler => {
        try {
          return await handler(data);
        } catch (err) {
          this.logger.warn(`Hook handler failed for ${event}: ${err}`);
          return null;
        }
      })
    );
  }
}
```

**Skills used**: abstraction (interface design), modularity (module boundaries), control-flow (error handling), metaprogramming (dynamic loading)

---

## 3. Solving a Complex Algorithm Problem (problem-solving + algorithms + recursion + data-structures)

Systematic approach to a dynamic programming challenge:

```python
# problem-solving: decompose using computational thinking
# Task: Find longest increasing subsequence with specific constraints

from typing import List, Tuple, Optional
from functools import lru_cache
from dataclasses import dataclass

@dataclass
class Constraint:
    max_gap: int
    min_length: int

# recursion: memoized top-down approach
class LongestIncreasingSubsequence:
    def __init__(self, nums: List[int], constraint: Constraint):
        self.nums = nums
        self.constraint = constraint
    
    @lru_cache(maxsize=None)
    def solve_recursive(self, index: int, last_value: int) -> int:
        """Recursive solution with memoization."""
        # Base case: end of array
        if index == len(self.nums):
            return 0
        
        # Skip current element
        skip = self.solve_recursive(index + 1, last_value)
        
        # Take current element if valid
        take = 0
        current = self.nums[index]
        
        # Constraint check: gap must be within limit
        if current > last_value and (current - last_value) <= self.constraint.max_gap:
            take = 1 + self.solve_recursive(index + 1, current)
        
        return max(skip, take)

    # algorithms: convert to iterative bottom-up DP
    def solve_iterative(self) -> Tuple[int, List[int]]:
        """Iterative DP solution with path reconstruction."""
        n = len(self.nums)
        
        # dp[i] = length of longest valid subsequence ending at index i
        dp = [1] * n
        parent = [-1] * n
        
        for i in range(n):
            for j in range(i):
                # Valid transition check
                if (self.nums[i] > self.nums[j] and 
                    self.nums[i] - self.nums[j] <= self.constraint.max_gap):
                    
                    if dp[j] + 1 > dp[i]:
                        dp[i] = dp[j] + 1
                        parent[i] = j
        
        # Reconstruct path
        max_len = max(dp)
        max_idx = dp.index(max_len)
        
        if max_len < self.constraint.min_length:
            return 0, []
        
        path = []
        idx = max_idx
        while idx != -1:
            path.append(self.nums[idx])
            idx = parent[idx]
        
        return max_len, list(reversed(path))

    # data-structures: segment tree for range maximum query (O(n log n))
    def solve_optimized(self) -> int:
        """O(n log n) using segment tree / Fenwick tree."""
        from bisect import bisect_left
        
        # Coordinate compression
        sorted_unique = sorted(set(self.nums))
        
        # Fenwick tree for range max queries
        class FenwickTree:
            def __init__(self, size):
                self.tree = [0] * (size + 1)
            
            def update(self, idx: int, val: int) -> None:
                while idx < len(self.tree):
                    self.tree[idx] = max(self.tree[idx], val)
                    idx += idx & -idx
            
            def query(self, idx: int) -> int:
                result = 0
                while idx > 0:
                    result = max(result, self.tree[idx])
                    idx -= idx & -idx
                return result
        
        ft = FenwickTree(len(sorted_unique))
        max_len = 0
        
        for num in self.nums:
            compressed = bisect_left(sorted_unique, num) + 1
            # Query valid range
            best = ft.query(compressed - 1)
            ft.update(compressed, best + 1)
            max_len = max(max_len, best + 1)
        
        return max_len if max_len >= self.constraint.min_length else 0
```

**Skills used**: problem-solving (decomposition), algorithms (DP patterns), recursion (memoization), data-structures (segment tree)

---

## 4. Type-Safe API Design (data-types + abstraction + modularity + control-flow)

Building a robust API with strong typing and validation:

```go
package api

import (
    "context"
    "encoding/json"
    "fmt"
    "time"
)

// data-types: domain-specific types over primitives
type UserID string
type Email string
type Money struct {
    Amount   int64  // Smallest currency unit (cents)
    Currency string // ISO 4217 code
}

func (m Money) Add(other Money) (Money, error) {
    if m.Currency != other.Currency {
        return Money{}, fmt.Errorf("currency mismatch: %s vs %s", m.Currency, other.Currency)
    }
    return Money{Amount: m.Amount + other.Amount, Currency: m.Currency}, nil
}

// abstraction: hide implementation, expose intent
type PaymentService interface {
    Transfer(ctx context.Context, from, to UserID, amount Money) (TransferID, error)
    GetStatus(ctx context.Context, id TransferID) (TransferStatus, error)
    Refund(ctx context.Context, id TransferID) error
}

// modularity: clean separation of concerns
type TransferService struct {
    validator  InputValidator
    repository TransferRepository
    notifier   EventNotifier
    logger     Logger
}

// control-flow: structured error handling
type ValidationError struct {
    Field   string
    Message string
}

func (e ValidationError) Error() string {
    return fmt.Sprintf("validation failed for %s: %s", e.Field, e.Message)
}

func (s *TransferService) Transfer(
    ctx context.Context,
    from UserID,
    to UserID,
    amount Money,
) (TransferID, error) {
    // Early validation with guard clauses
    if err := s.validator.ValidateUserID(from); err != nil {
        return "", ValidationError{Field: "from", Message: err.Error()}
    }
    
    if err := s.validator.ValidateUserID(to); err != nil {
        return "", ValidationError{Field: "to", Message: err.Error()}
    }
    
    if amount.Amount <= 0 {
        return "", ValidationError{Field: "amount", Message: "must be positive"}
    }
    
    if from == to {
        return "", ValidationError{Field: "to", Message: "cannot transfer to self"}
    }
    
    // Execute with timeout
    ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
    defer cancel()
    
    transfer := NewTransfer(from, to, amount)
    
    if err := s.repository.Save(ctx, transfer); err != nil {
        s.logger.Error("failed to save transfer", "error", err, "transfer_id", transfer.ID)
        return "", fmt.Errorf("transfer failed: %w", err)
    }
    
    s.notifier.Notify(ctx, TransferCreated{Transfer: transfer})
    
    return transfer.ID, nil
}
```

**Skills used**: data-types (domain modeling), abstraction (interface design), modularity (service separation), control-flow (error handling)

---

## 5. Code Generation Pipeline (metaprogramming + abstraction + algorithms)

Automating boilerplate code generation:

```python
from dataclasses import dataclass
from typing import List, Dict, Type, Any
import inspect
import ast

# metaprogramming: introspect and generate code
@dataclass
class Field:
    name: str
    type: str
    required: bool = True
    default: Any = None

class SchemaParser:
    """Parse dataclasses and generate validation code."""
    
    def parse(self, cls: Type) -> List[Field]:
        """Introspect class to extract field definitions."""
        fields = []
        
        for name, type_hint in cls.__annotations__.items():
            # Handle Optional types
            origin = getattr(type_hint, '__origin__', None)
            args = getattr(type_hint, '__args__', ())
            
            is_optional = origin is not None and type(None) in args
            
            if is_optional:
                actual_type = args[0].__name__ if args else 'Any'
            else:
                actual_type = getattr(type_hint, '__name__', str(type_hint))
            
            fields.append(Field(
                name=name,
                type=actual_type,
                required=not is_optional
            ))
        
        return fields

class CodeGenerator:
    """Generate validation functions from field definitions."""
    
    def generate_validator(self, class_name: str, fields: List[Field]) -> str:
        """Generate Python validation code."""
        lines = [
            f"def validate_{class_name.lower()}(data: dict) -> {class_name}:",
            '    errors = []',
            ''
        ]
        
        for field in fields:
            if field.required:
                lines.extend([
                    f'    if "{field.name}" not in data:',
                    f'        errors.append(f"Missing required field: {field.name}")',
                    f'    else:',
                    f'        value = data["{field.name}"]',
                ])
            else:
                lines.extend([
                    f'    value = data.get("{field.name}")',
                    f'    if value is not None:',
                ])
            
            # Type checking
            type_checks = {
                'str': 'isinstance(value, str)',
                'int': 'isinstance(value, int) and not isinstance(value, bool)',
                'float': 'isinstance(value, (int, float)) and not isinstance(value, bool)',
                'bool': 'isinstance(value, bool)',
                'list': 'isinstance(value, list)',
                'dict': 'isinstance(value, dict)',
            }
            
            check = type_checks.get(field.type, None)
            if check:
                lines.extend([
                    f'        if not ({check}):',
                    f'            errors.append(f"{field.name} must be {field.type}")',
                ])
            
            lines.append('')
        
        lines.extend([
            '    if errors:',
            '        raise ValidationError(errors)',
            f'    return {class_name}(**data)',
        ])
        
        return '\n'.join(lines)

# Usage example
@dataclass
class User:
    name: str
    age: int
    email: str
    is_active: bool = True

parser = SchemaParser()
generator = CodeGenerator()

fields = parser.parse(User)
validator_code = generator.generate_validator("User", fields)

# Output can be written to file or executed
print(validator_code)
```

**Skills used**: metaprogramming (introspection), abstraction (clean interfaces), algorithms (code generation patterns)

---

## Quick Reference: Skill Combinations by Task

| Task | Primary Skills | Supporting Skills |
|------|----------------|-------------------|
| **Build data pipeline** | functional-paradigm, iteration-patterns | data-structures, complexity-analysis |
| **Design extensible system** | abstraction, modularity | control-flow, metaprogramming |
| **Solve optimization problem** | problem-solving, algorithms | recursion, data-structures |
| **Build type-safe API** | data-types, abstraction | modularity, control-flow |
| **Generate code** | metaprogramming, abstraction | algorithms |
| **Process streaming data** | iteration-patterns, functional-paradigm | complexity-analysis |
| **Build search/index system** | data-structures, algorithms | complexity-analysis |

---

**See individual skill directories in `../skills/` for detailed implementation guidance.**
