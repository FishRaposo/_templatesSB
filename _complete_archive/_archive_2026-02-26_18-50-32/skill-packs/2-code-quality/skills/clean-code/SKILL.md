---
name: clean-code
description: Use this skill when writing new code or improving existing code for readability and maintainability. This includes naming conventions, function sizing, formatting, comments, and organizing code for clarity.
---

# Clean Code

I'll help you write readable, maintainable code that communicates intent clearly. When you invoke this skill, I can guide you through naming, structuring, and formatting code so it's easy to understand and modify.

# Core Approach

My approach focuses on:
1. Choosing names that reveal intent
2. Keeping functions small and single-purpose
3. Formatting for scanability
4. Eliminating unnecessary comments by making code self-documenting

# Step-by-Step Instructions

## 1. Naming

Names should reveal intent without needing a comment to explain them:

- Variables: describe what they hold, not their type
- Functions: describe what they do, use verb phrases
- Booleans: use `is`, `has`, `can`, `should` prefixes
- Avoid abbreviations, single letters (except loop counters), and generic names

**JavaScript:**
```javascript
// ❌ Bad
const d = new Date();
const list = users.filter(u => u.a > 18);
function process(data) { /* ... */ }

// ✅ Good
const registrationDate = new Date();
const adultUsers = users.filter(user => user.age > 18);
function sendWelcomeEmail(newUser) { /* ... */ }
```

**Python:**
```python
# ❌ Bad
def calc(lst):
    return [x for x in lst if x.s == "active"]

# ✅ Good
def filter_active_accounts(accounts):
    return [acct for acct in accounts if acct.status == "active"]
```

**Go:**
```go
// ❌ Bad
func proc(d []byte) error { /* ... */ }

// ✅ Good
func parseConfigFile(rawJSON []byte) error { /* ... */ }
```

## 2. Function Size and Responsibility

Functions should do one thing, do it well, and do it only:

- Aim for ≤20 lines per function (hard limit: 50)
- One level of abstraction per function
- Extract helper functions rather than adding comments
- If you need "and" in the function name, split it

**JavaScript:**
```javascript
// ❌ Does too much
async function handleOrder(order) {
  // validate
  if (!order.items.length) throw new Error('empty');
  if (order.total < 0) throw new Error('negative');
  // save
  await db.orders.insert(order);
  // notify
  await emailService.send(order.customerEmail, 'Order confirmed');
  // update inventory
  for (const item of order.items) {
    await inventory.decrement(item.sku, item.qty);
  }
}

// ✅ Each function does one thing
async function handleOrder(order) {
  validateOrder(order);
  await saveOrder(order);
  await notifyCustomer(order);
  await updateInventory(order.items);
}
```

## 3. Formatting and Structure

Consistent formatting reduces cognitive load:

- Group related code together with blank lines between groups
- Declare variables close to where they're used
- Keep consistent indentation (spaces or tabs, never mix)
- Order: constants → types → helpers → main logic → exports

**JavaScript:**
```javascript
// ✅ Well-structured module
import { setTimeout } from 'timers/promises';

const MAX_RETRY_ATTEMPTS = 3;
const DEFAULT_TIMEOUT_MS = 30_000;

class RetryConfig {
  constructor({ maxAttempts = MAX_RETRY_ATTEMPTS, timeoutMs = DEFAULT_TIMEOUT_MS } = {}) {
    this.maxAttempts = maxAttempts;
    this.timeoutMs = timeoutMs;
  }
}

async function executeWithRetry(operation, config = new RetryConfig()) {
  for (let attempt = 1; attempt <= config.maxAttempts; attempt++) {
    try {
      return await operation();
    } catch (err) {
      if (attempt === config.maxAttempts) throw err;
      await setTimeout(2 ** attempt * 1000);
    }
  }
}

export { RetryConfig, executeWithRetry };
```

**Python:**
```python
# ✅ Well-structured module
from dataclasses import dataclass
from datetime import datetime

MAX_RETRY_ATTEMPTS = 3
DEFAULT_TIMEOUT_SECONDS = 30

@dataclass
class RetryConfig:
    max_attempts: int = MAX_RETRY_ATTEMPTS
    timeout: float = DEFAULT_TIMEOUT_SECONDS

def execute_with_retry(operation, config=None):
    config = config or RetryConfig()
    for attempt in range(1, config.max_attempts + 1):
        try:
            return operation()
        except TransientError:
            if attempt == config.max_attempts:
                raise
            wait_seconds = 2 ** attempt
            time.sleep(wait_seconds)
```

**Go:**
```go
// ✅ Well-structured file
package retry

import "time"

const (
	MaxRetryAttempts      = 3
	DefaultTimeoutSeconds = 30
)

type Config struct {
	MaxAttempts int
	Timeout     time.Duration
}

func DefaultConfig() Config {
	return Config{MaxAttempts: MaxRetryAttempts, Timeout: DefaultTimeoutSeconds * time.Second}
}

func Execute(operation func() error, cfg Config) error {
	for attempt := 1; attempt <= cfg.MaxAttempts; attempt++ {
		if err := operation(); err != nil {
			if attempt == cfg.MaxAttempts {
				return err
			}
			time.Sleep(time.Duration(1<<attempt) * time.Second)
			continue
		}
		return nil
	}
	return nil
}
```

## 4. Comments and Self-Documenting Code

The best comment is code that doesn't need one:

- **Don't**: comment what the code does (the code already says that)
- **Do**: comment *why* something is done if not obvious
- **Do**: document public APIs and non-obvious business rules
- **Don't**: leave commented-out code (use version control)

```javascript
// ❌ Useless comment
// increment counter by 1
counter += 1;

// ✅ Explains WHY, not WHAT
// Rate limit requires 100ms between API calls (vendor SLA §4.2)
await delay(100);
```

# Best Practices

- Prefer explicit over clever — clarity beats brevity
- Functions should have ≤3 parameters; use an options object for more
- Return early to avoid deep nesting (guard clauses)
- Avoid magic numbers — extract to named constants
- Keep files focused — one primary concept per file
- Use consistent patterns across the codebase

# Validation Checklist

When reviewing code for cleanliness, verify:
- [ ] All names reveal intent without comments
- [ ] Functions do one thing and are ≤50 lines
- [ ] No magic numbers or strings — all extracted to constants
- [ ] No commented-out code
- [ ] Consistent formatting throughout
- [ ] Parameters ≤3 per function (or use options object)
- [ ] Early returns used instead of deep nesting

# Troubleshooting

## Issue: Long Functions That "Can't" Be Split

**Symptoms**: Function is 100+ lines with interleaved logic

**Solution**:
- Identify groups of lines that work together (natural paragraphs)
- Extract each group into a named function
- The parent function becomes a high-level outline
- Test after each extraction to ensure no regressions

## Issue: Naming Is Hard

**Symptoms**: Spending too long on names, or defaulting to generic ones

**Solution**:
- Start with a long descriptive name, shorten later if obvious
- Use the "read aloud" test — does it make sense spoken?
- Look at how the function is called — the call site should read like prose
- Ask: "If I saw this name in 6 months, would I know what it does?"

# Supporting Files

- See `./_examples/basic-examples.md` for naming, SRP, guard clause, and constant examples
- See `./README.md` for quick start and invocation examples

## Related Skills

- **code-refactoring** - Restructure code after identifying cleanliness issues
- **simplify-complexity** - Reduce deep nesting and convoluted logic
- **code-standards** - Automate clean code enforcement with linters
- **code-deduplication** - Remove repeated patterns found during cleanup
- → **1-programming-core**: abstraction (for designing clean interfaces)

Remember: Code is read 10× more than it's written — optimize for the reader!
