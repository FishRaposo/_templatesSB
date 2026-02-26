# Code Quality — Skill Integrations

Practical examples showing how multiple skills from this pack work together on real tasks.

---

## 1. Refactoring a Messy Controller (clean-code + code-refactoring + simplify-complexity)

A bloated Express route handler that does too much:

**Before** — 60-line handler with nested ifs, inline validation, mixed concerns:

```javascript
app.post('/orders', async (req, res) => {
  if (req.body.items) {
    if (req.body.items.length > 0) {
      let total = 0;
      for (let i = 0; i < req.body.items.length; i++) {
        if (req.body.items[i].price > 0) {
          if (req.body.items[i].quantity > 0) {
            total += req.body.items[i].price * req.body.items[i].quantity;
          } else {
            return res.status(400).json({ error: 'Bad quantity' });
          }
        } else {
          return res.status(400).json({ error: 'Bad price' });
        }
      }
      // ... 30 more lines of database calls, email sending, etc.
      const order = await db.orders.create({ items: req.body.items, total });
      await sendEmail(req.body.email, order);
      return res.json(order);
    }
  }
  return res.status(400).json({ error: 'No items' });
});
```

**After** — applying all three skills:

```javascript
// clean-code: descriptive names, small single-purpose functions
function calculateTotal(items) {
  return items.reduce((sum, item) => sum + item.price * item.quantity, 0);
}

// input-validation: validate at the boundary
function validateOrderItems(items) {
  if (!items?.length) throw new ValidationError('Order must have at least one item');
  for (const item of items) {
    if (item.price <= 0) throw new ValidationError(`Invalid price: ${item.price}`);
    if (item.quantity <= 0) throw new ValidationError(`Invalid quantity: ${item.quantity}`);
  }
}

// simplify-complexity: flat control flow with early validation
// code-refactoring: extract method pattern
app.post('/orders', async (req, res, next) => {
  try {
    validateOrderItems(req.body.items);
    const total = calculateTotal(req.body.items);
    const order = await createOrder(req.body.items, total);
    await notifyCustomer(req.body.email, order);
    res.json(order);
  } catch (err) {
    next(err);
  }
});
```

**Skills used**: clean-code (naming, small functions), code-refactoring (Extract Method), simplify-complexity (guard clauses, flat flow), input-validation (boundary validation), error-handling (centralized try/catch)

---

## 2. Adding Production Hardening (error-handling + input-validation + logging-strategies)

Taking a raw endpoint and making it production-ready:

```python
import logging
import uuid
from dataclasses import dataclass

logger = logging.getLogger(__name__)

# error-handling: typed error hierarchy
class AppError(Exception):
    def __init__(self, message: str, code: str, status: int = 500):
        self.message = message
        self.code = code
        self.status = status

class ValidationError(AppError):
    def __init__(self, message: str):
        super().__init__(message, "VALIDATION_ERROR", 400)

class NotFoundError(AppError):
    def __init__(self, resource: str, id: str):
        super().__init__(f"{resource} {id} not found", "NOT_FOUND", 404)

# input-validation: schema-based validation
@dataclass
class TransferRequest:
    from_account: str
    to_account: str
    amount: float

    def validate(self):
        if not self.from_account or not self.to_account:
            raise ValidationError("Both accounts are required")
        if self.from_account == self.to_account:
            raise ValidationError("Cannot transfer to the same account")
        if self.amount <= 0:
            raise ValidationError(f"Amount must be positive, got {self.amount}")
        if self.amount > 1_000_000:
            raise ValidationError("Amount exceeds maximum transfer limit")

# logging-strategies: structured logging with correlation
def transfer_funds(request: TransferRequest):
    correlation_id = str(uuid.uuid4())
    log = logger.bind(correlation_id=correlation_id,
                      from_acct=request.from_account,
                      to_acct=request.to_account)

    log.info("transfer.started", amount=request.amount)

    try:
        request.validate()
        result = execute_transfer(request)
        log.info("transfer.completed", transfer_id=result.id)
        return result
    except ValidationError:
        log.warning("transfer.validation_failed")
        raise
    except InsufficientFundsError:
        log.warning("transfer.insufficient_funds")
        raise
    except Exception as e:
        log.error("transfer.unexpected_error", error=str(e))
        raise AppError("Transfer failed", "TRANSFER_ERROR")
```

---

## 3. Setting Up Team Quality Gates (code-standards + code-metrics + code-quality-review)

Establishing automated quality enforcement for a TypeScript project:

```jsonc
// code-standards: ESLint config (.eslintrc.json)
{
  "extends": ["eslint:recommended", "plugin:@typescript-eslint/strict"],
  "rules": {
    "max-lines-per-function": ["warn", { "max": 50 }],
    "complexity": ["warn", { "max": 10 }],
    "max-depth": ["warn", { "max": 3 }],
    "no-duplicate-imports": "error",
    "prefer-const": "error"
  }
}
```

```yaml
# code-metrics: CI quality gate (.github/workflows/quality.yml)
name: Quality Gate
on: [pull_request]
jobs:
  quality:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm ci
      - run: npx eslint . --max-warnings 0
      - run: npx prettier --check .
      - run: npx jest --coverage --coverageThreshold='{"global":{"branches":80,"functions":80,"lines":80}}'
      - run: npx tsc --noEmit
```

```markdown
# code-quality-review: PR Review Checklist (PULL_REQUEST_TEMPLATE.md)

## Review Checklist
- [ ] Functions are ≤50 lines, cyclomatic complexity ≤10
- [ ] No duplicated logic (DRY)
- [ ] Error handling covers failure cases
- [ ] Input validation at service boundaries
- [ ] Structured logging for observable operations
- [ ] No TODO/FIXME without linked issue
- [ ] Tests cover the changed code paths
```

---

## 4. Paying Down Technical Debt (technical-debt + code-metrics + code-refactoring + legacy-code-migration)

Systematically reducing debt in a mature codebase:

```bash
# technical-debt: inventory current state
# code-metrics: measure what matters
npx madge --circular src/                     # Find circular dependencies
npx jscpd src/ --threshold 5                  # Find code duplication > 5%
npx plato -d report src/                      # Generate complexity report
git log --format='%H' --since='6 months ago' -- src/ | \
  xargs -I{} git diff-tree --no-commit-id -r {} -- src/ | \
  awk '{print $NF}' | sort | uniq -c | sort -rn | head -20  # Hotspot analysis
```

```python
# technical-debt: prioritize by impact × frequency
debt_items = [
    {"name": "Circular deps in auth module",    "impact": 8, "effort": 3, "churn": 15},
    {"name": "Duplicated validation logic",      "impact": 6, "effort": 2, "churn": 22},
    {"name": "God class: UserService (800 loc)", "impact": 9, "effort": 5, "churn": 30},
    {"name": "No error types, string errors",    "impact": 7, "effort": 4, "churn": 18},
]

# Priority score: (impact * churn) / effort — highest first
for item in sorted(debt_items, key=lambda d: (d["impact"] * d["churn"]) / d["effort"], reverse=True):
    score = (item["impact"] * item["churn"]) / item["effort"]
    print(f"  [{score:5.1f}] {item['name']}")

# Output:
#   [ 54.0] God class: UserService (800 loc)
#   [ 66.0] Duplicated validation logic
#   [ 50.0] Circular deps in auth module
#   [ 31.5] No error types, string errors
```

```go
// legacy-code-migration: strangler fig — wrap legacy behind new interface
// code-refactoring: adapter pattern for incremental migration

type UserRepository interface {
    FindByID(ctx context.Context, id string) (*User, error)
    Save(ctx context.Context, user *User) error
}

// Phase 1: Adapter wraps legacy
type LegacyUserAdapter struct {
    legacy *OldUserDAO
}

func (a *LegacyUserAdapter) FindByID(ctx context.Context, id string) (*User, error) {
    old, err := a.legacy.GetUser(id)
    if err != nil {
        return nil, fmt.Errorf("legacy lookup failed: %w", err)
    }
    return mapLegacyUser(old), nil
}

// Phase 2: New implementation behind same interface
type PostgresUserRepo struct {
    db *sql.DB
}

func (r *PostgresUserRepo) FindByID(ctx context.Context, id string) (*User, error) {
    // New clean implementation
    row := r.db.QueryRowContext(ctx, "SELECT id, name, email FROM users WHERE id = $1", id)
    // ...
}

// Phase 3: Feature flag to switch traffic
func NewUserRepository(cfg Config) UserRepository {
    if cfg.UseNewUserStore {
        return &PostgresUserRepo{db: cfg.DB}
    }
    return &LegacyUserAdapter{legacy: cfg.LegacyDAO}
}
```

---

## 5. Eliminating Duplication Across a Monorepo (code-deduplication + code-standards + clean-code)

```typescript
// BEFORE: duplicated fetch+retry+error logic in 3 services
// code-deduplication: extract to shared utility

// packages/shared/src/http-client.ts
interface RequestConfig {
  url: string;
  method?: 'GET' | 'POST' | 'PUT' | 'DELETE';
  body?: unknown;
  retries?: number;
  timeoutMs?: number;
}

async function resilientFetch<T>(config: RequestConfig): Promise<T> {
  const { url, method = 'GET', body, retries = 3, timeoutMs = 5000 } = config;
  
  for (let attempt = 1; attempt <= retries; attempt++) {
    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), timeoutMs);
      
      const response = await fetch(url, {
        method,
        headers: { 'Content-Type': 'application/json' },
        body: body ? JSON.stringify(body) : undefined,
        signal: controller.signal,
      });
      clearTimeout(timeout);
      
      if (!response.ok) {
        throw new HttpError(response.status, await response.text());
      }
      return response.json() as T;
    } catch (err) {
      if (attempt === retries) throw err;
      await delay(Math.min(1000 * 2 ** attempt, 10000)); // exponential backoff
    }
  }
  throw new Error('Unreachable');
}

// clean-code: each service now has a single clear call
// code-standards: shared types enforce consistency across services
```

---

## Quick Reference: Skill Combinations by Task

| Task | Primary Skills | Supporting Skills |
|------|----------------|-------------------|
| **Improve existing code** | clean-code, code-refactoring | simplify-complexity, code-deduplication |
| **Set up team standards** | code-standards, code-metrics | code-quality-review |
| **Harden a service** | error-handling, input-validation | logging-strategies |
| **Reduce tech debt** | technical-debt, code-metrics | code-refactoring, legacy-code-migration |
| **Modernize legacy code** | legacy-code-migration, code-refactoring | technical-debt, code-deduplication |
| **Prepare for code review** | code-quality-review, clean-code | code-standards, code-metrics |
| **Eliminate duplication** | code-deduplication, code-standards | clean-code |

---

**See individual skill directories in `../skills/` for detailed implementation guidance.**
