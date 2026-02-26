---
name: code-refactoring
description: Use this skill when restructuring existing code without changing its behavior. This includes extract method, rename, inline, move, and other refactoring patterns to improve design while preserving functionality.
---

# Code Refactoring

I'll help you improve code structure without changing its external behavior. When you invoke this skill, I can guide you through safe, incremental transformations using proven refactoring patterns.

# Core Approach

My approach focuses on:
1. Identifying code smells that indicate refactoring opportunities
2. Selecting the right refactoring pattern for each smell
3. Making small, testable changes one at a time
4. Verifying behavior is preserved after each step

# Step-by-Step Instructions

## 1. Identify Code Smells

First, I'll help you spot what needs refactoring:

- **Long Method**: Functions doing too much (>50 lines)
- **Large Class**: Classes with too many responsibilities
- **Feature Envy**: Method uses another class's data more than its own
- **Primitive Obsession**: Using primitives instead of small objects
- **Shotgun Surgery**: One change requires edits in many places
- **Duplicate Code**: Same logic in multiple locations

```bash
# Find long functions
grep -rn "function\|def \|func " src/ | awk '{print $1}' | \
  while read file; do echo "$file $(wc -l < "$file")"; done | \
  sort -t: -k2 -rn | head -20

# Find large files (potential god classes)
find src/ -name "*.ts" -o -name "*.py" -o -name "*.go" | \
  xargs wc -l | sort -rn | head -20
```

## 2. Apply Refactoring Patterns

### Extract Method
Pull a block of code into a named function:

**JavaScript:**
```javascript
// Before
function printReport(invoice) {
  console.log('=== Invoice ===');
  console.log(`Customer: ${invoice.customer}`);
  let total = 0;
  for (const item of invoice.items) {
    total += item.price * item.quantity;
    console.log(`  ${item.name}: $${item.price * item.quantity}`);
  }
  console.log(`Total: $${total}`);
}

// After: Extract Method
function printReport(invoice) {
  printHeader(invoice.customer);
  const total = printLineItems(invoice.items);
  printTotal(total);
}

function printHeader(customer) {
  console.log('=== Invoice ===');
  console.log(`Customer: ${customer}`);
}

function printLineItems(items) {
  let total = 0;
  for (const item of items) {
    const lineTotal = item.price * item.quantity;
    total += lineTotal;
    console.log(`  ${item.name}: $${lineTotal}`);
  }
  return total;
}
```

### Replace Conditional with Polymorphism

**Python:**
```python
# Before: type-checking conditional
def calculate_pay(employee):
    if employee.type == "full_time":
        return employee.salary / 12
    elif employee.type == "contractor":
        return employee.hours * employee.rate
    elif employee.type == "intern":
        return employee.stipend

# After: polymorphism
class FullTimeEmployee:
    def calculate_pay(self):
        return self.salary / 12

class Contractor:
    def calculate_pay(self):
        return self.hours * self.rate

class Intern:
    def calculate_pay(self):
        return self.stipend
```

### Introduce Parameter Object

**Go:**
```go
// Before: too many parameters
func createUser(name, email, phone string, age int, active bool, role string) error {
    // ...
}

// After: parameter object
type CreateUserRequest struct {
    Name   string
    Email  string
    Phone  string
    Age    int
    Active bool
    Role   string
}

func createUser(req CreateUserRequest) error {
    // ...
}
```

## 3. Verify Behavior Preservation

After each refactoring step:

```bash
# Run tests after every change
npm test                    # JavaScript
pytest -x                   # Python
go test ./...               # Go

# Check for regressions with coverage
npm test -- --coverage      # JS
pytest --cov=src --cov-fail-under=80  # Python
go test -cover ./...        # Go
```

# Best Practices

- Always have tests before refactoring — if none exist, write characterization tests first
- Make one refactoring at a time, commit after each
- Use IDE refactoring tools when available (rename, extract, inline)
- Refactor in small steps — never combine refactoring with feature changes
- If tests break, undo and try a smaller step
- Document the refactoring intent in commit messages

# Validation Checklist

When completing a refactoring, verify:
- [ ] All existing tests still pass
- [ ] No new behavior was introduced
- [ ] Code is measurably improved (shorter, clearer, less coupled)
- [ ] Each refactoring step was committed separately
- [ ] No refactoring was combined with feature changes

# Troubleshooting

## Issue: No Tests to Verify Against

**Symptoms**: Legacy code with no test coverage, afraid to change

**Solution**:
- Write characterization tests that capture current behavior
- Use approval testing to snapshot outputs
- Add tests around the specific area you're refactoring
- Consider using `git stash` to test before/after

## Issue: Refactoring Breaks Something

**Symptoms**: Tests fail after refactoring

**Solution**:
- Undo immediately (`git checkout -- .` or `git stash`)
- Break the refactoring into smaller steps
- Add more granular tests around the affected area
- Use IDE automated refactorings which are safer

# Supporting Files

- See `./_examples/basic-examples.md` for Extract Method, Parameter Object, and Polymorphism examples
- See `./README.md` for quick start and invocation examples

## Related Skills

- **clean-code** - Identify what needs refactoring through cleanliness review
- **code-deduplication** - Eliminate duplication discovered during refactoring
- **simplify-complexity** - Reduce complexity revealed by refactoring
- **technical-debt** - Prioritize which refactorings to tackle first
- → **3-testing-mastery**: unit-testing (for safety net before refactoring)
- → **1-programming-core**: abstraction (for designing better abstractions during refactoring)

Remember: Refactoring is not rewriting — change structure, preserve behavior!
