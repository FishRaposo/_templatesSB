# Code Refactoring — Basic Examples

## Extract Method

**JavaScript:**
```javascript
// ❌ Before: inline logic
function printInvoice(invoice) {
  console.log('=== INVOICE ===');
  let total = 0;
  for (const item of invoice.items) {
    const lineTotal = item.price * item.qty;
    total += lineTotal;
    console.log(`  ${item.name}: $${lineTotal.toFixed(2)}`);
  }
  const tax = total * 0.08;
  console.log(`  Subtotal: $${total.toFixed(2)}`);
  console.log(`  Tax: $${tax.toFixed(2)}`);
  console.log(`  Total: $${(total + tax).toFixed(2)}`);
}

// ✅ After: extracted methods
function printInvoice(invoice) {
  printHeader();
  const subtotal = printLineItems(invoice.items);
  printTotals(subtotal);
}

function printHeader() { console.log('=== INVOICE ==='); }

function printLineItems(items) {
  let total = 0;
  for (const item of items) {
    const lineTotal = item.price * item.qty;
    total += lineTotal;
    console.log(`  ${item.name}: $${lineTotal.toFixed(2)}`);
  }
  return total;
}

function printTotals(subtotal) {
  const tax = subtotal * 0.08;
  console.log(`  Subtotal: $${subtotal.toFixed(2)}`);
  console.log(`  Tax: $${tax.toFixed(2)}`);
  console.log(`  Total: $${(subtotal + tax).toFixed(2)}`);
}
```

## Introduce Parameter Object

**Python:**
```python
# ❌ Before: too many parameters
def search_products(query, category, min_price, max_price, sort_by, page, per_page):
    pass

# ✅ After: parameter object
@dataclass
class ProductSearch:
    query: str
    category: str = None
    min_price: float = 0
    max_price: float = float('inf')
    sort_by: str = 'relevance'
    page: int = 1
    per_page: int = 20

def search_products(search: ProductSearch):
    pass

# Clean call site
results = search_products(ProductSearch(query="laptop", category="electronics", max_price=1000))
```

## Replace Conditional with Polymorphism

**Go:**
```go
// ❌ Before: type switch
func calculateArea(shape map[string]interface{}) float64 {
    switch shape["type"] {
    case "circle":
        r := shape["radius"].(float64)
        return math.Pi * r * r
    case "rectangle":
        w := shape["width"].(float64)
        h := shape["height"].(float64)
        return w * h
    default:
        return 0
    }
}

// ✅ After: polymorphism
type Shape interface {
    Area() float64
}

type Circle struct{ Radius float64 }
func (c Circle) Area() float64 { return math.Pi * c.Radius * c.Radius }

type Rectangle struct{ Width, Height float64 }
func (r Rectangle) Area() float64 { return r.Width * r.Height }
```

## When to Use
- "Extract this block into a separate function"
- "This function has too many parameters"
- "Replace this switch statement with something cleaner"
- "Break this large class into smaller ones"
