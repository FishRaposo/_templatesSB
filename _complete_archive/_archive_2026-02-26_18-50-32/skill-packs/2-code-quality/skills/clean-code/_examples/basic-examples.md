# Clean Code — Basic Examples

## Naming: Reveal Intent

**JavaScript:**
```javascript
// ❌ Unclear
const d = new Date();
const list = data.filter(x => x.a);
function proc(r) { return r.s === 'ok'; }

// ✅ Clear
const accountCreatedDate = new Date();
const activeUsers = users.filter(user => user.isActive);
function isResponseSuccessful(response) { return response.status === 'ok'; }
```

**Python:**
```python
# ❌ Unclear
def calc(l):
    return sum(i.p * i.q for i in l)

# ✅ Clear
def calculate_order_total(line_items):
    return sum(item.price * item.quantity for item in line_items)
```

**Go:**
```go
// ❌ Unclear
func f(s []int) int {
    r := 0
    for _, v := range s { r += v }
    return r
}

// ✅ Clear
func sumTransactionAmounts(amounts []int) int {
    total := 0
    for _, amount := range amounts { total += amount }
    return total
}
```

## Function Size: Single Responsibility

**JavaScript:**
```javascript
// ❌ Does too many things
async function registerUser(data) {
  if (!data.email.includes('@')) throw new Error('Invalid email');
  if (data.password.length < 8) throw new Error('Password too short');
  const hash = await bcrypt.hash(data.password, 10);
  const user = await db.users.create({ ...data, password: hash });
  await sendEmail(user.email, 'Welcome!', welcomeTemplate(user));
  await analytics.track('user_registered', { userId: user.id });
  return user;
}

// ✅ Each function does one thing
async function registerUser(data) {
  validateRegistration(data);
  const user = await createUserRecord(data);
  await sendWelcomeEmail(user);
  await trackRegistration(user);
  return user;
}

function validateRegistration(data) {
  if (!data.email.includes('@')) throw new ValidationError('Invalid email');
  if (data.password.length < 8) throw new ValidationError('Password too short');
}

async function createUserRecord(data) {
  const hash = await bcrypt.hash(data.password, 10);
  return db.users.create({ ...data, password: hash });
}
```

## Guard Clauses: Flatten Nesting

**Python:**
```python
# ❌ Deep nesting
def process_payment(order):
    if order is not None:
        if order.status == "confirmed":
            if order.total > 0:
                if order.payment_method is not None:
                    return charge(order)
                else:
                    raise ValueError("No payment method")
            else:
                raise ValueError("Invalid total")
        else:
            raise ValueError("Not confirmed")
    else:
        raise ValueError("No order")

# ✅ Guard clauses
def process_payment(order):
    if order is None:
        raise ValueError("No order")
    if order.status != "confirmed":
        raise ValueError("Not confirmed")
    if order.total <= 0:
        raise ValueError("Invalid total")
    if order.payment_method is None:
        raise ValueError("No payment method")
    return charge(order)
```

## Constants: No Magic Numbers

**Go:**
```go
// ❌ Magic numbers
if attempts > 3 {
    time.Sleep(30 * time.Second)
}
if len(password) < 8 {
    return errors.New("too short")
}

// ✅ Named constants
const (
    MaxRetryAttempts    = 3
    RetryBackoffSeconds = 30
    MinPasswordLength   = 8
)

if attempts > MaxRetryAttempts {
    time.Sleep(RetryBackoffSeconds * time.Second)
}
if len(password) < MinPasswordLength {
    return fmt.Errorf("password must be at least %d characters", MinPasswordLength)
}
```

## When to Use
- "Make this code more readable"
- "Suggest better names for these variables"
- "This function is too long, break it up"
- "Remove the magic numbers from this code"
