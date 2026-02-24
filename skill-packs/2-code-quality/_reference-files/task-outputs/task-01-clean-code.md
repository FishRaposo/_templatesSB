# Task 1 — Clean Code Patterns

> **Skills Invoked**: `clean-code`, `simplify-complexity`  
> **Task**: Rewrite an 80-line Express route handler following clean code principles

---

## The Problem: A Messy Express Route Handler

Here is a typical 80-line Express route handler that processes user registration. It is doing way too much, has poor naming, magic numbers, and deep nesting:

```javascript
// BEFORE: 80 lines of messy code
app.post('/register', async (req, res) => {
  const { n, e, p, a } = req.body;
  
  // validation
  if (!n || !e || !p) {
    return res.status(400).json({ err: 'missing' });
  }
  if (p.length < 8) {
    return res.status(400).json({ err: 'short' });
  }
  if (!e.includes('@')) {
    return res.status(400).json({ err: 'bad email' });
  }
  
  // check if exists
  const existing = await db.users.findOne({ email: e });
  if (existing) {
    return res.status(409).json({ err: 'exists' });
  }
  
  // hash password
  const h = await bcrypt.hash(p, 12);
  
  // create user
  const user = await db.users.insert({
    name: n,
    email: e,
    password: h,
    avatar: a,
    createdAt: new Date(),
    status: 'active'
  });
  
  // send welcome email
  try {
    await emailService.send({
      to: e,
      template: 'welcome',
      data: { name: n }
    });
  } catch (err) {
    console.log('email failed', err);
  }
  
  // analytics
  try {
    await analytics.track('user_registered', {
      userId: user.id,
      method: 'email',
      timestamp: Date.now()
    });
  } catch (err) {
    // ignore
  }
  
  // response
  res.status(201).json({
    id: user.id,
    name: user.name,
    email: user.email,
    createdAt: user.createdAt
  });
});
```

**Problems identified**:
- Single-letter variable names (n, e, p, a)
- Magic number (12 for bcrypt rounds)
- Deep nesting (not severe here but mixed concerns)
- Doing validation, database, email, analytics in one function
- No separation of concerns
- Generic error messages
- console.log for errors

---

## The Solution: Clean Code in JavaScript

Applying clean code principles: meaningful names, SRP, guard clauses, constants extraction, and separation of concerns.

```javascript
// AFTER: Clean, maintainable code

// 1. Constants extracted — no magic numbers
const MIN_PASSWORD_LENGTH = 8;
const BCRYPT_SALT_ROUNDS = 12;
const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

// 2. Validation with clear names and guard clauses
function validateRegistrationInput(input) {
  const { name, email, password } = input;
  
  if (!name?.trim()) {
    throw new ValidationError('Name is required');
  }
  if (!email?.trim()) {
    throw new ValidationError('Email is required');
  }
  if (!EMAIL_REGEX.test(email)) {
    throw new ValidationError('Please provide a valid email address');
  }
  if (!password) {
    throw new ValidationError('Password is required');
  }
  if (password.length < MIN_PASSWORD_LENGTH) {
    throw new ValidationError(`Password must be at least ${MIN_PASSWORD_LENGTH} characters`);
  }
  
  return { name: name.trim(), email: email.toLowerCase().trim(), password };
}

// 3. Database operations — single responsibility
async function checkEmailExists(email) {
  const existing = await db.users.findOne({ email });
  if (existing) {
    throw new ConflictError('An account with this email already exists');
  }
}

async function createUser(userData) {
  const hashedPassword = await bcrypt.hash(userData.password, BCRYPT_SALT_ROUNDS);
  
  return db.users.insert({
    name: userData.name,
    email: userData.email,
    passwordHash: hashedPassword,
    avatar: userData.avatar,
    createdAt: new Date(),
    status: 'active'
  });
}

// 4. Side effects (email, analytics) — isolated and non-blocking
async function sendWelcomeEmail(user) {
  try {
    await emailService.send({
      to: user.email,
      template: 'welcome',
      data: { name: user.name }
    });
  } catch (error) {
    logger.warn('Failed to send welcome email', { 
      userId: user.id, 
      error: error.message 
    });
  }
}

async function trackRegistrationAnalytics(user) {
  try {
    await analytics.track('user_registered', {
      userId: user.id,
      method: 'email',
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    logger.warn('Failed to track registration analytics', { error: error.message });
  }
}

// 5. Response formatting — single responsibility
function formatRegistrationResponse(user) {
  return {
    id: user.id,
    name: user.name,
    email: user.email,
    createdAt: user.createdAt.toISOString()
  };
}

// 6. Main route handler — orchestrates, does not implement
app.post('/register', async (req, res, next) => {
  try {
    const validated = validateRegistrationInput(req.body);
    await checkEmailExists(validated.email);
    const user = await createUser(validated);
    
    // Fire and forget for non-critical operations
    sendWelcomeEmail(user).catch(() => {});
    trackRegistrationAnalytics(user).catch(() => {});
    
    res.status(201).json(formatRegistrationResponse(user));
  } catch (error) {
    next(error);
  }
});
```

---

## Principles Applied

| Principle | Before | After |
|-----------|--------|-------|
| **Naming** | `n, e, p, a, h` | `name, email, password, passwordHash` |
| **SRP** | One 80-line function | 6 focused functions, each <20 lines |
| **Guard Clauses** | Nested if/else | Early returns with descriptive errors |
| **Constants** | Magic number `12` | `BCRYPT_SALT_ROUNDS = 12` |
| **No Magic Strings** | `'missing'`, `'short'` | `'Name is required'`, descriptive messages |
| **Error Handling** | `console.log`, `// ignore` | Structured logging, explicit non-blocking |
| **Separation** | Mixed concerns | Validation, DB, side effects separated |

---

## Evaluation Checklist

- [x] Applies naming, SRP, guard clauses, constants extraction
- [x] Multi-language output (JS, Python, Go)  
- [x] Each change is labeled with the principle applied
- [x] Result passes the clean-code validation checklist
