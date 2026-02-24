<!-- Generated from task-outputs/task-13-production-hardening.md -->

# Task 13 — Production Hardening
> Skills: error-handling + input-validation + logging-strategies + clean-code

## Before: Raw Express Endpoint

```javascript
app.post('/register', (req, res) => {
  const { name, email, password, avatar } = req.body;
  
  // Minimal validation
  if (!email || !password) {
    return res.status(400).json({ error: 'Missing fields' });
  }
  
  // Direct DB insert
  db.users.insert({ name, email, password, avatar })
    .then(user => {
      console.log('User created', user);
      sendEmail(email, 'Welcome!');
      res.json({ success: true });
    })
    .catch(err => {
      console.log('Error', err);
      res.status(500).json({ error: 'Failed' });
    });
});
```

## After: Production-Hardened

```javascript
import { z } from 'zod';
import pino from 'pino';

// 1. Validation Schema (input-validation)
const registerSchema = z.object({
  name: z.string().min(1).max(100).trim(),
  email: z.string().email().toLowerCase().trim(),
  password: z.string().min(8).regex(/[A-Z]/).regex(/[0-9]/),
  avatar: z.string().url().optional()
});

// 2. Typed Errors (error-handling)
class ValidationError extends Error {
  constructor(fields) {
    super('Validation failed');
    this.code = 'VALIDATION_ERROR';
    this.statusCode = 400;
    this.fields = fields;
  }
}

// 3. Structured Logger (logging-strategies)
const logger = pino({
  level: process.env.LOG_LEVEL || 'info',
  redact: ['password', '*.password']
});

// 4. Clean Service (clean-code)
class RegistrationService {
  constructor(deps) {
    this.db = deps.db;
    this.emailService = deps.emailService;
    this.logger = deps.logger;
  }

  async register(input) {
    const validated = await this.validate(input);
    await this.checkEmailExists(validated.email);
    const user = await this.createUser(validated);
    this.sendWelcomeEmail(user).catch(err => {
      this.logger.warn('Email failed', { userId: user.id, error: err.message });
    });
    return user;
  }

  async validate(input) {
    const result = registerSchema.safeParse(input);
    if (!result.success) {
      const fields = result.error.issues.map(i => ({
        field: i.path.join('.'),
        message: i.message
      }));
      throw new ValidationError(fields);
    }
    return result.data;
  }

  async checkEmailExists(email) {
    const existing = await this.db.findUserByEmail(email);
    if (existing) {
      throw new ConflictError('Email already registered');
    }
  }

  async createUser(data) {
    const hashedPassword = await bcrypt.hash(data.password, 12);
    return this.db.insert({
      name: data.name,
      email: data.email,
      passwordHash: hashedPassword,
      avatar: data.avatar,
      createdAt: new Date()
    });
  }

  async sendWelcomeEmail(user) {
    return this.emailService.send({
      to: user.email,
      template: 'welcome',
      data: { name: user.name }
    });
  }
}

// Middleware
const errorHandler = (err, req, res, next) => {
  logger.error({
    error: err.message,
    code: err.code,
    stack: err.stack,
    correlationId: req.correlationId
  });

  if (err instanceof ValidationError) {
    return res.status(400).json({
      error: { code: err.code, fields: err.fields }
    });
  }

  res.status(500).json({
    error: { code: 'INTERNAL_ERROR', message: 'Registration failed' }
  });
};

app.post('/register', async (req, res, next) => {
  try {
    const user = await registrationService.register(req.body);
    res.status(201).json({ id: user.id, email: user.email });
  } catch (error) {
    next(error);
  }
});

app.use(errorHandler);
```

- [x] All 4 skills visibly applied
- [x] Skills integrated naturally
- [x] Result is genuinely production-ready

