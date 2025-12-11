# Universal Template System - Typescript Stack
# Generated: 2025-12-10
# Purpose: Testing utilities
# Tier: base
# Stack: typescript
# Category: testing

# TypeScript Unit Testing Pattern

> **Comprehensive unit testing strategies for TypeScript applications with Jest and type safety**

## 🎯 Overview

This pattern provides a robust framework for unit testing TypeScript applications with full type safety, mocking capabilities, and comprehensive test coverage strategies.

## 🛠️ Technology Stack

### Core Testing Framework
- **Jest**: JavaScript testing framework with excellent TypeScript support
- **ts-jest**: TypeScript preprocessor for Jest
- **@types/jest**: TypeScript type definitions for Jest

### Mocking & Utilities
- **jest.mock**: Built-in mocking capabilities
- **sinon**: Advanced spying, stubbing, and mocking
- **@types/sinon**: TypeScript definitions for Sinon

### Coverage & Reporting
- **Jest Coverage**: Built-in code coverage reporting
- **Istanbul**: Coverage instrumentation
- **Coverage Reporters**: HTML, LCOV, and text formats

## 📋 Test Structure

### Directory Organization

```
tests/
├── unit/                   # Unit tests
│   ├── controllers/        # Controller tests
│   ├── services/          # Service tests
│   ├── models/            # Model tests
│   ├── middleware/        # Middleware tests
│   ├── utils/             # Utility tests
│   └── fixtures/          # Test fixtures and data
├── integration/           # Integration tests
├── e2e/                   # End-to-end tests
├── helpers/               # Test helpers and utilities
├── mocks/                 # Mock implementations
└── setup/                 # Test setup files
```

### File Naming Conventions

```bash
# Test file patterns
*.test.ts          # Standard test files
*.spec.ts          # Specification-style tests
__tests__/         # Test directories
setup.ts           # Global test setup
teardown.ts        # Global test cleanup
```

## ⚙️ Configuration

### Jest Configuration (jest.config.js)

```javascript
module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  roots: ['<rootDir>/src', '<rootDir>/tests'],
  testMatch: [
    '**/__tests__/**/*.ts',
    '**/?(*.)+(spec|test).ts'
  ],
  transform: {
    '^.+\\.ts$': 'ts-jest',
  },
  collectCoverageFrom: [
    'src/**/*.ts',
    '!src/**/*.d.ts',
    '!src/**/*.test.ts',
    '!src/**/*.spec.ts',
    '!src/test/**/*',
  ],
  coverageDirectory: 'coverage',
  coverageReporters: ['text', 'lcov', 'html', 'json'],
  coverageThreshold: {
    global: {
      branches: 80,
      functions: 80,
      lines: 80,
      statements: 80,
    },
  },
  moduleNameMapping: {
    '^@/(.*)$': '<rootDir>/src/$1',
    '^@tests/(.*)$': '<rootDir>/tests/$1',
  },
  setupFilesAfterEnv: ['<rootDir>/tests/setup.ts'],
  testTimeout: 10000,
  verbose: true,
  clearMocks: true,
  restoreMocks: true,
};
```

### TypeScript Test Configuration

```json
// tsconfig.test.json
{
  "extends": "./tsconfig.json",
  "compilerOptions": {
    "types": ["jest", "node"],
    "esModuleInterop": true,
    "allowSyntheticDefaultImports": true
  },
  "include": [
    "src/**/*",
    "tests/**/*"
  ],
  "exclude": [
    "node_modules",
    "dist"
  ]
}
```

## 🧪 Test Patterns

### Basic Unit Test Structure

```typescript
// tests/unit/services/UserService.test.ts
import { UserService } from '@/services/UserService';
import { IUserRepository } from '@/interfaces/IUserRepository';
import { User } from '@/models/User';

describe('UserService', () => {
  let userService: UserService;
  let mockRepository: jest.Mocked<IUserRepository>;

  beforeEach(() => {
    // Create mock repository
    mockRepository = {
      findById: jest.fn(),
      findByEmail: jest.fn(),
      save: jest.fn(),
      delete: jest.fn(),
    } as jest.Mocked<IUserRepository>;

    // Create service instance with mock
    userService = new UserService(mockRepository);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('createUser', () => {
    it('should create a user with valid data', async () => {
      // Arrange
      const userData = {
        name: 'John Doe',
        email: 'john@example.com',
        password: 'securepassword123',
      };

      const expectedUser: User = {
        id: '123',
        ...userData,
        createdAt: new Date(),
        updatedAt: new Date(),
      };

      mockRepository.save.mockResolvedValue(expectedUser);

      // Act
      const result = await userService.createUser(userData);

      // Assert
      expect(result).toEqual(expectedUser);
      expect(mockRepository.save).toHaveBeenCalledWith(
        expect.objectContaining({
          name: userData.name,
          email: userData.email,
        })
      );
    });

    it('should throw error for duplicate email', async () => {
      // Arrange
      const userData = {
        name: 'John Doe',
        email: 'existing@example.com',
        password: 'securepassword123',
      };

      mockRepository.findByEmail.mockResolvedValue({
        id: '456',
        email: 'existing@example.com',
      } as User);

      // Act & Assert
      await expect(userService.createUser(userData))
        .rejects
        .toThrow('User with this email already exists');

      expect(mockRepository.save).not.toHaveBeenCalled();
    });
  });
});
```

### Controller Testing Pattern

```typescript
// tests/unit/controllers/UserController.test.ts
import request from 'supertest';
import { UserController } from '@/controllers/UserController';
import { UserService } from '@/services/UserService';
import { createApp } from '@/app';

describe('UserController', () => {
  let userController: UserController;
  let mockUserService: jest.Mocked<UserService>;
  let app: Express.Application;

  beforeEach(() => {
    // Mock service
    mockUserService = {
      createUser: jest.fn(),
      getUserById: jest.fn(),
      updateUser: jest.fn(),
      deleteUser: jest.fn(),
    } as jest.Mocked<UserService>;

    // Create controller with mock service
    userController = new UserController(mockUserService);

    // Create Express app with controller
    app = createApp();
    app.use('/users', userController.getRouter());
  });

  describe('POST /users', () => {
    it('should create a new user', async () => {
      // Arrange
      const userData = {
        name: 'John Doe',
        email: 'john@example.com',
        password: 'securepassword123',
      };

      const createdUser = {
        id: '123',
        ...userData,
        createdAt: new Date(),
      };

      mockUserService.createUser.mockResolvedValue(createdUser as any);

      // Act
      const response = await request(app)
        .post('/users')
        .send(userData)
        .expect(201);

      // Assert
      expect(response.body).toEqual({
        success: true,
        data: createdUser,
      });

      expect(mockUserService.createUser).toHaveBeenCalledWith(userData);
    });

    it('should return 400 for invalid data', async () => {
      // Arrange
      const invalidData = {
        name: '',
        email: 'invalid-email',
        password: '123',
      };

      // Act
      const response = await request(app)
        .post('/users')
        .send(invalidData)
        .expect(400);

      // Assert
      expect(response.body.success).toBe(false);
      expect(response.body.error).toContain('Validation failed');
    });
  });
});
```

### Service Testing with Mocks

```typescript
// tests/unit/services/EmailService.test.ts
import { EmailService } from '@/services/EmailService';
import nodemailer from 'nodemailer';

jest.mock('nodemailer');

describe('EmailService', () => {
  let emailService: EmailService;
  let mockTransporter: jest.Mocked<nodemailer.Transporter>;

  beforeEach(() => {
    // Mock nodemailer transporter
    mockTransporter = {
      sendMail: jest.fn(),
    } as any;

    (nodemailer.createTransporter as jest.Mock).mockReturnValue(mockTransporter);

    emailService = new EmailService({
      host: 'smtp.example.com',
      port: 587,
      auth: {
        user: 'test@example.com',
        pass: 'password',
      },
    });
  });

  describe('sendWelcomeEmail', () => {
    it('should send welcome email successfully', async () => {
      // Arrange
      const user = {
        id: '123',
        name: 'John Doe',
        email: 'john@example.com',
      };

      mockTransporter.sendMail.mockResolvedValue({ messageId: 'abc123' });

      // Act
      const result = await emailService.sendWelcomeEmail(user);

      // Assert
      expect(result).toBe(true);
      expect(mockTransporter.sendMail).toHaveBeenCalledWith(
        expect.objectContaining({
          to: user.email,
          subject: 'Welcome to our platform!',
          html: expect.stringContaining(user.name),
        })
      );
    });

    it('should handle email sending failure', async () => {
      // Arrange
      const user = {
        id: '123',
        name: 'John Doe',
        email: 'john@example.com',
      };

      mockTransporter.sendMail.mockRejectedValue(new Error('SMTP error'));

      // Act & Assert
      await expect(emailService.sendWelcomeEmail(user))
        .rejects
        .toThrow('Failed to send welcome email');
    });
  });
});
```

### Utility Function Testing

```typescript
// tests/unit/utils/validation.test.ts
import { 
  validateEmail, 
  validatePassword, 
  sanitizeInput,
  generateToken 
} from '@/utils/validation';

describe('Validation Utils', () => {
  describe('validateEmail', () => {
    it('should return true for valid email addresses', () => {
      expect(validateEmail('user@example.com')).toBe(true);
      expect(validateEmail('test.email+tag@domain.co.uk')).toBe(true);
      expect(validateEmail('user123@test-domain.com')).toBe(true);
    });

    it('should return false for invalid email addresses', () => {
      expect(validateEmail('invalid-email')).toBe(false);
      expect(validateEmail('@domain.com')).toBe(false);
      expect(validateEmail('user@')).toBe(false);
      expect(validateEmail('user..name@domain.com')).toBe(false);
    });

    it('should handle edge cases', () => {
      expect(validateEmail('')).toBe(false);
      expect(validateEmail(null as any)).toBe(false);
      expect(validateEmail(undefined as any)).toBe(false);
    });
  });

  describe('validatePassword', () => {
    it('should validate strong passwords', () => {
      const result = validatePassword('StrongP@ssw0rd123');
      expect(result.isValid).toBe(true);
      expect(result.errors).toHaveLength(0);
    });

    it('should reject weak passwords', () => {
      const result = validatePassword('weak');
      expect(result.isValid).toBe(false);
      expect(result.errors.length).toBeGreaterThan(0);
      expect(result.errors).toContain('Password must be at least 8 characters long');
    });
  });
});
```

## 🔧 Test Utilities

### Custom Matchers

```typescript
// tests/helpers/customMatchers.ts
import { User } from '@/models/User';

expect.extend({
  toBeValidUser(received: User) {
    const pass = received && 
      typeof received.id === 'string' &&
      typeof received.email === 'string' &&
      typeof received.name === 'string';

    if (pass) {
      return {
        message: () => `expected ${received} not to be a valid user`,
        pass: true,
      };
    } else {
      return {
        message: () => `expected ${received} to be a valid user`,
        pass: false,
      };
    }
  },

  toBeWithinRange(received: number, floor: number, ceiling: number) {
    const pass = received >= floor && received <= ceiling;
    
    if (pass) {
      return {
        message: () => `expected ${received} not to be within range ${floor} - ${ceiling}`,
        pass: true,
      };
    } else {
      return {
        message: () => `expected ${received} to be within range ${floor} - ${ceiling}`,
        pass: false,
      };
    }
  },
});

declare global {
  namespace jest {
    interface Matchers<R> {
      toBeValidUser(): R;
      toBeWithinRange(floor: number, ceiling: number): R;
    }
  }
}
```

### Test Fixtures

```typescript
// tests/fixtures/userFixtures.ts
import { User, CreateUserRequest } from '@/models/User';

export const userFixtures = {
  validUser: {
    name: 'John Doe',
    email: 'john@example.com',
    password: 'SecureP@ssw0rd123',
  } as CreateUserRequest,

  invalidUser: {
    name: '',
    email: 'invalid-email',
    password: '123',
  } as CreateUserRequest,

  existingUser: {
    id: '123',
    name: 'Jane Doe',
    email: 'jane@example.com',
    password: 'hashedpassword',
    createdAt: new Date('2023-01-01'),
    updatedAt: new Date('2023-01-01'),
  } as User,

  multipleUsers: [
    {
      id: '1',
      name: 'User One',
      email: 'user1@example.com',
      createdAt: new Date(),
      updatedAt: new Date(),
    },
    {
      id: '2',
      name: 'User Two',
      email: 'user2@example.com',
      createdAt: new Date(),
      updatedAt: new Date(),
    },
  ] as User[],
};
```

### Mock Factories

```typescript
// tests/mocks/mockFactory.ts
import { User, CreateUserRequest } from '@/models/User';

export class MockUserFactory {
  static createUser(overrides: Partial<User> = {}): User {
    return {
      id: Math.random().toString(36).substr(2, 9),
      name: 'Test User',
      email: 'test@example.com',
      password: 'hashedpassword',
      createdAt: new Date(),
      updatedAt: new Date(),
      ...overrides,
    };
  }

  static createUsers(count: number, overrides: Partial<User> = {}): User[] {
    return Array.from({ length: count }, () => this.createUser(overrides));
  }

  static createCreateUserRequest(overrides: Partial<CreateUserRequest> = {}): CreateUserRequest {
    return {
      name: 'Test User',
      email: 'test@example.com',
      password: 'SecureP@ssw0rd123',
      ...overrides,
    };
  }
}
```

### Database Test Helpers

```typescript
// tests/helpers/databaseHelper.ts
import { setupTestDatabase, cleanupTestDatabase } from '@/test/database';

export class DatabaseHelper {
  private static connection: any;

  static async setup(): Promise<void> {
    this.connection = await setupTestDatabase();
  }

  static async cleanup(): Promise<void> {
    await cleanupTestDatabase(this.connection);
    this.connection = null;
  }

  static async truncateTables(): Promise<void> {
    const tables = ['users', 'posts', 'comments'];
    
    for (const table of tables) {
      await this.connection.query(`TRUNCATE TABLE ${table} CASCADE`);
    }
  }

  static async seedData(data: any): Promise<void> {
    // Seed test data
    for (const [table, records] of Object.entries(data)) {
      if (Array.isArray(records) && records.length > 0) {
        await this.connection.insert(table, records);
      }
    }
  }
}
```

## 🎯 Testing Strategies

### Test-Driven Development (TDD)

```typescript
// Example TDD workflow for a new feature

// 1. Write failing test first
describe('UserService.calculateUserScore', () => {
  it('should calculate user score based on activity', async () => {
    // Arrange
    const user = MockUserFactory.createUser({
      postsCount: 10,
      commentsCount: 25,
      likesReceived: 100,
    });

    // Act
    const score = await userService.calculateUserScore(user.id);

    // Assert
    expect(score).toBe(135); // 10 + 25 + 100
  });
});

// 2. Implement minimal code to make test pass
class UserService {
  async calculateUserScore(userId: string): Promise<number> {
    // Implementation to satisfy test
    return 135;
  }
}

// 3. Refactor and improve implementation
class UserService {
  async calculateUserScore(userId: string): Promise<number> {
    const user = await this.userRepository.findById(userId);
    
    if (!user) {
      throw new Error('User not found');
    }

    return (user.postsCount || 0) + 
           (user.commentsCount || 0) + 
           (user.likesReceived || 0);
  }
}
```

### Behavior-Driven Development (BDD)

```typescript
// tests/unit/services/OrderService.bdd.test.ts
describe('Order Service', () => {
  let orderService: OrderService;
  let mockPaymentService: jest.Mocked<PaymentService>;

  beforeEach(() => {
    mockPaymentService = {
      processPayment: jest.fn(),
    } as any;
    
    orderService = new OrderService(mockPaymentService);
  });

  describe('Order Processing', () => {
    describe('When processing a valid order', () => {
      it('should charge the customer and confirm the order', async () => {
        // Given
        const order = createValidOrder();
        mockPaymentService.processPayment.mockResolvedValue({ success: true });

        // When
        const result = await orderService.processOrder(order);

        // Then
        expect(result.status).toBe('confirmed');
        expect(mockPaymentService.processPayment).toHaveBeenCalledWith(order.paymentDetails);
      });
    });

    describe('When payment fails', () => {
      it('should mark the order as failed', async () => {
        // Given
        const order = createValidOrder();
        mockPaymentService.processPayment.mockResolvedValue({ success: false });

        // When
        const result = await orderService.processOrder(order);

        // Then
        expect(result.status).toBe('payment_failed');
        expect(result.errorMessage).toContain('Payment declined');
      });
    });
  });
});
```

### Property-Based Testing

```typescript
// tests/unit/utils/mathUtils.test.ts
import fc from 'fast-check';

describe('Math Utils', () => {
  describe('add', () => {
    it('should be commutative', () => {
      fc.assert(
        fc.property(fc.integer(), fc.integer(), (a, b) => {
          expect(add(a, b)).toBe(add(b, a));
        })
      );
    });

    it('should be associative', () => {
      fc.assert(
        fc.property(fc.integer(), fc.integer(), fc.integer(), (a, b, c) => {
          expect(add(add(a, b), c)).toBe(add(a, add(b, c)));
        })
      );
    });

    it('should have identity element 0', () => {
      fc.assert(
        fc.property(fc.integer(), (a) => {
          expect(add(a, 0)).toBe(a);
          expect(add(0, a)).toBe(a);
        })
      );
    });
  });
});
```

## 📊 Coverage & Reporting

### Coverage Configuration

```javascript
// jest.config.js (coverage section)
module.exports = {
  // ... other config
  collectCoverageFrom: [
    'src/**/*.ts',
    '!src/**/*.d.ts',
    '!src/**/*.test.ts',
    '!src/**/*.spec.ts',
    '!src/test/**/*',
    '!src/migrations/**/*',
    '!src/seeds/**/*',
  ],
  coverageThreshold: {
    global: {
      branches: 80,
      functions: 80,
      lines: 80,
      statements: 80,
    },
    './src/services/': {
      branches: 90,
      functions: 90,
      lines: 90,
      statements: 90,
    },
  },
  coverageReporters: [
    'text',
    'text-summary',
    'lcov',
    'html',
    'json',
    'cobertura',
  ],
};
```

### Custom Coverage Scripts

```json
// package.json scripts
{
  "scripts": {
    "test": "jest",
    "test:watch": "jest --watch",
    "test:coverage": "jest --coverage",
    "test:coverage:watch": "jest --coverage --watchAll",
    "test:ci": "jest --coverage --ci --watchAll=false",
    "coverage:report": "jest --coverage && open coverage/lcov-report/index.html",
    "coverage:badge": "jest --coverage && coverage-badge-creator"
  }
}
```

## 🔧 Advanced Patterns

### Async Testing Patterns

```typescript
// tests/unit/services/AsyncService.test.ts
describe('AsyncService', () => {
  describe('async operations', () => {
    it('should handle promises correctly', async () => {
      const promise = Promise.resolve('test data');
      
      await expect(promise).resolves.toBe('test data');
      await expect(Promise.reject('error')).rejects.toBe('error');
    });

    it('should handle timeout scenarios', async () => {
      const timeoutPromise = new Promise((_, reject) => {
        setTimeout(() => reject(new Error('Timeout')), 100);
      });

      await expect(timeoutPromise).rejects.toThrow('Timeout');
    }, 200); // Test timeout

    it('should handle concurrent operations', async () => {
      const operations = [
        service.operation1(),
        service.operation2(),
        service.operation3(),
      ];

      const results = await Promise.all(operations);
      expect(results).toHaveLength(3);
    });
  });
});
```

### Error Handling Tests

```typescript
// tests/unit/services/ErrorHandlingService.test.ts
describe('ErrorHandlingService', () => {
  it('should handle service errors gracefully', async () => {
    // Arrange
    mockRepository.findById.mockRejectedValue(new Error('Database connection failed'));

    // Act & Assert
    await expect(service.getUser('123'))
      .rejects
      .toThrow('Database connection failed');
  });

  it('should validate error types', async () => {
    // Arrange
    mockRepository.findById.mockRejectedValue(new ValidationError('Invalid input'));

    // Act & Assert
    await expect(service.getUser('invalid-id'))
      .rejects
      .toThrow(ValidationError);
  });

  it('should handle null/undefined responses', async () => {
    // Arrange
    mockRepository.findById.mockResolvedValue(null);

    // Act & Assert
    await expect(service.getUser('nonexistent'))
      .rejects
      .toThrow('User not found');
  });
});
```

## 🎯 Best Practices

### Test Organization

1. **Describe blocks**: Use nested describe blocks for logical grouping
2. **Test naming**: Use clear, descriptive test names
3. **AAA pattern**: Arrange, Act, Assert structure
4. **One assertion per test**: Keep tests focused
5. **Independent tests**: Tests should not depend on each other

### Mocking Strategy

1. **Mock external dependencies**: Don't test external services
2. **Use factories**: Create test data with factories
3. **Avoid over-mocking**: Mock only what's necessary
4. **Reset mocks**: Clean up between tests
5. **Verify interactions**: Check that mocks are called correctly

### Type Safety

1. **Type assertions**: Use proper TypeScript types in tests
2. **Mock typing**: Type your mocks correctly
3. **Interface testing**: Test against interfaces, not implementations
4. **Generic tests**: Use generics for reusable test utilities

### Performance

1. **Parallel execution**: Run tests in parallel where possible
2. **Selective mocking**: Mock expensive operations
3. **Test isolation**: Ensure tests don't share state
4. **Coverage optimization**: Exclude unnecessary files from coverage

---

## 📚 Additional Resources

- [Jest Documentation](https://jestjs.io/docs/getting-started)
- [TypeScript Jest Guide](https://basarat.gitbook.io/typescript/testing/jest)
- [Testing Best Practices](https://kentcdodds.com/blog/common-mistakes-with-react-testing-library)

---

*Unit Testing Pattern Version: [[.Version]]*  
*Author: [[.Author]]*  
*Date: [[.Date]]*
