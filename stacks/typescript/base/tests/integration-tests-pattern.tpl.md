# Universal Template System - Typescript Stack
# Generated: 2025-12-10
# Purpose: Testing utilities
# Tier: base
# Stack: typescript
# Category: testing

# TypeScript Integration Testing Pattern

> **Comprehensive integration testing strategies for TypeScript applications with API testing, database integration, and end-to-end workflows**

## 🎯 Overview

This pattern provides a robust framework for integration testing TypeScript applications, covering API endpoints, database operations, external service integration, and complete user workflows.

## 🛠️ Technology Stack

### Core Testing Framework
- **Jest**: JavaScript testing framework with TypeScript support
- **Supertest**: HTTP assertion library for API testing
- **ts-jest**: TypeScript preprocessor for Jest

### Database & External Services
- **Test Containers**: Docker containers for database testing
- **MongoDB Memory Server**: In-memory MongoDB for testing
- **SQLite**: In-memory SQLite for testing
- **Nock**: HTTP mocking for external API calls

### Utilities & Helpers
- **Factory Boy**: Test data factories
- **Faker**: Fake data generation
- **Axios**: HTTP client for API testing
- **Wait-for**: Async waiting utilities

## 📋 Integration Test Structure

### Directory Organization

```
tests/
├── integration/            # Integration tests
│   ├── api/               # API endpoint tests
│   ├── database/          # Database integration tests
│   ├── services/          # Service integration tests
│   ├── external/          # External service tests
│   └── workflows/         # End-to-end workflow tests
├── e2e/                   # End-to-end tests
├── fixtures/              # Test fixtures and data
├── helpers/               # Integration test helpers
├── setup/                 # Integration test setup
└── docker/                # Docker configurations
```

### Test Configuration

```javascript
// jest.integration.config.js
module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  roots: ['<rootDir>/tests/integration'],
  testMatch: [
    '**/integration/**/*.test.ts',
    '**/integration/**/*.spec.ts'
  ],
  transform: {
    '^.+\\.ts$': 'ts-jest',
  },
  setupFilesAfterEnv: ['<rootDir>/tests/integration/setup.ts'],
  testTimeout: 30000, // Longer timeout for integration tests
  maxWorkers: 1, // Run sequentially to avoid database conflicts
  clearMocks: true,
  restoreMocks: true,
};
```

## 🌐 API Integration Testing

### Express API Testing

```typescript
// tests/integration/api/users.test.ts
import request from 'supertest';
import { createApp } from '@/app';
import { setupTestDatabase, cleanupTestDatabase } from '@/helpers/databaseHelper';

describe('Users API Integration', () => {
  let app: Express.Application;
  let databaseConnection: any;

  beforeAll(async () => {
    // Setup test database
    databaseConnection = await setupTestDatabase();
    
    // Create Express app with test configuration
    app = createApp({
      database: databaseConnection,
      environment: 'test',
    });
  });

  afterAll(async () => {
    // Cleanup database
    await cleanupTestDatabase(databaseConnection);
  });

  beforeEach(async () => {
    // Clean database before each test
    await databaseConnection.truncateAllTables();
  });

  describe('POST /api/users', () => {
    it('should create a new user', async () => {
      const userData = {
        name: 'John Doe',
        email: 'john@example.com',
        password: 'SecureP@ssw0rd123',
      };

      const response = await request(app)
        .post('/api/users')
        .send(userData)
        .expect(201);

      expect(response.body).toMatchObject({
        success: true,
        data: {
          name: userData.name,
          email: userData.email,
        },
      });

      expect(response.body.data.id).toBeDefined();
      expect(response.body.data.password).toBeUndefined(); // Password should not be returned
    });

    it('should return validation errors for invalid data', async () => {
      const invalidData = {
        name: '',
        email: 'invalid-email',
        password: '123',
      };

      const response = await request(app)
        .post('/api/users')
        .send(invalidData)
        .expect(400);

      expect(response.body.success).toBe(false);
      expect(response.body.error).toContain('Validation failed');
      expect(response.body.details).toBeInstanceOf(Array);
    });

    it('should handle duplicate email addresses', async () => {
      const userData = {
        name: 'John Doe',
        email: 'john@example.com',
        password: 'SecureP@ssw0rd123',
      };

      // Create first user
      await request(app)
        .post('/api/users')
        .send(userData)
        .expect(201);

      // Attempt to create duplicate user
      const response = await request(app)
        .post('/api/users')
        .send(userData)
        .expect(409);

      expect(response.body.success).toBe(false);
      expect(response.body.error).toContain('Email already exists');
    });
  });

  describe('GET /api/users/:id', () => {
    it('should retrieve user by ID', async () => {
      // Create user first
      const createResponse = await request(app)
        .post('/api/users')
        .send({
          name: 'Jane Doe',
          email: 'jane@example.com',
          password: 'SecureP@ssw0rd123',
        })
        .expect(201);

      const userId = createResponse.body.data.id;

      // Retrieve user
      const response = await request(app)
        .get(`/api/users/${userId}`)
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data).toMatchObject({
        id: userId,
        name: 'Jane Doe',
        email: 'jane@example.com',
      });
    });

    it('should return 404 for non-existent user', async () => {
      const response = await request(app)
        .get('/api/users/nonexistent-id')
        .expect(404);

      expect(response.body.success).toBe(false);
      expect(response.body.error).toContain('User not found');
    });
  });

  describe('PUT /api/users/:id', () => {
    it('should update user information', async () => {
      // Create user
      const createResponse = await request(app)
        .post('/api/users')
        .send({
          name: 'John Doe',
          email: 'john@example.com',
          password: 'SecureP@ssw0rd123',
        })
        .expect(201);

      const userId = createResponse.body.data.id;

      // Update user
      const updateData = {
        name: 'John Smith',
        email: 'johnsmith@example.com',
      };

      const response = await request(app)
        .put(`/api/users/${userId}`)
        .send(updateData)
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data).toMatchObject(updateData);
    });
  });
});
```

### Authentication Integration Testing

```typescript
// tests/integration/api/auth.test.ts
import request from 'supertest';
import { createApp } from '@/app';

describe('Authentication API Integration', () => {
  let app: Express.Application;

  beforeAll(async () => {
    app = createApp({ environment: 'test' });
  });

  describe('POST /api/auth/login', () => {
    beforeEach(async () => {
      // Create test user
      await request(app)
        .post('/api/users')
        .send({
          name: 'Test User',
          email: 'test@example.com',
          password: 'TestP@ssw0rd123',
        });
    });

    it('should authenticate valid credentials', async () => {
      const credentials = {
        email: 'test@example.com',
        password: 'TestP@ssw0rd123',
      };

      const response = await request(app)
        .post('/api/auth/login')
        .send(credentials)
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data.accessToken).toBeDefined();
      expect(response.body.data.refreshToken).toBeDefined();
      expect(response.body.data.tokenType).toBe('Bearer');
    });

    it('should reject invalid credentials', async () => {
      const credentials = {
        email: 'test@example.com',
        password: 'wrongpassword',
      };

      const response = await request(app)
        .post('/api/auth/login')
        .send(credentials)
        .expect(401);

      expect(response.body.success).toBe(false);
      expect(response.body.error).toContain('Invalid credentials');
    });
  });

  describe('Protected Routes', () => {
    let authToken: string;

    beforeEach(async () => {
      // Login to get token
      const loginResponse = await request(app)
        .post('/api/auth/login')
        .send({
          email: 'test@example.com',
          password: 'TestP@ssw0rd123',
        });

      authToken = loginResponse.body.data.accessToken;
    });

    it('should access protected routes with valid token', async () => {
      const response = await request(app)
        .get('/api/auth/profile')
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data.email).toBe('test@example.com');
    });

    it('should reject protected routes without token', async () => {
      const response = await request(app)
        .get('/api/auth/profile')
        .expect(401);

      expect(response.body.success).toBe(false);
      expect(response.body.error).toContain('Access token required');
    });

    it('should reject protected routes with invalid token', async () => {
      const response = await request(app)
        .get('/api/auth/profile')
        .set('Authorization', 'Bearer invalid-token')
        .expect(403);

      expect(response.body.success).toBe(false);
      expect(response.body.error).toContain('Invalid token');
    });
  });
});
```

## 🗄️ Database Integration Testing

### PostgreSQL Integration

```typescript
// tests/integration/database/UserRepository.test.ts
import { UserRepository } from '@/repositories/UserRepository';
import { setupTestPostgres, cleanupTestPostgres } from '@/helpers/postgresHelper';

describe('UserRepository Integration', () => {
  let userRepository: UserRepository;
  let postgresConnection: any;

  beforeAll(async () => {
    // Setup test PostgreSQL database
    postgresConnection = await setupTestPostgres();
    userRepository = new UserRepository(postgresConnection);
  });

  afterAll(async () => {
    await cleanupTestPostgres(postgresConnection);
  });

  beforeEach(async () => {
    // Clean database before each test
    await postgresConnection.query('TRUNCATE TABLE users CASCADE');
  });

  describe('create', () => {
    it('should create a new user in database', async () => {
      const userData = {
        name: 'John Doe',
        email: 'john@example.com',
        passwordHash: 'hashedpassword',
      };

      const user = await userRepository.create(userData);

      expect(user).toMatchObject({
        name: userData.name,
        email: userData.email,
      });
      expect(user.id).toBeDefined();
      expect(user.createdAt).toBeInstanceOf(Date);
    });

    it('should enforce unique email constraint', async () => {
      const userData = {
        name: 'John Doe',
        email: 'john@example.com',
        passwordHash: 'hashedpassword',
      };

      // Create first user
      await userRepository.create(userData);

      // Attempt to create duplicate
      await expect(userRepository.create(userData))
        .rejects
        .toThrow('duplicate key value violates unique constraint');
    });
  });

  describe('findById', () => {
    it('should find user by ID', async () => {
      const createdUser = await userRepository.create({
        name: 'Jane Doe',
        email: 'jane@example.com',
        passwordHash: 'hashedpassword',
      });

      const foundUser = await userRepository.findById(createdUser.id);

      expect(foundUser).toMatchObject(createdUser);
    });

    it('should return null for non-existent user', async () => {
      const user = await userRepository.findById('nonexistent-id');
      expect(user).toBeNull();
    });
  });

  describe('findByEmail', () => {
    it('should find user by email', async () => {
      const userData = {
        name: 'Test User',
        email: 'test@example.com',
        passwordHash: 'hashedpassword',
      };

      const createdUser = await userRepository.create(userData);
      const foundUser = await userRepository.findByEmail(userData.email);

      expect(foundUser).toMatchObject(createdUser);
    });
  });
});
```

### MongoDB Integration

```typescript
// tests/integration/database/MongoUserRepository.test.ts
import { MongoUserRepository } from '@/repositories/MongoUserRepository';
import { setupTestMongo, cleanupTestMongo } from '@/helpers/mongoHelper';

describe('MongoUserRepository Integration', () => {
  let userRepository: MongoUserRepository;
  let mongoConnection: any;

  beforeAll(async () => {
    mongoConnection = await setupTestMongo();
    userRepository = new MongoUserRepository(mongoConnection);
  });

  afterAll(async () => {
    await cleanupTestMongo(mongoConnection);
  });

  beforeEach(async () => {
    await mongoConnection.collection('users').deleteMany({});
  });

  describe('create', () => {
    it('should create user with MongoDB ObjectId', async () => {
      const userData = {
        name: 'John Doe',
        email: 'john@example.com',
        passwordHash: 'hashedpassword',
      };

      const user = await userRepository.create(userData);

      expect(user._id).toBeDefined();
      expect(user._id.toString()).toMatch(/^[0-9a-fA-F]{24}$/);
      expect(user).toMatchObject({
        name: userData.name,
        email: userData.email,
      });
    });
  });

  describe('complex queries', () => {
    it('should perform complex aggregation queries', async () => {
      // Create test data
      await userRepository.create({ name: 'User 1', email: 'user1@example.com', passwordHash: 'hash1' });
      await userRepository.create({ name: 'User 2', email: 'user2@example.com', passwordHash: 'hash2' });
      await userRepository.create({ name: 'User 3', email: 'user3@example.com', passwordHash: 'hash3' });

      // Perform aggregation
      const stats = await userRepository.getUserStats();

      expect(stats.totalUsers).toBe(3);
      expect(stats.averageNameLength).toBeGreaterThan(0);
    });
  });
});
```

## 🔌 External Service Integration

### HTTP Service Integration

```typescript
// tests/integration/external/EmailService.test.ts
import nock from 'nock';
import { EmailService } from '@/services/EmailService';

describe('EmailService External Integration', () => {
  let emailService: EmailService;

  beforeEach(() => {
    emailService = new EmailService({
      apiKey: 'test-api-key',
      baseUrl: 'https://api.emailservice.com',
    });
  });

  afterEach(() => {
    nock.cleanAll();
    nock.restore();
  });

  describe('sendEmail', () => {
    it('should send email via external API', async () => {
      // Mock external API
      const scope = nock('https://api.emailservice.com')
        .post('/emails')
        .reply(200, {
          success: true,
          messageId: 'msg-123',
        });

      const emailData = {
        to: 'recipient@example.com',
        subject: 'Test Email',
        html: '<p>Test content</p>',
      };

      const result = await emailService.sendEmail(emailData);

      expect(result.success).toBe(true);
      expect(result.messageId).toBe('msg-123');
      expect(scope.isDone()).toBe(true);
    });

    it('should handle API errors gracefully', async () => {
      // Mock API error
      nock('https://api.emailservice.com')
        .post('/emails')
        .reply(429, {
          error: 'Rate limit exceeded',
        });

      const emailData = {
        to: 'recipient@example.com',
        subject: 'Test Email',
        html: '<p>Test content</p>',
      };

      await expect(emailService.sendEmail(emailData))
        .rejects
        .toThrow('Rate limit exceeded');
    });

    it('should retry on temporary failures', async () => {
      // Mock temporary failure then success
      const scope = nock('https://api.emailservice.com')
        .post('/emails')
        .reply(500, { error: 'Internal server error' })
        .post('/emails')
        .reply(200, { success: true, messageId: 'msg-456' });

      const emailData = {
        to: 'recipient@example.com',
        subject: 'Test Email',
        html: '<p>Test content</p>',
      };

      const result = await emailService.sendEmail(emailData);

      expect(result.success).toBe(true);
      expect(result.messageId).toBe('msg-456');
      expect(scope.isDone()).toBe(true);
    });
  });
});
```

### Payment Gateway Integration

```typescript
// tests/integration/external/PaymentService.test.ts
import { PaymentService } from '@/services/PaymentService';

describe('PaymentService External Integration', () => {
  let paymentService: PaymentService;

  beforeAll(() => {
    // Use test/stripe keys for integration testing
    paymentService = new PaymentService({
      apiKey: process.env.STRIPE_TEST_KEY,
      environment: 'test',
    });
  });

  // Skip if no test key available
  beforeAll(() => {
    if (!process.env.STRIPE_TEST_KEY) {
      console.warn('Skipping Stripe integration tests - no test key provided');
    }
  });

  describe('createPaymentIntent', () => {
    it.skip('should create payment intent with Stripe', async () => {
      const paymentData = {
        amount: 2000, // $20.00 in cents
        currency: 'usd',
        customerId: 'cus_test123',
      };

      const paymentIntent = await paymentService.createPaymentIntent(paymentData);

      expect(paymentIntent.id).toBeDefined();
      expect(paymentIntent.amount).toBe(paymentData.amount);
      expect(paymentIntent.currency).toBe(paymentData.currency);
      expect(paymentIntent.status).toBe('requires_payment_method');
    });

    it.skip('should handle invalid payment data', async () => {
      const invalidData = {
        amount: -1000, // Negative amount
        currency: 'usd',
      };

      await expect(paymentService.createPaymentIntent(invalidData))
        .rejects
        .toThrow();
    });
  });
});
```

## 🔄 Workflow Integration Testing

### Complete User Registration Workflow

```typescript
// tests/integration/workflows/UserRegistration.test.ts
import request from 'supertest';
import { createApp } from '@/app';

describe('User Registration Workflow', () => {
  let app: Express.Application;

  beforeAll(async () => {
    app = createApp({ environment: 'test' });
  });

  it('should complete full user registration workflow', async () => {
    // Step 1: Register user
    const registrationData = {
      name: 'John Doe',
      email: 'john@example.com',
      password: 'SecureP@ssw0rd123',
    };

    const registerResponse = await request(app)
      .post('/api/users')
      .send(registrationData)
      .expect(201);

    const userId = registerResponse.body.data.id;

    // Step 2: Verify email (mock verification)
    await request(app)
      .post('/api/auth/verify-email')
      .send({
        token: 'verification-token',
        userId,
      })
      .expect(200);

    // Step 3: Login
    const loginResponse = await request(app)
      .post('/api/auth/login')
      .send({
        email: registrationData.email,
        password: registrationData.password,
      })
      .expect(200);

    const authToken = loginResponse.body.data.accessToken;

    // Step 4: Update profile
    const profileUpdate = {
      bio: 'Software developer',
      location: 'San Francisco',
    };

    const updateResponse = await request(app)
      .put(`/api/users/${userId}`)
      .set('Authorization', `Bearer ${authToken}`)
      .send(profileUpdate)
      .expect(200);

    expect(updateResponse.body.data).toMatchObject(profileUpdate);

    // Step 5: Verify profile is updated
    const profileResponse = await request(app)
      .get(`/api/users/${userId}`)
      .set('Authorization', `Bearer ${authToken}`)
      .expect(200);

    expect(profileResponse.body.data).toMatchObject({
      name: registrationData.name,
      email: registrationData.email,
      ...profileUpdate,
    });
  });
});
```

### E-commerce Order Processing Workflow

```typescript
// tests/integration/workflows/OrderProcessing.test.ts
import request from 'supertest';
import { createApp } from '@/app';

describe('Order Processing Workflow', () => {
  let app: Express.Application;
  let userToken: string;
  let productId: string;

  beforeAll(async () => {
    app = createApp({ environment: 'test' });

    // Setup test user and product
    const userResponse = await request(app)
      .post('/api/users')
      .send({
        name: 'Test Customer',
        email: 'customer@example.com',
        password: 'TestP@ssw0rd123',
      });

    const loginResponse = await request(app)
      .post('/api/auth/login')
      .send({
        email: 'customer@example.com',
        password: 'TestP@ssw0rd123',
      });

    userToken = loginResponse.body.data.accessToken;

    // Create test product
    const productResponse = await request(app)
      .post('/api/products')
      .send({
        name: 'Test Product',
        price: 2999,
        description: 'A test product',
        inventory: 10,
      });

    productId = productResponse.body.data.id;
  });

  it('should process complete order workflow', async () => {
    // Step 1: Add item to cart
    const cartResponse = await request(app)
      .post('/api/cart/items')
      .set('Authorization', `Bearer ${userToken}`)
      .send({
        productId,
        quantity: 2,
      })
      .expect(200);

    expect(cartResponse.body.data.items).toHaveLength(1);

    // Step 2: Create order from cart
    const orderResponse = await request(app)
      .post('/api/orders')
      .set('Authorization', `Bearer ${userToken}`)
      .send({
        shippingAddress: {
          street: '123 Test St',
          city: 'Test City',
          zipCode: '12345',
          country: 'USA',
        },
      })
      .expect(201);

    const orderId = orderResponse.body.data.id;

    // Step 3: Process payment (mock)
    const paymentResponse = await request(app)
      .post(`/api/orders/${orderId}/pay`)
      .set('Authorization', `Bearer ${userToken}`)
      .send({
        paymentMethod: 'credit_card',
        cardToken: 'tok_test',
      })
      .expect(200);

    expect(paymentResponse.body.data.status).toBe('paid');

    // Step 4: Verify order status
    const finalOrderResponse = await request(app)
      .get(`/api/orders/${orderId}`)
      .set('Authorization', `Bearer ${userToken}`)
      .expect(200);

    expect(finalOrderResponse.body.data.status).toBe('paid');
    expect(finalOrderResponse.body.data.items).toHaveLength(1);
    expect(finalOrderResponse.body.data.totalAmount).toBe(5998); // 2 * 2999
  });
});
```

## 🛠️ Test Utilities

### Database Helpers

```typescript
// tests/helpers/databaseHelper.ts
import { Pool } from 'pg';
import { MongoMemoryServer } from 'mongodb-memory-server';

export class PostgresTestHelper {
  private static pool: Pool;

  static async setup(): Promise<Pool> {
    this.pool = new Pool({
      host: process.env.TEST_DB_HOST || 'localhost',
      port: parseInt(process.env.TEST_DB_PORT || '5432'),
      database: process.env.TEST_DB_NAME || 'test_db',
      user: process.env.TEST_DB_USER || 'test_user',
      password: process.env.TEST_DB_PASSWORD || 'test_password',
    });

    // Run migrations
    await this.runMigrations();

    return this.pool;
  }

  static async cleanup(): Promise<void> {
    if (this.pool) {
      await this.pool.end();
    }
  }

  static async truncateAllTables(): Promise<void> {
    const tables = ['users', 'orders', 'products', 'cart_items'];
    
    for (const table of tables) {
      await this.pool.query(`TRUNCATE TABLE ${table} CASCADE`);
    }
  }

  private static async runMigrations(): Promise<void> {
    // Run database migrations
    const migrationFiles = await this.getMigrationFiles();
    
    for (const file of migrationFiles) {
      await this.runMigration(file);
    }
  }
}

export class MongoTestHelper {
  private static mongod: MongoMemoryServer;
  private static connection: any;

  static async setup(): Promise<any> {
    this.mongod = await MongoMemoryServer.create();
    const uri = this.mongod.getUri();
    
    this.connection = await MongoClient.connect(uri);
    const db = this.connection.db();
    
    return db;
  }

  static async cleanup(): Promise<void> {
    if (this.connection) {
      await this.connection.close();
    }
    
    if (this.mongod) {
      await this.mongod.stop();
    }
  }

  static async clearDatabase(): Promise<void> {
    const collections = await this.connection.collections();
    
    for (const collection of collections) {
      await collection.deleteMany({});
    }
  }
}
```

### API Test Helpers

```typescript
// tests/helpers/apiHelper.ts
import request from 'supertest';
import { Express } from 'express';

export class ApiTestHelper {
  static async createAuthenticatedUser(
    app: Express,
    userData: any
  ): Promise<{ user: any; token: string }> {
    // Create user
    const userResponse = await request(app)
      .post('/api/users')
      .send(userData)
      .expect(201);

    const user = userResponse.body.data;

    // Login to get token
    const loginResponse = await request(app)
      .post('/api/auth/login')
      .send({
        email: userData.email,
        password: userData.password,
      })
      .expect(200);

    const token = loginResponse.body.data.accessToken;

    return { user, token };
  }

  static async createTestProduct(
    app: Express,
    token: string,
    productData: any
  ): Promise<any> {
    const response = await request(app)
      .post('/api/products')
      .set('Authorization', `Bearer ${token}`)
      .send(productData)
      .expect(201);

    return response.body.data;
  }

  static expectErrorResponse(response: any, status: number, error: string): void {
    expect(response.status).toBe(status);
    expect(response.body.success).toBe(false);
    expect(response.body.error).toContain(error);
  }

  static expectSuccessResponse(response: any, status: number = 200): void {
    expect(response.status).toBe(status);
    expect(response.body.success).toBe(true);
    expect(response.body.data).toBeDefined();
  }
}
```

### Test Data Factories

```typescript
// tests/factories/userFactory.ts
import { faker } from '@faker-js/faker';
import { User, CreateUserRequest } from '@/models/User';

export class UserFactory {
  static create(overrides: Partial<User> = {}): User {
    return {
      id: faker.datatype.uuid(),
      name: faker.name.fullName(),
      email: faker.internet.email(),
      passwordHash: faker.datatype.string(),
      roles: ['user'],
      isActive: true,
      createdAt: faker.date.past(),
      updatedAt: faker.date.recent(),
      ...overrides,
    };
  }

  static createCreateRequest(overrides: Partial<CreateUserRequest> = {}): CreateUserRequest {
    return {
      name: faker.name.fullName(),
      email: faker.internet.email(),
      password: faker.internet.password(12),
      ...overrides,
    };
  }

  static createMany(count: number, overrides: Partial<User> = {}): User[] {
    return Array.from({ length: count }, () => this.create(overrides));
  }
}

export class ProductFactory {
  static create(overrides: Partial<Product> = {}): Product {
    return {
      id: faker.datatype.uuid(),
      name: faker.commerce.productName(),
      description: faker.commerce.productDescription(),
      price: parseFloat(faker.commerce.price(10, 1000, 2)),
      inventory: faker.datatype.number({ min: 0, max: 100 }),
      isActive: true,
      createdAt: faker.date.past(),
      updatedAt: faker.date.recent(),
      ...overrides,
    };
  }

  static createMany(count: number, overrides: Partial<Product> = {}): Product[] {
    return Array.from({ length: count }, () => this.create(overrides));
  }
}
```

## 🎯 Best Practices

### Test Organization

1. **Logical grouping**: Group tests by feature or workflow
2. **Clear naming**: Use descriptive test names that explain the scenario
3. **Independent tests**: Tests should not depend on each other
4. **Cleanup**: Properly clean up resources after each test
5. **Environment isolation**: Use separate test databases

### Data Management

1. **Factory pattern**: Use factories for test data generation
2. **Realistic data**: Use realistic test data with Faker
3. **Minimal setup**: Only create data needed for each test
4. **Database cleanup**: Clean database between tests
5. **Transaction rollback**: Use transactions for test isolation

### External Dependencies

1. **Mock external services**: Don't hit real external APIs
2. **Test containers**: Use Docker for database testing
3. **Environment variables**: Use test-specific configuration
4. **Network mocking**: Mock HTTP calls with Nock
5. **Rate limiting**: Handle API rate limits in tests

### Performance & Reliability

1. **Parallel execution**: Run tests in parallel where safe
2. **Timeout handling**: Set appropriate timeouts
3. **Retry logic**: Handle flaky external dependencies
4. **Resource cleanup**: Clean up resources properly
5. **Memory management**: Avoid memory leaks in tests

---

## 📚 Additional Resources

- [Supertest Documentation](https://github.com/visionmedia/supertest)
- [Jest Integration Testing](https://jestjs.io/docs/tutorial-async)
- [Test Containers](https://www.testcontainers.org/)
- [MongoDB Memory Server](https://github.com/nodkz/mongodb-memory-server)

---

*Integration Testing Pattern Version: [[.Version]]*  
*Author: [[.Author]]*  
*Date: [[.Date]]*
