<!--
File: test-utilities-pattern.tpl.md
Purpose: Template for unknown implementation
Template Version: 1.0
-->

# TypeScript Test Utilities Pattern

> **Comprehensive test utilities and helpers for TypeScript applications with type-safe mocking, generic utilities, and advanced testing patterns**

## 🎯 Overview

This pattern provides a robust set of test utilities specifically designed for TypeScript applications, emphasizing type safety, reusable components, and developer productivity.

## 🛠️ Technology Stack

### Core Testing Framework
- **Jest**: JavaScript testing framework with excellent TypeScript support
- **ts-jest**: TypeScript preprocessor for Jest
- **@types/jest**: Complete TypeScript type definitions

### Mocking & Utilities
- **Jest Mock Functions**: Type-safe mocking with `jest.Mocked<T>`
- **Sinon**: Advanced spying and stubbing with TypeScript support
- **Faker**: Type-safe fake data generation
- **Fast-Check**: Property-based testing for TypeScript

### Type-Safe Testing
- **Generic Test Utilities**: Reusable type-safe test helpers
- **Type Guards**: Runtime type checking in tests
- **Mock Factories**: Type-safe mock object creation

## 📋 Utility Structure

### Directory Organization

```
tests/
├── utilities/              # Test utilities
│   ├── mocks/             # Mock implementations
│   ├── factories/         # Data factories
│   ├── helpers/           # Helper functions
│   ├── matchers/          # Custom matchers
│   ├── fixtures/          # Test fixtures
│   └── types/             # Test-specific types
├── setup/                 # Setup files
└── config/                # Test configurations
```

## 🔧 Type-Safe Mocking

### Generic Mock Factory

```typescript
// tests/utilities/mocks/MockFactory.ts
import { Mocked, MockedClass, MockedFunction } from 'jest-mock';

export class MockFactory {
  /**
   * Create a type-safe mock of a class
   */
  static createClassMock<T extends new (...args: any[]) => any>(
    classConstructor: T
  ): MockedClass<T> {
    return jest.createMockFromModule(classConstructor.name) as MockedClass<T>;
  }

  /**
   * Create a type-safe mock of an object
   */
  static createObjectMock<T extends object>(
    obj: T
  ): Mocked<T> {
    return jest.mocked(obj);
  }

  /**
   * Create a type-safe mock function
   */
  static createFunctionMock<T extends (...args: any[]) => any>(
    implementation?: T
  ): MockedFunction<T> {
    return jest.fn(implementation) as MockedFunction<T>;
  }

  /**
   * Create a partial mock with type safety
   */
  static createPartialMock<T extends object>(
    partial: Partial<T>
  ): Mocked<T> {
    return {
      ...partial,
      ...Object.keys(partial).reduce((mocks, key) => {
        mocks[key as keyof T] = jest.fn();
        return mocks;
      }, {} as any)
    } as Mocked<T>;
  }
}
```

### Service Mock Builder

```typescript
// tests/utilities/mocks/ServiceMockBuilder.ts
import { Mocked } from 'jest-mock';

export class ServiceMockBuilder<T extends object> {
  private mock: Partial<Mocked<T>> = {};

  constructor(private serviceInterface: { new (): T }) {}

  /**
   * Mock a method with return value
   */
  withMethod<K extends keyof T>(
    methodName: K,
    returnValue: T[K] extends (...args: any[]) => any ? ReturnType<T[K]> : T[K]
  ): this {
    this.mock[methodName] = jest.fn().mockReturnValue(returnValue) as any;
    return this;
  }

  /**
   * Mock a method with implementation
   */
  withMethodImpl<K extends keyof T>(
    methodName: K,
    implementation: T[K] extends (...args: any[]) => any ? T[K] : never
  ): this {
    this.mock[methodName] = jest.fn(implementation) as any;
    return this;
  }

  /**
   * Mock a method to resolve a promise
   */
  withResolvedMethod<K extends keyof T>(
    methodName: K,
    resolvedValue: T[K] extends (...args: any[]) => Promise<any> ? 
      Awaited<ReturnType<T[K]>> : never
  ): this {
    this.mock[methodName] = jest.fn().mockResolvedValue(resolvedValue) as any;
    return this;
  }

  /**
   * Mock a method to reject a promise
   */
  withRejectedMethod<K extends keyof T>(
    methodName: K,
    error: Error
  ): this {
    this.mock[methodName] = jest.fn().mockRejectedValue(error) as any;
    return this;
  }

  /**
   * Build the complete mock
   */
  build(): Mocked<T> {
    return this.mock as Mocked<T>;
  }
}

// Usage example
const userServiceMock = new ServiceMockBuilder(UserService)
  .withMethod('findById', { id: '123', name: 'Test User' })
  .withResolvedMethod('createUser', { id: '456', name: 'New User' })
  .withRejectedMethod('deleteUser', new Error('User not found'))
  .build();
```

### Repository Mock Factory

```typescript
// tests/utilities/mocks/RepositoryMockFactory.ts
import { Mocked } from 'jest-mock';

export interface IRepository<T, ID = string> {
  findById(id: ID): Promise<T | null>;
  findAll(): Promise<T[]>;
  create(entity: Partial<T>): Promise<T>;
  update(id: ID, entity: Partial<T>): Promise<T>;
  delete(id: ID): Promise<void>;
}

export class RepositoryMockFactory<T, ID = string> {
  static create<T, ID = string>(): Mocked<IRepository<T, ID>> {
    return {
      findById: jest.fn(),
      findAll: jest.fn(),
      create: jest.fn(),
      update: jest.fn(),
      delete: jest.fn(),
    } as Mocked<IRepository<T, ID>>;
  }

  static withData<T, ID = string>(
    data: Map<ID, T>
  ): Mocked<IRepository<T, ID>> {
    return {
      findById: jest.fn((id: ID) => Promise.resolve(data.get(id) || null)),
      findAll: jest.fn(() => Promise.resolve(Array.from(data.values()))),
      create: jest.fn((entity: Partial<T>) => {
        const newEntity = { id: Math.random().toString() as ID, ...entity } as T;
        data.set(newEntity.id, newEntity);
        return Promise.resolve(newEntity);
      }),
      update: jest.fn((id: ID, entity: Partial<T>) => {
        const existing = data.get(id);
        if (existing) {
          const updated = { ...existing, ...entity };
          data.set(id, updated);
          return Promise.resolve(updated);
        }
        return Promise.reject(new Error('Entity not found'));
      }),
      delete: jest.fn((id: ID) => {
        data.delete(id);
        return Promise.resolve();
      }),
    } as Mocked<IRepository<T, ID>>;
  }
}
```

## 🏭 Type-Safe Data Factories

### Generic Factory Base

```typescript
// tests/utilities/factories/Factory.ts
import faker from '@faker-js/faker';

export abstract class Factory<T> {
  protected abstract definition(): Partial<T>;

  /**
   * Create a single instance
   */
  create(overrides: Partial<T> = {}): T {
    return {
      ...this.definition(),
      ...overrides,
    } as T;
  }

  /**
   * Create multiple instances
   */
  createMany(count: number, overrides: Partial<T> = {}): T[] {
    return Array.from({ length: count }, () => this.create(overrides));
  }

  /**
   * Create with random data
   */
  createRandom(): T {
    return this.create();
  }

  /**
   * Create with specific field values
   */
  createWith<K extends keyof T>(fields: Pick<T, K>): T {
    return this.create(fields);
  }

  // Helper methods for common data types
  protected static randomEmail(): string {
    return faker.internet.email();
  }

  protected static randomName(): string {
    return faker.name.fullName();
  }

  protected static randomUuid(): string {
    return faker.datatype.uuid();
  }

  protected static randomDate(): Date {
    return faker.date.past();
  }

  protected static randomString(length: number = 10): string {
    return faker.random.alphaNumeric(length);
  }

  protected static randomNumber(min: number = 0, max: number = 100): number {
    return faker.datatype.number({ min, max });
  }
}
```

### User Factory

```typescript
// tests/utilities/factories/UserFactory.ts
import { Factory } from './Factory';
import { User, CreateUserRequest, UserRole } from '@/models/User';

export class UserFactory extends Factory<User> {
  protected definition(): Partial<User> {
    return {
      id: Factory.randomUuid(),
      name: Factory.randomName(),
      email: Factory.randomEmail(),
      passwordHash: 'hashedpassword',
      roles: [UserRole.USER],
      permissions: ['read:profile', 'update:profile'],
      isActive: true,
      createdAt: Factory.randomDate(),
      updatedAt: Factory.randomDate(),
    };
  }

  static withRole(role: UserRole): UserFactory {
    const factory = new UserFactory();
    return factory.withOverrides({ roles: [role] });
  }

  static inactive(): UserFactory {
    const factory = new UserFactory();
    return factory.withOverrides({ isActive: false });
  }

  static withPermissions(permissions: string[]): UserFactory {
    const factory = new UserFactory();
    return factory.withOverrides({ permissions });
  }

  private withOverrides(overrides: Partial<User>): UserFactory {
    const originalDefinition = this.definition.bind(this);
    this.definition = () => ({ ...originalDefinition(), ...overrides });
    return this as any;
  }
}

export class CreateUserRequestFactory extends Factory<CreateUserRequest> {
  protected definition(): Partial<CreateUserRequest> {
    return {
      name: Factory.randomName(),
      email: Factory.randomEmail(),
      password: 'SecureP@ssw0rd123',
      roles: [UserRole.USER],
    };
  }

  static withPassword(password: string): CreateUserRequestFactory {
    const factory = new CreateUserRequestFactory();
    return factory.withOverrides({ password });
  }

  private withOverrides(overrides: Partial<CreateUserRequest>): CreateUserRequestFactory {
    const originalDefinition = this.definition.bind(this);
    this.definition = () => ({ ...originalDefinition(), ...overrides });
    return this as any;
  }
}
```

### Product Factory

```typescript
// tests/utilities/factories/ProductFactory.ts
import { Factory } from './Factory';
import { Product, ProductStatus } from '@/models/Product';

export class ProductFactory extends Factory<Product> {
  protected definition(): Partial<Product> {
    return {
      id: Factory.randomUuid(),
      name: faker.commerce.productName(),
      description: faker.commerce.productDescription(),
      price: parseFloat(faker.commerce.price(10, 1000, 2)),
      inventory: Factory.randomNumber(0, 100),
      status: ProductStatus.ACTIVE,
      categoryId: Factory.randomUuid(),
      createdAt: Factory.randomDate(),
      updatedAt: Factory.randomDate(),
    };
  }

  static inactive(): ProductFactory {
    const factory = new ProductFactory();
    return factory.withOverrides({ status: ProductStatus.INACTIVE });
  }

  static outOfStock(): ProductFactory {
    const factory = new ProductFactory();
    return factory.withOverrides({ inventory: 0 });
  }

  static withPriceRange(min: number, max: number): ProductFactory {
    const factory = new ProductFactory();
    return factory.withOverrides({
      price: parseFloat(faker.commerce.price(min, max, 2))
    });
  }

  private withOverrides(overrides: Partial<Product>): ProductFactory {
    const originalDefinition = this.definition.bind(this);
    this.definition = () => ({ ...originalDefinition(), ...overrides });
    return this as any;
  }
}
```

## 🔍 Type Guards & Assertions

### Runtime Type Guards

```typescript
// tests/utilities/types/TypeGuards.ts
import { User, Product, Order } from '@/models';

export class TypeGuards {
  static isUser(obj: any): obj is User {
    return obj && 
      typeof obj.id === 'string' &&
      typeof obj.name === 'string' &&
      typeof obj.email === 'string' &&
      Array.isArray(obj.roles) &&
      typeof obj.isActive === 'boolean';
  }

  static isProduct(obj: any): obj is Product {
    return obj &&
      typeof obj.id === 'string' &&
      typeof obj.name === 'string' &&
      typeof obj.price === 'number' &&
      typeof obj.inventory === 'number';
  }

  static isOrder(obj: any): obj is Order {
    return obj &&
      typeof obj.id === 'string' &&
      typeof obj.userId === 'string' &&
      Array.isArray(obj.items) &&
      typeof obj.totalAmount === 'number';
  }

  static isArrayOf<T>(guard: (obj: any) => obj is T, obj: any): obj is T[] {
    return Array.isArray(obj) && obj.every(guard);
  }

  static hasProperty<K extends string>(
    obj: any,
    property: K
  ): obj is Record<K, any> {
    return obj && typeof obj === 'object' && property in obj;
  }

  static isString(obj: any): obj is string {
    return typeof obj === 'string';
  }

  static isNumber(obj: any): obj is number {
    return typeof obj === 'number' && !isNaN(obj);
  }

  static isDate(obj: any): obj is Date {
    return obj instanceof Date && !isNaN(obj.getTime());
  }
}
```

### Custom Assertion Helpers

```typescript
// tests/utilities/helpers/AssertionHelpers.ts
import { TypeGuards } from '../types/TypeGuards';

export class AssertionHelpers {
  /**
   * Assert that object is of specific type
   */
  static assertIsType<T>(
    obj: any,
    typeGuard: (obj: any) => obj is T,
    message?: string
  ): asserts obj is T {
    if (!typeGuard(obj)) {
      throw new Error(message || `Object is not of expected type`);
    }
  }

  /**
   * Assert that response contains valid user data
   */
  static assertValidUser(obj: any): asserts obj is User {
    this.assertIsType(obj, TypeGuards.isUser, 'Response does not contain valid user data');
  }

  /**
   * Assert that response contains valid product data
   */
  static assertValidProduct(obj: any): asserts obj is Product {
    this.assertIsType(obj, TypeGuards.isProduct, 'Response does not contain valid product data');
  }

  /**
   * Assert that response contains valid order data
   */
  static assertValidOrder(obj: any): asserts obj is Order {
    this.assertIsType(obj, TypeGuards.isOrder, 'Response does not contain valid order data');
  }

  /**
   * Assert that array contains items of specific type
   */
  static assertArrayOfType<T>(
    obj: any,
    typeGuard: (obj: any) => obj is T,
    message?: string
  ): asserts obj is T[] {
    if (!TypeGuards.isArrayOf(typeGuard, obj)) {
      throw new Error(message || `Array does not contain items of expected type`);
    }
  }

  /**
   * Assert API response structure
   */
  static assertApiResponse(response: any): asserts response is {
    success: boolean;
    data?: any;
    error?: string;
  } {
    if (typeof response !== 'object' || response === null) {
      throw new Error('Response is not an object');
    }

    if (typeof response.success !== 'boolean') {
      throw new Error('Response does not have success property');
    }

    if (response.success && response.data === undefined) {
      throw new Error('Successful response must have data property');
    }

    if (!response.success && response.error === undefined) {
      throw new Error('Failed response must have error property');
    }
  }
}
```

## 🎯 Custom Matchers

### Type-Safe Custom Matchers

```typescript
// tests/utilities/matchers/CustomMatchers.ts
import { User, Product } from '@/models';

expect.extend({
  /**
   * Matcher for valid user objects
   */
  toBeValidUser(received: any) {
    const pass = TypeGuards.isUser(received);

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

  /**
   * Matcher for valid product objects
   */
  toBeValidProduct(received: any) {
    const pass = TypeGuards.isProduct(received);

    if (pass) {
      return {
        message: () => `expected ${received} not to be a valid product`,
        pass: true,
      };
    } else {
      return {
        message: () => `expected ${received} to be a valid product`,
        pass: false,
      };
    }
  },

  /**
   * Matcher for price range
   */
  toBeWithinPriceRange(received: any, min: number, max: number) {
    const pass = typeof received === 'number' && received >= min && received <= max;

    if (pass) {
      return {
        message: () => `expected ${received} not to be within price range ${min} - ${max}`,
        pass: true,
      };
    } else {
      return {
        message: () => `expected ${received} to be within price range ${min} - ${max}`,
        pass: false,
      };
    }
  },

  /**
   * Matcher for email format
   */
  toBeValidEmail(received: any) {
    const pass = typeof received === 'string' && 
      /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(received);

    if (pass) {
      return {
        message: () => `expected ${received} not to be a valid email`,
        pass: true,
      };
    } else {
      return {
        message: () => `expected ${received} to be a valid email`,
        pass: false,
      };
    }
  },

  /**
   * Matcher for UUID format
   */
  toBeValidUuid(received: any) {
    const pass = typeof received === 'string' && 
      /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(received);

    if (pass) {
      return {
        message: () => `expected ${received} not to be a valid UUID`,
        pass: true,
      };
    } else {
      return {
        message: () => `expected ${received} to be a valid UUID`,
        pass: false,
      };
    }
  },

  /**
   * Matcher for array length
   */
  toBeArrayOfSize(received: any, expectedSize: number) {
    const pass = Array.isArray(received) && received.length === expectedSize;

    if (pass) {
      return {
        message: () => `expected array not to have size ${expectedSize}`,
        pass: true,
      };
    } else {
      return {
        message: () => `expected array to have size ${expectedSize}, got ${received?.length}`,
        pass: false,
      };
    }
  },
});

// Extend Jest matchers interface
declare global {
  namespace jest {
    interface Matchers<R> {
      toBeValidUser(): R;
      toBeValidProduct(): R;
      toBeWithinPriceRange(min: number, max: number): R;
      toBeValidEmail(): R;
      toBeValidUuid(): R;
      toBeArrayOfSize(expectedSize: number): R;
    }
  }
}
```

## 🛠️ Test Helper Functions

### API Test Helpers

```typescript
// tests/utilities/helpers/ApiHelpers.ts
import request from 'supertest';
import { Express } from 'express';
import { AssertionHelpers } from './AssertionHelpers';

export class ApiHelpers {
  /**
   * Create authenticated request helper
   */
  static async createAuthenticatedRequest(
    app: Express,
    userData: { email: string; password: string }
  ): Promise<{ token: string; user: any }> {
    // Register user
    const registerResponse = await request(app)
      .post('/api/auth/register')
      .send(userData)
      .expect(201);

    // Login to get token
    const loginResponse = await request(app)
      .post('/api/auth/login')
      .send({
        email: userData.email,
        password: userData.password,
      })
      .expect(200);

    return {
      token: loginResponse.body.data.accessToken,
      user: registerResponse.body.data,
    };
  }

  /**
   * Make authenticated request
   */
  static authenticatedRequest(
    app: Express,
    token: string
  ): request.Test {
    return request(app).set('Authorization', `Bearer ${token}`);
  }

  /**
   * Expect successful API response
   */
  static expectSuccessResponse(
    response: request.Response,
    expectedStatus: number = 200
  ): void {
    expect(response.status).toBe(expectedStatus);
    AssertionHelpers.assertApiResponse(response.body);
    expect(response.body.success).toBe(true);
    expect(response.body.data).toBeDefined();
  }

  /**
   * Expect error API response
   */
  static expectErrorResponse(
    response: request.Response,
    expectedStatus: number,
    expectedError?: string
  ): void {
    expect(response.status).toBe(expectedStatus);
    AssertionHelpers.assertApiResponse(response.body);
    expect(response.body.success).toBe(false);
    expect(response.body.error).toBeDefined();
    
    if (expectedError) {
      expect(response.body.error).toContain(expectedError);
    }
  }

  /**
   * Expect paginated response
   */
  static expectPaginatedResponse(response: request.Response): void {
    this.expectSuccessResponse(response);
    
    const data = response.body.data;
    expect(data).toHaveProperty('items');
    expect(data).toHaveProperty('pagination');
    expect(data.pagination).toHaveProperty('page');
    expect(data.pagination).toHaveProperty('limit');
    expect(data.pagination).toHaveProperty('total');
    expect(data.pagination).toHaveProperty('totalPages');
  }
}
```

### Database Test Helpers

```typescript
// tests/utilities/helpers/DatabaseHelpers.ts
export class DatabaseHelpers {
  /**
   * Truncate all tables
   */
  static async truncateTables(db: any, tables: string[]): Promise<void> {
    for (const table of tables) {
      await db.query(`TRUNCATE TABLE ${table} CASCADE`);
    }
  }

  /**
   * Seed database with test data
   */
  static async seedDatabase(
    db: any,
    data: Record<string, any[]>
  ): Promise<void> {
    for (const [table, records] of Object.entries(data)) {
      if (records.length > 0) {
        await db.insert(table, records);
      }
    }
  }

  /**
   * Count records in table
   */
  static async countRecords(db: any, table: string): Promise<number> {
    const result = await db.query(`SELECT COUNT(*) as count FROM ${table}`);
    return parseInt(result.rows[0].count, 10);
  }

  /**
   * Assert database state
   */
  static async assertDatabaseState(
    db: any,
    expectedCounts: Record<string, number>
  ): Promise<void> {
    for (const [table, expectedCount] of Object.entries(expectedCounts)) {
      const actualCount = await this.countRecords(db, table);
      expect(actualCount).toBe(expectedCount);
    }
  }
}
```

### Async Test Helpers

```typescript
// tests/utilities/helpers/AsyncHelpers.ts
export class AsyncHelpers {
  /**
   * Wait for specified time
   */
  static async wait(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  /**
   * Wait for condition to be true
   */
  static async waitFor(
    condition: () => boolean | Promise<boolean>,
    timeout: number = 5000,
    interval: number = 100
  ): Promise<void> {
    const startTime = Date.now();
    
    while (Date.now() - startTime < timeout) {
      if (await condition()) {
        return;
      }
      await this.wait(interval);
    }
    
    throw new Error(`Condition not met within ${timeout}ms`);
  }

  /**
   * Wait for async function to complete
   */
  static async waitForAsync<T>(
    asyncFn: () => Promise<T>,
    timeout: number = 5000
  ): Promise<T> {
    return Promise.race([
      asyncFn(),
      new Promise<never>((_, reject) => 
        setTimeout(() => reject(new Error(`Async function timed out after ${timeout}ms`)), timeout)
      )
    ]);
  }

  /**
   * Retry async function
   */
  static async retry<T>(
    fn: () => Promise<T>,
    maxAttempts: number = 3,
    delay: number = 1000
  ): Promise<T> {
    let lastError: Error;
    
    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
      try {
        return await fn();
      } catch (error) {
        lastError = error as Error;
        
        if (attempt < maxAttempts) {
          await this.wait(delay * attempt);
        }
      }
    }
    
    throw lastError!;
  }
}
```

## 🧪 Property-Based Testing

### Generic Property Tests

```typescript
// tests/utilities/property/PropertyTests.ts
import fc from 'fast-check';
import { User } from '@/models/User';

export class PropertyTests {
  /**
   * Test user email validation
   */
  static userEmailValidation(): void {
    fc.assert(
      fc.property(
        fc.email(),
        (email) => {
          // Test that valid emails pass validation
          const result = validateEmail(email);
          expect(result).toBe(true);
        }
      )
    );
  }

  /**
   * Test user age validation
   */
  static userAgeValidation(): void {
    fc.assert(
      fc.property(
        fc.integer({ min: 0, max: 150 }),
        (age) => {
          // Test that valid ages pass validation
          const result = validateAge(age);
          expect(result).toBe(true);
        }
      )
    );
  }

  /**
   * Test price calculation
   */
  static priceCalculation(): void {
    fc.assert(
      fc.property(
        fc.record({
          price: fc.float({ min: 0, max: 1000 }),
          quantity: fc.integer({ min: 1, max: 100 }),
          taxRate: fc.float({ min: 0, max: 0.3 }),
        }),
        ({ price, quantity, taxRate }) => {
          const total = calculateTotalPrice(price, quantity, taxRate);
          
          expect(total).toBeGreaterThan(0);
          expect(total).toBe(price * quantity * (1 + taxRate));
        }
      )
    );
  }

  /**
   * Test array sorting properties
   */
  static arraySorting(): void {
    fc.assert(
      fc.property(
        fc.array(fc.integer()),
        (arr) => {
          const sorted = [...arr].sort((a, b) => a - b);
          
          // Test that sorted array is ordered
          for (let i = 1; i < sorted.length; i++) {
            expect(sorted[i - 1]).toBeLessThanOrEqual(sorted[i]);
          }
          
          // Test that sorted array contains same elements
          expect(sorted.sort()).toEqual([...arr].sort());
        }
      )
    );
  }
}
```

## 📊 Test Data Management

### Fixture Manager

```typescript
// tests/utilities/fixtures/FixtureManager.ts
export class FixtureManager {
  private fixtures: Map<string, any> = new Map();

  /**
   * Load fixture data
   */
  static async loadFixture<T>(name: string): Promise<T> {
    const fixturePath = `../fixtures/${name}.json`;
    const fixture = await import(fixturePath);
    return fixture.default as T;
  }

  /**
   * Save fixture data
   */
  static async saveFixture<T>(name: string, data: T): Promise<void> {
    const fixturePath = `./fixtures/${name}.json`;
    await fs.writeFile(fixturePath, JSON.stringify(data, null, 2));
  }

  /**
   * Create test scenario
   */
  static createScenario(name: string, setup: () => Promise<any>): void {
    // Store scenario setup function
    this.scenarios.set(name, setup);
  }

  /**
   * Load test scenario
   */
  static async loadScenario(name: string): Promise<any> {
    const setup = this.scenarios.get(name);
    if (!setup) {
      throw new Error(`Scenario ${name} not found`);
    }
    return await setup();
  }
}
```

## 🎯 Usage Examples

### Complete Test Example

```typescript
// tests/integration/UserService.integration.test.ts
import { UserService } from '@/services/UserService';
import { MockFactory } from '../utilities/mocks/MockFactory';
import { UserFactory } from '../utilities/factories/UserFactory';
import { ApiHelpers } from '../utilities/helpers/ApiHelpers';
import { AssertionHelpers } from '../utilities/helpers/AssertionHelpers';

describe('UserService Integration Tests', () => {
  let userService: UserService;
  let mockRepository: Mocked<IUserRepository>;

  beforeEach(() => {
    mockRepository = MockFactory.createClassMock(UserRepository);
    userService = new UserService(mockRepository);
  });

  describe('createUser', () => {
    it('should create user with valid data', async () => {
      // Arrange
      const userData = UserFactory.createCreateRequest();
      const expectedUser = UserFactory.create(userData);
      
      mockRepository.create.mockResolvedValue(expectedUser);
      mockRepository.findByEmail.mockResolvedValue(null);

      // Act
      const result = await userService.createUser(userData);

      // Assert
      AssertionHelpers.assertValidUser(result);
      expect(result.email).toBe(userData.email);
      expect(mockRepository.create).toHaveBeenCalledWith(
        expect.objectContaining({
          name: userData.name,
          email: userData.email,
        })
      );
    });

    it('should reject duplicate email', async () => {
      // Arrange
      const userData = UserFactory.createCreateRequest();
      const existingUser = UserFactory.create({ email: userData.email });
      
      mockRepository.findByEmail.mockResolvedValue(existingUser);

      // Act & Assert
      await expect(userService.createUser(userData))
        .rejects
        .toThrow('Email already exists');
      
      expect(mockRepository.create).not.toHaveBeenCalled();
    });
  });
});
```

---

## 📚 Best Practices

### Type Safety
1. **Use generics**: Create reusable type-safe utilities
2. **Type guards**: Validate data at runtime in tests
3. **Mock typing**: Ensure mocks have proper TypeScript types
4. **Assertion helpers**: Use type assertions for test validation

### Reusability
1. **Factory pattern**: Create reusable data factories
2. **Helper functions**: Extract common test logic
3. **Custom matchers**: Create domain-specific assertions
4. **Base classes**: Use inheritance for shared test setup

### Maintainability
1. **Clear naming**: Use descriptive names for utilities
2. **Documentation**: Document complex utilities with examples
3. **Separation of concerns**: Keep utilities focused and single-purpose
4. **Version compatibility**: Ensure utilities work with different library versions

---

## 📚 Additional Resources

- [Jest TypeScript Documentation](https://jestjs.io/docs/getting-started#using-typescript)
- [TypeScript Testing Best Practices](https://basarat.gitbook.io/typescript/testing)
- [Property-Based Testing with Fast-Check](https://github.com/dubzzz/fast-check)

---

*Test Utilities Pattern Version: [[.Version]]*  
*Author: [[.Author]]*  
*Date: [[.Date]]*
