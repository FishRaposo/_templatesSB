# Universal Template System - Node Stack
# Generated: 2025-12-10
# Purpose: Testing utilities
# Tier: base
# Stack: node
# Category: template

# TypeScript/Node Testing Examples - {{PROJECT_NAME}}

**Tier**: {{TIER}} | **Stack**: TypeScript/Node

## 🧪 Testing Strategy Overview

TypeScript/Node testing follows the **testing pyramid**: **Unit Tests > Integration Tests > End-to-End Tests**. Each tier requires different levels of testing rigor with Jest as the primary framework and Supertest for API testing.

## 📊 Tier-Specific Testing Requirements

| Tier | Unit Tests | Integration Tests | E2E Tests | Performance Tests |
|------|------------|-------------------|-----------|-------------------|
| **MVP** | Basic logic | API endpoints | Not required | Not required |
| **CORE** | Complete coverage | Database + external APIs | Critical flows | Load testing |
| **FULL** | Complete + edge cases | All integrations | All flows | Performance + chaos |

## 🔬 Unit Testing Examples

### **MVP Tier - Simple Logic Testing**

```typescript
// tests/unit/services/user.service.test.ts
import { UserService } from '../../../src/services/user.service';
import { User } from '../../../src/entities/user.entity';

describe('UserService', () => {
  let userService: UserService;

  beforeEach(() => {
    userService = new UserService();
  });

  describe('createUser', () => {
    it('should create a user with valid data', () => {
      // Arrange
      const userData = {
        email: 'test@example.com',
        name: 'Test User',
      };

      // Act
      const user = userService.createUser(userData);

      // Assert
      expect(user.email).toBe('test@example.com');
      expect(user.name).toBe('Test User');
      expect(user.id).toBeDefined();
      expect(user.createdAt).toBeInstanceOf(Date);
    });

    it('should throw error with invalid email', () => {
      // Arrange
      const userData = {
        email: 'invalid-email',
        name: 'Test User',
      };

      // Act & Assert
      expect(() => userService.createUser(userData))
        .toThrow('Invalid email format');
    });
  });

  describe('calculateUserAge', () => {
    it('should calculate correct age', () => {
      // Arrange
      const birthDate = new Date('1990-01-01');
      const user = new User({
        id: '1',
        email: 'test@example.com',
        name: 'Test User',
        birthDate,
      });

      // Act
      const age = userService.calculateAge(user);

      // Assert
      expect(age).toBeGreaterThanOrEqual(30);
    });
  });
});
```

### **CORE Tier - Business Logic Testing**

```typescript
// tests/unit/services/auth.service.test.ts
import { AuthService } from '../../../src/services/auth.service';
import { UserRepository } from '../../../src/repositories/user.repository';
import { JwtService } from '../../../src/services/jwt.service';
import { BcryptService } from '../../../src/services/bcrypt.service';
import { User } from '../../../src/entities/user.entity';
import { UnauthorizedException, BadRequestException } from '../../../src/exceptions';

jest.mock('../../../src/repositories/user.repository');
jest.mock('../../../src/services/jwt.service');
jest.mock('../../../src/services/bcrypt.service');

describe('AuthService', () => {
  let authService: AuthService;
  let mockUserRepository: jest.Mocked<UserRepository>;
  let mockJwtService: jest.Mocked<JwtService>;
  let mockBcryptService: jest.Mocked<BcryptService>;

  beforeEach(() => {
    mockUserRepository = new UserRepository() as jest.Mocked<UserRepository>;
    mockJwtService = new JwtService() as jest.Mocked<JwtService>;
    mockBcryptService = new BcryptService() as jest.Mocked<BcryptService>;

    authService = new AuthService(
      mockUserRepository,
      mockJwtService,
      mockBcryptService,
    );
  });

  describe('login', () => {
    it('should return access token for valid credentials', async () => {
      // Arrange
      const loginDto = {
        email: 'test@example.com',
        password: 'password123',
      };

      const user = new User({
        id: '1',
        email: 'test@example.com',
        name: 'Test User',
        password: 'hashedPassword',
      });

      mockUserRepository.findByEmail.mockResolvedValue(user);
      mockBcryptService.compare.mockResolvedValue(true);
      mockJwtService.sign.mockReturnValue('mock-token');

      // Act
      const result = await authService.login(loginDto);

      // Assert
      expect(result).toEqual({ accessToken: 'mock-token' });
      expect(mockUserRepository.findByEmail).toHaveBeenCalledWith('test@example.com');
      expect(mockBcryptService.compare).toHaveBeenCalledWith('password123', 'hashedPassword');
      expect(mockJwtService.sign).toHaveBeenCalledWith({ sub: '1', email: 'test@example.com' });
    });

    it('should throw UnauthorizedException for invalid credentials', async () => {
      // Arrange
      const loginDto = {
        email: 'test@example.com',
        password: 'wrong-password',
      };

      const user = new User({
        id: '1',
        email: 'test@example.com',
        name: 'Test User',
        password: 'hashedPassword',
      });

      mockUserRepository.findByEmail.mockResolvedValue(user);
      mockBcryptService.compare.mockResolvedValue(false);

      // Act & Assert
      await expect(authService.login(loginDto))
        .rejects.toThrow(UnauthorizedException);
    });

    it('should throw UnauthorizedException for non-existent user', async () => {
      // Arrange
      const loginDto = {
        email: 'nonexistent@example.com',
        password: 'password123',
      };

      mockUserRepository.findByEmail.mockResolvedValue(null);

      // Act & Assert
      await expect(authService.login(loginDto))
        .rejects.toThrow(UnauthorizedException);
    });
  });

  describe('register', () => {
    it('should create new user successfully', async () => {
      // Arrange
      const registerDto = {
        email: 'test@example.com',
        password: 'password123',
        name: 'Test User',
      };

      const hashedPassword = 'hashed-password';
      const createdUser = new User({
        id: '1',
        email: 'test@example.com',
        name: 'Test User',
        password: hashedPassword,
      });

      mockUserRepository.findByEmail.mockResolvedValue(null);
      mockBcryptService.hash.mockResolvedValue(hashedPassword);
      mockUserRepository.create.mockResolvedValue(createdUser);

      // Act
      const result = await authService.register(registerDto);

      // Assert
      expect(result).toEqual(createdUser);
      expect(mockUserRepository.findByEmail).toHaveBeenCalledWith('test@example.com');
      expect(mockBcryptService.hash).toHaveBeenCalledWith('password123');
      expect(mockUserRepository.create).toHaveBeenCalledWith({
        ...registerDto,
        password: hashedPassword,
      });
    });

    it('should throw BadRequestException if user already exists', async () => {
      // Arrange
      const registerDto = {
        email: 'existing@example.com',
        password: 'password123',
        name: 'Test User',
      };

      const existingUser = new User({
        id: '1',
        email: 'existing@example.com',
        name: 'Existing User',
        password: 'hashedPassword',
      });

      mockUserRepository.findByEmail.mockResolvedValue(existingUser);

      // Act & Assert
      await expect(authService.register(registerDto))
        .rejects.toThrow(BadRequestException);
    });
  });
});
```

### **FULL Tier - Advanced Logic Testing**

```typescript
// tests/unit/services/enterprise-order.service.test.ts
import { EnterpriseOrderService } from '../../../src/services/enterprise-order.service';
import { OrderRepository } from '../../../src/repositories/order.repository';
import { UserRepository } from '../../../src/repositories/user.repository';
import { InventoryRepository } from '../../../src/repositories/inventory.repository';
import { PaymentGatewayService } from '../../../src/integrations/payment-gateway.service';
import { NotificationService } from '../../../src/integrations/notification.service';
import { MetricsService } from '../../../src/monitoring/metrics.service';
import { TracingService } from '../../../src/monitoring/tracing.service';
import { EventBus } from '../../../src/events/event-bus.service';
import { AuditLogger } from '../../../src/enterprise/audit/audit-logger.service';
import { Order, OrderItem } from '../../../src/entities/order.entity';
import { BusinessRuleException, InventoryException } from '../../../src/exceptions';

describe('EnterpriseOrderService', () => {
  let orderService: EnterpriseOrderService;
  let mockOrderRepository: jest.Mocked<OrderRepository>;
  let mockUserRepository: jest.Mocked<UserRepository>;
  let mockInventoryRepository: jest.Mocked<InventoryRepository>;
  let mockPaymentGateway: jest.Mocked<PaymentGatewayService>;
  let mockNotificationService: jest.Mocked<NotificationService>;
  let mockMetrics: jest.Mocked<MetricsService>;
  let mockTracing: jest.Mocked<TracingService>;
  let mockEventBus: jest.Mocked<EventBus>;
  let mockAuditLogger: jest.Mocked<AuditLogger>;

  beforeEach(() => {
    // Create mocks
    mockOrderRepository = {
      create: jest.fn(),
      updateStatus: jest.fn(),
    } as any;

    mockUserRepository = {
      findById: jest.fn(),
    } as any;

    mockInventoryRepository = {
      getByProductId: jest.fn(),
    } as any;

    mockPaymentGateway = {
      processPayment: jest.fn(),
    } as any;

    mockNotificationService = {
      sendOrderConfirmation: jest.fn(),
    } as any;

    mockMetrics = {
      incrementCounter: jest.fn(),
    } as any;

    mockTracing = {
      startSpan: jest.fn(),
      recordException: jest.fn(),
    } as any;

    mockEventBus = {
      publish: jest.fn(),
    } as any;

    mockAuditLogger = {
      logOrderCreation: jest.fn(),
      logOrderCreationFailure: jest.fn(),
    } as any;

    orderService = new EnterpriseOrderService(
      mockOrderRepository,
      mockUserRepository,
      mockInventoryRepository,
      mockPaymentGateway,
      mockNotificationService,
      mockMetrics,
      mockTracing,
      mockEventBus,
      mockAuditLogger,
    );
  });

  describe('createOrder', () => {
    it('should create order successfully with all business rules', async () => {
      // Arrange
      const userId = 'user-123';
      const createOrderDto = {
        items: [
          { productId: 'prod-1', quantity: 2, price: 50 },
          { productId: 'prod-2', quantity: 1, price: 100 },
        ],
      };

      const user = { id: userId, isActive: true, isPremium: false };
      const inventory1 = { productId: 'prod-1', availableQuantity: 10 };
      const inventory2 = { productId: 'prod-2', availableQuantity: 5 };
      const createdOrder = new Order({
        id: 'order-123',
        userId,
        items: createOrderDto.items,
        totalAmount: 216, // (50*2 + 100*1) * 1.08 tax
        status: 'pending',
      });

      const paymentResult = { success: true, paymentMethod: 'credit_card' };

      // Setup mocks
      mockUserRepository.findById.mockResolvedValue(user);
      mockInventoryRepository.getByProductId
        .mockResolvedValueOnce(inventory1)
        .mockResolvedValueOnce(inventory2);
      mockOrderRepository.create.mockResolvedValue(createdOrder);
      mockPaymentGateway.processPayment.mockResolvedValue(paymentResult);
      mockOrderRepository.updateStatus.mockResolvedValue(createdOrder);

      // Mock tracing span
      const mockSpan = {
        setAttributes: jest.fn(),
        end: jest.fn(),
      };
      mockTracing.startSpan.mockReturnValue(mockSpan);

      // Act
      const result = await orderService.createOrder(userId, createOrderDto);

      // Assert
      expect(result).toEqual(createdOrder);
      expect(mockUserRepository.findById).toHaveBeenCalledWith(userId);
      expect(mockInventoryRepository.getByProductId).toHaveBeenCalledTimes(2);
      expect(mockOrderRepository.create).toHaveBeenCalled();
      expect(mockPaymentGateway.processPayment).toHaveBeenCalled();
      expect(mockOrderRepository.updateStatus).toHaveBeenCalledWith('order-123', 'confirmed');
      expect(mockMetrics.incrementCounter).toHaveBeenCalledWith('orders_created', {
        userId,
        status: 'confirmed',
        totalAmount: '216',
      });
      expect(mockEventBus.publish).toHaveBeenCalled();
      expect(mockNotificationService.sendOrderConfirmation).toHaveBeenCalled();
      expect(mockAuditLogger.logOrderCreation).toHaveBeenCalled();
    });

    it('should throw BusinessRuleException for inactive user', async () => {
      // Arrange
      const userId = 'user-123';
      const createOrderDto = { items: [{ productId: 'prod-1', quantity: 1, price: 50 }] };
      const user = { id: userId, isActive: false };

      mockUserRepository.findById.mockResolvedValue(user);

      // Act & Assert
      await expect(orderService.createOrder(userId, createOrderDto))
        .rejects.toThrow(BusinessRuleException);

      expect(mockMetrics.incrementCounter).toHaveBeenCalledWith('order_creation_failed', {
        userId,
        errorType: 'BusinessRuleException',
      });
    });

    it('should throw InventoryException for insufficient inventory', async () => {
      // Arrange
      const userId = 'user-123';
      const createOrderDto = { items: [{ productId: 'prod-1', quantity: 10, price: 50 }] };
      const user = { id: userId, isActive: true };
      const inventory = { productId: 'prod-1', availableQuantity: 5 };

      mockUserRepository.findById.mockResolvedValue(user);
      mockInventoryRepository.getByProductId.mockResolvedValue(inventory);

      // Act & Assert
      await expect(orderService.createOrder(userId, createOrderDto))
        .rejects.toThrow(InventoryException);
    });

    it('should handle payment failure gracefully', async () => {
      // Arrange
      const userId = 'user-123';
      const createOrderDto = { items: [{ productId: 'prod-1', quantity: 1, price: 50 }] };
      const user = { id: userId, isActive: true };
      const inventory = { productId: 'prod-1', availableQuantity: 10 };
      const createdOrder = new Order({
        id: 'order-123',
        userId,
        items: createOrderDto.items,
        totalAmount: 54,
        status: 'pending',
      });
      const paymentResult = { success: false, paymentMethod: 'credit_card' };

      mockUserRepository.findById.mockResolvedValue(user);
      mockInventoryRepository.getByProductId.mockResolvedValue(inventory);
      mockOrderRepository.create.mockResolvedValue(createdOrder);
      mockPaymentGateway.processPayment.mockResolvedValue(paymentResult);
      mockOrderRepository.updateStatus.mockResolvedValue(createdOrder);

      const mockSpan = { setAttributes: jest.fn(), end: jest.fn() };
      mockTracing.startSpan.mockReturnValue(mockSpan);

      // Act & Assert
      await expect(orderService.createOrder(userId, createOrderDto))
        .rejects.toThrow(BusinessRuleException);

      expect(mockOrderRepository.updateStatus).toHaveBeenCalledWith('order-123', 'payment_failed');
    });
  });
});
```

## 🌐 Integration Testing Examples

### **CORE Tier - API Endpoint Testing**

```typescript
// tests/integration/auth.test.ts
import request from 'supertest';
import { FastifyInstance } from 'fastify';
import { buildApp } from '../../src/app';
import { PrismaClient } from '@prisma/client';

describe('Auth Endpoints', () => {
  let app: FastifyInstance;
  let prisma: PrismaClient;

  beforeAll(async () => {
    app = buildApp();
    prisma = new PrismaClient({
      datasources: {
        db: {
          url: process.env.TEST_DATABASE_URL,
        },
      },
    });

    await app.ready();
  });

  afterAll(async () => {
    await app.close();
    await prisma.$disconnect();
  });

  beforeEach(async () => {
    // Clean database
    await prisma.user.deleteMany();
  });

  describe('POST /auth/register', () => {
    it('should register a new user successfully', async () => {
      // Arrange
      const userData = {
        email: 'test@example.com',
        password: 'password123',
        name: 'Test User',
      };

      // Act
      const response = await request(app.server)
        .post('/auth/register')
        .send(userData)
        .expect(201);

      // Assert
      expect(response.body).toMatchObject({
        id: expect.any(String),
        email: userData.email,
        name: userData.name,
      });
      expect(response.body).not.toHaveProperty('password');

      // Verify user in database
      const user = await prisma.user.findUnique({
        where: { email: userData.email },
      });
      expect(user).toBeTruthy();
      expect(user.email).toBe(userData.email);
    });

    it('should return 400 for invalid email', async () => {
      // Arrange
      const userData = {
        email: 'invalid-email',
        password: 'password123',
        name: 'Test User',
      };

      // Act & Assert
      const response = await request(app.server)
        .post('/auth/register')
        .send(userData)
        .expect(400);

      expect(response.body.message).toContain('email');
    });

    it('should return 400 for weak password', async () => {
      // Arrange
      const userData = {
        email: 'test@example.com',
        password: '123',
        name: 'Test User',
      };

      // Act & Assert
      const response = await request(app.server)
        .post('/auth/register')
        .send(userData)
        .expect(400);

      expect(response.body.message).toContain('password');
    });

    it('should return 400 for duplicate email', async () => {
      // Arrange
      const userData = {
        email: 'test@example.com',
        password: 'password123',
        name: 'Test User',
      };

      // Create existing user
      await prisma.user.create({
        data: {
          email: userData.email,
          name: 'Existing User',
          password: 'hashed-password',
        },
      });

      // Act & Assert
      const response = await request(app.server)
        .post('/auth/register')
        .send(userData)
        .expect(400);

      expect(response.body.message).toContain('already exists');
    });
  });

  describe('POST /auth/login', () => {
    beforeEach(async () => {
      // Create test user
      await prisma.user.create({
        data: {
          email: 'test@example.com',
          name: 'Test User',
          password: '$2b$10$hashed.password.here', // Mock hashed password
        },
      });
    });

    it('should login successfully with valid credentials', async () => {
      // Arrange
      const loginData = {
        email: 'test@example.com',
        password: 'password123',
      };

      // Act
      const response = await request(app.server)
        .post('/auth/login')
        .send(loginData)
        .expect(200);

      // Assert
      expect(response.body).toMatchObject({
        accessToken: expect.any(String),
      });
    });

    it('should return 401 for invalid credentials', async () => {
      // Arrange
      const loginData = {
        email: 'test@example.com',
        password: 'wrong-password',
      };

      // Act & Assert
      const response = await request(app.server)
        .post('/auth/login')
        .send(loginData)
        .expect(401);

      expect(response.body.message).toContain('Invalid credentials');
    });

    it('should return 401 for non-existent user', async () => {
      // Arrange
      const loginData = {
        email: 'nonexistent@example.com',
        password: 'password123',
      };

      // Act & Assert
      const response = await request(app.server)
        .post('/auth/login')
        .send(loginData)
        .expect(401);

      expect(response.body.message).toContain('Invalid credentials');
    });
  });
});
```

### **FULL Tier - Database Integration Testing**

```typescript
// tests/integration/order.repository.test.ts
import { OrderRepository } from '../../../src/repositories/order.repository';
import { PrismaClient } from '@prisma/client';
import { Order, OrderStatus } from '../../../src/entities/order.entity';

describe('OrderRepository', () => {
  let orderRepository: OrderRepository;
  let prisma: PrismaClient;
  let testUser: any;

  beforeAll(async () => {
    prisma = new PrismaClient({
      datasources: {
        db: {
          url: process.env.TEST_DATABASE_URL,
        },
      },
    });

    orderRepository = new OrderRepository(prisma);

    // Create test user
    testUser = await prisma.user.create({
      data: {
        email: 'test@example.com',
        name: 'Test User',
        password: 'hashed-password',
      },
    });
  });

  afterAll(async () => {
    await prisma.$disconnect();
  });

  beforeEach(async () => {
    await prisma.order.deleteMany();
  });

  describe('create', () => {
    it('should create order successfully', async () => {
      // Arrange
      const orderData = {
        userId: testUser.id,
        items: [
          { productId: 'prod-1', quantity: 2, price: 50 },
          { productId: 'prod-2', quantity: 1, price: 100 },
        ],
        totalAmount: 200,
        status: OrderStatus.PENDING,
      };

      // Act
      const order = await orderRepository.create(orderData);

      // Assert
      expect(order).toMatchObject({
        id: expect.any(String),
        userId: testUser.id,
        totalAmount: orderData.totalAmount,
        status: orderData.status,
      });
      expect(order.createdAt).toBeInstanceOf(Date);

      // Verify in database
      const dbOrder = await prisma.order.findUnique({
        where: { id: order.id },
        include: { items: true },
      });
      expect(dbOrder).toBeTruthy();
      expect(dbOrder.items).toHaveLength(2);
    });

    it('should create order with items', async () => {
      // Arrange
      const orderData = {
        userId: testUser.id,
        items: [
          { productId: 'prod-1', quantity: 2, price: 50 },
          { productId: 'prod-2', quantity: 1, price: 100 },
        ],
        totalAmount: 200,
        status: OrderStatus.PENDING,
      };

      // Act
      const order = await orderRepository.create(orderData);

      // Assert
      const dbOrder = await prisma.order.findUnique({
        where: { id: order.id },
        include: { items: true },
      });

      expect(dbOrder.items).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            productId: 'prod-1',
            quantity: 2,
            price: 50,
          }),
          expect.objectContaining({
            productId: 'prod-2',
            quantity: 1,
            price: 100,
          }),
        ])
      );
    });
  });

  describe('findByUserId', () => {
    it('should return orders for specific user', async () => {
      // Arrange
      const order1 = await prisma.order.create({
        data: {
          userId: testUser.id,
          totalAmount: 100,
          status: OrderStatus.PENDING,
        },
      });

      const order2 = await prisma.order.create({
        data: {
          userId: testUser.id,
          totalAmount: 200,
          status: OrderStatus.CONFIRMED,
        },
      });

      // Create order for different user
      const otherUser = await prisma.user.create({
        data: {
          email: 'other@example.com',
          name: 'Other User',
          password: 'hashed-password',
        },
      });

      await prisma.order.create({
        data: {
          userId: otherUser.id,
          totalAmount: 150,
          status: OrderStatus.PENDING,
        },
      });

      // Act
      const orders = await orderRepository.findByUserId(testUser.id);

      // Assert
      expect(orders).toHaveLength(2);
      expect(orders.map(o => o.id)).toEqual(
        expect.arrayContaining([order1.id, order2.id])
      );
    });

    it('should return empty array for user with no orders', async () => {
      // Act
      const orders = await orderRepository.findByUserId('non-existent-user');

      // Assert
      expect(orders).toHaveLength(0);
    });
  });

  describe('updateStatus', () => {
    it('should update order status successfully', async () => {
      // Arrange
      const order = await prisma.order.create({
        data: {
          userId: testUser.id,
          totalAmount: 100,
          status: OrderStatus.PENDING,
        },
      });

      // Act
      const updatedOrder = await orderRepository.updateStatus(
        order.id,
        OrderStatus.CONFIRMED
      );

      // Assert
      expect(updatedOrder.status).toBe(OrderStatus.CONFIRMED);
      expect(updatedOrder.updatedAt).not.toEqual(order.updatedAt);

      // Verify in database
      const dbOrder = await prisma.order.findUnique({
        where: { id: order.id },
      });
      expect(dbOrder.status).toBe(OrderStatus.CONFIRMED);
    });

    it('should throw error for non-existent order', async () => {
      // Act & Assert
      await expect(
        orderRepository.updateStatus('non-existent-order', OrderStatus.CONFIRMED)
      ).rejects.toThrow();
    });
  });
});
```

## 🚀 End-to-End Testing Examples

### **CORE Tier - Critical Flow Testing**

```typescript
// tests/e2e/user-journey.test.ts
import { test, expect } from '@playwright/test';

test.describe('User Registration and Login Flow', () => {
  test('should allow user to register and login', async ({ page }) => {
    // Navigate to registration page
    await page.goto('http://localhost:3000/register');

    // Fill registration form
    await page.fill('[data-testid="email-input"]', 'test@example.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.fill('[data-testid="name-input"]', 'Test User');
    await page.fill('[data-testid="confirm-password-input"]', 'password123');

    // Submit registration
    await page.click('[data-testid="register-button"]');

    // Wait for successful registration
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText(
      'Registration successful'
    );

    // Navigate to login page
    await page.goto('http://localhost:3000/login');

    // Fill login form
    await page.fill('[data-testid="email-input"]', 'test@example.com');
    await page.fill('[data-testid="password-input"]', 'password123');

    // Submit login
    await page.click('[data-testid="login-button"]');

    // Verify successful login
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();
    await expect(page.locator('[data-testid="user-email"]')).toContainText(
      'test@example.com'
    );
  });

  test('should show validation errors for invalid registration', async ({ page }) => {
    await page.goto('http://localhost:3000/register');

    // Submit empty form
    await page.click('[data-testid="register-button"]');

    // Check for validation errors
    await expect(page.locator('[data-testid="email-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="password-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="name-error"]')).toBeVisible();

    // Fill with invalid email
    await page.fill('[data-testid="email-input"]', 'invalid-email');
    await page.click('[data-testid="register-button"]');

    await expect(page.locator('[data-testid="email-error"]')).toContainText(
      'Invalid email format'
    );
  });
});
```

### **FULL Tier - Complex Scenario Testing**

```typescript
// tests/e2e/order-processing.test.ts
import { test, expect } from '@playwright/test';

test.describe('Complete Order Processing Flow', () => {
  test('should process order from creation to completion', async ({ page }) => {
    // Login as user
    await page.goto('http://localhost:3000/login');
    await page.fill('[data-testid="email-input"]', 'customer@example.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');

    // Navigate to products
    await page.goto('http://localhost:3000/products');

    // Add products to cart
    await page.click('[data-testid="product-1"] [data-testid="add-to-cart"]');
    await page.click('[data-testid="product-2"] [data-testid="add-to-cart"]');

    // Navigate to cart
    await page.click('[data-testid="cart-icon"]');
    await expect(page.locator('[data-testid="cart-item"]')).toHaveCount(2);

    // Proceed to checkout
    await page.click('[data-testid="checkout-button"]');

    // Fill shipping information
    await page.fill('[data-testid="shipping-address"]', '123 Test Street');
    await page.fill('[data-testid="shipping-city"]', 'Test City');
    await page.fill('[data-testid="shipping-zip"]', '12345');

    // Fill payment information
    await page.fill('[data-testid="card-number"]', '4242424242424242');
    await page.fill('[data-testid="card-expiry"]', '12/25');
    await page.fill('[data-testid="card-cvv"]', '123');

    // Place order
    await page.click('[data-testid="place-order-button"]');

    // Wait for order confirmation
    await expect(page.locator('[data-testid="order-confirmation"]')).toBeVisible();
    const orderId = await page.locator('[data-testid="order-id"]').textContent();

    // Verify order in admin panel
    await page.goto('http://localhost:3000/admin/login');
    await page.fill('[data-testid="email-input"]', 'admin@example.com');
    await page.fill('[data-testid="password-input"]', 'adminpassword');
    await page.click('[data-testid="login-button"]');

    await page.goto('http://localhost:3000/admin/orders');
    await expect(page.locator(`[data-testid="order-${orderId}"]`)).toBeVisible();

    // Check order status
    await expect(page.locator(`[data-testid="order-${orderId}-status"]`)).toContainText(
      'confirmed'
    );
  });

  test('should handle payment failure gracefully', async ({ page }) => {
    // Login and add items to cart (same as above)
    await page.goto('http://localhost:3000/login');
    await page.fill('[data-testid="email-input"]', 'customer@example.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');

    await page.goto('http://localhost:3000/products');
    await page.click('[data-testid="product-1"] [data-testid="add-to-cart"]');
    await page.click('[data-testid="cart-icon"]');
    await page.click('[data-testid="checkout-button"]');

    // Fill shipping information
    await page.fill('[data-testid="shipping-address"]', '123 Test Street');
    await page.fill('[data-testid="shipping-city"]', 'Test City');
    await page.fill('[data-testid="shipping-zip"]', '12345');

    // Use card that will be declined
    await page.fill('[data-testid="card-number"]', '4000000000000002');
    await page.fill('[data-testid="card-expiry"]', '12/25');
    await page.fill('[data-testid="card-cvv"]', '123');

    // Attempt to place order
    await page.click('[data-testid="place-order-button"]');

    // Verify payment failure message
    await expect(page.locator('[data-testid="payment-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="payment-error"]')).toContainText(
      'Payment declined'
    );

    // Verify user can try again
    await expect(page.locator('[data-testid="payment-form"]')).toBeVisible();
  });
});
```

## ⚡ Performance Testing Examples

### **FULL Tier - Load Testing**

```typescript
// tests/performance/api-load.test.ts
import { PerformanceTest } from '../utils/performance-test';

describe('API Load Tests', () => {
  const performanceTest = new PerformanceTest({
    baseUrl: 'http://localhost:3000',
    concurrentUsers: 50,
    duration: 30000, // 30 seconds
  });

  beforeAll(async () => {
    await performanceTest.setup();
  });

  afterAll(async () => {
    await performanceTest.cleanup();
  });

  test('should handle concurrent user requests', async () => {
    const results = await performanceTest.runLoadTest({
      endpoint: '/api/users',
      method: 'GET',
      headers: {
        'Authorization': 'Bearer valid-token',
      },
    });

    // Performance assertions
    expect(results.totalRequests).toBeGreaterThan(1000);
    expect(results.averageResponseTime).toBeLessThan(500); // Under 500ms
    expect(results.errorRate).toBeLessThan(0.01); // Under 1% error rate
    expect(results.p95ResponseTime).toBeLessThan(1000); // 95th percentile under 1s

    console.log(`Processed ${results.totalRequests} requests`);
    console.log(`Average response time: ${results.averageResponseTime}ms`);
    console.log(`Error rate: ${(results.errorRate * 100).toFixed(2)}%`);
  });

  test('should handle order creation under load', async () => {
    const results = await performanceTest.runLoadTest({
      endpoint: '/api/orders',
      method: 'POST',
      headers: {
        'Authorization': 'Bearer valid-token',
        'Content-Type': 'application/json',
      },
      body: {
        items: [
          { productId: 'prod-1', quantity: 2, price: 50 },
        ],
      },
    });

    expect(results.averageResponseTime).toBeLessThan(1000); // Under 1s for complex operations
    expect(results.errorRate).toBeLessThan(0.05); // Under 5% error rate for writes
  });
});
```

### **Memory and Resource Testing**

```typescript
// tests/performance/memory.test.ts
import { performance } from 'perf_hooks';
import { buildApp } from '../../src/app';

describe('Memory and Resource Tests', () => {
  let app: any;

  beforeAll(async () => {
    app = buildApp();
    await app.ready();
  });

  afterAll(async () => {
    await app.close();
  });

  test('should not leak memory during high load', async () => {
    const initialMemory = process.memoryUsage().heapUsed;
    const iterations = 10000;

    // Simulate high load
    for (let i = 0; i < iterations; i++) {
      await app.inject({
        method: 'GET',
        url: '/api/users',
      });
    }

    // Force garbage collection if available
    if (global.gc) {
      global.gc();
    }

    const finalMemory = process.memoryUsage().heapUsed;
    const memoryIncrease = finalMemory - initialMemory;

    // Memory increase should be reasonable (less than 100MB)
    expect(memoryIncrease).toBeLessThan(100 * 1024 * 1024);
    
    console.log(`Memory increase: ${(memoryIncrease / 1024 / 1024).toFixed(2)}MB`);
  });

  test('should handle concurrent database connections efficiently', async () => {
    const startTime = performance.now();
    const concurrentRequests = 100;

    const promises = Array.from({ length: concurrentRequests }, async () => {
      return app.inject({
        method: 'GET',
        url: '/api/orders',
        headers: {
          'Authorization': 'Bearer valid-token',
        },
      });
    });

    const results = await Promise.all(promises);
    const endTime = performance.now();

    const totalTime = endTime - startTime;
    const averageTime = totalTime / concurrentRequests;

    // Should handle concurrent requests efficiently
    expect(averageTime).toBeLessThan(100); // Average under 100ms per request
    expect(results.every(r => r.statusCode < 500)).toBe(true); // No server errors

    console.log(`Processed ${concurrentRequests} concurrent requests in ${totalTime.toFixed(2)}ms`);
    console.log(`Average time per request: ${averageTime.toFixed(2)}ms`);
  });
});
```

## 🛠️ Testing Utilities and Configuration

### **Test Configuration**

```typescript
// jest.config.js
module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  roots: ['<rootDir>/src', '<rootDir>/tests'],
  testMatch: ['**/__tests__/**/*.ts', '**/?(*.)+(spec|test).ts'],
  transform: {
    '^.+\\.ts$': 'ts-jest',
  },
  collectCoverageFrom: [
    'src/**/*.ts',
    '!src/**/*.d.ts',
    '!src/index.ts',
    '!src/**/__tests__/**',
    '!src/**/test-utils/**',
  ],
  coverageDirectory: 'coverage',
  coverageReporters: ['text', 'lcov', 'html'],
  coverageThreshold: {
    global: {
      branches: 80,
      functions: 80,
      lines: 80,
      statements: 80,
    },
  },
  setupFilesAfterEnv: ['<rootDir>/tests/setup.ts'],
  moduleNameMapping: {
    '^@/(.*)$': '<rootDir>/src/$1',
    '^@tests/(.*)$': '<rootDir>/tests/$1',
  },
};
```

### **Test Setup and Utilities**

```typescript
// tests/setup.ts
import { PrismaClient } from '@prisma/client';
import { execSync } from 'child_process';

const prisma = new PrismaClient();

beforeAll(async () => {
  // Reset database
  execSync('npx prisma migrate reset --force --skip-seed', {
    env: { ...process.env, DATABASE_URL: process.env.TEST_DATABASE_URL },
  });

  // Run migrations
  execSync('npx prisma migrate deploy', {
    env: { ...process.env, DATABASE_URL: process.env.TEST_DATABASE_URL },
  });
});

afterAll(async () => {
  await prisma.$disconnect();
});

// Global test utilities
global.createTestUser = async (overrides = {}) => {
  return prisma.user.create({
    data: {
      email: 'test@example.com',
      name: 'Test User',
      password: 'hashed-password',
      ...overrides,
    },
  });
};

global.createTestOrder = async (userId: string, overrides = {}) => {
  return prisma.order.create({
    data: {
      userId,
      totalAmount: 100,
      status: 'pending',
      ...overrides,
    },
  });
};
```

### **Mock Data Factories**

```typescript
// tests/factories/user.factory.ts
import { faker } from '@faker-js/faker';
import { User } from '../../src/entities/user.entity';

export class UserFactory {
  static create(overrides = {}): Partial<User> {
    return {
      email: faker.internet.email(),
      name: faker.person.fullName(),
      password: faker.internet.password(),
      isActive: true,
      ...overrides,
    };
  }

  static createMany(count: number, overrides = {}): Partial<User>[] {
    return Array.from({ length: count }, () => this.create(overrides));
  }
}

// tests/factories/order.factory.ts
import { faker } from '@faker-js/faker';
import { Order, OrderItem } from '../../src/entities/order.entity';

export class OrderFactory {
  static create(overrides = {}): Partial<Order> {
    return {
      userId: faker.string.uuid(),
      totalAmount: faker.number.float({ min: 10, max: 1000, precision: 0.01 }),
      status: 'pending',
      items: [
        {
          productId: faker.string.uuid(),
          quantity: faker.number.int({ min: 1, max: 10 }),
          price: faker.number.float({ min: 10, max: 100, precision: 0.01 }),
        },
      ],
      ...overrides,
    };
  }

  static createWithItems(items: OrderItem[], overrides = {}): Partial<Order> {
    const totalAmount = items.reduce((sum, item) => sum + item.price * item.quantity, 0);
    
    return {
      userId: faker.string.uuid(),
      totalAmount,
      status: 'pending',
      items,
      ...overrides,
    };
  }
}
```

### **Custom Test Matchers**

```typescript
// tests/utils/matchers.ts
import { expect } from '@jest/globals';

expect.extend({
  toBeValidEmail(received: string) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    const pass = emailRegex.test(received);
    
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

  toBeValidUUID(received: string) {
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
    const pass = uuidRegex.test(received);
    
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

  toBeRecentTimestamp(received: Date, minutes = 5) {
    const now = new Date();
    const diff = now.getTime() - received.getTime();
    const maxDiff = minutes * 60 * 1000;
    
    if (diff <= maxDiff) {
      return {
        message: () => `expected ${received} not to be within the last ${minutes} minutes`,
        pass: true,
      };
    } else {
      return {
        message: () => `expected ${received} to be within the last ${minutes} minutes`,
        pass: false,
      };
    }
  },
});

// Extend Jest types
declare global {
  namespace jest {
    interface Matchers<R> {
      toBeValidEmail(): R;
      toBeValidUUID(): R;
      toBeRecentTimestamp(minutes?: number): R;
    }
  }
}
```

### **Test Scripts**

```json
// package.json scripts
{
  "scripts": {
    "test": "jest",
    "test:watch": "jest --watch",
    "test:coverage": "jest --coverage",
    "test:integration": "jest --testPathPattern=integration",
    "test:e2e": "playwright test",
    "test:performance": "jest --testPathPattern=performance",
    "test:ci": "jest --coverage --ci --watchAll=false --passWithNoTests"
  }
}
```

---
*TypeScript/Node Testing Examples - Use these patterns for comprehensive test coverage*
