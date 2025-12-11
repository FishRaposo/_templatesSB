<!--
File: ARCHITECTURE-node.tpl.md
Purpose: Template for unknown implementation
Template Version: 1.0
-->

# TypeScript/Node Architecture Guide - {{PROJECT_NAME}}

**Tier**: {{TIER}} | **Stack**: TypeScript/Node

## 🏗️ TypeScript/Node Architecture Overview

TypeScript/Node applications follow **Clean Architecture** principles with **modular service-oriented design**. This ensures maintainability, testability, and scalability across MVP, CORE, and FULL tiers while leveraging TypeScript's type safety throughout the stack.

## 📊 Tier-Based Architecture Patterns

### **MVP Tier - Simple Monolithic Architecture**

```
{{PROJECT_NAME}}/
├── src/
│   ├── index.ts                 # Fastify app entry point
│   ├── routes.ts                # Route definitions
│   ├── services.ts              # Business logic
│   ├── entities.ts              # Data models
│   └── database.ts              # Database setup
├── prisma/
│   └── schema.prisma            # Prisma schema
├── package.json                 # Dependencies
├── tsconfig.json                # TypeScript config
└── README.md                    # Documentation
```

**Characteristics**:
- Single file application structure
- Direct database access with Prisma
- Simple service layer
- Minimal abstraction layers
- SQLite for development

**When to Use**:
- API prototypes
- Simple microservices
- Learning projects
- Internal tools

### **CORE Tier - Modular Clean Architecture**

```
{{PROJECT_NAME}}/
├── src/
│   ├── index.ts                 # Fastify app entry point
│   ├── app.ts                   # App configuration
│   ├── core/                    # Core infrastructure
│   │   ├── config/              # Configuration management
│   │   │   ├── index.ts
│   │   │   ├── database.ts      # Database config
│   │   │   └── validation.ts    # Validation config
│   │   ├── database/            # Database setup
│   │   │   ├── index.ts
│   │   │   ├── connection.ts    # Connection management
│   │   │   └── migrations/      # Migration files
│   │   ├── security/            # Security utilities
│   │   │   ├── index.ts
│   │   │   ├── jwt.ts           # JWT handling
│   │   │   ├── bcrypt.ts        # Password hashing
│   │   │   └── permissions.ts   # Role-based access
│   │   ├── errors/              # Custom exceptions
│   │   │   ├── index.ts
│   │   │   └── exceptions.ts    # Business exceptions
│   │   ├── utils/               # Shared utilities
│   │   │   ├── index.ts
│   │   │   ├── logger.ts        # Logging setup
│   │   │   └── helpers.ts       # Helper functions
│   │   └── types/               # Type definitions
│   │       ├── index.ts
│   │       └── common.ts        # Common types
│   ├── modules/                 # Feature modules
│   │   ├── auth/                # Authentication module
│   │   │   ├── index.ts
│   │   │   ├── controllers/     # Route controllers
│   │   │   │   ├── index.ts
│   │   │   │   └── auth.controller.ts
│   │   │   ├── services/        # Business logic
│   │   │   │   ├── index.ts
│   │   │   │   └── auth.service.ts
│   │   │   ├── repositories/    # Data access
│   │   │   │   ├── index.ts
│   │   │   │   └── user.repository.ts
│   │   │   ├── dto/             # Data transfer objects
│   │   │   │   ├── index.ts
│   │   │   │   ├── auth.dto.ts
│   │   │   │   └── user.dto.ts
│   │   │   └── entities/        # Domain entities
│   │   │       ├── index.ts
│   │   │       └── user.entity.ts
│   │   ├── users/               # User management module
│   │   │   ├── controllers/
│   │   │   ├── services/
│   │   │   ├── repositories/
│   │   │   ├── dto/
│   │   │   └── entities/
│   │   └── [business_modules]/  # Other business modules
│   │       ├── controllers/
│   │       ├── services/
│   │       ├── repositories/
│   │       ├── dto/
│   │       └── entities/
│   ├── shared/                  # Shared across modules
│   │   ├── decorators/          # Custom decorators
│   │   │   ├── index.ts
│   │   │   ├── controller.decorator.ts
│   │   │   └── injectable.decorator.ts
│   │   ├── middleware/          # Custom middleware
│   │   │   ├── index.ts
│   │   │   ├── auth.middleware.ts
│   │   │   └── validation.middleware.ts
│   │   └── interfaces/          # Shared interfaces
│   │       ├── index.ts
│   │       └── repository.interface.ts
│   └── server.ts                # Server bootstrap
├── tests/                       # Test suite
│   ├── unit/                    # Unit tests
│   ├── integration/             # Integration tests
│   ├── e2e/                     # End-to-end tests
│   ├── fixtures/                # Test fixtures
│   └── utils/                   # Test utilities
├── prisma/                      # Database schema and migrations
│   ├── schema.prisma            # Prisma schema
│   ├── migrations/              # Migration files
│   └── seed.ts                  # Seed data
├── scripts/                     # Utility scripts
│   ├── build.ts                 # Build script
│   ├── dev.ts                   # Development script
│   └── migrate.ts               # Migration script
├── package.json                 # Dependencies
├── tsconfig.json                # TypeScript config
├── jest.config.js               # Jest test config
├── .env.example                 # Environment variables example
└── README.md                    # Documentation
```

**Characteristics**:
- Multi-layered architecture
- Repository pattern implementation
- Dependency injection with decorators
- Comprehensive error handling
- PostgreSQL for production
- Complete test suite

**When to Use**:
- Production APIs
- SaaS backend services
- Enterprise applications
- Multi-team development

### **FULL Tier - Enterprise Architecture**

```
{{PROJECT_NAME}}/
├── [CORE tier structure]
├── src/
│   ├── background/              # Background processing
│   │   ├── workers/             # Bull queue workers
│   │   │   ├── index.ts
│   │   │   ├── order.worker.ts
│   │   │   └── notification.worker.ts
│   │   ├── jobs/                # Queue job definitions
│   │   │   ├── index.ts
│   │   │   ├── email.jobs.ts
│   │   │   └── analytics.jobs.ts
│   │   └── scheduler.ts         # Task scheduling
│   ├── monitoring/              # Monitoring and observability
│   │   ├── metrics/             # Prometheus metrics
│   │   │   ├── index.ts
│   │   │   └── business.metrics.ts
│   │   ├── health/              # Health checks
│   │   │   ├── index.ts
│   │   │   └── health.check.ts
│   │   └── tracing/             # OpenTelemetry tracing
│   │       ├── index.ts
│   │       └── tracer.ts
│   ├── analytics/               # Analytics and events
│   │   ├── events/              # Event definitions
│   │   │   ├── index.ts
│   │   │   ├── user.events.ts
│   │   │   └── business.events.ts
│   │   ├── tracking/            # Event tracking
│   │   │   ├── index.ts
│   │   │   └── event.tracker.ts
│   │   └── reporting/           # Analytics reporting
│   │       ├── index.ts
│   │       └── reports.ts
│   ├── integrations/            # External integrations
│   │   ├── external-apis/       # External API clients
│   │   │   ├── index.ts
│   │   │   ├── payment.gateway.ts
│   │   │   └── shipping.api.ts
│   │   ├── message-queues/      # Message queue clients
│   │   │   ├── index.ts
│   │   │   ├── redis.client.ts
│   │   │   └── rabbitmq.client.ts
│   │   └── storage/             # Storage clients
│   │       ├── index.ts
│   │       ├── s3.client.ts
│   │       └── cdn.client.ts
│   ├── enterprise/              # Enterprise features
│   │   ├── audit/               # Audit logging
│   │   │   ├── index.ts
│   │   │   └── audit.logger.ts
│   │   ├── compliance/          # Compliance features
│   │   │   ├── index.ts
│   │   │   └── gdpr.compliance.ts
│   │   └── security/            # Advanced security
│   │       ├── index.ts
│   │       ├── rate.limiting.ts
│   │       └── threat.detection.ts
│   └── graphql/                 # GraphQL support (optional)
│       ├── schema/              # GraphQL schema
│       ├── resolvers/           # GraphQL resolvers
│       └── gateway/             # GraphQL gateway
├── infrastructure/              # Infrastructure as code
│   ├── docker/                  # Docker configurations
│   │   ├── Dockerfile
│   │   ├── Dockerfile.dev
│   │   ├── docker-compose.yml
│   │   └── docker-compose.prod.yml
│   ├── kubernetes/              # K8s manifests
│   │   ├── deployment.yaml
│   │   ├── service.yaml
│   │   ├── configmap.yaml
│   │   └── ingress.yaml
│   └── terraform/               # Terraform configs
│       ├── main.tf
│       ├── variables.tf
│       └── outputs.tf
└── [CORE tier files]
```

**Characteristics**:
- Microservices-ready architecture
- Advanced monitoring and observability
- Background job processing
- Enterprise security and compliance
- Infrastructure as code
- Complete analytics pipeline
- GraphQL support

## 🎯 Layer Responsibilities

### **1. Controllers Layer (modules/*/controllers/)**

#### **Purpose**: HTTP interface and request/response handling

#### **MVP Implementation**:
```typescript
// src/routes.ts - Simple route handlers
import { FastifyInstance } from 'fastify';
import { z } from 'zod';

const UserSchema = z.object({
  id: z.number(),
  email: z.string().email(),
  name: z.string(),
});

export async function userRoutes(fastify: FastifyInstance) {
  const users: User[] = [];

  fastify.get('/users', async () => {
    return users;
  });

  fastify.post('/users', async (request, reply) => {
    const user = UserSchema.parse(request.body);
    users.push(user);
    return user;
  });
}
```

#### **CORE Implementation**:
```typescript
// src/modules/auth/controllers/auth.controller.ts
import { Controller, POST, Body, Inject } from '../../../shared/decorators';
import { AuthService } from '../services/auth.service';
import { LoginDto, RegisterDto } from '../dto/auth.dto';
import { Response } from 'fastify';

@Controller('/auth')
export class AuthController {
  constructor(@Inject(AuthService) private authService: AuthService) {}

  @POST('/login')
  async login(@Body() loginDto: LoginDto, reply: Response) {
    try {
      const result = await this.authService.login(loginDto);
      return result;
    } catch (error) {
      reply.code(401);
      return { message: error.message };
    }
  }

  @POST('/register')
  async register(@Body() registerDto: RegisterDto, reply: Response) {
    try {
      const user = await this.authService.register(registerDto);
      reply.code(201);
      return user;
    } catch (error) {
      reply.code(400);
      return { message: error.message };
    }
  }
}
```

#### **FULL Implementation**:
```typescript
// src/modules/order/controllers/order.controller.ts
import { Controller, POST, GET, Body, Param, Inject } from '../../../shared/decorators';
import { OrderService } from '../services/order.service';
import { CreateOrderDto } from '../dto/order.dto';
import { MetricsService } from '../../../monitoring/metrics/metrics.service';
import { TracingService } from '../../../monitoring/tracing/tracer.service';
import { Response } from 'fastify';

@Controller('/orders')
export class OrderController {
  constructor(
    @Inject(OrderService) private orderService: OrderService,
    @Inject(MetricsService) private metrics: MetricsService,
    @Inject(TracingService) private tracing: TracingService,
  ) {}

  @POST('/')
  async createOrder(
    @Body() createOrderDto: CreateOrderDto,
    reply: Response,
    request: any,
  ) {
    const span = this.tracing.startSpan('createOrderEndpoint');
    
    try {
      const userId = request.user?.id;
      const order = await this.orderService.createOrder(userId, createOrderDto);
      
      // Metrics and analytics
      this.metrics.incrementCounter('orders_created_endpoint', {
        userId,
        status: order.status,
      });
      
      reply.code(201);
      return order;
      
    } catch (error) {
      this.metrics.incrementCounter('order_creation_failed_endpoint', {
        errorType: error.constructor.name,
      });
      this.tracing.recordException(error);
      
      reply.code(400);
      return { message: error.message };
    } finally {
      span.end();
    }
  }

  @GET('/:id')
  async getOrder(@Param('id') orderId: string, request: any) {
    const span = this.tracing.startSpan('getOrderEndpoint', { orderId });
    
    try {
      const userId = request.user?.id;
      const order = await this.orderService.getOrderById(orderId, userId);
      
      if (!order) {
        reply.code(404);
        return { message: 'Order not found' };
      }
      
      return order;
      
    } catch (error) {
      this.tracing.recordException(error);
      reply.code(500);
      return { message: 'Internal server error' };
    } finally {
      span.end();
    }
  }
}
```

### **2. Services Layer (modules/*/services/)**

#### **Purpose**: Business logic and orchestration

#### **MVP Implementation**:
```typescript
// src/services.ts - Simple business logic
export class UserService {
  private users: User[] = [];

  createUser(userData: any): User {
    if (!userData.email || !userData.email.includes('@')) {
      throw new Error('Invalid email format');
    }
    
    const user = {
      id: this.users.length + 1,
      ...userData,
      createdAt: new Date(),
    };
    
    this.users.push(user);
    return user;
  }

  getUser(id: number): User | undefined {
    return this.users.find(user => user.id === id);
  }
}
```

#### **CORE Implementation**:
```typescript
// src/modules/auth/services/auth.service.ts
import { injectable, inject } from 'inversify';
import { UserRepository } from '../repositories/user.repository';
import { User } from '../entities/user.entity';
import { JwtService } from '../../../core/security/jwt.service';
import { BcryptService } from '../../../core/security/bcrypt.service';
import { LoginDto, RegisterDto } from '../dto/auth.dto';
import { UnauthorizedException, BadRequestException } from '../../../core/errors/exceptions';

@injectable()
export class AuthService {
  constructor(
    @inject(UserRepository) private userRepository: UserRepository,
    @inject(JwtService) private jwtService: JwtService,
    @inject(BcryptService) private bcryptService: BcryptService,
  ) {}

  async login(loginDto: LoginDto): Promise<{ accessToken: string }> {
    const user = await this.userRepository.findByEmail(loginDto.email);
    if (!user) {
      throw new UnauthorizedException('Invalid credentials');
    }

    const isPasswordValid = await this.bcryptService.compare(
      loginDto.password,
      user.password,
    );
    if (!isPasswordValid) {
      throw new UnauthorizedException('Invalid credentials');
    }

    const accessToken = this.jwtService.sign({ sub: user.id, email: user.email });
    return { accessToken };
  }

  async register(registerDto: RegisterDto): Promise<User> {
    const existingUser = await this.userRepository.findByEmail(registerDto.email);
    if (existingUser) {
      throw new BadRequestException('User already exists');
    }

    const hashedPassword = await this.bcryptService.hash(registerDto.password);
    
    const user = await this.userRepository.create({
      ...registerDto,
      password: hashedPassword,
    });

    return user;
  }
}
```

#### **FULL Implementation**:
```typescript
// src/modules/order/services/enterprise-order.service.ts
import { injectable, inject } from 'inversify';
import { OrderRepository } from '../repositories/order.repository';
import { UserRepository } from '../repositories/user.repository';
import { InventoryRepository } from '../repositories/inventory.repository';
import { Order, OrderItem } from '../entities/order.entity';
import { CreateOrderDto } from '../dto/order.dto';
import { PaymentGatewayService } from '../../../integrations/external-apis/payment-gateway.service';
import { NotificationService } from '../../../integrations/message-queues/notification.service';
import { MetricsService } from '../../../monitoring/metrics/metrics.service';
import { TracingService } from '../../../monitoring/tracing/tracer.service';
import { EventBus } from '../../../analytics/events/event-bus.service';
import { OrderCreatedEvent, PaymentProcessedEvent } from '../../../analytics/events/order.events';
import { AuditLogger } from '../../../enterprise/audit/audit-logger.service';
import { BusinessRuleException, InventoryException } from '../../../core/errors/exceptions';

@injectable()
export class EnterpriseOrderService {
  constructor(
    @inject(OrderRepository) private orderRepository: OrderRepository,
    @inject(UserRepository) private userRepository: UserRepository,
    @inject(InventoryRepository) private inventoryRepository: InventoryRepository,
    @inject(PaymentGatewayService) private paymentGateway: PaymentGatewayService,
    @inject(NotificationService) private notificationService: NotificationService,
    @inject(MetricsService) private metrics: MetricsService,
    @inject(TracingService) private tracing: TracingService,
    @inject(EventBus) private eventBus: EventBus,
    @inject(AuditLogger) private auditLogger: AuditLogger,
  ) {}

  async createOrder(userId: string, createOrderDto: CreateOrderDto): Promise<Order> {
    const span = this.tracing.startSpan('createOrder', { userId });
    
    try {
      // Business rule: Verify user exists and is active
      const user = await this.userRepository.findById(userId);
      if (!user || !user.isActive) {
        throw new BusinessRuleException('User not found or inactive');
      }

      // Business rule: Check inventory availability
      await this.checkInventoryAvailability(createOrderDto.items);

      // Business rule: Calculate pricing with discounts
      const totalAmount = await this.calculateTotalAmount(userId, createOrderDto.items);

      // Create order with business logic
      const order = await this.orderRepository.create({
        userId,
        items: createOrderDto.items,
        totalAmount,
        status: 'pending',
        createdAt: new Date(),
      });

      // Reserve inventory
      await this.reserveInventory(order.id, createOrderDto.items);

      // Process payment with monitoring
      const paymentResult = await this.processPayment(order);

      // Update order status
      if (paymentResult.success) {
        order.status = 'confirmed';
        await this.orderRepository.updateStatus(order.id, 'confirmed');
      } else {
        order.status = 'payment_failed';
        await this.orderRepository.updateStatus(order.id, 'payment_failed');
        throw new BusinessRuleException('Payment processing failed');
      }

      // Audit logging
      await this.auditLogger.logOrderCreation(order, userId);

      // Metrics and analytics
      this.metrics.incrementCounter('orders_created', {
        userId,
        status: order.status,
        totalAmount: totalAmount.toString(),
      });

      // Event publishing
      const orderEvent = new OrderCreatedEvent({
        orderId: order.id,
        userId,
        totalAmount,
        items: createOrderDto.items,
      });
      await this.eventBus.publish(orderEvent);

      // Async notification
      await this.notificationService.sendOrderConfirmation(order);

      span.setAttributes({ orderId: order.id, status: order.status });
      return order;

    } catch (error) {
      this.metrics.incrementCounter('order_creation_failed', {
        userId,
        errorType: error.constructor.name,
      });
      this.tracing.recordException(error);
      await this.auditLogger.logOrderCreationFailure(userId, error.message);
      throw error;
    } finally {
      span.end();
    }
  }

  private async checkInventoryAvailability(items: OrderItem[]): Promise<void> {
    for (const item of items) {
      const inventory = await this.inventoryRepository.getByProductId(item.productId);
      if (!inventory || inventory.availableQuantity < item.quantity) {
        throw new InventoryException(`Insufficient inventory for product ${item.productId}`);
      }
    }
  }

  private async calculateTotalAmount(userId: string, items: OrderItem[]): Promise<number> {
    // Complex pricing logic with discounts, taxes, etc.
    const baseTotal = items.reduce((sum, item) => sum + item.price * item.quantity, 0);

    // Apply user-specific discounts
    const user = await this.userRepository.findById(userId);
    if (user?.isPremium) {
      return baseTotal * 0.9; // 10% discount for premium users
    }

    // Apply taxes
    return baseTotal * 1.08; // 8% tax
  }

  private async processPayment(order: Order): Promise<PaymentResult> {
    const paymentData = {
      orderId: order.id,
      amount: order.totalAmount,
      currency: 'USD',
    };

    const result = await this.paymentGateway.processPayment(paymentData);

    // Track payment event
    const paymentEvent = new PaymentProcessedEvent({
      orderId: order.id,
      amount: order.totalAmount,
      success: result.success,
      paymentMethod: result.paymentMethod,
    });
    await this.eventBus.publish(paymentEvent);

    return result;
  }
}
```

### **3. Repository Layer (modules/*/repositories/)**

#### **Purpose**: Data access abstraction

#### **MVP Implementation**:
```typescript
// src/database.ts - Simple data access
import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

export class UserRepository {
  async findByEmail(email: string): Promise<User | null> {
    return prisma.user.findUnique({
      where: { email },
    });
  }

  async create(userData: any): Promise<User> {
    return prisma.user.create({
      data: userData,
    });
  }

  async findById(id: string): Promise<User | null> {
    return prisma.user.findUnique({
      where: { id },
    });
  }
}
```

#### **CORE Implementation**:
```typescript
// src/modules/auth/repositories/user.repository.ts
import { injectable } from 'inversify';
import { PrismaClient, User as PrismaUser } from '@prisma/client';
import { User } from '../entities/user.entity';
import { IRepository } from '../../../shared/interfaces/repository.interface';

@injectable()
export class UserRepository implements IRepository<User> {
  constructor(private prisma: PrismaClient) {}

  async findByEmail(email: string): Promise<User | null> {
    const prismaUser = await this.prisma.user.findUnique({
      where: { email },
    });

    return prismaUser ? this.mapToEntity(prismaUser) : null;
  }

  async findById(id: string): Promise<User | null> {
    const prismaUser = await this.prisma.user.findUnique({
      where: { id },
    });

    return prismaUser ? this.mapToEntity(prismaUser) : null;
  }

  async create(userData: Partial<User>): Promise<User> {
    const prismaUser = await this.prisma.user.create({
      data: {
        email: userData.email!,
        name: userData.name!,
        password: userData.password!,
        isActive: userData.isActive ?? true,
      },
    });

    return this.mapToEntity(prismaUser);
  }

  async update(id: string, updateData: Partial<User>): Promise<User> {
    const prismaUser = await this.prisma.user.update({
      where: { id },
      data: {
        ...updateData,
        updatedAt: new Date(),
      },
    });

    return this.mapToEntity(prismaUser);
  }

  async delete(id: string): Promise<void> {
    await this.prisma.user.delete({
      where: { id },
    });
  }

  async findMany(options?: {
    skip?: number;
    take?: number;
    where?: any;
  }): Promise<User[]> {
    const prismaUsers = await this.prisma.user.findMany({
      skip: options?.skip,
      take: options?.take,
      where: options?.where,
    });

    return prismaUsers.map(user => this.mapToEntity(user));
  }

  private mapToEntity(prismaUser: PrismaUser): User {
    return new User({
      id: prismaUser.id,
      email: prismaUser.email,
      name: prismaUser.name,
      password: prismaUser.password,
      isActive: prismaUser.isActive,
      createdAt: prismaUser.createdAt,
      updatedAt: prismaUser.updatedAt,
    });
  }
}
```

#### **FULL Implementation**:
```typescript
// src/modules/order/repositories/enterprise-order.repository.ts
import { injectable } from 'inversify';
import { PrismaClient, Order as PrismaOrder, OrderItem as PrismaOrderItem } from '@prisma/client';
import { Order, OrderItem, OrderStatus } from '../entities/order.entity';
import { IRepository } from '../../../shared/interfaces/repository.interface';

@injectable()
export class EnterpriseOrderRepository implements IRepository<Order> {
  constructor(private prisma: PrismaClient) {}

  async findById(id: string): Promise<Order | null> {
    const prismaOrder = await this.prisma.order.findUnique({
      where: { id },
      include: {
        items: true,
        user: {
          select: {
            id: true,
            email: true,
            name: true,
          },
        },
      },
    });

    return prismaOrder ? this.mapToEntity(prismaOrder) : null;
  }

  async findByUserId(userId: string, options?: {
    skip?: number;
    take?: number;
    status?: OrderStatus;
  }): Promise<Order[]> {
    const prismaOrders = await this.prisma.order.findMany({
      where: {
        userId,
        ...(options?.status && { status: options.status }),
      },
      include: {
        items: true,
      },
      skip: options?.skip,
      take: options?.take,
      orderBy: {
        createdAt: 'desc',
      },
    });

    return prismaOrders.map(order => this.mapToEntity(order));
  }

  async create(orderData: Partial<Order>): Promise<Order> {
    const prismaOrder = await this.prisma.$transaction(async (tx) => {
      // Create order
      const order = await tx.order.create({
        data: {
          userId: orderData.userId!,
          totalAmount: orderData.totalAmount!,
          status: orderData.status || OrderStatus.PENDING,
        },
      });

      // Create order items
      if (orderData.items) {
        await tx.orderItem.createMany({
          data: orderData.items.map(item => ({
            orderId: order.id,
            productId: item.productId,
            quantity: item.quantity,
            price: item.price,
          })),
        });
      }

      return order;
    });

    // Fetch complete order with items
    const completeOrder = await this.prisma.order.findUnique({
      where: { id: prismaOrder.id },
      include: { items: true },
    });

    return this.mapToEntity(completeOrder!);
  }

  async updateStatus(id: string, status: OrderStatus): Promise<Order> {
    const prismaOrder = await this.prisma.order.update({
      where: { id },
      data: {
        status,
        updatedAt: new Date(),
      },
      include: { items: true },
    });

    return this.mapToEntity(prismaOrder);
  }

  async getOrderAnalytics(startDate: Date, endDate: Date): Promise<{
    totalOrders: number;
    totalRevenue: number;
    averageOrderValue: number;
    ordersByStatus: Record<OrderStatus, number>;
  }> {
    const analytics = await this.prisma.order.aggregate({
      where: {
        createdAt: {
          gte: startDate,
          lte: endDate,
        },
      },
      _sum: {
        totalAmount: true,
      },
      _count: {
        id: true,
      },
    });

    const ordersByStatus = await this.prisma.order.groupBy({
      by: ['status'],
      where: {
        createdAt: {
          gte: startDate,
          lte: endDate,
        },
      },
      _count: {
        id: true,
      },
    });

    const totalOrders = analytics._count.id || 0;
    const totalRevenue = analytics._sum.totalAmount || 0;
    const averageOrderValue = totalOrders > 0 ? totalRevenue / totalOrders : 0;

    const statusCounts = ordersByStatus.reduce((acc, group) => {
      acc[group.status as OrderStatus] = group._count.id;
      return acc;
    }, {} as Record<OrderStatus, number>);

    return {
      totalOrders,
      totalRevenue,
      averageOrderValue,
      ordersByStatus: statusCounts,
    };
  }

  private mapToEntity(prismaOrder: PrismaOrder & { items?: PrismaOrderItem[] }): Order {
    return new Order({
      id: prismaOrder.id,
      userId: prismaOrder.userId,
      totalAmount: prismaOrder.totalAmount,
      status: prismaOrder.status as OrderStatus,
      items: prismaOrder.items?.map(item => new OrderItem({
        id: item.id,
        orderId: item.orderId,
        productId: item.productId,
        quantity: item.quantity,
        price: item.price,
      })) || [],
      createdAt: prismaOrder.createdAt,
      updatedAt: prismaOrder.updatedAt,
    });
  }
}
```

## 🔄 Module Communication

### **Dependency Injection with Inversify**

```typescript
// src/core/container.ts
import { Container } from 'inversify';
import { TYPES } from './types';
import { UserService } from '../modules/user/services/user.service';
import { UserRepository } from '../modules/user/repositories/user.repository';
import { AuthService } from '../modules/auth/services/auth.service';
import { JwtService } from './security/jwt.service';
import { BcryptService } from './security/bcrypt.service';

const container = new Container();

// Bind services
container.bind<UserService>(TYPES.UserService).to(UserService).inSingletonScope();
container.bind<AuthService>(TYPES.AuthService).to(AuthService).inSingletonScope();

// Bind repositories
container.bind<UserRepository>(TYPES.UserRepository).to(UserRepository).inSingletonScope();

// Bind core services
container.bind<JwtService>(TYPES.JwtService).to(JwtService).inSingletonScope();
container.bind<BcryptService>(TYPES.BcryptService).to(BcryptService).inSingletonScope();

export { container };
```

### **Event-Driven Communication**

```typescript
// src/analytics/events/event-bus.service.ts
import { EventEmitter } from 'events';
import { injectable } from 'inversify';

export interface Event {
  type: string;
  data: any;
  timestamp: Date;
}

@injectable()
export class EventBus extends EventEmitter {
  async publish(event: Event): Promise<void> {
    this.emit(event.type, event);
  }

  subscribe(eventType: string, handler: (event: Event) => Promise<void>): void {
    this.on(eventType, handler);
  }

  unsubscribe(eventType: string, handler: (event: Event) => Promise<void>): void {
    this.off(eventType, handler);
  }
}

// Usage in services
@injectable()
export class OrderService {
  constructor(
    @inject(EventBus) private eventBus: EventBus,
  ) {}

  async createOrder(orderData: CreateOrderDto): Promise<Order> {
    const order = await this.orderRepository.create(orderData);
    
    // Publish event
    const event: Event = {
      type: 'ORDER_CREATED',
      data: { orderId: order.id, userId: order.userId },
      timestamp: new Date(),
    };
    
    await this.eventBus.publish(event);
    
    return order;
  }
}
```

## 🔒 Security Architecture

### **Authentication and Authorization**

```typescript
// src/shared/middleware/auth.middleware.ts
import { FastifyRequest, FastifyReply } from 'fastify';
import { JwtService } from '../../core/security/jwt.service';
import { UserRepository } from '../../modules/user/repositories/user.repository';
import { UnauthorizedException } from '../../core/errors/exceptions';

export interface AuthenticatedRequest extends FastifyRequest {
  user?: {
    id: string;
    email: string;
    role: string;
  };
}

export const authMiddleware = async (
  request: AuthenticatedRequest,
  reply: FastifyReply,
) => {
  try {
    const authHeader = request.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      throw new UnauthorizedException('No token provided');
    }

    const token = authHeader.substring(7);
    const jwtService = new JwtService();
    const payload = jwtService.verify(token);

    const userRepository = new UserRepository(prisma);
    const user = await userRepository.findById(payload.sub);
    
    if (!user || !user.isActive) {
      throw new UnauthorizedException('Invalid token');
    }

    request.user = {
      id: user.id,
      email: user.email,
      role: user.role,
    };

  } catch (error) {
    reply.code(401);
    return { message: 'Unauthorized' };
  }
};

export const requireRole = (roles: string[]) => {
  return async (request: AuthenticatedRequest, reply: FastifyReply) => {
    if (!request.user || !roles.includes(request.user.role)) {
      reply.code(403);
      return { message: 'Insufficient permissions' };
    }
  };
};
```

### **Input Validation with Zod**

```typescript
// src/shared/middleware/validation.middleware.ts
import { FastifyRequest, FastifyReply } from 'fastify';
import { ZodSchema } from 'zod';
import { BadRequestException } from '../../core/errors/exceptions';

export const validateBody = (schema: ZodSchema) => {
  return async (request: FastifyRequest, reply: FastifyReply) => {
    try {
      request.body = schema.parse(request.body);
    } catch (error) {
      throw new BadRequestException(error.errors[0].message);
    }
  };
};

export const validateParams = (schema: ZodSchema) => {
  return async (request: FastifyRequest, reply: FastifyReply) => {
    try {
      request.params = schema.parse(request.params);
    } catch (error) {
      throw new BadRequestException(error.errors[0].message);
    }
  };
};

export const validateQuery = (schema: ZodSchema) => {
  return async (request: FastifyRequest, reply: FastifyReply) => {
    try {
      request.query = schema.parse(request.query);
    } catch (error) {
      throw new BadRequestException(error.errors[0].message);
    }
  };
};
```

## 📊 Monitoring and Observability

### **Structured Logging**

```typescript
// src/core/utils/logger.ts
import winston from 'winston';

export interface LogContext {
  userId?: string;
  requestId?: string;
  [key: string]: any;
}

export class Logger {
  private logger: winston.Logger;

  constructor() {
    this.logger = winston.createLogger({
      level: process.env.LOG_LEVEL || 'info',
      format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.errors({ stack: true }),
        winston.format.json(),
      ),
      defaultMeta: { service: '{{PROJECT_NAME}}' },
      transports: [
        new winston.transports.File({ filename: 'error.log', level: 'error' }),
        new winston.transports.File({ filename: 'combined.log' }),
        new winston.transports.Console({
          format: winston.format.simple(),
        }),
      ],
    });
  }

  info(message: string, context?: LogContext): void {
    this.logger.info(message, context);
  }

  error(message: string, error?: Error, context?: LogContext): void {
    this.logger.error(message, { error: error?.stack, ...context });
  }

  warn(message: string, context?: LogContext): void {
    this.logger.warn(message, context);
  }

  debug(message: string, context?: LogContext): void {
    this.logger.debug(message, context);
  }
}

export const logger = new Logger();
```

### **Metrics Collection**

```typescript
// src/monitoring/metrics/metrics.service.ts
import { register, Counter, Histogram, Gauge } from 'prom-client';

@injectable()
export class MetricsService {
  private httpRequestCounter: Counter<string>;
  private httpRequestDuration: Histogram<string>;
  private activeConnections: Gauge<string>;

  constructor() {
    this.httpRequestCounter = new Counter({
      name: 'http_requests_total',
      help: 'Total number of HTTP requests',
      labelNames: ['method', 'route', 'status_code'],
    });

    this.httpRequestDuration = new Histogram({
      name: 'http_request_duration_seconds',
      help: 'Duration of HTTP requests in seconds',
      labelNames: ['method', 'route'],
      buckets: [0.1, 0.5, 1, 2, 5],
    });

    this.activeConnections = new Gauge({
      name: 'active_connections',
      help: 'Number of active connections',
    });

    register.registerMetric(this.httpRequestCounter);
    register.registerMetric(this.httpRequestDuration);
    register.registerMetric(this.activeConnections);
  }

  incrementHttpRequest(method: string, route: string, statusCode: string): void {
    this.httpRequestCounter.inc({ method, route, status_code: statusCode });
  }

  recordHttpRequestDuration(method: string, route: string, duration: number): void {
    this.httpRequestDuration.observe({ method, route }, duration);
  }

  setActiveConnections(count: number): void {
    this.activeConnections.set(count);
  }

  incrementCounter(name: string, labels: Record<string, string>): void {
    const counter = register.getSingleMetric(name) as Counter<string>;
    if (counter) {
      counter.inc(labels);
    }
  }
}
```

## 🚀 Performance Patterns

### **Connection Pooling**

```typescript
// src/core/database/connection.ts
import { PrismaClient } from '@prisma/client';

export class DatabaseConnection {
  private static instance: PrismaClient;

  static getInstance(): PrismaClient {
    if (!DatabaseConnection.instance) {
      DatabaseConnection.instance = new PrismaClient({
        datasources: {
          db: {
            url: process.env.DATABASE_URL,
          },
        },
        log: process.env.NODE_ENV === 'development' ? ['query', 'info', 'warn', 'error'] : ['error'],
      });
    }

    return DatabaseConnection.instance;
  }

  static async disconnect(): Promise<void> {
    if (DatabaseConnection.instance) {
      await DatabaseConnection.instance.$disconnect();
    }
  }
}

export const prisma = DatabaseConnection.getInstance();
```

### **Caching Strategy**

```typescript
// src/core/cache/redis.service.ts
import Redis from 'ioredis';

@injectable()
export class RedisService {
  private redis: Redis;

  constructor() {
    this.redis = new Redis(process.env.REDIS_URL);
  }

  async get<T>(key: string): Promise<T | null> {
    const value = await this.redis.get(key);
    return value ? JSON.parse(value) : null;
  }

  async set(key: string, value: any, ttl?: number): Promise<void> {
    const serialized = JSON.stringify(value);
    if (ttl) {
      await this.redis.setex(key, ttl, serialized);
    } else {
      await this.redis.set(key, serialized);
    }
  }

  async del(key: string): Promise<void> {
    await this.redis.del(key);
  }

  async exists(key: string): Promise<boolean> {
    const result = await this.redis.exists(key);
    return result === 1;
  }

  async invalidatePattern(pattern: string): Promise<void> {
    const keys = await this.redis.keys(pattern);
    if (keys.length > 0) {
      await this.redis.del(...keys);
    }
  }
}

// Usage in repositories
@injectable()
export class CachedUserRepository extends UserRepository {
  constructor(
    prisma: PrismaClient,
    @Inject(RedisService) private redis: RedisService,
  ) {
    super(prisma);
  }

  async findById(id: string): Promise<User | null> {
    const cacheKey = `user:${id}`;
    
    // Try cache first
    const cachedUser = await this.redis.get<User>(cacheKey);
    if (cachedUser) {
      return cachedUser;
    }

    // Fetch from database
    const user = await super.findById(id);
    
    // Cache for 5 minutes
    if (user) {
      await this.redis.set(cacheKey, user, 300);
    }

    return user;
  }

  async update(id: string, updateData: Partial<User>): Promise<User> {
    const user = await super.update(id, updateData);
    
    // Invalidate cache
    await this.redis.del(`user:${id}`);
    
    return user;
  }
}
```

---
*TypeScript/Node Architecture Guide - Use these patterns for maintainable and scalable TypeScript/Node applications*
