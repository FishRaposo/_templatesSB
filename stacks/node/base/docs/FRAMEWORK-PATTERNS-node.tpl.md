<!--
File: FRAMEWORK-PATTERNS-node.tpl.md
Purpose: Template for unknown implementation
Template Version: 1.0
-->

# TypeScript/Node Framework Patterns - {{PROJECT_NAME}}

**Tier**: {{TIER}} | **Stack**: TypeScript/Node

## 🟢 TypeScript/Node's Role in Your Ecosystem

TypeScript/Node serves as the **backend API layer** - your "ship type-safe APIs and services fast" weapon. It handles REST APIs, GraphQL services, microservices, and enterprise backend applications with strong type safety.

### **Core Responsibilities**
- **REST/GraphQL APIs**: Fastify-based high-performance APIs
- **Type Safety**: End-to-end TypeScript with strict typing
- **Microservices**: Service-oriented architecture
- **Background Processing**: Bull queues with Redis
- **Enterprise Integration**: Message brokers, external APIs

## 🏗️ Three Pillars Integration

### **1. Universal Principles Applied to TypeScript/Node**
- **Clean Architecture**: Service layer with repository pattern
- **Dependency Injection**: Inversify or Awilix for DI
- **Testing Pyramid**: Unit, Integration, E2E tests
- **Configuration Management**: Environment-based config with validation

### **2. Tier-Specific TypeScript/Node Patterns**

#### **MVP Tier - Prototyping Mode**
**Purpose**: Validate API ideas quickly with minimal complexity
**Characteristics**:
- Single file application structure
- Simple Fastify routes with Zod validation
- SQLite database with direct Prisma usage
- Basic JWT authentication
- Minimal testing (unit tests only)

**When to Use**:
- API proof of concepts
- Microservice prototypes
- Internal tools and scripts
- Learning new domains

**MVP TypeScript/Node Pattern**:
```typescript
// src/index.ts - Single file MVP
import Fastify from 'fastify';
import { z } from 'zod';

const fastify = Fastify({ logger: true });

const UserSchema = z.object({
  id: z.number(),
  email: z.string().email(),
  name: z.string(),
});

const users: User[] = [];

fastify.get('/users', async () => {
  return users;
});

fastify.post('/users', async (request, reply) => {
  const user = UserSchema.parse(request.body);
  users.push(user);
  return user;
});

const start = async () => {
  try {
    await fastify.listen({ port: 3000 });
  } catch (err) {
    fastify.log.error(err);
    process.exit(1);
  }
};

start();
```

#### **CORE Tier - Production Baseline**
**Purpose**: Real-world APIs with proper architecture
**Characteristics**:
- Modular service architecture
- Repository pattern with dependency injection
- PostgreSQL with Prisma ORM
- Advanced authentication and authorization
- Comprehensive testing (unit + integration)

**When to Use**:
- Production APIs
- SaaS backend services
- Enterprise internal APIs
- Consumer-facing backends

**CORE TypeScript/Node Pattern**:
```typescript
// src/modules/auth/services/auth.service.ts
import { injectable, inject } from 'inversify';
import { UserRepository } from '../repositories/user.repository';
import { User } from '../entities/user.entity';
import { JwtService } from '../services/jwt.service';
import { BcryptService } from '../services/bcrypt.service';
import { LoginDto, RegisterDto } from '../dto/auth.dto';

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

// src/modules/auth/controllers/auth.controller.ts
import { Controller, POST, Body } from '../decorators/controller.decorator';
import { AuthService } from '../services/auth.service';
import { LoginDto, RegisterDto } from '../dto/auth.dto';

@Controller('/auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @POST('/login')
  async login(@Body() loginDto: LoginDto) {
    return this.authService.login(loginDto);
  }

  @POST('/register')
  async register(@Body() registerDto: RegisterDto) {
    return this.authService.register(registerDto);
  }
}
```

#### **FULL Tier - Enterprise Excellence**
**Purpose**: Large-scale APIs with enterprise requirements
**Characteristics**:
- Microservices architecture
- Advanced async patterns with message queues
- Enterprise security and compliance
- Complete observability (metrics, tracing, logging)
- Advanced testing (performance, contract, chaos)

**When to Use**:
- Fortune 500 backend services
- Multi-team enterprise projects
- High-traffic APIs
- Compliance-heavy applications

**FULL TypeScript/Node Pattern**:
```typescript
// src/modules/order/services/enterprise-order.service.ts
import { injectable, inject } from 'inversify';
import { OrderRepository } from '../repositories/order.repository';
import { UserRepository } from '../repositories/user.repository';
import { InventoryRepository } from '../repositories/inventory.repository';
import { Order } from '../entities/order.entity';
import { CreateOrderDto } from '../dto/order.dto';
import { PaymentGatewayService } from '../integrations/payment-gateway.service';
import { NotificationService } from '../integrations/notification.service';
import { MetricsService } from '../monitoring/metrics.service';
import { TracingService } from '../monitoring/tracing.service';
import { EventBus } from '../events/event-bus.service';
import { OrderCreatedEvent, PaymentProcessedEvent } from '../events/order.events';
import { AuditLogger } from '../enterprise/audit/audit-logger.service';

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

## 📦 Blessed Patterns (Never Deviate)

### **Web Framework: Fastify**
**Why Fastify**:
- Native TypeScript support
- Excellent performance
- Plugin ecosystem
- Built-in validation with JSON Schema
- Extensive middleware support

**Fastify Patterns**:
```typescript
// MVP: Simple routes
fastify.get('/users', async () => {
  return users;
});

// CORE: Dependency injection with decorators
@Controller('/users')
export class UserController {
  constructor(private userService: UserService) {}

  @GET('/:id')
  async getUser(@Param('id') id: string) {
    return this.userService.findById(id);
  }
}

// FULL: Advanced middleware and monitoring
fastify.addHook('preHandler', async (request, reply) => {
  const startTime = Date.now();
  request.startTime = startTime;
});

fastify.addHook('onSend', async (request, reply) => {
  const duration = Date.now() - request.startTime;
  metrics.recordHttpRequest(request.method, request.url, reply.statusCode, duration);
});
```

### **ORM: Prisma**
**Why Prisma**:
- Type-safe database access
- Excellent TypeScript integration
- Auto-generated client
- Great migration system
- Built-in query optimization

**Prisma Patterns**:
```typescript
// MVP: Simple models
model User {
  id    Int     @id @default(autoincrement())
  email String  @unique
  name  String
}

// CORE: Advanced models with relations
model User {
  id        String   @id @default(cuid())
  email     String   @unique
  name      String
  createdAt DateTime @default(now())
  updatedAt DateTime @updatedAt
  
  orders    Order[]
  
  @@map("users")
}

model Order {
  id         String   @id @default(cuid())
  userId     String
  totalAmount Float
  status     String   @default("pending")
  createdAt  DateTime @default(now())
  updatedAt  DateTime @updatedAt
  
  user       User     @relation(fields: [userId], references: [id])
  
  @@map("orders")
}

// FULL: Enterprise models with audit trail
model User {
  id        String    @id @default(cuid())
  email     String    @unique
  name      String
  createdAt DateTime  @default(now())
  updatedAt DateTime  @updatedAt
  createdBy String?
  updatedBy String?
  isActive  Boolean   @default(true)
  
  // Soft delete
  deletedAt DateTime?
  
  orders    Order[]
  
  @@map("users")
}
```

### **Validation: Zod**
**Why Zod**:
- TypeScript-first validation
- Excellent type inference
- Composable schemas
- Great error messages
- Performance optimized

**Zod Patterns**:
```typescript
// MVP: Simple schemas
const UserSchema = z.object({
  email: z.string().email(),
  name: z.string().min(2),
});

// CORE: Advanced validation with custom rules
const CreateUserSchema = z.object({
  email: z.string().email('Invalid email format'),
  password: z.string().min(8, 'Password must be at least 8 characters'),
  name: z.string().min(2, 'Name must be at least 2 characters'),
}).refine((data) => !data.email.includes('+'), {
  message: 'Email aliases are not allowed',
  path: ['email'],
});

// FULL: Enterprise validation with business rules
const CreateOrderSchema = z.object({
  userId: z.string().cuid(),
  items: z.array(z.object({
    productId: z.string().cuid(),
    quantity: z.number().min(1).max(100),
    price: z.number().positive(),
  })).min(1),
}).refine(async (data) => {
  // Async validation for inventory
  const inventoryService = container.get(InventoryService);
  for (const item of data.items) {
    const available = await inventoryService.checkAvailability(item.productId, item.quantity);
    if (!available) return false;
  }
  return true;
}, {
  message: 'Insufficient inventory for one or more items',
});
```

## 🗄️ Database Integration

### **Database Strategy**
```typescript
// MVP: SQLite for development
const prisma = new PrismaClient({
  datasources: {
    db: {
      url: 'file:./dev.db',
    },
  },
});

// CORE: PostgreSQL for production
const prisma = new PrismaClient({
  datasources: {
    db: {
      url: process.env.DATABASE_URL,
    },
  },
});

// FULL: PostgreSQL with connection pooling and read replicas
const prisma = new PrismaClient({
  datasources: {
    db: {
      url: process.env.DATABASE_URL,
    },
  },
  log: ['query', 'info', 'warn', 'error'],
});
```

### **Migration Strategy**
```typescript
// prisma/migrations/001_initial_migration.sql
CREATE TABLE "users" (
    "id" TEXT NOT NULL,
    "email" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "created_at" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" DATETIME NOT NULL,

    CONSTRAINT "users_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "users_email_key" ON "users"("email");
```

## 🧪 Testing Strategy by Tier

### **MVP Testing**
- Unit tests for business logic
- Simple API endpoint tests
- Database model tests

### **CORE Testing**
- Complete unit test coverage
- Integration tests for API endpoints
- Database integration tests
- Authentication flow tests

### **FULL Testing**
- All CORE tests plus:
- Performance tests
- Contract tests
- Chaos engineering tests
- End-to-end tests

## 🔗 Integration Patterns

### **External API Integration**
```typescript
// src/integrations/external-api.service.ts
import axios, { AxiosInstance } from 'axios';

@Injectable()
export class ExternalAPIService {
  private client: AxiosInstance;

  constructor() {
    this.client = axios.create({
      baseURL: process.env.EXTERNAL_API_URL,
      timeout: 10000,
      headers: {
        'Authorization': `Bearer ${process.env.EXTERNAL_API_KEY}`,
        'Content-Type': 'application/json',
      },
    });

    this.setupInterceptors();
  }

  private setupInterceptors() {
    this.client.interceptors.request.use(
      (config) => {
        console.log(`Making request to ${config.url}`);
        return config;
      },
      (error) => Promise.reject(error)
    );

    this.client.interceptors.response.use(
      (response) => response,
      (error) => {
        console.error('API request failed:', error);
        throw error;
      }
    );
  }

  async getData<T>(endpoint: string): Promise<T> {
    const response = await this.client.get(endpoint);
    return response.data;
  }

  async postData<T>(endpoint: string, data: any): Promise<T> {
    const response = await this.client.post(endpoint, data);
    return response.data;
  }
}
```

### **Message Queue Integration**
```typescript
// src/integrations/queue.service.ts
import Bull from 'bull';
import Redis from 'ioredis';

@Injectable()
export class QueueService {
  private orderQueue: Bull.Queue;
  private emailQueue: Bull.Queue;

  constructor() {
    const redis = new Redis(process.env.REDIS_URL);

    this.orderQueue = new Bull('order processing', {
      redis: process.env.REDIS_URL,
    });

    this.emailQueue = new Bull('email sending', {
      redis: process.env.REDIS_URL,
    });

    this.setupProcessors();
  }

  private setupProcessors() {
    this.orderQueue.process(5, async (job) => {
      const { orderId, userId } = job.data;
      await this.processOrder(orderId, userId);
    });

    this.emailQueue.process(10, async (job) => {
      const { to, subject, template } = job.data;
      await this.sendEmail(to, subject, template);
    });
  }

  async addOrderJob(orderId: string, userId: string) {
    await this.orderQueue.add('process', { orderId, userId }, {
      attempts: 3,
      backoff: 'exponential',
    });
  }

  async addEmailJob(to: string, subject: string, template: string) {
    await this.emailQueue.add('send', { to, subject, template }, {
      delay: 1000, // 1 second delay
      attempts: 5,
    });
  }

  private async processOrder(orderId: string, userId: string) {
    // Order processing logic
    console.log(`Processing order ${orderId} for user ${userId}`);
  }

  private async sendEmail(to: string, subject: string, template: string) {
    // Email sending logic
    console.log(`Sending email to ${to}: ${subject}`);
  }
}
```

## 📊 Monitoring and Observability

### **MVP**: Basic logging
### **CORE**: Structured logging + metrics
```typescript
// src/monitoring/logger.service.ts
import winston from 'winston';

@Injectable()
export class LoggerService {
  private logger: winston.Logger;

  constructor() {
    this.logger = winston.createLogger({
      level: process.env.LOG_LEVEL || 'info',
      format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.errors({ stack: true }),
        winston.format.json()
      ),
      defaultMeta: { service: '{{PROJECT_NAME}}' },
      transports: [
        new winston.transports.File({ filename: 'error.log', level: 'error' }),
        new winston.transports.File({ filename: 'combined.log' }),
        new winston.transports.Console({
          format: winston.format.simple()
        })
      ],
    });
  }

  info(message: string, meta?: any) {
    this.logger.info(message, meta);
  }

  error(message: string, error?: Error, meta?: any) {
    this.logger.error(message, { error: error?.stack, ...meta });
  }

  warn(message: string, meta?: any) {
    this.logger.warn(message, meta);
  }
}
```

### **FULL**: Complete observability
- Structured logging with correlation IDs
- Prometheus metrics
- OpenTelemetry tracing
- Error tracking with Sentry

## 🚀 Performance Patterns

### **Async/Await Best Practices**
```typescript
// Use async for I/O operations
async function getUserData(userId: string): Promise<{ user: User; orders: Order[] }> {
  const [user, orders] = await Promise.all([
    this.userRepository.findById(userId),
    this.orderRepository.findByUserId(userId),
  ]);
  
  return { user, orders };
}

// Use async generators for streaming data
async function* streamUsers(batchSize: number = 100) {
  let offset = 0;
  
  while (true) {
    const users = await this.userRepository.findMany({
      skip: offset,
      take: batchSize,
    });
    
    if (users.length === 0) break;
    
    yield* users;
    offset += batchSize;
  }
}
```

### **Database Optimization**
```typescript
// Use transactions for complex operations
async function createOrderWithItems(orderData: CreateOrderDto): Promise<Order> {
  return await this.prisma.$transaction(async (tx) => {
    const order = await tx.order.create({
      data: {
        userId: orderData.userId,
        totalAmount: orderData.totalAmount,
      },
    });

    await tx.orderItem.createMany({
      data: orderData.items.map(item => ({
        orderId: order.id,
        productId: item.productId,
        quantity: item.quantity,
        price: item.price,
      })),
    });

    return order;
  });
}

// Use batch operations for performance
async function updateMultipleUsers(updates: UserUpdate[]): Promise<void> {
  await this.prisma.$transaction(
    updates.map(update => 
      this.prisma.user.update({
        where: { id: update.id },
        data: update.data,
      })
    )
  );
}
```

## 🔒 Security Best Practices

### **Input Validation and Sanitization**
```typescript
import { z } from 'zod';
import DOMPurify from 'isomorphic-dompurify';

const CreateUserSchema = z.object({
  email: z.string().email().transform(val => val.toLowerCase().trim()),
  name: z.string().min(2).max(100).transform(val => DOMPurify.sanitize(val)),
  bio: z.string().max(500).optional().transform(val => 
    val ? DOMPurify.sanitize(val) : undefined
  ),
});

// Rate limiting
import rateLimit from 'express-rate-limit';

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // limit each IP to 5 requests per windowMs
  message: 'Too many authentication attempts, please try again later.',
});
```

### **SQL Injection Prevention**
```typescript
// Prisma automatically prevents SQL injection
const user = await prisma.user.findUnique({
  where: { email: userInput.email },
});

// For raw queries, use parameterized queries
const result = await prisma.$queryRaw`
  SELECT * FROM users WHERE email = ${userEmail}
`;
```

---
*TypeScript/Node Framework Patterns - Use this as your canonical reference for all TypeScript/Node backend development*
