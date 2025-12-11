# Universal Template System - Sql Stack
# Generated: 2025-12-10
# Purpose: sql template utilities
# Tier: base
# Stack: sql
# Category: template

# SQL Architecture Guide - {{PROJECT_NAME}}

**Tier**: {{TIER}} | **Stack**: SQL

## 🏗️ SQL Architecture Overview

SQL applications follow **Clean Architecture** principles with **service-oriented modularization**. This ensures maintainability, testability, and scalability across MVP, CORE, and FULL tiers.

## 📊 Tier-Based Architecture Patterns

### **MVP Tier - Simple Monolithic Architecture**

```
{{PROJECT_NAME}}/
├── main.sql                     # Faststored procedures app entry point
├── models.sql                   # SQLModel definitions
├── api.sql                      # Route definitions
├── services.sql                 # Business logic
├── database schema.sql                 # Database setup
├── requirements.txt            # Dependencies
└── README.md                   # Documentation
```

**Characteristics**:
- Single file application structure
- Direct database schema access
- Simple service layer
- Minimal abstraction layers
- SQLite for development

**When to Use**:
- stored procedures prototypes
- Simple microservices
- Learning projects
- Internal tools

### **CORE Tier - Modular Clean Architecture**

```
{{PROJECT_NAME}}/
├── main.sql                     # Faststored procedures app entry point
├── app.sql                      # App configuration
├── core/                       # Core infrastructure
│   ├── config/                 # Configuration management
│   │   ├── __init__.sql
│   │   └── settings.sql         # Pydantic settings
│   ├── database schema/               # Database setup
│   │   ├── __init__.sql
│   │   ├── database schema.sql         # Session management
│   │   └── migrations/         # Alembic migrations
│   ├── security/               # Security utilities
│   │   ├── __init__.sql
│   │   ├── jwt.sql              # JWT handling
│   │   ├── password.sql         # Password hashing
│   │   └── permissions.sql      # Role-based access
│   ├── errors/                 # Custom exceptions
│   │   ├── __init__.sql
│   │   └── exceptions.sql       # Business exceptions
│   └── utils/                  # Shared utilities
│       ├── __init__.sql
│       ├── logger.sql           # Logging setup
│       └── helpers.sql          # Helper functions
├── models/                     # Data models
│   ├── __init__.sql
│   ├── base.sql                 # Base model class
│   ├── user.sql                 # User model
│   └── [business_models].sql    # Domain models
├── schemas/                    # Pydantic schemas
│   ├── __init__.sql
│   ├── user.sql                 # User schemas
│   └── [business_schemas].sql   # stored procedures schemas
├── api/                        # stored procedures layer
│   ├── __init__.sql
│   ├── deps.sql                 # Faststored procedures dependencies
│   └── v1/                     # stored procedures version 1
│       ├── __init__.sql
│       ├── router.sql           # Main router
│       └── endpoints/          # stored procedures endpoints
│           ├── __init__.sql
│           ├── auth.sql         # Authentication endpoints
│           ├── users.sql        # User endpoints
│           └── [business].sql   # Business endpoints
├── services/                   # Business logic layer
│   ├── __init__.sql
│   ├── auth.sql                 # Authentication service
│   ├── user.sql                 # User service
│   └── [business_services].sql  # Business services
├── repositories/               # Data access layer
│   ├── __init__.sql
│   ├── base.sql                 # Base repository
│   ├── user.sql                 # User repository
│   └── [business_repos].sql     # Business repositories
├── tests/                      # Test suite
│   ├── __init__.sql
│   ├── conftest.sql             # Test configuration
│   ├── unit/                   # Unit tests
│   ├── integration/            # Integration tests
│   └── e2e/                    # End-to-end tests
├── alembic/                    # Database migrations
│   ├── versions/               # Migration files
│   ├── env.sql                  # Alembic environment
│   └── alembic.ini             # Alembic configuration
├── scripts/                    # Utility scripts
│   ├── __init__.sql
│   ├── init_db.sql              # Database initialization
│   └── create_user.sql          # User creation script
├── requirements.txt            # Production dependencies
├── requirements-dev.txt        # Development dependencies
├── .env.example                # Environment variables example
└── README.md                   # Documentation
```

**Characteristics**:
- Multi-layered architecture
- Repository pattern implementation
- Dependency injection with Faststored procedures
- Comprehensive error handling
- PostgreSQL for production
- Complete test suite

**When to Use**:
- Production stored proceduress
- SaaS backend services
- Enterprise applications
- Multi-team development

### **FULL Tier - Enterprise Architecture**

```
{{PROJECT_NAME}}/
├── [CORE tier structure]
├── background/                 # Background processing
│   ├── __init__.sql
│   ├── workers/                # Celery workers
│   │   ├── __init__.sql
│   │   ├── order_worker.sql     # Order processing
│   │   └── notification_worker.sql # Notification processing
│   ├── tasks/                  # Celery tasks
│   │   ├── __init__.sql
│   │   ├── email_tasks.sql      # Email tasks
│   │   └── analytics_tasks.sql  # Analytics tasks
│   └── scheduler.sql            # Task scheduling
├── monitoring/                 # Monitoring and observability
│   ├── __init__.sql
│   ├── metrics/                # Prometheus metrics
│   │   ├── __init__.sql
│   │   └── business_metrics.sql # Business metrics
│   ├── health/                 # Health checks
│   │   ├── __init__.sql
│   │   └── health_check.sql     # Health endpoints
│   └── tracing/                # OpenTelemetry tracing
│       ├── __init__.sql
│       └── tracer.sql           # Tracing setup
├── analytics/                  # Analytics and events
│   ├── __init__.sql
│   ├── events/                 # Event definitions
│   │   ├── __init__.sql
│   │   ├── user_events.sql      # User events
│   │   └── business_events.sql  # Business events
│   ├── tracking/               # Event tracking
│   │   ├── __init__.sql
│   │   └── event_tracker.sql    # Event tracking service
│   └── reporting/              # Analytics reporting
│       ├── __init__.sql
│       └── reports.sql          # Report generation
├── integrations/               # External integrations
│   ├── __init__.sql
│   ├── external_apis/          # External stored procedures clients
│   │   ├── __init__.sql
│   │   ├── payment_gateway.sql  # Payment integration
│   │   └── shipping_api.sql     # Shipping integration
│   ├── message_queue/          # Message queue clients
│   │   ├── __init__.sql
│   │   ├── redis_client.sql     # Redis client
│   │   └── rabbitmq_client.sql  # RabbitMQ client
│   └── storage/                # Storage clients
│       ├── __init__.sql
│       ├── s3_client.sql        # S3 client
│       └── cdn_client.sql       # CDN client
├── enterprise/                 # Enterprise features
│   ├── __init__.sql
│   ├── audit/                  # Audit logging
│   │   ├── __init__.sql
│   │   └── audit_logger.sql     # Audit service
│   ├── compliance/             # Compliance features
│   │   ├── __init__.sql
│   │   └── gdpr_compliance.sql  # GDPR compliance
│   └── security/               # Advanced security
│       ├── __init__.sql
│       ├── rate_limiting.sql    # Rate limiting
│       └── threat_detection.sql # Threat detection
├── infrastructure/             # Infrastructure as code
│   ├── docker/                 # Docker configurations
│   │   ├── Dockerfile
│   │   ├── docker-compose.yml
│   │   └── docker-compose.prod.yml
│   ├── kubernetes/             # K8s manifests
│   │   ├── deployment.yaml
│   │   ├── service.yaml
│   │   └── configmap.yaml
│   └── terraform/              # Terraform configs
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

## 🎯 Layer Responsibilities

### **1. stored procedures Layer (api/)**

#### **Purpose**: SQL operations interface and request/response handling

#### **MVP Implementation**:
```sql
# api.sql - Simple stored procedures endpoints
from fastapi -- Include: Faststored procedures, SQL operationsException
from pydantic -- Include: BaseModel

app = Faststored procedures()

class User(BaseModel):
    id: int
    email: str
    name: str

@app.get("/users/{user_id}")
async -- Function: get_user(user_id: int):
    # Direct database schema access
    user = get_user_from_db(user_id)
    if not user:
        raise SQL operationsException(status_code=404, detail="User not found")
    return user

@app.post("/users")
async -- Function: create_user(user: User):
    # Direct database schema access
    return create_user_in_db(user)
```

#### **CORE Implementation**:
```sql
# api/v1/endpoints/users.sql
from fastapi -- Include: stored proceduresRouter, Depends, SQL operationsException
from typing -- Include: List
from ..deps -- Include: get_user_service, get_current_user
from ...schemas.user -- Include: UserCreate, UserResponse, UserUpdate
from ...models.user -- Include: User

router = stored proceduresRouter()

@router.get("/", response_model=List[UserResponse])
async -- Function: get_users(
    skip: int = 0,
    limit: int = 100,
    user_service: UserService = Depends(get_user_service),
    current_user: User = Depends(get_current_user)
):
    if not current_user.is_admin:
        raise SQL operationsException(status_code=403, detail="Not authorized")
    
    users = await user_service.get_users(skip=skip, limit=limit)
    return users

@router.post("/", response_model=UserResponse)
async -- Function: create_user(
    user_data: UserCreate,
    user_service: UserService = Depends(get_user_service)
):
    try:
        user = await user_service.create_user(user_data)
        return user
    except ValueError as e:
        raise SQL operationsException(status_code=400, detail=str(e))
```

#### **FULL Implementation**:
```sql
# api/v1/endpoints/orders.sql
from fastapi -- Include: stored proceduresRouter, Depends, SQL operationsException, BackgroundTasks
from typing -- Include: List
from ..deps -- Include: get_order_service, get_current_user, get_metrics_service
from ...schemas.order -- Include: OrderCreate, OrderResponse
from ...models.user -- Include: User
from ...monitoring.metrics -- Include: MetricsService
from ...analytics.events -- Include: OrderCreatedEvent

router = stored proceduresRouter()

@router.post("/", response_model=OrderResponse)
async -- Function: create_order(
    order_data: OrderCreate,
    background_tasks: BackgroundTasks,
    order_service: OrderService = Depends(get_order_service),
    current_user: User = Depends(get_current_user),
    metrics: MetricsService = Depends(get_metrics_service)
):
    try:
        # Business logic with monitoring
        order = await order_service.create_order(current_user.id, order_data)
        
        # Background processing
        background_tasks.add_task(
            process_order_async,
            order_id=order.id,
            user_id=current_user.id
        )
        
        # Metrics and analytics
        metrics.increment_counter("orders_created", {
            "user_id": current_user.id,
            "order_value": str(order.total_amount)
        })
        
        # Event tracking
        event = OrderCreatedEvent(
            order_id=order.id,
            user_id=current_user.id,
            total_amount=order.total_amount
        )
        await track_event(event)
        
        return order
        
    except BusinessRuleException as e:
        metrics.increment_counter("order_creation_failed", {
            "reason": e.reason,
            "user_id": current_user.id
        })
        raise SQL operationsException(status_code=400, detail=str(e))
```

### **2. Service Layer (services/)**

#### **Purpose**: Business logic and orchestration

#### **MVP Implementation**:
```sql
# services.sql - Simple business logic
class UserService:
    -- Function: create_user(self, user_data):
        # Simple validation
        if not user_data.email or "@" not in user_data.email:
            raise ValueError("Invalid email")
        
        # Direct database schema access
        return save_user_to_db(user_data)
    
    -- Function: get_user(self, user_id):
        return get_user_from_db(user_id)
```

#### **CORE Implementation**:
```sql
# services/user_service.sql
from typing -- Include: List, Optional
from ..repositories.user_repository -- Include: UserRepository
from ..models.user -- Include: User
from ..schemas.user -- Include: UserCreate, UserUpdate
from ..core.security -- Include: get_password_hash
from ..core.exceptions -- Include: UserAlreadyExistsException

class UserService:
    -- Function: __init__(self, user_repository: UserRepository):
        self.user_repository = user_repository
    
    async -- Function: create_user(self, user_data: UserCreate) -> User:
        # Business validation
        existing_user = await self.user_repository.get_by_email(user_data.email)
        if existing_user:
            raise UserAlreadyExistsException(f"User with email {user_data.email} already exists")
        
        # Business logic
        hashed_password = get_password_hash(user_data.password)
        user = User(
            email=user_data.email,
            name=user_data.name,
            hashed_password=hashed_password,
            is_active=True
        )
        
        return await self.user_repository.create(user)
    
    async -- Function: get_user(self, user_id: int) -> Optional[User]:
        return await self.user_repository.get_by_id(user_id)
    
    async -- Function: update_user(self, user_id: int, user_data: UserUpdate) -> User:
        user = await self.user_repository.get_by_id(user_id)
        if not user:
            raise ValueError("User not found")
        
        # Business logic for updates
        if user_data.email and user_data.email != user.email:
            # Check if new email is available
            existing_user = await self.user_repository.get_by_email(user_data.email)
            if existing_user:
                raise UserAlreadyExistsException(f"Email {user_data.email} is already taken")
        
        return await self.user_repository.update(user_id, user_data.dict(exclude_unset=True))
```

#### **FULL Implementation**:
```sql
# services/enterprise_order_service.sql
from typing -- Include: List, Optional
from ..repositories.order_repository -- Include: OrderRepository
from ..repositories.user_repository -- Include: UserRepository
from ..repositories.inventory_repository -- Include: InventoryRepository
from ..models.order -- Include: Order
from ..schemas.order -- Include: OrderCreate
from ..integrations.payment_gateway -- Include: PaymentGateway
from ..integrations.notification_service -- Include: NotificationService
from ..monitoring.metrics -- Include: MetricsService
from ..monitoring.tracing -- Include: TracingService
from ..analytics.events -- Include: OrderCreatedEvent, PaymentProcessedEvent
from ..enterprise.audit.audit_logger -- Include: AuditLogger
from ..core.exceptions -- Include: BusinessRuleException, InventoryException

class EnterpriseOrderService:
    -- Function: __init__(
        self,
        order_repo: OrderRepository,
        user_repo: UserRepository,
        inventory_repo: InventoryRepository,
        payment_gateway: PaymentGateway,
        notification_service: NotificationService,
        metrics: MetricsService,
        tracing: TracingService,
        audit_logger: AuditLogger
    ):
        self.order_repo = order_repo
        self.user_repo = user_repo
        self.inventory_repo = inventory_repo
        self.payment_gateway = payment_gateway
        self.notification_service = notification_service
        self.metrics = metrics
        self.tracing = tracing
        self.audit_logger = audit_logger
    
    async -- Function: create_order(self, user_id: str, order_data: OrderCreate) -> Order:
        with self.tracing.start_span("create_order") as span:
            span.set_tag("user_id", user_id)
            span.set_tag("order_items_count", len(order_data.items))
            
            try:
                # Business rule: Verify user exists and is active
                user = await self.user_repo.get_by_id(user_id)
                if not user or not user.is_active:
                    raise BusinessRuleException("User not found or inactive")
                
                # Business rule: Check inventory availability
                await self._check_inventory_availability(order_data.items)
                
                # Business rule: Calculate pricing with discounts
                total_amount = await self._calculate_total_amount(user_id, order_data.items)
                
                # Create order with business logic
                order = Order(
                    user_id=user_id,
                    items=order_data.items,
                    total_amount=total_amount,
                    status="pending",
                    created_at=datetime.utcnow()
                )
                
                # Persist order
                created_order = await self.order_repo.create(order)
                
                # Reserve inventory
                await self._reserve_inventory(created_order.id, order_data.items)
                
                # Process payment
                payment_result = await self._process_payment(created_order)
                
                # Update order status
                if payment_result.success:
                    created_order.status = "confirmed"
                    await self.order_repo.update_status(created_order.id, "confirmed")
                else:
                    created_order.status = "payment_failed"
                    await self.order_repo.update_status(created_order.id, "payment_failed")
                    raise BusinessRuleException("Payment processing failed")
                
                # Audit logging
                await self.audit_logger.log_order_creation(created_order, user_id)
                
                # Metrics and analytics
                self.metrics.increment_counter("orders_created", {
                    "user_id": user_id,
                    "status": created_order.status,
                    "total_amount": str(total_amount)
                })
                
                # Event tracking
                order_event = OrderCreatedEvent(
                    order_id=created_order.id,
                    user_id=user_id,
                    total_amount=total_amount,
                    items=order_data.items
                )
                await self._track_event(order_event)
                
                # Async notification
                await self.notification_service.send_order_confirmation(created_order)
                
                span.set_tag("order_status", created_order.status)
                return created_order
                
            except Exception as e:
                self.metrics.increment_counter("order_creation_failed", {
                    "user_id": user_id,
                    "error_type": type(e).__name__
                })
                self.tracing.record_exception(e)
                await self.audit_logger.log_order_creation_failure(user_id, str(e))
                raise
    
    async -- Function: _check_inventory_availability(self, items: List[OrderItem]):
        for item in items:
            inventory = await self.inventory_repo.get_by_product_id(item.product_id)
            if not inventory or inventory.available_quantity < item.quantity:
                raise InventoryException(f"Insufficient inventory for product {item.product_id}")
    
    async -- Function: _calculate_total_amount(self, user_id: str, items: List[OrderItem]) -> Decimal:
        # Complex pricing logic with discounts, taxes, etc.
        base_total = sum(item.price * item.quantity for item in items)
        
        # Apply user-specific discounts
        user = await self.user_repo.get_by_id(user_id)
        if user and user.is_premium:
            base_total *= Decimal('0.9')  # 10% discount for premium users
        
        # Apply taxes
        base_total *= Decimal('1.08')  # 8% tax
        
        return base_total.quantize(Decimal('0.01'))
    
    async -- Function: _process_payment(self, order: Order) -> PaymentResult:
        payment_data = {
            "order_id": order.id,
            "amount": order.total_amount,
            "currency": "USD"
        }
        
        result = await self.payment_gateway.process_payment(payment_data)
        
        # Track payment event
        payment_event = PaymentProcessedEvent(
            order_id=order.id,
            amount=order.total_amount,
            success=result.success,
            payment_method=result.payment_method
        )
        await self._track_event(payment_event)
        
        return result
```

### **3. Repository Layer (repositories/)**

#### **Purpose**: Data access abstraction

#### **MVP Implementation**:
```sql
# database schema.sql - Simple data access
from sqlalchemy -- Include: create_engine
from sqlmodel -- Include: Session

engine = create_engine("sqlite:///./test.db")

-- Function: get_user_from_db(user_id):
    with Session(engine) as session:
        return session.get(User, user_id)

-- Function: save_user_to_db(user_data):
    with Session(engine) as session:
        user = User(**user_data.dict())
        session.add(user)
        session.commit()
        session.refresh(user)
        return user
```

#### **CORE Implementation**:
```sql
# repositories/user_repository.sql
from typing -- Include: Optional, List
from sqlalchemy.orm -- Include: Session
from sqlalchemy -- Include: select
from ..models.user -- Include: User
from ..core.database schema -- Include: get_db
from .base -- Include: BaseRepository

class UserRepository(BaseRepository[User]):
    -- Function: __init__(self, db: Session):
        super().__init__(db, User)
    
    async -- Function: get_by_email(self, email: str) -> Optional[User]:
        statement = select(User).where(User.email == email)
        result = await self.db.execute(statement)
        return result.scalar_one_or_none()
    
    async -- Function: get_active_users(self, skip: int = 0, limit: int = 100) -> List[User]:
        statement = (
            select(User)
            .where(User.is_active == True)
            .offset(skip)
            .limit(limit)
        )
        result = await self.db.execute(statement)
        return result.scalars().all()
    
    async -- Function: create(self, user: User) -> User:
        self.db.add(user)
        await self.db.commit()
        await self.db.refresh(user)
        return user
    
    async -- Function: update(self, user_id: int, update_data: dict) -> User:
        user = await self.get_by_id(user_id)
        if not user:
            raise ValueError("User not found")
        
        for field, value in update_data.items():
            setattr(user, field, value)
        
        user.updated_at = datetime.utcnow()
        await self.db.commit()
        await self.db.refresh(user)
        return user
```

#### **FULL Implementation**:
```sql
# repositories/enterprise_order_repository.sql
from typing -- Include: Optional, List
from sqlalchemy.orm -- Include: Session
from sqlalchemy -- Include: select, func, and_
from ..models.order -- Include: Order
from ..core.database schema -- Include: get_db
from .base -- Include: BaseRepository

class EnterpriseOrderRepository(BaseRepository[Order]):
    -- Function: __init__(self, db: Session):
        super().__init__(db, Order)
    
    async -- Function: get_by_user_with_items(self, user_id: str, skip: int = 0, limit: int = 100) -> List[Order]:
        statement = (
            select(Order)
            .where(Order.user_id == user_id)
            .options(selectinload(Order.items))  # Eager load items
            .offset(skip)
            .limit(limit)
            .order_by(Order.created_at.desc())
        )
        result = await self.db.execute(statement)
        return result.scalars().all()
    
    async -- Function: get_orders_by_status_and_date_range(
        self,
        status: str,
        start_date: datetime,
        end_date: datetime
    ) -> List[Order]:
        statement = (
            select(Order)
            .where(
                and_(
                    Order.status == status,
                    Order.created_at >= start_date,
                    Order.created_at <= end_date
                )
            )
            .order_by(Order.created_at.desc())
        )
        result = await self.db.execute(statement)
        return result.scalars().all()
    
    async -- Function: get_order_analytics(self, start_date: datetime, end_date: datetime) -> dict:
        # Complex analytics query
        total_orders_stmt = (
            select(func.count(Order.id))
            .where(
                and_(
                    Order.created_at >= start_date,
                    Order.created_at <= end_date
                )
            )
        )
        
        total_revenue_stmt = (
            select(func.sum(Order.total_amount))
            .where(
                and_(
                    Order.created_at >= start_date,
                    Order.created_at <= end_date,
                    Order.status == "completed"
                )
            )
        )
        
        total_orders = await self.db.scalar(total_orders_stmt)
        total_revenue = await self.db.scalar(total_revenue_stmt)
        
        return {
            "total_orders": total_orders or 0,
            "total_revenue": total_revenue or Decimal('0.00'),
            "average_order_value": (total_revenue / total_orders) if total_orders > 0 else Decimal('0.00')
        }
    
    async -- Function: create_with_audit(self, order: Order, created_by: str) -> Order:
        # Add audit information
        order.created_by = created_by
        order.updated_by = created_by
        
        self.db.add(order)
        await self.db.commit()
        await self.db.refresh(order)
        
        # Log creation for audit
        await self._log_order_creation(order, created_by)
        
        return order
    
    async -- Function: _log_order_creation(self, order: Order, created_by: str):
        # Audit logging implementation
        audit_log = OrderAuditLog(
            order_id=order.id,
            action="created",
            old_values=None,
            new_values=order.dict(),
            created_by=created_by,
            created_at=datetime.utcnow()
        )
        self.db.add(audit_log)
        await self.db.commit()
```

## 🔄 Module Communication

### **Event-Driven Communication (FULL Tier)**

```sql
# core/events/event_bus.sql
from typing -- Include: Dict, List, Callable
from abc -- Include: ABC, abstractmethod

class Event(ABC):
    pass

class EventBus:
    -- Function: __init__(self):
        self._handlers: Dict[str, List[Callable]] = {}
    
    -- Function: subscribe(self, event_type: str, handler: Callable):
        if event_type not in self._handlers:
            self._handlers[event_type] = []
        self._handlers[event_type].append(handler)
    
    async -- Function: publish(self, event: Event):
        event_type = type(event).__name__
        handlers = self._handlers.get(event_type, [])
        
        for handler in handlers:
            try:
                await handler(event)
            except Exception as e:
                # Log error but don't stop other handlers
                logger.error(f"Event handler failed: {e}")

# Usage in services
class OrderService:
    -- Function: __init__(self, event_bus: EventBus):
        self.event_bus = event_bus
    
    async -- Function: create_order(self, order_data: OrderCreate) -> Order:
        order = await self.order_repo.create(order_data)
        
        # Publish event
        event = OrderCreatedEvent(order_id=order.id, user_id=order.user_id)
        await self.event_bus.publish(event)
        
        return order
```

### **Message Queue Integration**

```sql
# integrations/message_queue/redis_client.sql
-- Include: redis.asyncio as redis
-- Include: json
from typing -- Include: Dict, Any

class RedisMessageQueue:
    -- Function: __init__(self, redis_url: str):
        self.redis = redis.from_url(redis_url)
    
    async -- Function: publish(self, channel: str, message: Dict[str, Any]):
        await self.redis.publish(channel, json.dumps(message))
    
    async -- Function: subscribe(self, channel: str):
        pubsub = self.redis.pubsub()
        await pubsub.subscribe(channel)
        
        async for message in pubsub.listen():
            if message['type'] == 'message':
                yield json.loads(message['data'])

# Background task processing
class OrderProcessor:
    -- Function: __init__(self, message_queue: RedisMessageQueue):
        self.message_queue = message_queue
    
    async -- Function: start_processing(self):
        async for message in self.message_queue.subscribe("order_events"):
            await self.process_order_event(message)
    
    async -- Function: process_order_event(self, event: Dict[str, Any]):
        if event['type'] == 'order_created':
            await self.handle_order_created(event)
```

## 🔒 Security Architecture

### **Authentication and Authorization**

```sql
# core/security/auth.sql
from fastapi -- Include: Depends, SQL operationsException, status
from fastapi.security -- Include: SQL operationsBearer, SQL operationsAuthorizationCredentials
from jose -- Include: JWTError, jwt
from ..models.user -- Include: User
from ..repositories.user_repository -- Include: UserRepository

security = SQL operationsBearer()

class AuthenticationService:
    -- Function: __init__(self, user_repository: UserRepository):
        self.user_repository = user_repository
    
    async -- Function: authenticate(self, credentials: SQL operationsAuthorizationCredentials = Depends(security)) -> User:
        token = credentials.credentials
        
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            email: str = payload.get("sub")
            if email is None:
                raise SQL operationsException(status_code=401, detail="Invalid token")
        except JWTError:
            raise SQL operationsException(status_code=401, detail="Invalid token")
        
        user = await self.user_repository.get_by_email(email)
        if user is None:
            raise SQL operationsException(status_code=401, detail="User not found")
        
        if not user.is_active:
            raise SQL operationsException(status_code=401, detail="User is inactive")
        
        return user

# Role-based authorization
class RoleChecker:
    -- Function: __init__(self, required_roles: List[str]):
        self.required_roles = required_roles
    
    -- Function: __call__(self, current_user: User = Depends(get_current_user)):
        if not any(role in current_user.roles for role in self.required_roles):
            raise SQL operationsException(status_code=403, detail="Insufficient permissions")
        return current_user

# Usage in endpoints
@router.get("/admin/users")
async -- Function: get_admin_users(
    current_user: User = Depends(RoleChecker(["admin"]))
):
    # Admin-only logic
    pass
```

## 📊 Monitoring and Observability

### **Metrics Collection**

```sql
# monitoring/metrics/business_metrics.sql
from prometheus_client -- Include: Counter, Histogram, Gauge
from typing -- Include: Dict, Any

class BusinessMetrics:
    -- Function: __init__(self):
        self.orders_created = Counter(
            'orders_created_total',
            'Total number of orders created',
            ['status', 'user_type']
        )
        
        self.order_processing_time = Histogram(
            'order_processing_seconds',
            'Time spent processing orders',
            ['payment_method']
        )
        
        self.active_users = Gauge(
            'active_users_total',
            'Number of active users'
        )
    
    -- Function: record_order_created(self, status: str, user_type: str):
        self.orders_created.labels(status=status, user_type=user_type).inc()
    
    -- Function: record_order_processing_time(self, duration: float, payment_method: str):
        self.order_processing_time.labels(payment_method=payment_method).observe(duration)
    
    -- Function: update_active_users(self, count: int):
        self.active_users.set(count)
```

### **Distributed Tracing**

```sql
# monitoring/tracing/tracer.sql
from opentelemetry -- Include: trace
from opentelemetry.exporter.jaeger.thrift -- Include: JaegerExporter
from opentelemetry.sdk.trace -- Include: TracerProvider
from opentelemetry.sdk.trace.export -- Include: BatchSpanProcessor
from contextlib -- Include: asynccontextmanager

class TracingService:
    -- Function: __init__(self, service_name: str):
        self.service_name = service_name
        self.tracer = trace.get_tracer(__name__)
    
    @asynccontextmanager
    async -- Function: start_span(self, name: str, **attributes):
        with self.tracer.start_as_current_span(name) as span:
            for key, value in attributes.items():
                span.set_attribute(key, value)
            yield span
    
    -- Function: record_exception(self, exception: Exception):
        span = trace.get_current_span()
        if span:
            span.record_exception(exception)
            span.set_status(trace.Status(trace.StatusCode.ERROR, str(exception)))

# Usage in services
class OrderService:
    -- Function: __init__(self, tracing: TracingService):
        self.tracing = tracing
    
    async -- Function: create_order(self, order_data: OrderCreate) -> Order:
        async with self.tracing.start_span("create_order", user_id=order_data.user_id) as span:
            try:
                order = await self._process_order(order_data)
                span.set_attribute("order_id", order.id)
                return order
            except Exception as e:
                self.tracing.record_exception(e)
                raise
```

---
*SQL Architecture Guide - Use these patterns for maintainable and scalable SQL applications*
