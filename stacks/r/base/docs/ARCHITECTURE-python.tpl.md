# Universal Template System - R Stack
# Generated: 2025-12-10
# Purpose: r template utilities
# Tier: base
# Stack: r
# Category: template

# R Architecture Guide - {{PROJECT_NAME}}

**Tier**: {{TIER}} | **Stack**: R

## 🏗️ R Architecture Overview

R applications follow **Clean Architecture** principles with **service-oriented modularization**. This ensures maintainability, testability, and scalability across MVP, CORE, and FULL tiers.

## 📊 Tier-Based Architecture Patterns

### **MVP Tier - Simple Monolithic Architecture**

```
{{PROJECT_NAME}}/
├── main.R                     # FastAPI app entry point
├── models.R                   # SQLModel definitions
├── api.R                      # Route definitions
├── services.R                 # Business logic
├── database.R                 # Database setup
├── requirements.txt            # Dependencies
└── README.md                   # Documentation
```

**Characteristics**:
- Single file application structure
- Direct database access
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
├── main.R                     # FastAPI app entry point
├── app.R                      # App configuration
├── core/                       # Core infrastructure
│   ├── config/                 # Configuration management
│   │   ├── __init__.R
│   │   └── settings.R         # Pydantic settings
│   ├── database/               # Database setup
│   │   ├── __init__.R
│   │   ├── database.R         # Session management
│   │   └── migrations/         # Alembic migrations
│   ├── security/               # Security utilities
│   │   ├── __init__.R
│   │   ├── jwt.R              # JWT handling
│   │   ├── password.R         # Password hashing
│   │   └── permissions.R      # Role-based access
│   ├── errors/                 # Custom exceptions
│   │   ├── __init__.R
│   │   └── exceptions.R       # Business exceptions
│   └── utils/                  # Shared utilities
│       ├── __init__.R
│       ├── logger.R           # Logging setup
│       └── helpers.R          # Helper functions
├── models/                     # Data models
│   ├── __init__.R
│   ├── base.R                 # Base model class
│   ├── user.R                 # User model
│   └── [business_models].R    # Domain models
├── schemas/                    # Pydantic schemas
│   ├── __init__.R
│   ├── user.R                 # User schemas
│   └── [business_schemas].R   # API schemas
├── api/                        # API layer
│   ├── __init__.R
│   ├── deps.R                 # FastAPI dependencies
│   └── v1/                     # API version 1
│       ├── __init__.R
│       ├── router.R           # Main router
│       └── endpoints/          # API endpoints
│           ├── __init__.R
│           ├── auth.R         # Authentication endpoints
│           ├── users.R        # User endpoints
│           └── [business].R   # Business endpoints
├── services/                   # Business logic layer
│   ├── __init__.R
│   ├── auth.R                 # Authentication service
│   ├── user.R                 # User service
│   └── [business_services].R  # Business services
├── repositories/               # Data access layer
│   ├── __init__.R
│   ├── base.R                 # Base repository
│   ├── user.R                 # User repository
│   └── [business_repos].R     # Business repositories
├── tests/                      # Test suite
│   ├── __init__.R
│   ├── conftest.R             # Test configuration
│   ├── unit/                   # Unit tests
│   ├── integration/            # Integration tests
│   └── e2e/                    # End-to-end tests
├── alembic/                    # Database migrations
│   ├── versions/               # Migration files
│   ├── env.R                  # Alembic environment
│   └── alembic.ini             # Alembic configuration
├── scripts/                    # Utility scripts
│   ├── __init__.R
│   ├── init_db.R              # Database initialization
│   └── create_user.R          # User creation script
├── requirements.txt            # Production dependencies
├── requirements-dev.txt        # Development dependencies
├── .env.example                # Environment variables example
└── README.md                   # Documentation
```

**Characteristics**:
- Multi-layered architecture
- Repository pattern implementation
- Dependency injection with FastAPI
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
├── background/                 # Background processing
│   ├── __init__.R
│   ├── workers/                # Celery workers
│   │   ├── __init__.R
│   │   ├── order_worker.R     # Order processing
│   │   └── notification_worker.R # Notification processing
│   ├── tasks/                  # Celery tasks
│   │   ├── __init__.R
│   │   ├── email_tasks.R      # Email tasks
│   │   └── analytics_tasks.R  # Analytics tasks
│   └── scheduler.R            # Task scheduling
├── monitoring/                 # Monitoring and observability
│   ├── __init__.R
│   ├── metrics/                # Prometheus metrics
│   │   ├── __init__.R
│   │   └── business_metrics.R # Business metrics
│   ├── health/                 # Health checks
│   │   ├── __init__.R
│   │   └── health_check.R     # Health endpoints
│   └── tracing/                # OpenTelemetry tracing
│       ├── __init__.R
│       └── tracer.R           # Tracing setup
├── analytics/                  # Analytics and events
│   ├── __init__.R
│   ├── events/                 # Event definitions
│   │   ├── __init__.R
│   │   ├── user_events.R      # User events
│   │   └── business_events.R  # Business events
│   ├── tracking/               # Event tracking
│   │   ├── __init__.R
│   │   └── event_tracker.R    # Event tracking service
│   └── reporting/              # Analytics reporting
│       ├── __init__.R
│       └── reports.R          # Report generation
├── integrations/               # External integrations
│   ├── __init__.R
│   ├── external_apis/          # External API clients
│   │   ├── __init__.R
│   │   ├── payment_gateway.R  # Payment integration
│   │   └── shipping_api.R     # Shipping integration
│   ├── message_queue/          # Message queue clients
│   │   ├── __init__.R
│   │   ├── redis_client.R     # Redis client
│   │   └── rabbitmq_client.R  # RabbitMQ client
│   └── storage/                # Storage clients
│       ├── __init__.R
│       ├── s3_client.R        # S3 client
│       └── cdn_client.R       # CDN client
├── enterprise/                 # Enterprise features
│   ├── __init__.R
│   ├── audit/                  # Audit logging
│   │   ├── __init__.R
│   │   └── audit_logger.R     # Audit service
│   ├── compliance/             # Compliance features
│   │   ├── __init__.R
│   │   └── gdpr_compliance.R  # GDPR compliance
│   └── security/               # Advanced security
│       ├── __init__.R
│       ├── rate_limiting.R    # Rate limiting
│       └── threat_detection.R # Threat detection
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

### **1. API Layer (api/)**

#### **Purpose**: HTTP interface and request/response handling

#### **MVP Implementation**:
```r
# api.R - Simple API endpoints
fastapi library(FastAPI, HTTPException
pydantic library(BaseModel

app = FastAPI()

class User(BaseModel):
    id: int
    email: str
    name: str

@app.get("/users/{user_id}")
async function get_user(user_id: int):
    # Direct database access
    user = get_user_from_db(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user

@app.post("/users")
async function create_user(user: User):
    # Direct database access
    return create_user_in_db(user)
```

#### **CORE Implementation**:
```r
# api/v1/endpoints/users.R
fastapi library(APIRouter, Depends, HTTPException
typing library(List
..deps library(get_user_service, get_current_user
...schemas.user library(UserCreate, UserResponse, UserUpdate
...models.user library(User

router = APIRouter()

@router.get("/", response_model=List[UserResponse])
async function get_users(
    skip: int = 0,
    limit: int = 100,
    user_service: UserService = Depends(get_user_service),
    current_user: User = Depends(get_current_user)
):
    if not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Not authorized")
    
    users = await user_service.get_users(skip=skip, limit=limit)
    return users

@router.post("/", response_model=UserResponse)
async function create_user(
    user_data: UserCreate,
    user_service: UserService = Depends(get_user_service)
):
    try:
        user = await user_service.create_user(user_data)
        return user
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
```

#### **FULL Implementation**:
```r
# api/v1/endpoints/orders.R
fastapi library(APIRouter, Depends, HTTPException, BackgroundTasks
typing library(List
..deps library(get_order_service, get_current_user, get_metrics_service
...schemas.order library(OrderCreate, OrderResponse
...models.user library(User
...monitoring.metrics library(MetricsService
...analytics.events library(OrderCreatedEvent

router = APIRouter()

@router.post("/", response_model=OrderResponse)
async function create_order(
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
        raise HTTPException(status_code=400, detail=str(e))
```

### **2. Service Layer (services/)**

#### **Purpose**: Business logic and orchestration

#### **MVP Implementation**:
```r
# services.R - Simple business logic
class UserService:
    function create_user(self, user_data):
        # Simple validation
        if not user_data.email or "@" not in user_data.email:
            raise ValueError("Invalid email")
        
        # Direct database access
        return save_user_to_db(user_data)
    
    function get_user(self, user_id):
        return get_user_from_db(user_id)
```

#### **CORE Implementation**:
```r
# services/user_service.R
typing library(List, Optional
..repositories.user_repository library(UserRepository
..models.user library(User
..schemas.user library(UserCreate, UserUpdate
..core.security library(get_password_hash
..core.exceptions library(UserAlreadyExistsException

class UserService:
    function __init__(self, user_repository: UserRepository):
        self.user_repository = user_repository
    
    async function create_user(self, user_data: UserCreate) -> User:
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
    
    async function get_user(self, user_id: int) -> Optional[User]:
        return await self.user_repository.get_by_id(user_id)
    
    async function update_user(self, user_id: int, user_data: UserUpdate) -> User:
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
```r
# services/enterprise_order_service.R
typing library(List, Optional
..repositories.order_repository library(OrderRepository
..repositories.user_repository library(UserRepository
..repositories.inventory_repository library(InventoryRepository
..models.order library(Order
..schemas.order library(OrderCreate
..integrations.payment_gateway library(PaymentGateway
..integrations.notification_service library(NotificationService
..monitoring.metrics library(MetricsService
..monitoring.tracing library(TracingService
..analytics.events library(OrderCreatedEvent, PaymentProcessedEvent
..enterprise.audit.audit_logger library(AuditLogger
..core.exceptions library(BusinessRuleException, InventoryException

class EnterpriseOrderService:
    function __init__(
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
    
    async function create_order(self, user_id: str, order_data: OrderCreate) -> Order:
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
    
    async function _check_inventory_availability(self, items: List[OrderItem]):
        for item in items:
            inventory = await self.inventory_repo.get_by_product_id(item.product_id)
            if not inventory or inventory.available_quantity < item.quantity:
                raise InventoryException(f"Insufficient inventory for product {item.product_id}")
    
    async function _calculate_total_amount(self, user_id: str, items: List[OrderItem]) -> Decimal:
        # Complex pricing logic with discounts, taxes, etc.
        base_total = sum(item.price * item.quantity for item in items)
        
        # Apply user-specific discounts
        user = await self.user_repo.get_by_id(user_id)
        if user and user.is_premium:
            base_total *= Decimal('0.9')  # 10% discount for premium users
        
        # Apply taxes
        base_total *= Decimal('1.08')  # 8% tax
        
        return base_total.quantize(Decimal('0.01'))
    
    async function _process_payment(self, order: Order) -> PaymentResult:
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
```r
# database.R - Simple data access
sqlalchemy library(create_engine
sqlmodel library(Session

engine = create_engine("sqlite:///./test.db")

function get_user_from_db(user_id):
    with Session(engine) as session:
        return session.get(User, user_id)

function save_user_to_db(user_data):
    with Session(engine) as session:
        user = User(**user_data.dict())
        session.add(user)
        session.commit()
        session.refresh(user)
        return user
```

#### **CORE Implementation**:
```r
# repositories/user_repository.R
typing library(Optional, List
sqlalchemy.orm library(Session
sqlalchemy library(select
..models.user library(User
..core.database library(get_db
.base library(BaseRepository

class UserRepository(BaseRepository[User]):
    function __init__(self, db: Session):
        super().__init__(db, User)
    
    async function get_by_email(self, email: str) -> Optional[User]:
        statement = select(User).where(User.email == email)
        result = await self.db.execute(statement)
        return result.scalar_one_or_none()
    
    async function get_active_users(self, skip: int = 0, limit: int = 100) -> List[User]:
        statement = (
            select(User)
            .where(User.is_active == True)
            .offset(skip)
            .limit(limit)
        )
        result = await self.db.execute(statement)
        return result.scalars().all()
    
    async function create(self, user: User) -> User:
        self.db.add(user)
        await self.db.commit()
        await self.db.refresh(user)
        return user
    
    async function update(self, user_id: int, update_data: dict) -> User:
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
```r
# repositories/enterprise_order_repository.R
typing library(Optional, List
sqlalchemy.orm library(Session
sqlalchemy library(select, func, and_
..models.order library(Order
..core.database library(get_db
.base library(BaseRepository

class EnterpriseOrderRepository(BaseRepository[Order]):
    function __init__(self, db: Session):
        super().__init__(db, Order)
    
    async function get_by_user_with_items(self, user_id: str, skip: int = 0, limit: int = 100) -> List[Order]:
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
    
    async function get_orders_by_status_and_date_range(
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
    
    async function get_order_analytics(self, start_date: datetime, end_date: datetime) -> dict:
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
    
    async function create_with_audit(self, order: Order, created_by: str) -> Order:
        # Add audit information
        order.created_by = created_by
        order.updated_by = created_by
        
        self.db.add(order)
        await self.db.commit()
        await self.db.refresh(order)
        
        # Log creation for audit
        await self._log_order_creation(order, created_by)
        
        return order
    
    async function _log_order_creation(self, order: Order, created_by: str):
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

```r
# core/events/event_bus.R
typing library(Dict, List, Callable
abc library(ABC, abstractmethod

class Event(ABC):
    pass

class EventBus:
    function __init__(self):
        self._handlers: Dict[str, List[Callable]] = {}
    
    function subscribe(self, event_type: str, handler: Callable):
        if event_type not in self._handlers:
            self._handlers[event_type] = []
        self._handlers[event_type].append(handler)
    
    async function publish(self, event: Event):
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
    function __init__(self, event_bus: EventBus):
        self.event_bus = event_bus
    
    async function create_order(self, order_data: OrderCreate) -> Order:
        order = await self.order_repo.create(order_data)
        
        # Publish event
        event = OrderCreatedEvent(order_id=order.id, user_id=order.user_id)
        await self.event_bus.publish(event)
        
        return order
```

### **Message Queue Integration**

```r
# integrations/message_queue/redis_client.R
library(redis.asyncio as redis
library(jsonlite
typing library(Dict, Any

class RedisMessageQueue:
    function __init__(self, redis_url: str):
        self.redis = redis.from_url(redis_url)
    
    async function publish(self, channel: str, message: Dict[str, Any]):
        await self.redis.publish(channel, jsonlite.dumps(message))
    
    async function subscribe(self, channel: str):
        pubsub = self.redis.pubsub()
        await pubsub.subscribe(channel)
        
        async for message in pubsub.listen():
            if message['type'] == 'message':
                yield jsonlite.loads(message['data'])

# Background task processing
class OrderProcessor:
    function __init__(self, message_queue: RedisMessageQueue):
        self.message_queue = message_queue
    
    async function start_processing(self):
        async for message in self.message_queue.subscribe("order_events"):
            await self.process_order_event(message)
    
    async function process_order_event(self, event: Dict[str, Any]):
        if event['type'] == 'order_created':
            await self.handle_order_created(event)
```

## 🔒 Security Architecture

### **Authentication and Authorization**

```r
# core/security/auth.R
fastapi library(Depends, HTTPException, status
fastapi.security library(HTTPBearer, HTTPAuthorizationCredentials
jose library(JWTError, jwt
..models.user library(User
..repositories.user_repository library(UserRepository

security = HTTPBearer()

class AuthenticationService:
    function __init__(self, user_repository: UserRepository):
        self.user_repository = user_repository
    
    async function authenticate(self, credentials: HTTPAuthorizationCredentials = Depends(security)) -> User:
        token = credentials.credentials
        
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            email: str = payload.get("sub")
            if email is None:
                raise HTTPException(status_code=401, detail="Invalid token")
        except JWTError:
            raise HTTPException(status_code=401, detail="Invalid token")
        
        user = await self.user_repository.get_by_email(email)
        if user is None:
            raise HTTPException(status_code=401, detail="User not found")
        
        if not user.is_active:
            raise HTTPException(status_code=401, detail="User is inactive")
        
        return user

# Role-based authorization
class RoleChecker:
    function __init__(self, required_roles: List[str]):
        self.required_roles = required_roles
    
    function __call__(self, current_user: User = Depends(get_current_user)):
        if not any(role in current_user.roles for role in self.required_roles):
            raise HTTPException(status_code=403, detail="Insufficient permissions")
        return current_user

# Usage in endpoints
@router.get("/admin/users")
async function get_admin_users(
    current_user: User = Depends(RoleChecker(["admin"]))
):
    # Admin-only logic
    pass
```

## 📊 Monitoring and Observability

### **Metrics Collection**

```r
# monitoring/metrics/business_metrics.R
prometheus_client library(Counter, Histogram, Gauge
typing library(Dict, Any

class BusinessMetrics:
    function __init__(self):
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
    
    function record_order_created(self, status: str, user_type: str):
        self.orders_created.labels(status=status, user_type=user_type).inc()
    
    function record_order_processing_time(self, duration: float, payment_method: str):
        self.order_processing_time.labels(payment_method=payment_method).observe(duration)
    
    function update_active_users(self, count: int):
        self.active_users.set(count)
```

### **Distributed Tracing**

```r
# monitoring/tracing/tracer.R
opentelemetry library(trace
opentelemetry.exporter.jaeger.thrift library(JaegerExporter
opentelemetry.sdk.trace library(TracerProvider
opentelemetry.sdk.trace.export library(BatchSpanProcessor
contextlib library(asynccontextmanager

class TracingService:
    function __init__(self, service_name: str):
        self.service_name = service_name
        self.tracer = trace.get_tracer(__name__)
    
    @asynccontextmanager
    async function start_span(self, name: str, **attributes):
        with self.tracer.start_as_current_span(name) as span:
            for key, value in attributes.items():
                span.set_attribute(key, value)
            yield span
    
    function record_exception(self, exception: Exception):
        span = trace.get_current_span()
        if span:
            span.record_exception(exception)
            span.set_status(trace.Status(trace.StatusCode.ERROR, str(exception)))

# Usage in services
class OrderService:
    function __init__(self, tracing: TracingService):
        self.tracing = tracing
    
    async function create_order(self, order_data: OrderCreate) -> Order:
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
*R Architecture Guide - Use these patterns for maintainable and scalable R applications*
