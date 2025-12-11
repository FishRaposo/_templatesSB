# Universal Template System - Python Stack
# Generated: 2025-12-10
# Purpose: python template utilities
# Tier: base
# Stack: python
# Category: template

# Python Architecture Guide - {{PROJECT_NAME}}

**Tier**: {{TIER}} | **Stack**: Python

## 🏗️ Python Architecture Overview

Python applications follow **Clean Architecture** principles with **service-oriented modularization**. This ensures maintainability, testability, and scalability across MVP, CORE, and FULL tiers.

## 📊 Tier-Based Architecture Patterns

### **MVP Tier - Simple Monolithic Architecture**

```
{{PROJECT_NAME}}/
├── main.py                     # FastAPI app entry point
├── models.py                   # SQLModel definitions
├── api.py                      # Route definitions
├── services.py                 # Business logic
├── database.py                 # Database setup
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
├── main.py                     # FastAPI app entry point
├── app.py                      # App configuration
├── core/                       # Core infrastructure
│   ├── config/                 # Configuration management
│   │   ├── __init__.py
│   │   └── settings.py         # Pydantic settings
│   ├── database/               # Database setup
│   │   ├── __init__.py
│   │   ├── database.py         # Session management
│   │   └── migrations/         # Alembic migrations
│   ├── security/               # Security utilities
│   │   ├── __init__.py
│   │   ├── jwt.py              # JWT handling
│   │   ├── password.py         # Password hashing
│   │   └── permissions.py      # Role-based access
│   ├── errors/                 # Custom exceptions
│   │   ├── __init__.py
│   │   └── exceptions.py       # Business exceptions
│   └── utils/                  # Shared utilities
│       ├── __init__.py
│       ├── logger.py           # Logging setup
│       └── helpers.py          # Helper functions
├── models/                     # Data models
│   ├── __init__.py
│   ├── base.py                 # Base model class
│   ├── user.py                 # User model
│   └── [business_models].py    # Domain models
├── schemas/                    # Pydantic schemas
│   ├── __init__.py
│   ├── user.py                 # User schemas
│   └── [business_schemas].py   # API schemas
├── api/                        # API layer
│   ├── __init__.py
│   ├── deps.py                 # FastAPI dependencies
│   └── v1/                     # API version 1
│       ├── __init__.py
│       ├── router.py           # Main router
│       └── endpoints/          # API endpoints
│           ├── __init__.py
│           ├── auth.py         # Authentication endpoints
│           ├── users.py        # User endpoints
│           └── [business].py   # Business endpoints
├── services/                   # Business logic layer
│   ├── __init__.py
│   ├── auth.py                 # Authentication service
│   ├── user.py                 # User service
│   └── [business_services].py  # Business services
├── repositories/               # Data access layer
│   ├── __init__.py
│   ├── base.py                 # Base repository
│   ├── user.py                 # User repository
│   └── [business_repos].py     # Business repositories
├── tests/                      # Test suite
│   ├── __init__.py
│   ├── conftest.py             # Test configuration
│   ├── unit/                   # Unit tests
│   ├── integration/            # Integration tests
│   └── e2e/                    # End-to-end tests
├── alembic/                    # Database migrations
│   ├── versions/               # Migration files
│   ├── env.py                  # Alembic environment
│   └── alembic.ini             # Alembic configuration
├── scripts/                    # Utility scripts
│   ├── __init__.py
│   ├── init_db.py              # Database initialization
│   └── create_user.py          # User creation script
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
│   ├── __init__.py
│   ├── workers/                # Celery workers
│   │   ├── __init__.py
│   │   ├── order_worker.py     # Order processing
│   │   └── notification_worker.py # Notification processing
│   ├── tasks/                  # Celery tasks
│   │   ├── __init__.py
│   │   ├── email_tasks.py      # Email tasks
│   │   └── analytics_tasks.py  # Analytics tasks
│   └── scheduler.py            # Task scheduling
├── monitoring/                 # Monitoring and observability
│   ├── __init__.py
│   ├── metrics/                # Prometheus metrics
│   │   ├── __init__.py
│   │   └── business_metrics.py # Business metrics
│   ├── health/                 # Health checks
│   │   ├── __init__.py
│   │   └── health_check.py     # Health endpoints
│   └── tracing/                # OpenTelemetry tracing
│       ├── __init__.py
│       └── tracer.py           # Tracing setup
├── analytics/                  # Analytics and events
│   ├── __init__.py
│   ├── events/                 # Event definitions
│   │   ├── __init__.py
│   │   ├── user_events.py      # User events
│   │   └── business_events.py  # Business events
│   ├── tracking/               # Event tracking
│   │   ├── __init__.py
│   │   └── event_tracker.py    # Event tracking service
│   └── reporting/              # Analytics reporting
│       ├── __init__.py
│       └── reports.py          # Report generation
├── integrations/               # External integrations
│   ├── __init__.py
│   ├── external_apis/          # External API clients
│   │   ├── __init__.py
│   │   ├── payment_gateway.py  # Payment integration
│   │   └── shipping_api.py     # Shipping integration
│   ├── message_queue/          # Message queue clients
│   │   ├── __init__.py
│   │   ├── redis_client.py     # Redis client
│   │   └── rabbitmq_client.py  # RabbitMQ client
│   └── storage/                # Storage clients
│       ├── __init__.py
│       ├── s3_client.py        # S3 client
│       └── cdn_client.py       # CDN client
├── enterprise/                 # Enterprise features
│   ├── __init__.py
│   ├── audit/                  # Audit logging
│   │   ├── __init__.py
│   │   └── audit_logger.py     # Audit service
│   ├── compliance/             # Compliance features
│   │   ├── __init__.py
│   │   └── gdpr_compliance.py  # GDPR compliance
│   └── security/               # Advanced security
│       ├── __init__.py
│       ├── rate_limiting.py    # Rate limiting
│       └── threat_detection.py # Threat detection
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
```python
# api.py - Simple API endpoints
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

app = FastAPI()

class User(BaseModel):
    id: int
    email: str
    name: str

@app.get("/users/{user_id}")
async def get_user(user_id: int):
    # Direct database access
    user = get_user_from_db(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user

@app.post("/users")
async def create_user(user: User):
    # Direct database access
    return create_user_in_db(user)
```

#### **CORE Implementation**:
```python
# api/v1/endpoints/users.py
from fastapi import APIRouter, Depends, HTTPException
from typing import List
from ..deps import get_user_service, get_current_user
from ...schemas.user import UserCreate, UserResponse, UserUpdate
from ...models.user import User

router = APIRouter()

@router.get("/", response_model=List[UserResponse])
async def get_users(
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
async def create_user(
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
```python
# api/v1/endpoints/orders.py
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from typing import List
from ..deps import get_order_service, get_current_user, get_metrics_service
from ...schemas.order import OrderCreate, OrderResponse
from ...models.user import User
from ...monitoring.metrics import MetricsService
from ...analytics.events import OrderCreatedEvent

router = APIRouter()

@router.post("/", response_model=OrderResponse)
async def create_order(
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
```python
# services.py - Simple business logic
class UserService:
    def create_user(self, user_data):
        # Simple validation
        if not user_data.email or "@" not in user_data.email:
            raise ValueError("Invalid email")
        
        # Direct database access
        return save_user_to_db(user_data)
    
    def get_user(self, user_id):
        return get_user_from_db(user_id)
```

#### **CORE Implementation**:
```python
# services/user_service.py
from typing import List, Optional
from ..repositories.user_repository import UserRepository
from ..models.user import User
from ..schemas.user import UserCreate, UserUpdate
from ..core.security import get_password_hash
from ..core.exceptions import UserAlreadyExistsException

class UserService:
    def __init__(self, user_repository: UserRepository):
        self.user_repository = user_repository
    
    async def create_user(self, user_data: UserCreate) -> User:
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
    
    async def get_user(self, user_id: int) -> Optional[User]:
        return await self.user_repository.get_by_id(user_id)
    
    async def update_user(self, user_id: int, user_data: UserUpdate) -> User:
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
```python
# services/enterprise_order_service.py
from typing import List, Optional
from ..repositories.order_repository import OrderRepository
from ..repositories.user_repository import UserRepository
from ..repositories.inventory_repository import InventoryRepository
from ..models.order import Order
from ..schemas.order import OrderCreate
from ..integrations.payment_gateway import PaymentGateway
from ..integrations.notification_service import NotificationService
from ..monitoring.metrics import MetricsService
from ..monitoring.tracing import TracingService
from ..analytics.events import OrderCreatedEvent, PaymentProcessedEvent
from ..enterprise.audit.audit_logger import AuditLogger
from ..core.exceptions import BusinessRuleException, InventoryException

class EnterpriseOrderService:
    def __init__(
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
    
    async def create_order(self, user_id: str, order_data: OrderCreate) -> Order:
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
    
    async def _check_inventory_availability(self, items: List[OrderItem]):
        for item in items:
            inventory = await self.inventory_repo.get_by_product_id(item.product_id)
            if not inventory or inventory.available_quantity < item.quantity:
                raise InventoryException(f"Insufficient inventory for product {item.product_id}")
    
    async def _calculate_total_amount(self, user_id: str, items: List[OrderItem]) -> Decimal:
        # Complex pricing logic with discounts, taxes, etc.
        base_total = sum(item.price * item.quantity for item in items)
        
        # Apply user-specific discounts
        user = await self.user_repo.get_by_id(user_id)
        if user and user.is_premium:
            base_total *= Decimal('0.9')  # 10% discount for premium users
        
        # Apply taxes
        base_total *= Decimal('1.08')  # 8% tax
        
        return base_total.quantize(Decimal('0.01'))
    
    async def _process_payment(self, order: Order) -> PaymentResult:
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
```python
# database.py - Simple data access
from sqlalchemy import create_engine
from sqlmodel import Session

engine = create_engine("sqlite:///./test.db")

def get_user_from_db(user_id):
    with Session(engine) as session:
        return session.get(User, user_id)

def save_user_to_db(user_data):
    with Session(engine) as session:
        user = User(**user_data.dict())
        session.add(user)
        session.commit()
        session.refresh(user)
        return user
```

#### **CORE Implementation**:
```python
# repositories/user_repository.py
from typing import Optional, List
from sqlalchemy.orm import Session
from sqlalchemy import select
from ..models.user import User
from ..core.database import get_db
from .base import BaseRepository

class UserRepository(BaseRepository[User]):
    def __init__(self, db: Session):
        super().__init__(db, User)
    
    async def get_by_email(self, email: str) -> Optional[User]:
        statement = select(User).where(User.email == email)
        result = await self.db.execute(statement)
        return result.scalar_one_or_none()
    
    async def get_active_users(self, skip: int = 0, limit: int = 100) -> List[User]:
        statement = (
            select(User)
            .where(User.is_active == True)
            .offset(skip)
            .limit(limit)
        )
        result = await self.db.execute(statement)
        return result.scalars().all()
    
    async def create(self, user: User) -> User:
        self.db.add(user)
        await self.db.commit()
        await self.db.refresh(user)
        return user
    
    async def update(self, user_id: int, update_data: dict) -> User:
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
```python
# repositories/enterprise_order_repository.py
from typing import Optional, List
from sqlalchemy.orm import Session
from sqlalchemy import select, func, and_
from ..models.order import Order
from ..core.database import get_db
from .base import BaseRepository

class EnterpriseOrderRepository(BaseRepository[Order]):
    def __init__(self, db: Session):
        super().__init__(db, Order)
    
    async def get_by_user_with_items(self, user_id: str, skip: int = 0, limit: int = 100) -> List[Order]:
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
    
    async def get_orders_by_status_and_date_range(
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
    
    async def get_order_analytics(self, start_date: datetime, end_date: datetime) -> dict:
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
    
    async def create_with_audit(self, order: Order, created_by: str) -> Order:
        # Add audit information
        order.created_by = created_by
        order.updated_by = created_by
        
        self.db.add(order)
        await self.db.commit()
        await self.db.refresh(order)
        
        # Log creation for audit
        await self._log_order_creation(order, created_by)
        
        return order
    
    async def _log_order_creation(self, order: Order, created_by: str):
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

```python
# core/events/event_bus.py
from typing import Dict, List, Callable
from abc import ABC, abstractmethod

class Event(ABC):
    pass

class EventBus:
    def __init__(self):
        self._handlers: Dict[str, List[Callable]] = {}
    
    def subscribe(self, event_type: str, handler: Callable):
        if event_type not in self._handlers:
            self._handlers[event_type] = []
        self._handlers[event_type].append(handler)
    
    async def publish(self, event: Event):
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
    def __init__(self, event_bus: EventBus):
        self.event_bus = event_bus
    
    async def create_order(self, order_data: OrderCreate) -> Order:
        order = await self.order_repo.create(order_data)
        
        # Publish event
        event = OrderCreatedEvent(order_id=order.id, user_id=order.user_id)
        await self.event_bus.publish(event)
        
        return order
```

### **Message Queue Integration**

```python
# integrations/message_queue/redis_client.py
import redis.asyncio as redis
import json
from typing import Dict, Any

class RedisMessageQueue:
    def __init__(self, redis_url: str):
        self.redis = redis.from_url(redis_url)
    
    async def publish(self, channel: str, message: Dict[str, Any]):
        await self.redis.publish(channel, json.dumps(message))
    
    async def subscribe(self, channel: str):
        pubsub = self.redis.pubsub()
        await pubsub.subscribe(channel)
        
        async for message in pubsub.listen():
            if message['type'] == 'message':
                yield json.loads(message['data'])

# Background task processing
class OrderProcessor:
    def __init__(self, message_queue: RedisMessageQueue):
        self.message_queue = message_queue
    
    async def start_processing(self):
        async for message in self.message_queue.subscribe("order_events"):
            await self.process_order_event(message)
    
    async def process_order_event(self, event: Dict[str, Any]):
        if event['type'] == 'order_created':
            await self.handle_order_created(event)
```

## 🔒 Security Architecture

### **Authentication and Authorization**

```python
# core/security/auth.py
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt
from ..models.user import User
from ..repositories.user_repository import UserRepository

security = HTTPBearer()

class AuthenticationService:
    def __init__(self, user_repository: UserRepository):
        self.user_repository = user_repository
    
    async def authenticate(self, credentials: HTTPAuthorizationCredentials = Depends(security)) -> User:
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
    def __init__(self, required_roles: List[str]):
        self.required_roles = required_roles
    
    def __call__(self, current_user: User = Depends(get_current_user)):
        if not any(role in current_user.roles for role in self.required_roles):
            raise HTTPException(status_code=403, detail="Insufficient permissions")
        return current_user

# Usage in endpoints
@router.get("/admin/users")
async def get_admin_users(
    current_user: User = Depends(RoleChecker(["admin"]))
):
    # Admin-only logic
    pass
```

## 📊 Monitoring and Observability

### **Metrics Collection**

```python
# monitoring/metrics/business_metrics.py
from prometheus_client import Counter, Histogram, Gauge
from typing import Dict, Any

class BusinessMetrics:
    def __init__(self):
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
    
    def record_order_created(self, status: str, user_type: str):
        self.orders_created.labels(status=status, user_type=user_type).inc()
    
    def record_order_processing_time(self, duration: float, payment_method: str):
        self.order_processing_time.labels(payment_method=payment_method).observe(duration)
    
    def update_active_users(self, count: int):
        self.active_users.set(count)
```

### **Distributed Tracing**

```python
# monitoring/tracing/tracer.py
from opentelemetry import trace
from opentelemetry.exporter.jaeger.thrift import JaegerExporter
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from contextlib import asynccontextmanager

class TracingService:
    def __init__(self, service_name: str):
        self.service_name = service_name
        self.tracer = trace.get_tracer(__name__)
    
    @asynccontextmanager
    async def start_span(self, name: str, **attributes):
        with self.tracer.start_as_current_span(name) as span:
            for key, value in attributes.items():
                span.set_attribute(key, value)
            yield span
    
    def record_exception(self, exception: Exception):
        span = trace.get_current_span()
        if span:
            span.record_exception(exception)
            span.set_status(trace.Status(trace.StatusCode.ERROR, str(exception)))

# Usage in services
class OrderService:
    def __init__(self, tracing: TracingService):
        self.tracing = tracing
    
    async def create_order(self, order_data: OrderCreate) -> Order:
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
*Python Architecture Guide - Use these patterns for maintainable and scalable Python applications*
