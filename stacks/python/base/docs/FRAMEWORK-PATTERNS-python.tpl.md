<!--
File: FRAMEWORK-PATTERNS-python.tpl.md
Purpose: Template for unknown implementation
Template Version: 1.0
-->

# Python Framework Patterns - {{PROJECT_NAME}}

**Tier**: {{TIER}} | **Stack**: Python

## 🐍 Python's Role in Your Ecosystem

Python serves as the **backend API layer** - your "ship robust APIs and data processing fast" weapon. It handles REST APIs, data processing, background jobs, and enterprise backend services.

### **Core Responsibilities**
- **REST APIs**: FastAPI-based high-performance APIs
- **Data Processing**: ETL pipelines, analytics, ML workflows
- **Background Jobs**: Async task processing with Celery
- **Database Management**: SQLModel with PostgreSQL
- **Enterprise Integration**: Message queues, external APIs

## 🏗️ Three Pillars Integration

### **1. Universal Principles Applied to Python**
- **Clean Architecture**: Service layer with repository pattern
- **Dependency Injection**: FastAPI's built-in DI system
- **Testing Pyramid**: Unit, Integration, E2E tests
- **Configuration Management**: Pydantic settings with environment variables

### **2. Tier-Specific Python Patterns**

#### **MVP Tier - Prototyping Mode**
**Purpose**: Validate API ideas quickly with minimal complexity
**Characteristics**:
- Single file application structure
- Simple FastAPI routes with Pydantic models
- SQLite database with direct SQLModel usage
- Basic authentication with JWT
- Minimal testing (unit tests only)

**When to Use**:
- API proof of concepts
- Microservice prototypes
- Internal tools and scripts
- Learning new domains

**MVP Python Pattern**:
```python
# main.py - Single file MVP
from fastapi import FastAPI, Depends
from sqlmodel import SQLModel, Session, create_engine
from pydantic import BaseModel

app = FastAPI()

class User(BaseModel):
    id: int
    email: str
    name: str

# Simple in-memory storage
users = []

@app.get("/users")
async def get_users():
    return users

@app.post("/users")
async def create_user(user: User):
    users.append(user)
    return user
```

#### **CORE Tier - Production Baseline**
**Purpose**: Real-world APIs with proper architecture
**Characteristics**:
- Modular service architecture
- Repository pattern with dependency injection
- PostgreSQL with proper migrations
- Advanced authentication and authorization
- Comprehensive testing (unit + integration)

**When to Use**:
- Production APIs
- SaaS backend services
- Enterprise internal APIs
- Consumer-facing backends

**CORE Python Pattern**:
```python
# services/auth_service.py
from typing import Optional
from ..repositories.user_repository import UserRepository
from ..models.user import User
from ..core.security import verify_password, create_access_token

class AuthService:
    def __init__(self, user_repo: UserRepository):
        self.user_repo = user_repo
    
    async def authenticate(self, email: str, password: str) -> Optional[User]:
        user = await self.user_repo.get_by_email(email)
        if not user or not verify_password(password, user.hashed_password):
            return None
        return user
    
    async def create_access_token(self, user: User) -> str:
        return create_access_token(data={"sub": user.email})

# api/v1/endpoints/auth.py
from fastapi import APIRouter, Depends, HTTPException
from ..services.auth_service import AuthService
from ..schemas.auth import LoginRequest, TokenResponse

router = APIRouter()

@router.post("/login", response_model=TokenResponse)
async def login(
    login_data: LoginRequest,
    auth_service: AuthService = Depends(get_auth_service)
):
    user = await auth_service.authenticate(login_data.email, login_data.password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    token = await auth_service.create_access_token(user)
    return TokenResponse(access_token=token, token_type="bearer")
```

#### **FULL Tier - Enterprise Excellence**
**Purpose**: Large-scale APIs with enterprise requirements
**Characteristics**:
- Microservices architecture
- Advanced async patterns with background jobs
- Enterprise security and compliance
- Complete observability (metrics, tracing, logging)
- Advanced testing (performance, contract, chaos)

**When to Use**:
- Fortune 500 backend services
- Multi-team enterprise projects
- High-traffic APIs
- Compliance-heavy applications

**FULL Python Pattern**:
```python
# services/enterprise_order_service.py
from typing import List
from ..repositories.order_repository import OrderRepository
from ..models.order import Order
from ..integrations.payment_gateway import PaymentGateway
from ..integrations.notification_service import NotificationService
from ..monitoring.metrics import MetricsService
from ..monitoring.tracing import TracingService

class EnterpriseOrderService:
    def __init__(
        self,
        order_repo: OrderRepository,
        payment_gateway: PaymentGateway,
        notification_service: NotificationService,
        metrics: MetricsService,
        tracing: TracingService
    ):
        self.order_repo = order_repo
        self.payment_gateway = payment_gateway
        self.notification_service = notification_service
        self.metrics = metrics
        self.tracing = tracing
    
    async def create_order(self, order_data: CreateOrderRequest) -> Order:
        with self.tracing.start_span("create_order") as span:
            span.set_tag("user_id", order_data.user_id)
            
            try:
                # Business logic with audit trail
                order = await self._process_order(order_data)
                
                # Metrics and analytics
                self.metrics.increment_counter("orders_created", {"status": "success"})
                
                # Async notification
                await self.notification_service.send_order_confirmation(order)
                
                return order
                
            except Exception as e:
                self.metrics.increment_counter("orders_created", {"status": "error"})
                self.tracing.record_exception(e)
                raise
    
    async def _process_order(self, order_data: CreateOrderRequest) -> Order:
        # Complex business logic with enterprise rules
        pass
```

## 📦 Blessed Patterns (Never Deviate)

### **Web Framework: FastAPI**
**Why FastAPI**:
- Native async support
- Automatic OpenAPI documentation
- Pydantic integration for validation
- Excellent performance
- Built-in dependency injection

**FastAPI Patterns**:
```python
# MVP: Simple routes
@app.get("/users")
async def get_users():
    return users

# CORE: Dependency injection
@app.get("/users/{user_id}")
async def get_user(
    user_id: int,
    current_user: User = Depends(get_current_user),
    user_service: UserService = Depends(get_user_service)
):
    return await user_service.get_user(user_id)

# FULL: Advanced middleware and monitoring
@app.middleware("http")
async def monitoring_middleware(request: Request, call_next):
    start_time = time.time()
    response = await call_next(request)
    process_time = time.time() - start_time
    metrics.record_http_request(request.method, request.url.path, response.status_code, process_time)
    return response
```

### **ORM: SQLModel**
**Why SQLModel**:
- Pydantic integration for validation
- SQLAlchemy power underneath
- Type safety with IDE support
- Excellent migration support with Alembic

**SQLModel Patterns**:
```python
# MVP: Simple models
class User(SQLModel, table=True):
    id: int = Field(default=None, primary_key=True)
    email: str
    name: str

# CORE: Advanced models with relationships
class User(SQLModel, table=True):
    id: int = Field(default=None, primary_key=True)
    email: str = Field(index=True, unique=True)
    name: str
    created_at: datetime = Field(default_factory=datetime.utcnow)
    
    orders: List["Order"] = Relationship(back_populates="user")

# FULL: Enterprise models with audit trail
class User(SQLModel, table=True):
    id: int = Field(default=None, primary_key=True)
    email: str = Field(index=True, unique=True)
    name: str
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    created_by: Optional[str] = None
    updated_by: Optional[str] = None
    is_active: bool = True
    
    # Soft delete
    deleted_at: Optional[datetime] = None
```

### **Authentication: JWT + OAuth2**
**Why JWT + OAuth2**:
- Industry standard
- Stateless authentication
- Easy integration with frontend
- Supports refresh tokens

**Authentication Patterns**:
```python
# MVP: Simple JWT
def create_access_token(data: dict):
    return jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM)

# CORE: OAuth2 with password flow
class OAuth2PasswordBearerWithCookie(OAuth2):
    async def __call__(self, request: Request) -> Optional[str]:
        token = request.cookies.get("access_token")
        return token

# FULL: Advanced auth with roles and permissions
class RoleBasedAccess:
    def __init__(self, required_permissions: List[str]):
        self.required_permissions = required_permissions
    
    async def __call__(self, current_user: User = Depends(get_current_user)):
        if not self._has_permissions(current_user, self.required_permissions):
            raise HTTPException(status_code=403, detail="Insufficient permissions")
```

## 🗄️ Database Integration

### **Database Strategy**
```python
# MVP: SQLite for development
DATABASE_URL = "sqlite:///./test.db"

# CORE: PostgreSQL for production
DATABASE_URL = "postgresql://user:password@localhost/dbname"

# FULL: PostgreSQL with connection pooling and read replicas
DATABASE_URL = "postgresql://user:password@localhost/dbname"
DATABASE_READ_URL = "postgresql://user:password@replica/dbname"
```

### **Migration Strategy**
```python
# alembic/versions/001_initial_migration.py
def upgrade():
    # Create tables with proper constraints
    op.create_table('users',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('email', sa.String(), nullable=False),
        sa.Column('name', sa.String(), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('email')
    )

def downgrade():
    op.drop_table('users')
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
```python
# services/external_api_service.py
import httpx
from typing import Dict, Any

class ExternalAPIService:
    def __init__(self, base_url: str, api_key: str):
        self.base_url = base_url
        self.api_key = api_key
        self.client = httpx.AsyncClient()
    
    async def get_data(self, endpoint: str) -> Dict[str, Any]:
        response = await self.client.get(
            f"{self.base_url}{endpoint}",
            headers={"Authorization": f"Bearer {self.api_key}"}
        )
        response.raise_for_status()
        return response.json()
```

### **Message Queue Integration**
```python
# services/message_queue_service.py
from celery import Celery

celery_app = Celery("{{PROJECT_NAME}}")

@celery_app.task
def process_order_async(order_id: int):
    # Background order processing
    pass
```

## 📊 Monitoring and Observability

### **MVP**: Basic logging
### **CORE**: Structured logging + metrics
```python
import structlog

logger = structlog.get_logger()

@app.post("/orders")
async def create_order(order: CreateOrderRequest):
    logger.info("Creating order", order_id=order.id, user_id=order.user_id)
    # Process order
    logger.info("Order created successfully", order_id=order.id)
```

### **FULL**: Complete observability
- Structured logging with correlation IDs
- Prometheus metrics
- OpenTelemetry tracing
- Error tracking with Sentry

## 🚀 Performance Patterns

### **Async/Await Best Practices**
```python
# Use async for I/O operations
async def get_user_data(user_id: int):
    user = await user_repo.get(user_id)  # Database call
    orders = await order_repo.get_by_user(user_id)  # Database call
    return {"user": user, "orders": orders}

# Use async context managers for resources
async def process_file(file_path: str):
    async with aiofiles.open(file_path, 'r') as file:
        content = await file.read()
        return process_content(content)
```

### **Database Optimization**
```python
# Use database sessions efficiently
async def get_db():
    async with SessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()

# Use bulk operations for performance
async def create_users_bulk(users_data: List[CreateUserRequest]):
    users = [User(**user.dict()) for user in users_data]
    session.bulk_save_objects(users)
    await session.commit()
```

## 🔒 Security Best Practices

### **Input Validation**
```python
from pydantic import BaseModel, validator

class CreateUserRequest(BaseModel):
    email: str
    password: str
    
    @validator('email')
    def validate_email(cls, v):
        if not re.match(r"[^@]+@[^@]+\.[^@]+", v):
            raise ValueError('Invalid email format')
        return v
    
    @validator('password')
    def validate_password(cls, v):
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters')
        return v
```

### **SQL Injection Prevention**
```python
# Always use parameterized queries
async def get_user_by_email(email: str):
    query = "SELECT * FROM users WHERE email = :email"
    result = await session.execute(text(query), {"email": email})
    return result.scalar_one_or_none()
```

---
*Python Framework Patterns - Use this as your canonical reference for all Python backend development*
