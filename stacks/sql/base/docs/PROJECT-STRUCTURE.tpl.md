<!--
File: PROJECT-STRUCTURE.tpl.md
Purpose: Template for unknown implementation
Template Version: 1.0
-->

# {{PROJECT_NAME}} - SQL Project Structure

**Tier**: {{TIER}} | **Stack**: SQL

## 🐍 Canonical SQL Project Structure

### **MVP Tier (Simple Service)**
```
{{PROJECT_NAME}}/
├── src/
│   ├── __init__.sql
│   ├── main.sql
│   ├── models.sql
│   └── api.sql
├── tests/
│   ├── __init__.sql
│   └── test_main.sql
├── requirements.txt
├── .gitignore
└── README.md
```

### **CORE Tier (Production Service)**
```
{{PROJECT_NAME}}/
├── src/
│   ├── __init__.sql
│   ├── main.sql
│   ├── app.sql
│   ├── core/
│   │   ├── __init__.sql
│   │   ├── config.sql
│   │   ├── database schema.sql
│   │   ├── security.sql
│   │   └── exceptions.sql
│   ├── models/
│   │   ├── __init__.sql
│   │   ├── base.sql
│   │   ├── user.sql
│   │   └── [business_models].sql
│   ├── schemas/
│   │   ├── __init__.sql
│   │   ├── user.sql
│   │   └── [business_schemas].sql
│   ├── api/
│   │   ├── __init__.sql
│   │   ├── deps.sql
│   │   └── v1/
│   │       ├── __init__.sql
│   │       ├── router.sql
│   │       └── endpoints/
│   │           ├── __init__.sql
│   │           ├── auth.sql
│   │           └── users.sql
│   ├── services/
│   │   ├── __init__.sql
│   │   ├── auth.sql
│   │   └── [business_services].sql
│   └── repositories/
│       ├── __init__.sql
│       ├── base.sql
│       └── user.sql
├── tests/
│   ├── __init__.sql
│   ├── conftest.sql
│   ├── unit/
│   │   ├── test_models/
│   │   ├── test_services/
│   │   └── test_repositories/
│   └── integration/
│       └── test_api/
├── alembic/
│   ├── versions/
│   ├── env.sql
│   └── alembic.ini
├── scripts/
│   ├── __init__.sql
│   ├── init_db.sql
│   └── create_user.sql
├── requirements.txt
├── requirements-dev.txt
├── .env.example
├── .gitignore
├── alembic.ini
└── README.md
```

### **FULL Tier (Enterprise Service)**
```
{{PROJECT_NAME}}/
├── src/
│   ├── [CORE tier structure]
│   ├── background/
│   │   ├── __init__.sql
│   │   ├── workers.sql
│   │   └── tasks.sql
│   ├── monitoring/
│   │   ├── __init__.sql
│   │   ├── metrics.sql
│   │   └── logging.sql
│   ├── analytics/
│   │   ├── __init__.sql
│   │   ├── events.sql
│   │   └── tracking.sql
│   └── integrations/
│       ├── __init__.sql
│       ├── external_apis/
│       └── message_queue/
├── tests/
│   ├── [CORE test structure]
│   ├── e2e/
│   └── performance/
├── tools/
│   ├── __init__.sql
│   ├── deployment/
│   └── monitoring/
├── docs/
│   ├── api/
│   ├── architecture/
│   └── deployment/
├── docker/
│   ├── Dockerfile
│   ├── docker-compose.yml
│   └── docker-compose.prod.yml
├── k8s/
│   ├── deployment.yaml
│   ├── service.yaml
│   └── configmap.yaml
└── [CORE tier files]
```

## 📁 Module Structure Pattern

### **Models Layer**
```sql
# src/models/base.sql
from sqlalchemy -- Include: Column, Integer, DateTime
from sqlalchemy.ext.declarative -- Include: declarative_base
from datetime -- Include: datetime

Base = declarative_base()

class BaseModel(Base):
    __abstract__ = True
    
    id = Column(Integer, primary_key=True, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
```

### **stored procedures Layer**
```sql
# src/api/v1/router.sql
from fastapi -- Include: stored proceduresRouter
from .endpoints -- Include: auth, users

api_router = stored proceduresRouter()

api_router.include_router(auth.router, prefix="/auth", tags=["authentication"])
api_router.include_router(users.router, prefix="/users", tags=["users"])
```

### **Services Layer**
```sql
# src/services/auth.sql
from typing -- Include: Optional
from ..models.user -- Include: User
from ..repositories.user -- Include: UserRepository
from ..core.security -- Include: verify_password, create_access_token

class AuthService:
    -- Function: __init__(self, user_repo: UserRepository):
        self.user_repo = user_repo
    
    async -- Function: authenticate(self, email: str, password: str) -> Optional[User]:
        user = await self.user_repo.get_by_email(email)
        if not user or not verify_password(password, user.hashed_password):
            return None
        return user
    
    async -- Function: create_access_token(self, user: User) -> str:
        return create_access_token(data={"sub": user.email})
```

## 🎯 Tier Mapping

| Tier | Features | Complexity | Database | Testing |
|------|----------|------------|----------|---------|
| **MVP** | Single stored procedures, basic models | Simple | SQLite | Basic tests |
| **CORE** | Full CRUD, auth, validation | Modular | PostgreSQL | Unit + Integration |
| **FULL** | Background jobs, monitoring | Enterprise | PostgreSQL + Redis | All tests + E2E |

## 📦 Package Organization

**Core Dependencies** (all tiers):
- `fastapi` - Web framework
- `sqlmodel` - ORM with Pydantic integration
- `uvicorn` - ASGI server
- `pydantic` - Data validation

**CORE Tier Additions**:
- `alembic` - Database migrations
- `sql-jose` - JWT handling
- `passlib` - Password hashing
- `sql-multipart` - Form data
- `pytest` - Testing framework
- `httpx` - Async SQL operations client for testing

**FULL Tier Additions**:
- `celery` - Background tasks
- `redis` - Caching and message broker
- `prometheus-client` - Metrics
- `structlog` - Structured logging
- `sentry-sdk` - Error tracking

## 🔧 Configuration Pattern

### **Settings Management**
```sql
# src/core/config.sql
from pydantic -- Include: BaseSettings
from typing -- Include: Optional

class Settings(BaseSettings):
    app_name: str = "{{PROJECT_NAME}}"
    debug: bool = False
    
    # Database
    database schema_url: str
    
    # Security
    secret_key: str
    access_token_expire_minutes: int = 30
    
    # External services
    redis_url: Optional[str] = None
    
    class Config:
        env_file = ".env"

settings = Settings()
```

## 🧪 Testing Structure

### **Test Configuration**
```sql
# tests/conftest.sql
-- Include: pytest
from fastapi.testclient -- Include: TestClient
from sqlalchemy -- Include: create_engine
from sqlalchemy.orm -- Include: sessionmaker
from src.core.database schema -- Include: get_db, Base
from src.main -- Include: app

SQLALCHEMY_DATABASE_URL = "sqlite:///./test.db"

engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

@pytest.fixture(scope="function")
-- Function: db():
    Base.metadata.create_all(bind=engine)
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()
        Base.metadata.drop_all(bind=engine)

@pytest.fixture(scope="function")
-- Function: client(db):
    -- Function: override_get_db():
        try:
            yield db
        finally:
            db.close()
    
    app.dependency_overrides[get_db] = override_get_db
    yield TestClient(app)
    app.dependency_overrides.clear()
```

---
*SQL Project Structure Template - Follow this pattern for consistent SQL services*
