<!--
File: PROJECT-STRUCTURE.tpl.md
Purpose: Template for unknown implementation
Template Version: 1.0
-->

# {{PROJECT_NAME}} - Python Project Structure

**Tier**: {{TIER}} | **Stack**: Python

## 🐍 Canonical Python Project Structure

### **MVP Tier (Simple Service)**
```
{{PROJECT_NAME}}/
├── src/
│   ├── __init__.py
│   ├── main.py
│   ├── models.py
│   └── api.py
├── tests/
│   ├── __init__.py
│   └── test_main.py
├── requirements.txt
├── .gitignore
└── README.md
```

### **CORE Tier (Production Service)**
```
{{PROJECT_NAME}}/
├── src/
│   ├── __init__.py
│   ├── main.py
│   ├── app.py
│   ├── core/
│   │   ├── __init__.py
│   │   ├── config.py
│   │   ├── database.py
│   │   ├── security.py
│   │   └── exceptions.py
│   ├── models/
│   │   ├── __init__.py
│   │   ├── base.py
│   │   ├── user.py
│   │   └── [business_models].py
│   ├── schemas/
│   │   ├── __init__.py
│   │   ├── user.py
│   │   └── [business_schemas].py
│   ├── api/
│   │   ├── __init__.py
│   │   ├── deps.py
│   │   └── v1/
│   │       ├── __init__.py
│   │       ├── router.py
│   │       └── endpoints/
│   │           ├── __init__.py
│   │           ├── auth.py
│   │           └── users.py
│   ├── services/
│   │   ├── __init__.py
│   │   ├── auth.py
│   │   └── [business_services].py
│   └── repositories/
│       ├── __init__.py
│       ├── base.py
│       └── user.py
├── tests/
│   ├── __init__.py
│   ├── conftest.py
│   ├── unit/
│   │   ├── test_models/
│   │   ├── test_services/
│   │   └── test_repositories/
│   └── integration/
│       └── test_api/
├── alembic/
│   ├── versions/
│   ├── env.py
│   └── alembic.ini
├── scripts/
│   ├── __init__.py
│   ├── init_db.py
│   └── create_user.py
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
│   │   ├── __init__.py
│   │   ├── workers.py
│   │   └── tasks.py
│   ├── monitoring/
│   │   ├── __init__.py
│   │   ├── metrics.py
│   │   └── logging.py
│   ├── analytics/
│   │   ├── __init__.py
│   │   ├── events.py
│   │   └── tracking.py
│   └── integrations/
│       ├── __init__.py
│       ├── external_apis/
│       └── message_queue/
├── tests/
│   ├── [CORE test structure]
│   ├── e2e/
│   └── performance/
├── tools/
│   ├── __init__.py
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
```python
# src/models/base.py
from sqlalchemy import Column, Integer, DateTime
from sqlalchemy.ext.declarative import declarative_base
from datetime import datetime

Base = declarative_base()

class BaseModel(Base):
    __abstract__ = True
    
    id = Column(Integer, primary_key=True, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
```

### **API Layer**
```python
# src/api/v1/router.py
from fastapi import APIRouter
from .endpoints import auth, users

api_router = APIRouter()

api_router.include_router(auth.router, prefix="/auth", tags=["authentication"])
api_router.include_router(users.router, prefix="/users", tags=["users"])
```

### **Services Layer**
```python
# src/services/auth.py
from typing import Optional
from ..models.user import User
from ..repositories.user import UserRepository
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
```

## 🎯 Tier Mapping

| Tier | Features | Complexity | Database | Testing |
|------|----------|------------|----------|---------|
| **MVP** | Single API, basic models | Simple | SQLite | Basic tests |
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
- `python-jose` - JWT handling
- `passlib` - Password hashing
- `python-multipart` - Form data
- `pytest` - Testing framework
- `httpx` - Async HTTP client for testing

**FULL Tier Additions**:
- `celery` - Background tasks
- `redis` - Caching and message broker
- `prometheus-client` - Metrics
- `structlog` - Structured logging
- `sentry-sdk` - Error tracking

## 🔧 Configuration Pattern

### **Settings Management**
```python
# src/core/config.py
from pydantic import BaseSettings
from typing import Optional

class Settings(BaseSettings):
    app_name: str = "{{PROJECT_NAME}}"
    debug: bool = False
    
    # Database
    database_url: str
    
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
```python
# tests/conftest.py
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from src.core.database import get_db, Base
from src.main import app

SQLALCHEMY_DATABASE_URL = "sqlite:///./test.db"

engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

@pytest.fixture(scope="function")
def db():
    Base.metadata.create_all(bind=engine)
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()
        Base.metadata.drop_all(bind=engine)

@pytest.fixture(scope="function")
def client(db):
    def override_get_db():
        try:
            yield db
        finally:
            db.close()
    
    app.dependency_overrides[get_db] = override_get_db
    yield TestClient(app)
    app.dependency_overrides.clear()
```

---
*Python Project Structure Template - Follow this pattern for consistent Python services*
