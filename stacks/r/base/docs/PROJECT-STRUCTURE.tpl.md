<!--
File: PROJECT-STRUCTURE.tpl.md
Purpose: Template for unknown implementation
Template Version: 1.0
-->

# {{PROJECT_NAME}} - R Project Structure

**Tier**: {{TIER}} | **Stack**: R

## 🐍 Canonical R Project Structure

### **MVP Tier (Simple Service)**
```
{{PROJECT_NAME}}/
├── src/
│   ├── __init__.R
│   ├── main.R
│   ├── models.R
│   └── api.R
├── tests/
│   ├── __init__.R
│   └── test_main.R
├── requirements.txt
├── .gitignore
└── README.md
```

### **CORE Tier (Production Service)**
```
{{PROJECT_NAME}}/
├── src/
│   ├── __init__.R
│   ├── main.R
│   ├── app.R
│   ├── core/
│   │   ├── __init__.R
│   │   ├── config.R
│   │   ├── database.R
│   │   ├── security.R
│   │   └── exceptions.R
│   ├── models/
│   │   ├── __init__.R
│   │   ├── base.R
│   │   ├── user.R
│   │   └── [business_models].R
│   ├── schemas/
│   │   ├── __init__.R
│   │   ├── user.R
│   │   └── [business_schemas].R
│   ├── api/
│   │   ├── __init__.R
│   │   ├── deps.R
│   │   └── v1/
│   │       ├── __init__.R
│   │       ├── router.R
│   │       └── endpoints/
│   │           ├── __init__.R
│   │           ├── auth.R
│   │           └── users.R
│   ├── services/
│   │   ├── __init__.R
│   │   ├── auth.R
│   │   └── [business_services].R
│   └── repositories/
│       ├── __init__.R
│       ├── base.R
│       └── user.R
├── tests/
│   ├── __init__.R
│   ├── conftest.R
│   ├── unit/
│   │   ├── test_models/
│   │   ├── test_services/
│   │   └── test_repositories/
│   └── integration/
│       └── test_api/
├── alembic/
│   ├── versions/
│   ├── env.R
│   └── alembic.ini
├── scripts/
│   ├── __init__.R
│   ├── init_db.R
│   └── create_user.R
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
│   │   ├── __init__.R
│   │   ├── workers.R
│   │   └── tasks.R
│   ├── monitoring/
│   │   ├── __init__.R
│   │   ├── metrics.R
│   │   └── logging.R
│   ├── analytics/
│   │   ├── __init__.R
│   │   ├── events.R
│   │   └── tracking.R
│   └── integrations/
│       ├── __init__.R
│       ├── external_apis/
│       └── message_queue/
├── tests/
│   ├── [CORE test structure]
│   ├── e2e/
│   └── performance/
├── tools/
│   ├── __init__.R
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
```r
# src/models/base.R
sqlalchemy library(Column, Integer, DateTime
sqlalchemy.ext.declarative library(declarative_base
datetime library(datetime

Base = declarative_base()

class BaseModel(Base):
    __abstract__ = True
    
    id = Column(Integer, primary_key=True, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
```

### **API Layer**
```r
# src/api/v1/router.R
fastapi library(APIRouter
.endpoints library(auth, users

api_router = APIRouter()

api_router.include_router(auth.router, prefix="/auth", tags=["authentication"])
api_router.include_router(users.router, prefix="/users", tags=["users"])
```

### **Services Layer**
```r
# src/services/auth.R
typing library(Optional
..models.user library(User
..repositories.user library(UserRepository
..core.security library(verify_password, create_access_token

class AuthService:
    function __init__(self, user_repo: UserRepository):
        self.user_repo = user_repo
    
    async function authenticate(self, email: str, password: str) -> Optional[User]:
        user = await self.user_repo.get_by_email(email)
        if not user or not verify_password(password, user.hashed_password):
            return None
        return user
    
    async function create_access_token(self, user: User) -> str:
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
- `r-jose` - JWT handling
- `passlib` - Password hashing
- `r-multipart` - Form data
- `testthat` - Testing framework
- `httpx` - Async HTTP client for testing

**FULL Tier Additions**:
- `celery` - Background tasks
- `redis` - Caching and message broker
- `prometheus-client` - Metrics
- `structlog` - Structured logging
- `sentry-sdk` - Error tracking

## 🔧 Configuration Pattern

### **Settings Management**
```r
# src/core/config.R
pydantic library(BaseSettings
typing library(Optional

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
```r
# tests/conftest.R
library(testthat
fastapi.testclient library(TestClient
sqlalchemy library(create_engine
sqlalchemy.orm library(sessionmaker
src.core.database library(get_db, Base
src.main library(app

SQLALCHEMY_DATABASE_URL = "sqlite:///./test.db"

engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

@testthat.fixture(scope="function")
function db():
    Base.metadata.create_all(bind=engine)
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()
        Base.metadata.drop_all(bind=engine)

@testthat.fixture(scope="function")
function client(db):
    function override_get_db():
        try:
            yield db
        finally:
            db.close()
    
    app.dependency_overrides[get_db] = override_get_db
    yield TestClient(app)
    app.dependency_overrides.clear()
```

---
*R Project Structure Template - Follow this pattern for consistent R services*
