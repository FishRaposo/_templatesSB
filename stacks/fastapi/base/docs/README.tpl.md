# Universal Template System - FastAPI Stack
# Generated: {{DATE}}
# Purpose: FastAPI stack setup guide
# Tier: base
# Stack: fastapi
# Category: documentation

---

# FastAPI Stack Setup Guide

This guide helps you set up and configure a FastAPI project using the Universal Template System.

## 📋 Prerequisites

- Python 3.10 or higher
- pip or poetry for package management
- PostgreSQL 14+ (for database integration)
- Redis (optional, for caching)

## 🚀 Quick Start

### 1. Create New Project

```bash
# Using the template system
python scripts/setup-project.py --manual-stack fastapi --manual-tier mvp --name "MyAPI"

# Or manually
mkdir my-fastapi-app
cd my-fastapi-app
```

### 2. Install Dependencies

```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### 3. Configure Environment

Create a `.env` file:

```bash
# Application
APP_NAME=MyAPI
APP_VERSION=1.0.0
ENVIRONMENT=development
DEBUG=true

# Database
DB_HOST=localhost
DB_PORT=5432
DB_USER=postgres
DB_PASSWORD=yourpassword
DB_NAME=myapi

# Authentication
AUTH_SECRET_KEY=your-secret-key-min-32-chars-long
AUTH_ALGORITHM=HS256
AUTH_ACCESS_TOKEN_EXPIRE_MINUTES=30

# Redis (optional)
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_DB=0

# Server
SERVER_HOST=0.0.0.0
SERVER_PORT=8000
SERVER_WORKERS=1
SERVER_RELOAD=true
```

### 4. Database Setup

```bash
# Create database
createdb myapi

# Run migrations (using Alembic)
alembic upgrade head

# Or initialize schema directly
psql -U postgres -d myapi -f schema.sql
```

### 5. Run Development Server

```bash
# Using uvicorn directly
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

# Or using the configuration
python -m uvicorn app.main:app --reload
```

### 6. Access Documentation

Open your browser and navigate to:
- Swagger UI: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc
- OpenAPI JSON: http://localhost:8000/openapi.json

## 📁 Project Structure

```
my-fastapi-app/
├── app/
│   ├── __init__.py
│   ├── main.py              # FastAPI application
│   ├── config.py            # Configuration management
│   ├── dependencies.py      # Dependency injection
│   ├── models.py            # SQLAlchemy models
│   ├── schemas.py           # Pydantic schemas
│   ├── auth.py              # Authentication
│   ├── middleware.py        # Custom middleware
│   ├── error_handling.py    # Exception handlers
│   └── routers/             # API routes
│       ├── __init__.py
│       ├── auth.py
│       ├── users.py
│       └── items.py
├── tests/
│   ├── conftest.py          # Pytest fixtures
│   ├── test_auth.py
│   ├── test_users.py
│   └── test_items.py
├── alembic/                 # Database migrations
│   ├── versions/
│   └── env.py
├── requirements.txt         # Dependencies
├── .env                     # Environment variables
├── alembic.ini             # Alembic configuration
└── README.md               # Project documentation
```

## 🔧 Development Workflow

### Creating API Endpoints

1. **Define Pydantic schemas** in `schemas.py`:
```python
from pydantic import BaseModel

class ItemCreate(BaseModel):
    name: str
    price: float
```

2. **Create SQLAlchemy models** in `models.py`:
```python
from sqlalchemy import Column, Integer, String, Float
from .dependencies import Base

class Item(Base):
    __tablename__ = "items"
    id = Column(Integer, primary_key=True)
    name = Column(String, nullable=False)
    price = Column(Float, nullable=False)
```

3. **Implement routes** in `routers/items.py`:
```python
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from ..dependencies import get_db
from ..schemas import ItemCreate, ItemResponse

router = APIRouter()

@router.post("/", response_model=ItemResponse)
async def create_item(
    item: ItemCreate,
    db: AsyncSession = Depends(get_db)
):
    # Implementation
    pass
```

4. **Register router** in `main.py`:
```python
from .routers import items

app.include_router(
    items.router,
    prefix="/api/v1/items",
    tags=["items"]
)
```

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=app --cov-report=html

# Run specific test file
pytest tests/test_users.py

# Run in watch mode
pytest-watch
```

### Database Migrations

```bash
# Create new migration
alembic revision --autogenerate -m "Add users table"

# Apply migrations
alembic upgrade head

# Rollback migration
alembic downgrade -1

# Show current version
alembic current
```

## 🐳 Docker Deployment

### Using Docker Compose

```bash
# Build and start
docker-compose up -d

# View logs
docker-compose logs -f app

# Stop services
docker-compose down
```

### Production Deployment

```bash
# Build production image
docker build -t myapi:latest .

# Run container
docker run -d \
  --name myapi \
  -p 8000:8000 \
  -e DATABASE_URL=postgresql://... \
  myapi:latest
```

## 📊 Monitoring & Logging

### Structured Logging

The stack uses structured logging with JSON output:

```python
import logging

logger = logging.getLogger(__name__)
logger.info(
    "User created",
    extra={
        "user_id": user.id,
        "username": user.username
    }
)
```

### Health Checks

Access health endpoints:
- `/health` - Basic health check
- `/health/detailed` - Detailed health with dependencies

## 🔒 Security Best Practices

1. **Never commit secrets** - Use environment variables
2. **Use HTTPS in production** - Configure SSL/TLS
3. **Enable CORS properly** - Restrict origins in production
4. **Validate all inputs** - Use Pydantic schemas
5. **Use rate limiting** - Protect against abuse
6. **Hash passwords** - Never store plain text passwords
7. **Use security headers** - Enable SecurityHeadersMiddleware

## 🚀 Performance Optimization

### Connection Pooling

Configure database pool size:
```python
DB_POOL_SIZE=20
DB_MAX_OVERFLOW=10
```

### Caching

Use Redis for caching:
```python
from aiocache import Cache

cache = Cache(Cache.REDIS, endpoint="localhost", port=6379)

@cache.cached(ttl=3600)
async def get_expensive_data():
    # Implementation
    pass
```

### Async Operations

Use async/await for I/O operations:
```python
async def get_users(db: AsyncSession):
    result = await db.execute(select(User))
    return result.scalars().all()
```

## 📚 Additional Resources

- [FastAPI Documentation](https://fastapi.tiangolo.com/)
- [SQLAlchemy Documentation](https://docs.sqlalchemy.org/)
- [Pydantic Documentation](https://docs.pydantic.dev/)
- [Uvicorn Documentation](https://www.uvicorn.org/)
- [Alembic Tutorial](https://alembic.sqlalchemy.org/en/latest/tutorial.html)

---

**Last Updated**: {{DATE}}  
**Stack Version**: 1.0  
**Minimum Python**: 3.10+
