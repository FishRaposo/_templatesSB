# FastAPI Stack - Production Dependencies
# Generated for: {{PROJECT_NAME}}
# Python Version: 3.10+

# Core FastAPI
fastapi==0.109.0
uvicorn[standard]==0.27.0
pydantic==2.5.3
pydantic-settings==2.1.0

# Database & ORM
sqlalchemy[asyncio]==2.0.25
asyncpg==0.29.0
alembic==1.13.1
greenlet==3.0.3

# Authentication & Security
python-jose[cryptography]==3.3.0
passlib[bcrypt]==1.7.4
python-multipart==0.0.6
bcrypt==4.1.2

# HTTP Client
httpx==0.26.0
aiohttp==3.9.1

# Caching & Performance
redis==5.0.1
aiocache==0.12.2

# Background Tasks
celery==5.3.4
redis==5.0.1

# Data Validation & Serialization
email-validator==2.1.0
python-dateutil==2.8.2

# Monitoring & Logging
python-json-logger==2.0.7
structlog==24.1.0
opentelemetry-api==1.22.0
opentelemetry-sdk==1.22.0
opentelemetry-instrumentation-fastapi==0.43b0

# Development Tools
black==24.1.1
ruff==0.1.14
mypy==1.8.0
pre-commit==3.6.0

# Testing
pytest==7.4.4
pytest-asyncio==0.23.3
pytest-cov==4.1.0
pytest-mock==3.12.0
httpx==0.26.0
faker==22.2.0

# Documentation
mkdocs==1.5.3
mkdocs-material==9.5.6

# CORS & Middleware
python-cors==1.0.0

# Environment & Configuration
python-dotenv==1.0.0
