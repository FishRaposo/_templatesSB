# {{PROJECT_NAME}} - SaaS API Reference Project

A production-ready SaaS API built with FastAPI, demonstrating best practices for authentication, billing, multi-tenancy, and API design.

## Features

- **Authentication**: JWT-based auth with refresh tokens, OAuth2 support
- **Multi-tenancy**: Organization-based data isolation
- **Billing**: Stripe integration with subscription management
- **API Design**: RESTful endpoints with OpenAPI documentation
- **Background Jobs**: Celery-based async task processing
- **Caching**: Redis caching with decorator patterns
- **Testing**: Comprehensive test suite with fixtures

## Tech Stack

- **Framework**: FastAPI 0.100+
- **Database**: PostgreSQL with SQLAlchemy 2.0
- **Cache**: Redis
- **Queue**: Celery + Redis
- **Auth**: JWT + OAuth2
- **Payments**: Stripe
- **Testing**: pytest + pytest-asyncio

## Project Structure

```
{{PROJECT_NAME}}/
├── app/
│   ├── __init__.py
│   ├── main.py              # Application entry point
│   ├── config.py            # Configuration management
│   ├── dependencies.py      # FastAPI dependencies
│   │
│   ├── api/                 # API routes
│   │   ├── v1/
│   │   │   ├── auth.py
│   │   │   ├── users.py
│   │   │   ├── organizations.py
│   │   │   ├── billing.py
│   │   │   └── webhooks.py
│   │   └── router.py
│   │
│   ├── core/               # Core functionality
│   │   ├── security.py     # Auth, JWT, password hashing
│   │   ├── middleware.py   # Custom middleware
│   │   └── exceptions.py   # Custom exceptions
│   │
│   ├── db/                 # Database
│   │   ├── base.py         # Base model
│   │   ├── session.py      # Session management
│   │   └── migrations/     # Alembic migrations
│   │
│   ├── models/             # SQLAlchemy models
│   │   ├── user.py
│   │   ├── organization.py
│   │   ├── subscription.py
│   │   └── api_key.py
│   │
│   ├── schemas/            # Pydantic schemas
│   │   ├── user.py
│   │   ├── auth.py
│   │   ├── organization.py
│   │   └── billing.py
│   │
│   ├── services/           # Business logic
│   │   ├── auth_service.py
│   │   ├── user_service.py
│   │   ├── billing_service.py
│   │   └── email_service.py
│   │
│   ├── tasks/              # Celery tasks
│   │   ├── email_tasks.py
│   │   └── billing_tasks.py
│   │
│   └── utils/              # Utilities
│       ├── cache.py
│       └── pagination.py
│
├── tests/
│   ├── conftest.py
│   ├── fixtures/
│   ├── unit/
│   └── integration/
│
├── alembic/
├── docker/
├── scripts/
├── pyproject.toml
├── Dockerfile
└── docker-compose.yml
```

## Quick Start

### Prerequisites

- Python 3.11+
- PostgreSQL 14+
- Redis 7+

### Installation

```bash
# Clone repository
git clone https://github.com/example/{{PROJECT_NAME}}.git
cd {{PROJECT_NAME}}

# Create virtual environment
python -m venv venv
source venv/bin/activate  # or `venv\Scripts\activate` on Windows

# Install dependencies
pip install -e ".[dev]"

# Set up environment
cp .env.example .env
# Edit .env with your settings

# Run migrations
alembic upgrade head

# Start development server
uvicorn app.main:app --reload
```

### Docker

```bash
# Start all services
docker-compose up -d

# Run migrations
docker-compose exec api alembic upgrade head

# View logs
docker-compose logs -f api
```

## Configuration

Key environment variables:

```bash
# Application
APP_NAME={{PROJECT_NAME}}
APP_ENVIRONMENT=development
DEBUG=true

# Database
DB_HOST=localhost
DB_PORT=5432
DB_NAME=app_db
DB_USER=postgres
DB_PASSWORD=password

# Redis
REDIS_HOST=localhost
REDIS_PORT=6379

# Security
SECURITY_SECRET_KEY=your-secret-key-here
SECURITY_ACCESS_TOKEN_EXPIRE_MINUTES=30

# Stripe
STRIPE_SECRET_KEY=sk_test_...
STRIPE_WEBHOOK_SECRET=whsec_...
```

## API Documentation

- Swagger UI: `http://localhost:8000/docs`
- ReDoc: `http://localhost:8000/redoc`
- OpenAPI JSON: `http://localhost:8000/openapi.json`

## Testing

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=app --cov-report=html

# Run specific tests
pytest tests/unit/
pytest tests/integration/
pytest -k "test_auth"
```

## License

MIT License - see LICENSE file for details.
