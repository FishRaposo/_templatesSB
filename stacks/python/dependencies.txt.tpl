#!/usr/bin/env python3
"""
Python Stack Dependencies Template
Complete package management and tooling configurations for Python projects
"""

# ====================
# PACKAGE MANAGEMENT
# ====================

# Core Python Version Requirements
python_requires = ">=3.9,<3.12"

# Production Dependencies - FastAPI Web Framework
fastapi = "^0.104.0"
uvicorn = { extras = ["standard"], version = "^0.24.0" }
pydantic = "^2.5.0"
pydantic-settings = "^2.1.0"

# Database & ORM
sqlalchemy = "^2.0.23"
alembic = "^1.12.0"
psycopg2-binary = "^2.9.9"  # PostgreSQL
pymysql = "^1.1.0"  # MySQL

# Data Science & ML (if applicable)
numpy = "^1.24.0"
pandas = "^2.1.0"
scikit-learn = "^1.3.0"

# API & HTTP Clients
httpx = "^0.25.0"
requests = "^2.31.0"
aiohttp = "^3.9.0"

# Authentication & Security
python-jose = { extras = ["cryptography"], version = "^3.3.0" }
passlib = { extras = ["bcrypt"], version = "^1.7.4" }
python-multipart = "^0.0.6"

# Background Tasks & Queues
celery = "^5.3.0"
redis = "^5.0.0"
rq = "^1.15.0"

# Monitoring & Observability
prometheus-client = "^0.19.0"
opentelemetry-api = "^1.21.0"
opentelemetry-sdk = "^1.21.0"
python-json-logger = "^2.0.7"

# Utilities
python-dotenv = "^1.0.0"
click = "^8.1.0"
tenacity = "^8.2.0"

# ====================
# DEVELOPMENT DEPENDENCIES
# ====================

pytest = "^7.4.0"
pytest-asyncio = "^0.21.0"
pytest-cov = "^4.1.0"
pytest-mock = "^3.12.0"
pytest-benchmark = "^4.0.0"

# Linting & Formatting
black = "^23.0.0"
isort = "^5.12.0"
flake8 = "^6.1.0"
mypy = "^1.7.0"
pre-commit = "^3.5.0"
pylint = "^3.0.0"

# Testing Utilities
factory-boy = "^3.3.0"
faker = "^20.0.0"
freezegun = "^1.2.0"
responses = "^0.24.0"

# ====================
# DOCUMENTATION DEPENDENCIES
# ====================

mkdocs = "^1.5.0"
mkdocs-material = "^9.4.0"
mkdocs-click = "^0.8.0"
pydoc-markdown = "^4.8.0"

# ====================
# BUILD & DEPLOYMENT
# ====================

build = "^1.0.0"
twine = "^4.0.0"
docker = "^6.1.0"

# ====================
# MYPY TYPE CHECKING
# ====================

[[tool.mypy.overrides]]
module = [
    "tests.*",
]
disallow_untyped_defs = false

# ====================
# PYTEST CONFIGURATION
# ====================

[tool.pytest.ini_options]
minversion = "7.0"
addopts = "-ra -q --strict-markers --strict-config"
testpaths = [
    "tests",
    "integration",
]
python_files = [
    "test_*.py",
    "*_test.py",
]
python_classes = [
    "Test*",
]
python_functions = [
    "test_*",
]
markers = [
    "slow: marks tests as slow (deselect with '-m \"not slow\"')",
    "integration: marks tests as integration tests",
    "unit: marks tests as unit tests",
    "e2e: marks tests as end-to-end tests",
]

# ====================
# BLACK CONFIGURATION
# ====================

[tool.black]
line-length = 88
target-version = ['py39']
include = '\.pyi?$'
extend-exclude = '''
/(
  # directories
  \.eggs
  | \.git
  | \.hg
  | \.mypy_cache
  | \.tox
  | \.venv
  | build
  | dist
)/
'''

# ====================
# ISORT CONFIGURATION
# ====================

[tool.isort]
profile = "black"
multi_line_output = 3
line_length = 88
known_first_party = ["app"]

# ====================
# COVERAGE CONFIGURATION
# ====================

[tool.coverage.run]
source = ["."]
omit = [
    "*/tests/*",
    "*/test_*",
    "setup.py",
]

[tool.coverage.report]
exclude_lines = [
    "pragma: no cover",
    "def __repr__",
    "raise AssertionError",
    "raise NotImplementedError",
    "if __name__ == .__main__.:",
]
precision = 2
show_missing = True
skip_covered = False

# ====================
# PRE-COMMIT HOOKS
# ====================

# Install with: pre-commit install
# Config file: .pre-commit-config.yaml (create separately)

# ====================
# DOCKER INSTRUCTIONS
# ====================

# Build: docker build -t my-python-app .
# Run: docker run -p 8000:8000 my-python-app

# ====================
# DEVELOPMENT WORKFLOW
# ====================

# Install dependencies:
#   pip install -r requirements.txt
#   pip install -r requirements-dev.txt

# Run tests:
#   pytest
#   pytest --cov=app
#   pytest tests/unit/
#   pytest tests/integration/

# Linting:
#   black .
#   isort .
#   flake8 .
#   mypy .

# Type checking:
#   mypy --strict .

# Build documentation:
#   mkdocs serve

# ====================
# PRODUCTION DEPLOYMENT CHECKLIST
# ====================

# 1. Update version in pyproject.toml
# 2. Run full test suite: pytest
# 3. Check code coverage: pytest --cov=app
# 4. Run security scan: pip install safety && safety check
# 5. Build Docker image: docker build -t app:v1.0.0 .
# 6. Run security scan on image: docker scan app:v1.0.0
# 7. Push to registry: docker push my-registry/app:v1.0.0
# 8. Deploy to production environment

# ====================
# TROUBLESHOOTING
# ====================

# If you encounter dependency conflicts:
#   1. Create a fresh virtual environment
#   2. Install production deps first: pip install -r requirements.txt
#   3. Then install dev deps: pip install -r requirements-dev.txt

# If tests fail with import errors:
#   1. Check PYTHONPATH includes your source directory
#   2. Install package in editable mode: pip install -e .
#   3. Verify all dependencies are installed

# If mypy shows many errors:
#   1. Run with --ignore-missing-imports first
#   2. Add type stubs: pip install types-requests types-pyyaml
#   3. Gradually add type annotations to your code
