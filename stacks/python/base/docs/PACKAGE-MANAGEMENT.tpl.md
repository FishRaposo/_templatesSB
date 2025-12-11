# Universal Template System - Python Stack
# Generated: 2025-12-10
# Purpose: python template utilities
# Tier: base
# Stack: python
# Category: template

# Python Package Management Patterns

## Purpose
Comprehensive guide to Python package management, including dependency management, virtual environments, and distribution strategies.

## Core Package Management

### 1. Virtual Environments
```bash
# Create virtual environment
python -m venv myenv

# Activate environment
# Windows
myenv\Scripts\activate
# Unix/MacOS
source myenv/bin/activate

# Deactivate environment
deactivate
```

### 2. pip Requirements Management
```bash
# Install from requirements.txt
pip install -r requirements.txt

# Generate requirements.txt
pip freeze > requirements.txt

# Install specific package
pip install package-name==1.2.3

# Install with extras
pip install package-name[extra1,extra2]

# Install in development mode
pip install -e .
```

### 3. requirements.txt Structure
```txt
# Production requirements
requests==2.31.0
fastapi==0.104.1
uvicorn[standard]==0.24.0
sqlalchemy==2.0.23
asyncpg==0.29.0
pydantic==2.5.0

# Development requirements
pytest==7.4.3
pytest-asyncio==0.21.1
black==23.11.0
flake8==6.1.0
mypy==1.7.1

# Pinned versions for reproducibility
```

## Modern Package Management

### 1. Poetry Configuration
```toml
# pyproject.toml
[tool.poetry]
name = "my-python-project"
version = "0.1.0"
description = "A Python project using Poetry"
authors = ["Your Name <your.email@example.com>"]
readme = "README.md"
packages = [{include = "my_project"}]

[tool.poetry.dependencies]
python = "^3.9"
fastapi = "^0.104.0"
uvicorn = {extras = ["standard"], version = "^0.24.0"}
sqlalchemy = "^2.0.0"
asyncpg = "^0.29.0"

[tool.poetry.group.dev.dependencies]
pytest = "^7.4.0"
pytest-asyncio = "^0.21.0"
black = "^23.0.0"
flake8 = "^6.0.0"
mypy = "^1.7.0"

[build-system]
requires = ["poetry-core"]
build-backend = "poetry.core.masonry.api"
```

### 2. Poetry Commands
```bash
# Install dependencies
poetry install

# Install with dev dependencies
poetry install --with dev

# Add new dependency
poetry add fastapi

# Add dev dependency
poetry add --group dev pytest

# Update dependencies
poetry update

# Run commands in virtual environment
poetry run python script.py
poetry run pytest

# Activate virtual environment
poetry shell
```

### 3. Pipenv Configuration
```toml
# Pipfile
[[source]]
url = "https://pypi.org/simple"
verify_ssl = true
name = "pypi"

[packages]
fastapi = "*"
uvicorn = {extras = ["standard"], version = "*"}
sqlalchemy = "*"

[dev-packages]
pytest = "*"
black = "*"
flake8 = "*"

[requires]
python_version = "3.9"
```

```bash
# Install dependencies
pipenv install

# Install dev dependencies
pipenv install --dev

# Add package
pipenv install fastapi

# Add dev package
pipenv install --dev pytest

# Run commands
pipenv run python script.py
pipenv run pytest
```

## Dependency Management Strategies

### 1. Semantic Versioning Constraints
```toml
# Poetry - Semantic versioning
[tool.poetry.dependencies]
# Caret (^) - Allows compatible updates
fastapi = "^0.104.0"  # >=0.104.0, <0.105.0

# Tilde (~) - Allows patch updates
requests = "~2.31.0"  # >=2.31.0, <2.32.0

# Exact version
critical-lib = "1.2.3"

# Greater than or equal
python = "^3.9.0"

# Multiple constraints
numpy = [
    {version = ">=1.21.0", python = "^3.9"},
    {version = ">=1.19.0", python = "^3.8"}
]
```

### 2. Dependency Groups
```toml
# Poetry - Dependency groups
[tool.poetry.group.web.dependencies]
fastapi = "^0.104.0"
uvicorn = {extras = ["standard"], version = "^0.24.0"}

[tool.poetry.group.database.dependencies]
sqlalchemy = "^2.0.0"
asyncpg = "^0.29.0"

[tool.poetry.group.dev.dependencies]
pytest = "^7.4.0"
black = "^23.0.0"

[tool.poetry.group.docs.dependencies]
mkdocs = "^1.5.0"
mkdocs-material = "^9.4.0"
```

```bash
# Install specific groups
poetry install --with web,dev
poetry install --only web
poetry install --with dev --only dev
```

### 3. Lock Files and Reproducibility
```bash
# Poetry - Generate and use lock file
poetry lock  # Generate poetry.lock
poetry install  # Install from lock file

# Pipenv - Generate and use lock file
pipenv lock  # Generate Pipfile.lock
pipenv install  # Install from lock file

# pip - Use pip-tools
pip-compile requirements.in  # Generate requirements.txt
pip-sync requirements.txt  # Install exact versions
```

## Private Package Repositories

### 1. Configuring Private PyPI
```bash
# Poetry - Configure private repository
poetry config repositories.private https://pypi.private.com/simple/
poetry config http-basic.private username password

# Add private package
poetry add --repository private my-private-package

# poetry.toml configuration
[repositories]
private = { url = "https://pypi.private.com/simple/" }
```

### 2. pip Configuration
```bash
# pip.conf or ~/.pip/pip.conf
[global]
extra-index-url = https://pypi.private.com/simple/

# Install from private repository
pip install --index-url https://pypi.private.com/simple/ my-private-package
```

### 3. AWS CodeArtifact
```bash
# Configure AWS CodeArtifact
aws codeartifact login --tool pip --domain my-domain --domain-owner 123456789012

# Install from CodeArtifact
pip install my-package --index-url https://my-domain-123456789012.d.codeartifact.us-west-2.amazonaws.com/pypi/my-repo/simple/
```

## Package Distribution

### 1. Setup Configuration
```toml
# pyproject.toml - Build configuration
[build-system]
requires = ["setuptools>=61.0", "wheel"]
build-backend = "setuptools.build_meta"

[project]
name = "my-package"
version = "0.1.0"
description = "My Python package"
readme = "README.md"
requires-python = ">=3.9"
license = {text = "MIT"}
authors = [
    {name = "Your Name", email = "your.email@example.com"},
]
keywords = ["python", "package"]
classifiers = [
    "Development Status :: 3 - Alpha",
    "Intended Audience :: Developers",
    "License :: OSI Approved :: MIT License",
    "Programming Language :: Python :: 3",
    "Programming Language :: Python :: 3.9",
    "Programming Language :: Python :: 3.10",
    "Programming Language :: Python :: 3.11",
]

dependencies = [
    "requests>=2.25.0",
    "click>=8.0.0",
]

[project.optional-dependencies]
dev = [
    "pytest>=7.0.0",
    "black>=22.0.0",
    "flake8>=4.0.0",
]

[project.scripts]
my-cli = "my_package.cli:main"

[project.urls]
Homepage = "https://github.com/yourusername/my-package"
Documentation = "https://my-package.readthedocs.io/"
Repository = "https://github.com/yourusername/my-package.git"
"Bug Tracker" = "https://github.com/yourusername/my-package/issues"
```

### 2. Building and Publishing
```bash
# Build package
python -m build

# Build source and wheel distributions
python setup.py sdist bdist_wheel

# Check package
twine check dist/*

# Upload to Test PyPI
twine upload --repository testpypi dist/*

# Upload to PyPI
twine upload dist/*

# Install from Test PyPI
pip install --index-url https://test.pypi.org/simple/ my-package
```

### 3. Version Management
```python
# my_package/__init__.py
__version__ = "0.1.0"

# setup.py or pyproject.toml can reference this
from my_package import __version__

# Or use version from git tags
import subprocess
from setuptools_scm import get_version

version = get_version()
```

## Container and Environment Management

### 1. Docker Integration
```dockerfile
# Dockerfile
FROM python:3.11-slim

WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Install application in development mode
RUN pip install -e .

CMD ["python", "-m", "my_package"]
```

### 2. Docker Compose with Multiple Services
```yaml
# docker-compose.yml
version: '3.8'

services:
  app:
    build: .
    environment:
      - DATABASE_URL=postgresql://user:pass@db:5432/mydb
    depends_on:
      - db
      - redis
    volumes:
      - .:/app
    command: poetry run uvicorn my_package.main:app --host 0.0.0.0 --port 8000

  db:
    image: postgres:15
    environment:
      - POSTGRES_DB=mydb
      - POSTGRES_USER=user
      - POSTGRES_PASSWORD=pass
    volumes:
      - postgres_data:/var/lib/postgresql/data

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"

volumes:
  postgres_data:
```

### 3. Environment Variable Management
```python
# my_package/config.py
import os
from typing import Optional
from pydantic import BaseSettings

class Settings(BaseSettings):
    # Database
    database_url: str = "sqlite:///./app.db"
    
    # Redis
    redis_url: str = "redis://localhost:6379"
    
    # Security
    secret_key: str = "dev-secret-key"
    
    # Application
    debug: bool = False
    log_level: str = "INFO"
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"

settings = Settings()
```

```bash
# .env file
DATABASE_URL=postgresql://user:pass@localhost:5432/mydb
REDIS_URL=redis://localhost:6379
SECRET_KEY=your-secret-key-here
DEBUG=true
LOG_LEVEL=DEBUG
```

## Development Workflow

### 1. Pre-commit Hooks
```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v4.4.0
    hooks:
      - id: trailing-whitespace
      - id: end-of-file-fixer
      - id: check-yaml
      - id: check-added-large-files

  - repo: https://github.com/psf/black
    rev: 23.11.0
    hooks:
      - id: black
        language_version: python3

  - repo: https://github.com/pycqa/flake8
    rev: 6.1.0
    hooks:
      - id: flake8

  - repo: https://github.com/pycqa/isort
    rev: 5.12.0
    hooks:
      - id: isort
        args: ["--profile", "black"]

  - repo: https://github.com/pre-commit/mirrors-mypy
    rev: v1.7.1
    hooks:
      - id: mypy
        additional_dependencies: [types-all]
```

```bash
# Install pre-commit hooks
pre-commit install

# Run hooks manually
pre-commit run --all-files
```

### 2. Makefile for Common Tasks
```makefile
# Makefile
.PHONY: install dev test lint format clean build upload

install:
	pip install -e .

dev:
	pip install -e ".[dev]"

test:
	pytest tests/ -v

test-cov:
	pytest tests/ --cov=my_package --cov-report=html

lint:
	flake8 my_package tests/
	mypy my_package

format:
	black my_package tests/
	isort my_package tests/

clean:
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info/
	rm -rf .pytest_cache/
	rm -rf .coverage
	rm -rf htmlcov/

build: clean
	python -m build

upload-test: build
	twine upload --repository testpypi dist/*

upload: build
	twine upload dist/*
```

## Best Practices

### 1. Dependency Hygiene
```python
# requirements.txt with categorized dependencies
# Core dependencies
fastapi==0.104.1
uvicorn[standard]==0.24.0
pydantic==2.5.0

# Database
sqlalchemy==2.0.23
asyncpg==0.29.0
alembic==1.12.1

# Development
pytest==7.4.3
pytest-asyncio==0.21.1
black==23.11.0
flake8==6.1.0
mypy==1.7.1

# Optional dependencies
# redis==5.0.1  # Uncomment if using Redis
# celery==5.3.4  # Uncomment if using Celery
```

### 2. Version Pinning Strategy
```bash
# Development - Use ranges for flexibility
poetry add "fastapi>=0.100,<0.105"

# Production - Pin exact versions
poetry add "fastapi==0.104.1"

# Security updates - Update specific packages
poetry update requests

# Full dependency update
poetry update
```

### 3. Security Considerations
```bash
# Check for known vulnerabilities
pip-audit

# Or with safety
safety check

# Update vulnerable packages
poetry update package-name

# Use private repositories for sensitive packages
poetry add --repository private my-internal-package
```

## Troubleshooting

### 1. Common Issues
```bash
# Dependency conflicts
poetry add package@latest  # Force latest version
poetry update --lock  # Regenerate lock file

# Permission issues
pip install --user package-name  # Install to user directory

# Cache issues
pip cache purge  # Clear pip cache
poetry cache clear pypi --all  # Clear poetry cache
```

### 2. Environment Issues
```bash
# Check virtual environment
which python
python --version
pip list

# Recreate environment
rm -rf venv
python -m venv venv
source venv/bin/activate  # Unix/MacOS
# or
venv\Scripts\activate  # Windows
pip install -r requirements.txt
```

This comprehensive package management guide covers all aspects of Python dependency management from basic pip usage to modern tools like Poetry and container integration.
