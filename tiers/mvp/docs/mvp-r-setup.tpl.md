<!--
File: mvp-r-setup.tpl.md
Purpose: Template for unknown implementation
Template Version: 1.0
-->

# MVP Python Setup Guide

## Overview

This guide extends the foundational Python templates with MVP-specific configurations for rapid backend development with minimal feature set.

## Prerequisites

- Python 3.8+
- pip or poetry
- Code editor (VS Code recommended)
- Git

## Quick Start

### 1. Project Setup

```bash
# Copy MVP Python boilerplate
cp tiers/mvp/code/minimal-boilerplate-python.tpl.py [project-name]/src/app.py

# Copy foundational templates
cp -r stacks/python/base/code/* [project-name]/src/
cp -r stacks/python/base/tests/* [project-name]/tests/

# Setup dependencies
cp stacks/python/requirements.txt.tpl [project-name]/requirements.txt
cd [project-name]
pip install -r requirements.txt
```

### 2. Configuration

```python
# src/config/app_config.py - extends foundational config
class AppConfig(BaseConfig):
    async def load(self):
        await super().load()
        
        # MVP-specific settings
        self.enable_analytics = False
        self.enable_crashlytics = False
        self.enable_remote_config = False
        
        # Minimal feature set
        self.max_retries = 2
        self.timeout = 15
```

## MVP Architecture

### Core Components

1. **Minimal Server Setup**
   - Flask basics
   - Simple middleware
   - Basic error handling

2. **Essential API Layer**
   - RESTful endpoints
   - Basic validation
   - Simple authentication

3. **Basic Data Layer**
   - File-based storage
   - Simple HTTP client
   - Basic caching

4. **Core Features**
   - Authentication (JWT)
   - Basic CRUD operations
   - Simple logging

## File Structure

```
src/
├── app.py                    # MVP boilerplate
├── config/
│   ├── app_config.py         # MVP-specific config
│   └── env_config.py         # Environment settings
├── core/
│   ├── constants.py          # App constants
│   ├── middleware.py         # Flask middleware
│   └── routes.py             # Route definitions
├── data/
│   ├── models/               # Data models
│   ├── services/             # Basic services
│   └── repositories/         # Simple repositories
├── presentation/
│   ├── controllers/          # API controllers
│   ├── routes/               # Route handlers
│   └── middleware/           # Custom middleware
└── utils/
    ├── helpers.py            # Utility functions
    └── validators.py         # Input validation
```

## MVP Features

### 1. Authentication

```python
# src/services/auth_service.py
import jwt
from datetime import datetime, timedelta

class AuthService(BaseService):
    # JWT authentication only
    async def login(self, email: str, password: str) -> dict:
        try:
            # Basic validation
            if not self.validate_email(email):
                raise ValueError("Invalid email")
            
            # Generate JWT token
            token = self.generate_jwt({"email": email})
            return {"success": True, "token": token, "user": {"email": email}}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def logout(self, token: str) -> dict:
        # Basic token invalidation
        return {"success": True}
    
    def generate_jwt(self, payload: dict) -> str:
        payload["exp"] = datetime.utcnow() + timedelta(hours=24)
        return jwt.encode(payload, os.getenv("JWT_SECRET", "fallback-secret"))
```

### 2. Data Management

```python
# src/services/data_service.py
import json
import os
from pathlib import Path

class DataService(BaseService):
    # Simple file-based storage
    async def get_items(self) -> list:
        try:
            data_file = Path("data/items.json")
            if not data_file.exists():
                return []
            
            with open(data_file, 'r') as f:
                return json.load(f)
        except Exception:
            return []
    
    async def save_items(self, items: list) -> dict:
        try:
            data_dir = Path("data")
            data_dir.mkdir(exist_ok=True)
            
            with open(data_dir / "items.json", 'w') as f:
                json.dump(items, f, indent=2)
            return {"success": True}
        except Exception as e:
            return {"success": False, "error": str(e)}
```

### 3. API Routes

```python
# src/presentation/routes/api_routes.py
from flask import Blueprint
from .item_controller import ItemController
from .auth_controller import AuthController

api_bp = Blueprint('api', __name__)

# Basic CRUD routes
@api_bp.route('/items', methods=['GET'])
def get_items():
    return ItemController.get_items()

@api_bp.route('/items', methods=['POST'])
def create_item():
    return ItemController.create_item()

@api_bp.route('/items/<int:item_id>', methods=['PUT'])
def update_item(item_id):
    return ItemController.update_item(item_id)

@api_bp.route('/items/<int:item_id>', methods=['DELETE'])
def delete_item(item_id):
    return ItemController.delete_item(item_id)

# Authentication routes
@api_bp.route('/auth/login', methods=['POST'])
def login():
    return AuthController.login()

@api_bp.route('/auth/logout', methods=['POST'])
def logout():
    return AuthController.logout()
```

## Configuration Options

### Environment Variables

```python
# src/config/env_config.py
import os

class EnvConfig:
    APP_NAME = '[[.ProjectName]]'
    PORT = int(os.getenv('PORT', 3000))
    API_BASE_URL = os.getenv('API_BASE_URL', 'https://api.example.com')
    
    # MVP-specific flags
    ENABLE_DEBUG_MODE = os.getenv('FLASK_ENV') != 'production'
    ENABLE_LOGGING = os.getenv('ENABLE_LOGGING', 'true').lower() != 'false'
    
    # API settings
    TIMEOUT = int(os.getenv('API_TIMEOUT', 15))
    MAX_RETRIES = int(os.getenv('MAX_RETRIES', 2))
    
    # Security
    JWT_SECRET = os.getenv('JWT_SECRET', 'fallback-secret')
    BCRYPT_ROUNDS = int(os.getenv('BCRYPT_ROUNDS', 10))
```

### Feature Flags

```python
# src/config/feature_flags.py
class FeatureFlags:
    # MVP features - minimal set
    ENABLE_FILE_STORAGE = True
    ENABLE_JWT_AUTH = True
    ENABLE_RATE_LIMITING = False
    ENABLE_CORS = True
    ENABLE_COMPRESSION = False
    ENABLE_HELMET = False
    ENABLE_ANALYTICS = False
    ENABLE_CRASHLYTICS = False
```

## Development Workflow

### 1. Local Development

```bash
# Start development server
flask run

# Start with specific port
flask run --port 3001

# Start in debug mode
flask run --debug
```

### 2. Testing

```bash
# Run all tests
python -m pytest

# Run tests with coverage
python -m pytest --cov=src

# Run tests in watch mode
python -m pytest --watch
```

### 3. Building

```bash
# Install dependencies
pip install -r requirements.txt

# Run production server
gunicorn -w 4 -b 0.0.0.0:3000 src.app:app
```

## Deployment

### 1. Traditional Server

```bash
# Install production dependencies
pip install gunicorn

# Start production server
gunicorn -w 4 -b 0.0.0.0:3000 src.app:app
```

### 2. Docker

```bash
# Build Docker image
docker build -t [[.ProjectName]] .

# Run container
docker run -p 3000:3000 [[.ProjectName]]
```

### 3. Cloud Platforms

```bash
# Deploy to Heroku
git push heroku main

# Deploy to PythonAnywhere
# Use web interface or API
```

## MVP Components

### 1. Basic Server

```python
# src/app.py - MVP boilerplate
from flask import Flask, jsonify
from flask_cors import CORS
from .presentation.routes.api_routes import api_bp
from .core.middleware import error_handler

def create_app():
    app = Flask(__name__)
    
    # Basic middleware
    CORS(app)
    
    # Register blueprints
    app.register_blueprint(api_bp, url_prefix='/api')
    
    # Health check
    @app.route('/health')
    def health_check():
        return jsonify({
            'status': 'ok',
            'timestamp': datetime.utcnow().isoformat()
        })
    
    # Error handling
    app.register_error_handler(500, error_handler)
    
    return app

app = create_app()

if __name__ == '__main__':
    app.run(debug=True, port=3000)
```

### 2. Authentication Controller

```python
# src/presentation/controllers/auth_controller.py
from flask import request, jsonify
from ..services.auth_service import AuthService

class AuthController:
    @staticmethod
    def login():
        try:
            data = request.get_json()
            email = data.get('email')
            password = data.get('password')
            
            auth_service = AuthService()
            result = await auth_service.login(email, password)
            
            if result['success']:
                return jsonify(result), 200
            else:
                return jsonify(result), 401
        except Exception as e:
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500
    
    @staticmethod
    def logout():
        try:
            token = request.headers.get('Authorization', '').replace('Bearer ', '')
            auth_service = AuthService()
            result = await auth_service.logout(token)
            return jsonify(result), 200
        except Exception as e:
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500
```

### 3. Basic Service

```python
# src/services/base_service.py
import os
import re
from pathlib import Path
from typing import Dict, Any

class BaseService:
    def __init__(self):
        from ..config.app_config import AppConfig
        self.config = AppConfig()
    
    async def handle_error(self, error: Exception, response=None) -> Dict[str, Any]:
        print(f"Service error: {error}")
        
        error_response = {
            'success': False,
            'error': str(error) or 'An error occurred',
        }
        
        if response:
            return response, 500, error_response
        
        return error_response
    
    def validate_email(self, email: str) -> bool:
        pattern = r'^[^\s@]+@[^\s@]+\.[^\s@]+$'
        return re.match(pattern, email) is not None
    
    async def ensure_data_dir(self):
        data_dir = Path("data")
        data_dir.mkdir(exist_ok=True)
```

## MVP Limitations

### What's NOT Included

- No database integration (file-based only)
- No advanced authentication (OAuth, SSO)
- No real-time features (WebSockets)
- No advanced caching (Redis)
- No message queues
- No advanced logging (structured logging)
- No API documentation (Swagger)
- No rate limiting
- No advanced security features

### Upgrade Path

When ready to move to Core tier:

1. **Database**: Add PostgreSQL/MySQL/MongoDB integration
2. **Authentication**: Add OAuth providers and SSO
3. **Caching**: Add Redis for advanced caching
4. **Security**: Add rate limiting, advanced headers
5. **Monitoring**: Add structured logging and metrics
6. **Documentation**: Add Swagger/OpenAPI docs
7. **Performance**: Add compression, optimization

## Best Practices

### 1. Code Organization

- Keep features separate and focused
- Use consistent naming conventions
- Follow PEP 8 style guidelines
- Document public APIs

### 2. Performance

- Use async/await properly
- Implement proper error handling
- Use connection pooling
- Optimize database queries

### 3. Security

- Validate all inputs
- Use HTTPS in production
- Implement proper authentication
- Sanitize outputs

## Troubleshooting

### Common Issues

1. **Port Conflicts**: Change PORT environment variable
2. **Module Not Found**: Check requirements.txt and run pip install
3. **Permission Errors**: Check file permissions for data directory
4. **Import Errors**: Check PYTHONPATH and module structure

### Debug Tips

- Use Python debugger (pdb) for debugging
- Use print statements for quick debugging
- Check environment variables
- Monitor server logs

## Resources

- [Python Documentation](https://docs.python.org/3/)
- [Flask Documentation](https://flask.palletsprojects.com/)
- [JWT Documentation](https://jwt.io/)
- [Python Best Practices](https://docs.python-guide.org/)

## Next Steps

1. Review the foundational templates for detailed implementation
2. Customize the MVP boilerplate for your specific needs
3. Implement your business logic using the provided structure
4. Add tests for your custom code
5. Prepare for deployment

---

**Note**: This MVP setup provides a solid foundation for rapid backend development. When your application grows, consider upgrading to the Core tier for additional features and capabilities.
