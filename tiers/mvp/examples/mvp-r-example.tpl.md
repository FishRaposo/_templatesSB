<!--
File: mvp-r-example.tpl.md
Purpose: Template for unknown implementation
Template Version: 1.0
-->

# MVP Python Example Project

## Overview

This example demonstrates a complete MVP Python backend application using the minimal boilerplate template with JWT authentication, basic CRUD operations, and simple API endpoints.

## Project Structure

```
mvp_python_example/
├── src/
│   ├── app.py                        # MVP boilerplate entry point
│   ├── config/
│   │   ├── app_config.py             # MVP configuration
│   │   └── env_config.py             # Environment settings
│   ├── core/
│   │   ├── constants.py              # App constants
│   │   ├── middleware.py             # Flask middleware
│   │   └── routes.py                 # Route definitions
│   ├── data/
│   │   ├── models/
│   │   │   ├── user.py                # User model
│   │   │   └── task.py                # Task model
│   │   ├── services/
│   │   │   ├── auth_service.py        # Authentication service
│   │   │   └── task_service.py        # Task management service
│   │   └── repositories/
│   │       └── task_repository.py     # Task data repository
│   ├── presentation/
│   │   ├── controllers/
│   │   │   ├── auth_controller.py     # Authentication endpoints
│   │   │   └── task_controller.py     # Task CRUD endpoints
│   │   ├── routes/
│   │   │   ├── auth_routes.py          # Authentication routes
│   │   │   └── task_routes.py          # Task routes
│   │   └── middleware/
│   │       ├── auth_middleware.py     # JWT verification
│   │       └── error_middleware.py    # Error handling
│   └── utils/
│       ├── helpers.py                 # Utility functions
│       └── validators.py              # Input validation
├── test/
│   ├── unit/
│   │   ├── services/
│   │   │   ├── test_auth_service.py
│   │   │   └── test_task_service.py
│   │   └── controllers/
│   │       ├── test_auth_controller.py
│   │       └── test_task_controller.py
│   └── integration/
│       ├── test_auth.py
│       └── test_tasks.py
├── data/
│   └── tasks.json                     # File-based storage
├── requirements.txt                   # Dependencies
└── README.md                          # Project documentation
```

## Key Features Demonstrated

### 1. JWT Authentication
```python
# src/services/auth_service.py
import jwt
import bcrypt
from datetime import datetime, timedelta
from typing import Dict, Any, Optional

class AuthService:
    def __init__(self):
        self.jwt_secret = os.getenv('JWT_SECRET', 'fallback-secret')
        self.users = [
            {
                'id': 1,
                'email': 'test@example.com',
                'password': bcrypt.hashpw('password'.encode(), bcrypt.gensalt()).decode()
            }
        ]
    
    async def login(self, email: str, password: str) -> Dict[str, Any]:
        try:
            # Basic validation
            if not self.validate_email(email):
                raise ValueError('Invalid email format')
            
            # Find user
            user = next((u for u in self.users if u['email'] == email), None)
            if not user:
                raise ValueError('User not found')
            
            # Verify password
            if not bcrypt.checkpw(password.encode(), user['password'].encode()):
                raise ValueError('Invalid credentials')
            
            # Generate JWT token
            token = jwt.encode({
                'user_id': user['id'],
                'email': user['email'],
                'exp': datetime.utcnow() + timedelta(hours=24)
            }, self.jwt_secret, algorithm='HS256')
            
            return {
                'success': True,
                'token': token,
                'user': {'id': user['id'], 'email': user['email']}
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def verify_token(self, token: str) -> Dict[str, Any]:
        try:
            return jwt.decode(token, self.jwt_secret, algorithms=['HS256'])
        except jwt.InvalidTokenError:
            raise ValueError('Invalid token')
    
    def validate_email(self, email: str) -> bool:
        import re
        pattern = r'^[^\s@]+@[^\s@]+\.[^\s@]+$'
        return re.match(pattern, email) is not None
```

### 2. Task CRUD Operations
```python
# src/services/task_service.py
import json
import os
from pathlib import Path
from typing import Dict, Any, List, Optional
from datetime import datetime

class TaskService:
    def __init__(self):
        self.data_file = Path('data/tasks.json')
    
    async def get_tasks(self) -> List[Dict[str, Any]]:
        try:
            # Simulate API delay
            import asyncio
            await asyncio.sleep(0.2)
            
            return self._read_data_file()
        except Exception as e:
            print(f'Error getting tasks: {e}')
            return []
    
    async def create_task(self, task_data: Dict[str, Any]) -> Dict[str, Any]:
        try:
            tasks = await self.get_tasks()
            new_task = {
                'id': int(datetime.now().timestamp()),
                'title': task_data['title'],
                'description': task_data.get('description', ''),
                'is_completed': False,
                'created_at': datetime.utcnow().isoformat(),
                'updated_at': datetime.utcnow().isoformat(),
                'user_id': task_data['user_id']
            }
            
            tasks.append(new_task)
            self._write_data_file(tasks)
            
            return {'success': True, 'task': new_task}
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    async def update_task(self, task_id: int, updates: Dict[str, Any], user_id: int) -> Dict[str, Any]:
        try:
            tasks = await self.get_tasks()
            task_index = next((i for i, t in enumerate(tasks) 
                             if t['id'] == task_id and t['user_id'] == user_id), None)
            
            if task_index is None:
                raise ValueError('Task not found')
            
            tasks[task_index].update(updates)
            tasks[task_index]['updated_at'] = datetime.utcnow().isoformat()
            
            self._write_data_file(tasks)
            return {'success': True, 'task': tasks[task_index]}
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    async def delete_task(self, task_id: int, user_id: int) -> Dict[str, Any]:
        try:
            tasks = await self.get_tasks()
            original_length = len(tasks)
            tasks = [t for t in tasks if not (t['id'] == task_id and t['user_id'] == user_id)]
            
            if len(tasks) == original_length:
                raise ValueError('Task not found')
            
            self._write_data_file(tasks)
            return {'success': True}
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    async def get_tasks_by_user(self, user_id: int) -> List[Dict[str, Any]]:
        try:
            tasks = await self.get_tasks()
            return [t for t in tasks if t['user_id'] == user_id]
        except Exception:
            return []
    
    def _read_data_file(self) -> List[Dict[str, Any]]:
        try:
            if not self.data_file.exists():
                return []
            
            with open(self.data_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            print(f'Error reading data file: {e}')
            return []
    
    def _write_data_file(self, data: List[Dict[str, Any]]) -> None:
        self.data_file.parent.mkdir(parents=True, exist_ok=True)
        with open(self.data_file, 'w') as f:
            json.dump(data, f, indent=2)
```

### 3. Authentication Middleware
```python
# src/presentation/middleware/auth_middleware.py
from functools import wraps
from flask import request, jsonify, g
from ...services.auth_service import AuthService

auth_service = AuthService()

def auth_middleware(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            token = request.headers.get('Authorization', '').replace('Bearer ', '')
            
            if not token:
                return jsonify({
                    'success': False,
                    'error': 'Access denied. No token provided.'
                }), 401
            
            decoded = auth_service.verify_token(token)
            g.current_user = decoded
            return f(*args, **kwargs)
        except Exception as e:
            return jsonify({
                'success': False,
                'error': 'Invalid token.'
            }), 401
    
    return decorated_function
```

## Usage Instructions

### 1. Setup Project
```bash
# Create new Python project
mkdir mvp-python-example
cd mvp-python-example

# Copy MVP boilerplate and templates
cp tiers/mvp/code/minimal-boilerplate-python.tpl.py src/app.py
cp -r stacks/python/base/code/* src/
cp -r stacks/python/base/tests/* test/

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install flask flask-cors pyjwt bcrypt python-dotenv
pip install pytest pytest-asyncio
```

### 2. Environment Setup
```bash
# Create .env file
echo "JWT_SECRET=your-super-secret-jwt-key-here" > .env
echo "FLASK_ENV=development" >> .env
echo "FLASK_PORT=3000" >> .env
```

### 3. Run the Application
```bash
# Development mode
flask run

# Production mode
gunicorn -w 4 -b 0.0.0.0:3000 src.app:app

# Start with specific port
FLASK_PORT=3001 flask run
```

### 4. Test the Application
```bash
# Run all tests
python -m pytest

# Run tests with coverage
python -m pytest --cov=src

# Run tests in watch mode
python -m pytest --watch
```

## Example API Endpoints

### Authentication Routes
```python
# src/presentation/routes/auth_routes.py
from flask import Blueprint, request, jsonify
from ..controllers.auth_controller import AuthController

auth_bp = Blueprint('auth', __name__)
auth_controller = AuthController()

@auth_bp.route('/login', methods=['POST'])
async def login():
    return await auth_controller.login()

@auth_bp.route('/logout', methods=['POST'])
async def logout():
    return await auth_controller.logout()

@auth_bp.route('/me', methods=['GET'])
async def get_current_user():
    return await auth_controller.get_current_user()
```

### Task Routes
```python
# src/presentation/routes/task_routes.py
from flask import Blueprint, request, jsonify
from ..controllers.task_controller import TaskController
from ..middleware.auth_middleware import auth_middleware

task_bp = Blueprint('tasks', __name__)
task_controller = TaskController()

# Apply authentication middleware to all routes
@task_bp.before_request
async def require_auth():
    return auth_middleware(lambda: None)()

@task_bp.route('/', methods=['GET'])
async def get_tasks():
    return await task_controller.get_tasks()

@task_bp.route('/', methods=['POST'])
async def create_task():
    return await task_controller.create_task()

@task_bp.route('/<int:task_id>', methods=['PUT'])
async def update_task(task_id):
    return await task_controller.update_task(task_id)

@task_bp.route('/<int:task_id>', methods=['DELETE'])
async def delete_task(task_id):
    return await task_controller.delete_task(task_id)

@task_bp.route('/<int:task_id>', methods=['GET'])
async def get_task_by_id(task_id):
    return await task_controller.get_task_by_id(task_id)
```

### Controllers
```python
# src/presentation/controllers/auth_controller.py
from flask import request, jsonify, g
from ...services.auth_service import AuthService

class AuthController:
    def __init__(self):
        self.auth_service = AuthService()
    
    async def login(self):
        try:
            data = request.get_json()
            email = data.get('email')
            password = data.get('password')
            
            if not email or not password:
                return jsonify({
                    'success': False,
                    'error': 'Email and password are required'
                }), 400
            
            result = await self.auth_service.login(email, password)
            
            if result['success']:
                return jsonify(result), 200
            else:
                return jsonify(result), 401
        except Exception as e:
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500
    
    async def logout(self):
        try:
            # In a real app, you might want to invalidate the token
            return jsonify({
                'success': True,
                'message': 'Logged out successfully'
            }), 200
        except Exception as e:
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500
    
    async def get_current_user(self):
        try:
            user = g.current_user
            return jsonify({
                'success': True,
                'user': {
                    'id': user['user_id'],
                    'email': user['email']
                }
            }), 200
        except Exception as e:
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500
```

### Main Application
```python
# src/app.py - MVP boilerplate
import os
from flask import Flask, jsonify
from flask_cors import CORS
from dotenv import load_dotenv

from .presentation.routes.auth_routes import auth_bp
from .presentation.routes.task_routes import task_bp
from .presentation.middleware.error_middleware import handle_error

load_dotenv()

def create_app():
    app = Flask(__name__)
    
    # Basic configuration
    app.config['SECRET_KEY'] = os.getenv('JWT_SECRET', 'fallback-secret')
    
    # CORS setup
    CORS(app)
    
    # Request logging
    @app.before_request
    def log_request():
        print(f"{datetime.utcnow().isoformat()} - {request.method} {request.path}")
    
    # Routes
    app.register_blueprint(auth_bp, url_prefix='/api/auth')
    app.register_blueprint(task_bp, url_prefix='/api/tasks')
    
    # Health check endpoint
    @app.route('/health')
    def health_check():
        return jsonify({
            'status': 'ok',
            'timestamp': datetime.utcnow().isoformat(),
            'uptime': str(datetime.utcnow() - start_time)
        })
    
    # API documentation endpoint
    @app.route('/')
    def api_docs():
        return jsonify({
            'name': 'MVP Python Example API',
            'version': '1.0.0',
            'endpoints': {
                'auth': {
                    'login': 'POST /api/auth/login',
                    'logout': 'POST /api/auth/logout',
                    'me': 'GET /api/auth/me'
                },
                'tasks': {
                    'get_tasks': 'GET /api/tasks',
                    'create_task': 'POST /api/tasks',
                    'update_task': 'PUT /api/tasks/<id>',
                    'delete_task': 'DELETE /api/tasks/<id>',
                    'get_task': 'GET /api/tasks/<id>'
                }
            }
        })
    
    # Error handling
    app.register_error_handler(500, handle_error)
    app.register_error_handler(404, lambda e: jsonify({
        'success': False,
        'error': 'Route not found'
    }), 404)
    
    return app

if __name__ == '__main__':
    start_time = datetime.utcnow()
    app = create_app()
    port = int(os.getenv('FLASK_PORT', 3000))
    
    print(f"Server running on port {port}")
    print(f"Health check: http://localhost:{port}/health")
    print(f"API docs: http://localhost:{port}/")
    
    app.run(debug=True, port=port)
```

## Testing Examples

### Unit Test for Auth Service
```python
# test/unit/services/test_auth_service.py
import pytest
import asyncio
from src.services.auth_service import AuthService

class TestAuthService:
    def setup_method(self):
        self.auth_service = AuthService()
    
    @pytest.mark.asyncio
    async def test_login_valid_credentials(self):
        result = await self.auth_service.login('test@example.com', 'password')
        
        assert result['success'] is True
        assert 'token' in result
        assert result['user']['email'] == 'test@example.com'
    
    @pytest.mark.asyncio
    async def test_login_invalid_email(self):
        result = await self.auth_service.login('invalid-email', 'password')
        
        assert result['success'] is False
        assert 'Invalid email' in result['error']
    
    @pytest.mark.asyncio
    async def test_login_invalid_credentials(self):
        result = await self.auth_service.login('test@example.com', 'wrong-password')
        
        assert result['success'] is False
        assert 'Invalid credentials' in result['error']
    
    def test_verify_token_valid(self):
        # First get a token
        result = asyncio.run(self.auth_service.login('test@example.com', 'password'))
        token = result['token']
        
        # Then verify it
        decoded = self.auth_service.verify_token(token)
        
        assert decoded['user_id'] == 1
        assert decoded['email'] == 'test@example.com'
    
    def test_verify_token_invalid(self):
        with pytest.raises(ValueError, match='Invalid token'):
            self.auth_service.verify_token('invalid-token')
```

### Integration Test for API
```python
# test/integration/test_auth.py
import pytest
import json
from src.app import create_app

@pytest.fixture
def app():
    app = create_app()
    app.config['TESTING'] = True
    return app

@pytest.fixture
def client(app):
    return app.test_client()

@pytest.fixture
def auth_token(client):
    # Login to get token
    response = client.post('/api/auth/login', 
                          json={'email': 'test@example.com', 'password': 'password'})
    return json.loads(response.data)['token']

class TestAuthAPI:
    def test_login_valid_credentials(self, client):
        response = client.post('/api/auth/login', 
                              json={'email': 'test@example.com', 'password': 'password'})
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['success'] is True
        assert 'token' in data
        assert data['user']['email'] == 'test@example.com'
    
    def test_login_invalid_credentials(self, client):
        response = client.post('/api/auth/login', 
                              json={'email': 'test@example.com', 'password': 'wrong-password'})
        
        assert response.status_code == 401
        data = json.loads(response.data)
        assert data['success'] is False
    
    def test_login_missing_fields(self, client):
        response = client.post('/api/auth/login', json={})
        
        assert response.status_code == 400
        data = json.loads(response.data)
        assert 'required' in data['error'].lower()
    
    def test_get_current_user_valid_token(self, client, auth_token):
        response = client.get('/api/auth/me', 
                             headers={'Authorization': f'Bearer {auth_token}'})
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['success'] is True
        assert data['user']['email'] == 'test@example.com'
    
    def test_get_current_user_no_token(self, client):
        response = client.get('/api/auth/me')
        
        assert response.status_code == 401
        data = json.loads(response.data)
        assert data['success'] is False
```

## API Usage Examples

### Using the API with curl
```bash
# Login
curl -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"password"}'

# Get tasks (requires token)
TOKEN="your-jwt-token-here"
curl -X GET http://localhost:3000/api/tasks \
  -H "Authorization: Bearer $TOKEN"

# Create task
curl -X POST http://localhost:3000/api/tasks \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"title":"New Task","description":"Task description"}'

# Update task
curl -X PUT http://localhost:3000/api/tasks/1234567890 \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"is_completed":true}'

# Delete task
curl -X DELETE http://localhost:3000/api/tasks/1234567890 \
  -H "Authorization: Bearer $TOKEN"
```

## Key MVP Patterns Demonstrated

1. **Simple Authentication**: JWT-based authentication with local user storage
2. **File-based Storage**: Tasks stored in JSON file
3. **Basic Middleware**: Authentication and error handling middleware
4. **RESTful API**: Standard CRUD operations with proper HTTP methods
5. **Minimal Dependencies**: Only essential Python packages
6. **Error Handling**: Centralized error handling and logging
7. **Testing Coverage**: Unit tests for services, integration tests for API

## Deployment Instructions

### 1. Traditional Server
```bash
# Install production dependencies
pip install gunicorn

# Start production server
gunicorn -w 4 -b 0.0.0.0:3000 src.app:app
```

### 2. Docker
```dockerfile
# Dockerfile
FROM python:3.9-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
EXPOSE 3000

CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:3000", "src.app:app"]
```

```bash
# Build and run
docker build -t mvp-python-example .
docker run -p 3000:3000 mvp-python-example
```

### 3. Cloud Platforms
```bash
# Deploy to Heroku
heroku create
git push heroku main

# Deploy to PythonAnywhere
# Use web interface or API
```

## Next Steps

This example provides a complete MVP foundation that can be extended with:
- Database integration (PostgreSQL, MySQL, MongoDB)
- Advanced authentication (OAuth, SSO)
- API documentation (Swagger/OpenAPI)
- Rate limiting and security features
- Monitoring and logging
- Caching with Redis
- Asynchronous task processing

---

**Note**: This example demonstrates the MVP tier capabilities with minimal complexity while maintaining a functional, testable backend API structure.
