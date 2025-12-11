# Universal Template System - Unknown Stack
# Generated: 2025-12-10
# Purpose: unknown template utilities
# Tier: mvp
# Stack: unknown
# Category: template

# MVP Node.js Example Project

## Overview

This example demonstrates a complete MVP Node.js backend application using the minimal boilerplate template with JWT authentication, basic CRUD operations, and simple API endpoints.

## Project Structure

```
mvp_node_example/
├── src/
│   ├── app.js                        # MVP boilerplate entry point
│   ├── config/
│   │   ├── appConfig.js              # MVP configuration
│   │   └── envConfig.js              # Environment settings
│   ├── core/
│   │   ├── constants.js              # App constants
│   │   ├── middleware.js             # Express middleware
│   │   └── routes.js                 # Route definitions
│   ├── data/
│   │   ├── models/
│   │   │   ├── user.js                # User model
│   │   │   └── task.js                # Task model
│   │   ├── services/
│   │   │   ├── authService.js         # Authentication service
│   │   │   └── taskService.js         # Task management service
│   │   └── repositories/
│   │       └── taskRepository.js      # Task data repository
│   ├── presentation/
│   │   ├── controllers/
│   │   │   ├── authController.js      # Authentication endpoints
│   │   │   └── taskController.js      # Task CRUD endpoints
│   │   ├── routes/
│   │   │   ├── authRoutes.js          # Authentication routes
│   │   │   └── taskRoutes.js          # Task routes
│   │   └── middleware/
│   │       ├── authMiddleware.js      # JWT verification
│   │       └── errorMiddleware.js     # Error handling
│   └── utils/
│       ├── helpers.js                 # Utility functions
│       └── validators.js              # Input validation
├── test/
│   ├── unit/
│   │   ├── services/
│   │   │   ├── authService.test.js
│   │   │   └── taskService.test.js
│   │   └── controllers/
│   │       ├── authController.test.js
│   │       └── taskController.test.js
│   └── integration/
│       ├── auth.test.js
│       └── tasks.test.js
├── data/
│   └── tasks.json                     # File-based storage
├── package.json                       # Dependencies
└── README.md                          # Project documentation
```

## Key Features Demonstrated

### 1. JWT Authentication
```javascript
// src/services/authService.js
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');

class AuthService {
  constructor() {
    this.jwtSecret = process.env.JWT_SECRET || 'fallback-secret';
    this.users = [
      {
        id: 1,
        email: 'test@example.com',
        password: bcrypt.hashSync('password', 10)
      }
    ];
  }
  
  async login(email, password) {
    try {
      // Basic validation
      if (!this.validateEmail(email)) {
        throw new Error('Invalid email format');
      }
      
      // Find user
      const user = this.users.find(u => u.email === email);
      if (!user) {
        throw new Error('User not found');
      }
      
      // Verify password
      const isValidPassword = await bcrypt.compare(password, user.password);
      if (!isValidPassword) {
        throw new Error('Invalid credentials');
      }
      
      // Generate JWT token
      const token = jwt.sign(
        { userId: user.id, email: user.email },
        this.jwtSecret,
        { expiresIn: '24h' }
      );
      
      return {
        success: true,
        token,
        user: { id: user.id, email: user.email }
      };
    } catch (error) {
      return { success: false, error: error.message };
    }
  }
  
  verifyToken(token) {
    try {
      return jwt.verify(token, this.jwtSecret);
    } catch (error) {
      throw new Error('Invalid token');
    }
  }
  
  validateEmail(email) {
    const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return re.test(email);
  }
}

module.exports = new AuthService();
```

### 2. Task CRUD Operations
```javascript
// src/services/taskService.js
const fs = require('fs').promises;
const path = require('path');

class TaskService {
  constructor() {
    this.dataFile = path.join(__dirname, '../../data/tasks.json');
  }
  
  async getTasks() {
    try {
      // Simulate API delay
      await new Promise(resolve => setTimeout(resolve, 200));
      
      const data = await this.readDataFile();
      return data || [];
    } catch (error) {
      console.error('Error getting tasks:', error);
      return [];
    }
  }
  
  async createTask(taskData) {
    try {
      const tasks = await this.getTasks();
      const newTask = {
        id: Date.now(),
        title: taskData.title,
        description: taskData.description || '',
        isCompleted: false,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        userId: taskData.userId
      };
      
      tasks.push(newTask);
      await this.writeDataFile(tasks);
      
      return { success: true, task: newTask };
    } catch (error) {
      return { success: false, error: error.message };
    }
  }
  
  async updateTask(taskId, updates, userId) {
    try {
      const tasks = await this.getTasks();
      const index = tasks.findIndex(task => task.id === taskId && task.userId === userId);
      
      if (index === -1) {
        throw new Error('Task not found');
      }
      
      tasks[index] = {
        ...tasks[index],
        ...updates,
        updatedAt: new Date().toISOString()
      };
      
      await this.writeDataFile(tasks);
      return { success: true, task: tasks[index] };
    } catch (error) {
      return { success: false, error: error.message };
    }
  }
  
  async deleteTask(taskId, userId) {
    try {
      const tasks = await this.getTasks();
      const filteredTasks = tasks.filter(task => !(task.id === taskId && task.userId === userId));
      
      if (tasks.length === filteredTasks.length) {
        throw new Error('Task not found');
      }
      
      await this.writeDataFile(filteredTasks);
      return { success: true };
    } catch (error) {
      return { success: false, error: error.message };
    }
  }
  
  async getTasksByUser(userId) {
    try {
      const tasks = await this.getTasks();
      return tasks.filter(task => task.userId === userId);
    } catch (error) {
      return [];
    }
  }
  
  async readDataFile() {
    try {
      const data = await fs.readFile(this.dataFile, 'utf8');
      return JSON.parse(data);
    } catch (error) {
      if (error.code === 'ENOENT') {
        return [];
      }
      throw error;
    }
  }
  
  async writeDataFile(data) {
    await fs.mkdir(path.dirname(this.dataFile), { recursive: true });
    await fs.writeFile(this.dataFile, JSON.stringify(data, null, 2));
  }
}

module.exports = new TaskService();
```

### 3. Authentication Middleware
```javascript
// src/presentation/middleware/authMiddleware.js
const authService = require('../../services/authService');

const authMiddleware = (req, res, next) => {
  try {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    
    if (!token) {
      return res.status(401).json({
        success: false,
        error: 'Access denied. No token provided.'
      });
    }
    
    const decoded = authService.verifyToken(token);
    req.user = decoded;
    next();
  } catch (error) {
    res.status(401).json({
      success: false,
      error: 'Invalid token.'
    });
  }
};

module.exports = authMiddleware;
```

## Usage Instructions

### 1. Setup Project
```bash
# Create new Node.js project
mkdir mvp-node-example
cd mvp-node-example
npm init -y

# Copy MVP boilerplate and templates
cp tiers/mvp/code/minimal-boilerplate-node.tpl.js src/app.js
cp -r stacks/node/base/code/* src/
cp -r stacks/node/base/tests/* test/

# Install dependencies
npm install express cors helmet bcryptjs jsonwebtoken
npm install --save-dev jest supertest nodemon
```

### 2. Environment Setup
```bash
# Create .env file
echo "JWT_SECRET=your-super-secret-jwt-key-here" > .env
echo "PORT=3000" >> .env
echo "NODE_ENV=development" >> .env
```

### 3. Run the Application
```bash
# Development mode
npm run dev

# Production mode
npm start

# Start with specific port
PORT=3001 npm run dev
```

### 4. Test the Application
```bash
# Run all tests
npm test

# Run tests in watch mode
npm run test:watch

# Run tests with coverage
npm run test:coverage
```

## Example API Endpoints

### Authentication Routes
```javascript
// src/presentation/routes/authRoutes.js
const express = require('express');
const router = express.Router();
const authController = require('../controllers/authController');

// Login endpoint
router.post('/login', authController.login);

// Logout endpoint (protected)
router.post('/logout', authController.logout);

// Get current user (protected)
router.get('/me', authController.getCurrentUser);

module.exports = router;
```

### Task Routes
```javascript
// src/presentation/routes/taskRoutes.js
const express = require('express');
const router = express.Router();
const taskController = require('../controllers/taskController');
const authMiddleware = require('../middleware/authMiddleware');

// Apply authentication middleware to all routes
router.use(authMiddleware);

// CRUD operations for tasks
router.get('/', taskController.getTasks);
router.post('/', taskController.createTask);
router.put('/:id', taskController.updateTask);
router.delete('/:id', taskController.deleteTask);

// Get task by ID
router.get('/:id', taskController.getTaskById);

module.exports = router;
```

### Controllers
```javascript
// src/presentation/controllers/authController.js
const authService = require('../../services/authService');

class AuthController {
  async login(req, res) {
    try {
      const { email, password } = req.body;
      
      if (!email || !password) {
        return res.status(400).json({
          success: false,
          error: 'Email and password are required'
        });
      }
      
      const result = await authService.login(email, password);
      
      if (result.success) {
        res.json(result);
      } else {
        res.status(401).json(result);
      }
    } catch (error) {
      res.status(500).json({
        success: false,
        error: error.message
      });
    }
  }
  
  async logout(req, res) {
    try {
      // In a real app, you might want to invalidate the token
      res.json({
        success: true,
        message: 'Logged out successfully'
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: error.message
      });
    }
  }
  
  async getCurrentUser(req, res) {
    try {
      res.json({
        success: true,
        user: {
          id: req.user.userId,
          email: req.user.email
        }
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: error.message
      });
    }
  }
}

module.exports = new AuthController();
```

### Main Application
```javascript
// src/app.js - MVP boilerplate
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
require('dotenv').config();

const authRoutes = require('./presentation/routes/authRoutes');
const taskRoutes = require('./presentation/routes/taskRoutes');
const errorMiddleware = require('./presentation/middleware/errorMiddleware');

const app = express();
const PORT = process.env.PORT || 3000;

// Basic middleware
app.use(helmet());
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Request logging
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} - ${req.method} ${req.path}`);
  next();
});

// Routes
app.use('/api/auth', authRoutes);
app.use('/api/tasks', taskRoutes);

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    uptime: process.uptime()
  });
});

// API documentation endpoint
app.get('/', (req, res) => {
  res.json({
    name: 'MVP Node.js Example API',
    version: '1.0.0',
    endpoints: {
      auth: {
        login: 'POST /api/auth/login',
        logout: 'POST /api/auth/logout',
        me: 'GET /api/auth/me'
      },
      tasks: {
        getTasks: 'GET /api/tasks',
        createTask: 'POST /api/tasks',
        updateTask: 'PUT /api/tasks/:id',
        deleteTask: 'DELETE /api/tasks/:id',
        getTask: 'GET /api/tasks/:id'
      }
    }
  });
});

// Error handling middleware
app.use(errorMiddleware);

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({
    success: false,
    error: 'Route not found'
  });
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Health check: http://localhost:${PORT}/health`);
  console.log(`API docs: http://localhost:${PORT}/`);
});

module.exports = app;
```

## Testing Examples

### Unit Test for Auth Service
```javascript
// test/unit/services/authService.test.js
const authService = require('../../../src/services/authService');

describe('AuthService', () => {
  describe('login', () => {
    it('should login with valid credentials', async () => {
      const result = await authService.login('test@example.com', 'password');
      
      expect(result.success).toBe(true);
      expect(result.token).toBeDefined();
      expect(result.user.email).toBe('test@example.com');
    });
    
    it('should fail login with invalid email', async () => {
      const result = await authService.login('invalid-email', 'password');
      
      expect(result.success).toBe(false);
      expect(result.error).toContain('Invalid email');
    });
    
    it('should fail login with invalid credentials', async () => {
      const result = await authService.login('test@example.com', 'wrong-password');
      
      expect(result.success).toBe(false);
      expect(result.error).toContain('Invalid credentials');
    });
  });
  
  describe('verifyToken', () => {
    it('should verify valid token', async () => {
      const loginResult = await authService.login('test@example.com', 'password');
      const decoded = authService.verifyToken(loginResult.token);
      
      expect(decoded.userId).toBe(1);
      expect(decoded.email).toBe('test@example.com');
    });
    
    it('should throw error for invalid token', () => {
      expect(() => {
        authService.verifyToken('invalid-token');
      }).toThrow('Invalid token');
    });
  });
});
```

### Integration Test for API
```javascript
// test/integration/auth.test.js
const request = require('supertest');
const app = require('../../src/app');

describe('Auth API', () => {
  describe('POST /api/auth/login', () => {
    it('should login with valid credentials', async () => {
      const response = await request(app)
        .post('/api/auth/login')
        .send({
          email: 'test@example.com',
          password: 'password'
        });
      
      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
      expect(response.body.token).toBeDefined();
      expect(response.body.user.email).toBe('test@example.com');
    });
    
    it('should fail login with invalid credentials', async () => {
      const response = await request(app)
        .post('/api/auth/login')
        .send({
          email: 'test@example.com',
          password: 'wrong-password'
        });
      
      expect(response.status).toBe(401);
      expect(response.body.success).toBe(false);
    });
    
    it('should require email and password', async () => {
      const response = await request(app)
        .post('/api/auth/login')
        .send({});
      
      expect(response.status).toBe(400);
      expect(response.body.error).toContain('required');
    });
  });
  
  describe('GET /api/auth/me', () => {
    it('should return current user with valid token', async () => {
      // First login to get token
      const loginResponse = await request(app)
        .post('/api/auth/login')
        .send({
          email: 'test@example.com',
          password: 'password'
        });
      
      const token = loginResponse.body.token;
      
      // Then get current user
      const response = await request(app)
        .get('/api/auth/me')
        .set('Authorization', `Bearer ${token}`);
      
      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
      expect(response.body.user.email).toBe('test@example.com');
    });
    
    it('should fail without token', async () => {
      const response = await request(app)
        .get('/api/auth/me');
      
      expect(response.status).toBe(401);
      expect(response.body.success).toBe(false);
    });
  });
});
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
  -d '{"isCompleted":true}'

# Delete task
curl -X DELETE http://localhost:3000/api/tasks/1234567890 \
  -H "Authorization: Bearer $TOKEN"
```

## Key MVP Patterns Demonstrated

1. **Simple Authentication**: JWT-based authentication with local user storage
2. **File-based Storage**: Tasks stored in JSON file
3. **Basic Middleware**: Authentication and error handling middleware
4. **RESTful API**: Standard CRUD operations with proper HTTP methods
5. **Minimal Dependencies**: Only essential Node.js packages
6. **Error Handling**: Centralized error handling and logging
7. **Testing Coverage**: Unit tests for services, integration tests for API

## Deployment Instructions

### 1. Traditional Server
```bash
# Build and start
npm start

# Use PM2 for process management
npm install -g pm2
pm2 start ecosystem.config.js
```

### 2. Docker
```dockerfile
# Dockerfile
FROM node:16-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production
COPY . .
EXPOSE 3000
CMD ["npm", "start"]
```

```bash
# Build and run
docker build -t mvp-node-example .
docker run -p 3000:3000 mvp-node-example
```

### 3. Cloud Platforms
```bash
# Deploy to Heroku
heroku create
git push heroku main

# Deploy to Vercel (serverless)
npm install -g vercel
vercel --prod
```

## Next Steps

This example provides a complete MVP foundation that can be extended with:
- Database integration (PostgreSQL, MySQL, MongoDB)
- Advanced authentication (OAuth, SSO)
- API documentation (Swagger/OpenAPI)
- Rate limiting and security features
- Monitoring and logging
- Caching with Redis
- Message queues for async processing

---

**Note**: This example demonstrates the MVP tier capabilities with minimal complexity while maintaining a functional, testable backend API structure.
