<!--
File: mvp-node-setup.tpl.md
Purpose: Template for unknown implementation
Template Version: 1.0
-->

# MVP Node.js Setup Guide

## Overview

This guide extends the foundational Node.js templates with MVP-specific configurations for rapid backend development with minimal feature set.

## Prerequisites

- Node.js 16+
- npm or yarn
- Code editor (VS Code recommended)
- Git

## Quick Start

### 1. Project Setup

```bash
# Copy MVP Node.js boilerplate
cp tiers/mvp/code/minimal-boilerplate-node.tpl.js [project-name]/src/app.js

# Copy foundational templates
cp -r stacks/node/base/code/* [project-name]/src/
cp -r stacks/node/base/tests/* [project-name]/test/

# Setup dependencies
cp stacks/node/package.json.tpl [project-name]/package.json
cd [project-name]
npm install
```

### 2. Configuration

```javascript
// src/config/appConfig.js - extends foundational config
class AppConfig extends BaseConfig {
  async load() {
    await super.load();
    
    // MVP-specific settings
    this.enableAnalytics = false;
    this.enableCrashlytics = false;
    this.enableRemoteConfig = false;
    
    // Minimal feature set
    this.maxRetries = 2;
    this.timeout = 15000;
  }
}
```

## MVP Architecture

### Core Components

1. **Minimal Server Setup**
   - Express.js basics
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
├── app.js                    # MVP boilerplate
├── config/
│   ├── appConfig.js          # MVP-specific config
│   └── envConfig.js          # Environment settings
├── core/
│   ├── constants.js          # App constants
│   ├── middleware.js         # Express middleware
│   └── routes.js             # Route definitions
├── data/
│   ├── models/               # Data models
│   ├── services/             # Basic services
│   └── repositories/         # Simple repositories
├── presentation/
│   ├── controllers/          # API controllers
│   ├── routes/               # Route handlers
│   └── middleware/           # Custom middleware
└── utils/
    ├── helpers.js            # Utility functions
    └── validators.js         # Input validation
```

## MVP Features

### 1. Authentication

```javascript
// src/services/authService.js
class AuthService extends BaseService {
  // JWT authentication only
  async login(email, password) {
    try {
      // Basic validation
      if (!this.validateEmail(email)) {
        throw new Error('Invalid email');
      }
      
      // Generate JWT token
      const token = this.generateJWT({ email });
      return { success: true, token, user: { email } };
    } catch (error) {
      return { success: false, error: error.message };
    }
  }
  
  async logout(token) {
    // Basic token invalidation
    return { success: true };
  }
  
  generateJWT(payload) {
    return jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '24h' });
  }
}
```

### 2. Data Management

```javascript
// src/services/dataService.js
class DataService extends BaseService {
  // Simple file-based storage
  async getItems() {
    try {
      const data = await fs.readFile('./data/items.json', 'utf8');
      return JSON.parse(data);
    } catch (error) {
      return [];
    }
  }
  
  async saveItems(items) {
    try {
      await fs.writeFile('./data/items.json', JSON.stringify(items, null, 2));
      return { success: true };
    } catch (error) {
      return { success: false, error: error.message };
    }
  }
}
```

### 3. API Routes

```javascript
// src/presentation/routes/apiRoutes.js
const express = require('express');
const router = express.Router();
const ItemController = require('../controllers/itemController');

// Basic CRUD routes
router.get('/items', ItemController.getItems);
router.post('/items', ItemController.createItem);
router.put('/items/:id', ItemController.updateItem);
router.delete('/items/:id', ItemController.deleteItem);

// Authentication routes
router.post('/auth/login', AuthController.login);
router.post('/auth/logout', AuthController.logout);

module.exports = router;
```

## Configuration Options

### Environment Variables

```javascript
// src/config/envConfig.js
module.exports = {
  appName: '[[.ProjectName]]',
  port: process.env.PORT || 3000,
  apiBaseUrl: process.env.API_BASE_URL || 'https://api.example.com',
  
  // MVP-specific flags
  enableDebugMode: process.env.NODE_ENV !== 'production',
  enableLogging: process.env.ENABLE_LOGGING !== 'false',
  
  // API settings
  timeout: parseInt(process.env.API_TIMEOUT) || 15000,
  maxRetries: parseInt(process.env.MAX_RETRIES) || 2,
  
  // Security
  jwtSecret: process.env.JWT_SECRET || 'fallback-secret',
  bcryptRounds: parseInt(process.env.BCRYPT_ROUNDS) || 10,
};
```

### Feature Flags

```javascript
// src/config/featureFlags.js
module.exports = {
  // MVP features - minimal set
  enableFileStorage: true,
  enableJWTAuth: true,
  enableRateLimiting: false,
  enableCORS: true,
  enableCompression: false,
  enableHelmet: false,
  enableAnalytics: false,
  enableCrashlytics: false,
};
```

## Development Workflow

### 1. Local Development

```bash
# Start development server
npm run dev

# Start with nodemon
npm run dev:watch

# Start with specific port
PORT=3001 npm run dev
```

### 2. Testing

```bash
# Run all tests
npm test

# Run tests in watch mode
npm run test:watch

# Run tests with coverage
npm run test:coverage
```

### 3. Building

```bash
# Build for production
npm run build

# Start production server
npm start
```

## Deployment

### 1. Traditional Server

```bash
# Build and start
npm run build
npm start

# Use PM2 for process management
pm2 start ecosystem.config.js
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
# Deploy to Vercel
npm run deploy:vercel

# Deploy to Heroku
git push heroku main
```

## MVP Components

### 1. Basic Server

```javascript
// src/app.js - MVP boilerplate
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const apiRoutes = require('./presentation/routes/apiRoutes');
const { errorHandler } = require('./core/middleware');

const app = express();

// Basic middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Routes
app.use('/api', apiRoutes);

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Error handling
app.use(errorHandler);

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

module.exports = app;
```

### 2. Authentication Controller

```javascript
// src/presentation/controllers/authController.js
const AuthService = require('../../services/authService');

class AuthController {
  static async login(req, res) {
    try {
      const { email, password } = req.body;
      const authService = new AuthService();
      const result = await authService.login(email, password);
      
      if (result.success) {
        res.json(result);
      } else {
        res.status(401).json(result);
      }
    } catch (error) {
      res.status(500).json({ success: false, error: error.message });
    }
  }
  
  static async logout(req, res) {
    try {
      const authService = new AuthService();
      const result = await authService.logout(req.headers.authorization);
      res.json(result);
    } catch (error) {
      res.status(500).json({ success: false, error: error.message });
    }
  }
}

module.exports = AuthController;
```

### 3. Basic Service

```javascript
// src/services/baseService.js
const fs = require('fs').promises;
const path = require('path');

class BaseService {
  constructor() {
    this.config = require('../config/appConfig');
  }

  async handleError(error, res = null) {
    console.error('Service error:', error);
    
    if (res) {
      return res.status(500).json({
        success: false,
        error: error.message || 'An error occurred',
      });
    }
    
    return {
      success: false,
      error: error.message || 'An error occurred',
    };
  }

  validateEmail(email) {
    const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return re.test(email);
  }

  async ensureDataDir() {
    const dataDir = path.join(__dirname, '../../data');
    try {
      await fs.access(dataDir);
    } catch {
      await fs.mkdir(dataDir, { recursive: true });
    }
  }
}

module.exports = BaseService;
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
7. **Performance**: Add compression, CDN, optimization

## Best Practices

### 1. Code Organization

- Keep features separate and focused
- Use consistent naming conventions
- Follow Node.js style guidelines
- Document public APIs

### 2. Performance

- Use async/await properly
- Implement proper error handling
- Use compression for responses
- Optimize database queries

### 3. Security

- Validate all inputs
- Use HTTPS in production
- Implement proper authentication
- Sanitize outputs

## Troubleshooting

### Common Issues

1. **Port Conflicts**: Change PORT environment variable
2. **Module Not Found**: Check package.json and run npm install
3. **Permission Errors**: Check file permissions for data directory
4. **Memory Issues**: Implement proper cleanup and monitoring

### Debug Tips

- Use Node.js debugger for debugging
- Use console.log for quick debugging
- Check environment variables
- Monitor server logs

## Resources

- [Node.js Documentation](https://nodejs.org/docs/)
- [Express.js Guide](https://expressjs.com/en/guide/)
- [JWT Documentation](https://jwt.io/)
- [Node.js Best Practices](https://github.com/goldbergyoni/nodebestpractices)

## Next Steps

1. Review the foundational templates for detailed implementation
2. Customize the MVP boilerplate for your specific needs
3. Implement your business logic using the provided structure
4. Add tests for your custom code
5. Prepare for deployment

---

**Note**: This MVP setup provides a solid foundation for rapid backend development. When your application grows, consider upgrading to the Core tier for additional features and capabilities.
