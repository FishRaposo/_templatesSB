<!--
File: mvp-next-setup.tpl.md
Purpose: Template for unknown implementation
Template Version: 1.0
-->

# MVP React Setup Guide

## Overview

This guide extends the foundational React templates with MVP-specific configurations for rapid web application development with minimal feature set.

## Prerequisites

- Node.js 16+
- React 18+
- Modern web browser
- Code editor (VS Code recommended)

## Quick Start

### 1. Project Setup

```bash
# Copy MVP React boilerplate
cp tiers/mvp/code/minimal-boilerplate-react.tpl.jsx [project-name]/src/App.jsx

# Copy foundational templates
cp -r stacks/react/base/code/* [project-name]/src/
cp -r stacks/react/base/tests/* [project-name]/test/

# Setup dependencies
cp stacks/react/package.json.tpl [project-name]/package.json
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

1. **Minimal State Management**
   - React Context API
   - Simple state reducers
   - No complex state persistence

2. **Essential UI Components**
   - Basic HTML/CSS components
   - Common form components
   - Simple routing

3. **Basic Data Layer**
   - Local storage for data
   - Simple HTTP client
   - Basic caching

4. **Core Features**
   - Authentication (local)
   - Basic CRUD operations
   - Simple settings

## File Structure

```
src/
├── App.jsx                   # MVP boilerplate
├── config/
│   ├── appConfig.js          # MVP-specific config
│   └── envConfig.js          # Environment settings
├── core/
│   ├── constants.js          # App constants
│   ├── themes.js             # Basic themes
│   └── routes.js             # Route definitions
├── data/
│   ├── models/               # Data models
│   ├── services/             # Basic services
│   └── repositories/         # Simple repositories
├── presentation/
│   ├── pages/                # Main pages
│   ├── components/           # Common components
│   └── context/              # State management
└── utils/
    ├── helpers.js            # Utility functions
    └── validators.js         # Input validation
```

## MVP Features

### 1. Authentication

```javascript
// src/services/authService.js
class AuthService extends BaseService {
  // Local authentication only
  async login(email, password) {
    try {
      // Basic validation
      if (!this.validateEmail(email)) {
        throw new Error('Invalid email');
      }
      
      // Local storage
      localStorage.setItem('userToken', 'mock-token');
      return { success: true, user: { email } };
    } catch (error) {
      return { success: false, error: error.message };
    }
  }
  
  async logout() {
    localStorage.removeItem('userToken');
    return { success: true };
  }
}
```

### 2. Data Management

```javascript
// src/services/dataService.js
class DataService extends BaseService {
  // Simple HTTP calls
  async getItems() {
    try {
      const response = await this.httpClient.get('/items');
      return response.data;
    } catch (error) {
      // Fallback to cached data
      return this.getCachedItems();
    }
  }
  
  async getCachedItems() {
    const cached = localStorage.getItem('cachedItems');
    return cached ? JSON.parse(cached) : [];
  }
}
```

### 3. Routing

```javascript
// src/core/routes.js
import { BrowserRouter, Routes, Route } from 'react-router-dom';

export const AppRoutes = () => {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<HomePage />} />
        <Route path="/login" element={<LoginPage />} />
        <Route path="/settings" element={<SettingsPage />} />
      </Routes>
    </BrowserRouter>
  );
};
```

## Configuration Options

### Environment Variables

```javascript
// src/config/envConfig.js
export const EnvConfig = {
  appName: '[[.ProjectName]]',
  apiBaseUrl: process.env.REACT_APP_API_URL || 'https://api.example.com',
  
  // MVP-specific flags
  enableDebugMode: process.env.REACT_APP_DEBUG === 'true',
  enableLogging: process.env.REACT_APP_LOGGING !== 'false',
  
  // API settings
  timeout: parseInt(process.env.REACT_APP_TIMEOUT) || 15000,
  maxRetries: parseInt(process.env.REACT_APP_MAX_RETRIES) || 2,
};
```

### Feature Flags

```javascript
// src/config/featureFlags.js
export const FeatureFlags = {
  // MVP features - minimal set
  enableOfflineMode: true,
  enableDarkMode: true,
  enableNotifications: false,
  enableAnalytics: false,
  enableCrashlytics: false,
  enableSSO: false,
};
```

## Development Workflow

### 1. Local Development

```bash
# Start development server
npm start

# Start with specific port
npm start -- --port 3001

# Start with HTTPS
npm start -- --https
```

### 2. Testing

```bash
# Run all tests
npm test

# Run tests in watch mode
npm test -- --watch

# Run tests with coverage
npm test -- --coverage
```

### 3. Building

```bash
# Build for development
npm run build

# Build for production
npm run build:production

# Analyze bundle size
npm run analyze
```

## Deployment

### 1. Static Hosting

```bash
# Build for production
npm run build

# Deploy to Netlify
npm run deploy:netlify

# Deploy to Vercel
npm run deploy:vercel
```

### 2. Docker

```bash
# Build Docker image
docker build -t [[.ProjectName]] .

# Run container
docker run -p 3000:3000 [[.ProjectName]]
```

## MVP Components

### 1. Basic Pages

```javascript
// src/presentation/pages/HomePage.jsx
import React, { useContext } from 'react';
import { AuthContext } from '../context/AuthContext';

export const HomePage = () => {
  const { user, logout } = useContext(AuthContext);
  
  return (
    <div className="home-page">
      <h1>Welcome, {user?.email}</h1>
      <button onClick={() => window.location.href = '/settings'}>
        Go to Settings
      </button>
      <button onClick={logout}>
        Logout
      </button>
    </div>
  );
};
```

### 2. Authentication Context

```javascript
// src/presentation/context/AuthContext.js
import React, { createContext, useState, useEffect } from 'react';
import { AuthService } from '../../services/authService';

export const AuthContext = createContext();

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const authService = new AuthService();

  useEffect(() => {
    checkAuthStatus();
  }, []);

  const checkAuthStatus = () => {
    try {
      const token = localStorage.getItem('userToken');
      if (token) {
        setUser({ email: 'user@example.com' });
      }
    } catch (error) {
      console.error('Auth check failed:', error);
    } finally {
      setLoading(false);
    }
  };

  const login = async (email, password) => {
    const result = await authService.login(email, password);
    if (result.success) {
      setUser(result.user);
    }
    return result;
  };

  const logout = async () => {
    await authService.logout();
    setUser(null);
  };

  return (
    <AuthContext.Provider value={{ user, loading, login, logout }}>
      {children}
    </AuthContext.Provider>
  );
};
```

### 3. Basic Service

```javascript
// src/services/baseService.js
export class BaseService {
  constructor() {
    this.httpClient = new HttpClient();
    this.config = new AppConfig();
  }

  async handleError(error) {
    console.error('Service error:', error);
    // Basic error handling
    return {
      success: false,
      error: error.message || 'An error occurred',
    };
  }

  validateEmail(email) {
    const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return re.test(email);
  }
}
```

## MVP Limitations

### What's NOT Included

- No advanced state management (Redux, Zustand)
- No offline data synchronization
- No push notifications
- No analytics or crash reporting
- No advanced caching strategies
- No OAuth authentication
- No real-time features
- No server-side rendering
- No progressive web app features

### Upgrade Path

When ready to move to Core tier:

1. **State Management**: Upgrade to Redux or Zustand
2. **Data Layer**: Add offline sync and advanced caching
3. **Authentication**: Add OAuth providers
4. **Features**: Enable analytics, notifications, crashlytics
5. **Performance**: Add performance monitoring and optimization
6. **Deployment**: Add SSR, PWA, advanced hosting

## Best Practices

### 1. Code Organization

- Keep features separate and focused
- Use consistent naming conventions
- Follow React style guidelines
- Document public APIs

### 2. Performance

- Use React.memo for expensive components
- Implement proper code splitting
- Optimize bundle size
- Use proper state management patterns

### 3. Testing

- Write unit tests for business logic
- Write component tests for UI components
- Test error scenarios
- Maintain good test coverage

## Troubleshooting

### Common Issues

1. **Build Errors**: Check Node.js version and dependencies
2. **Import Errors**: Verify file paths and exports
3. **State Issues**: Review context setup and component re-renders
4. **Routing Problems**: Check route definitions and browser history

### Debug Tips

- Use React DevTools for debugging
- Use browser developer tools
- Use console.log for quick debugging
- Check network tab for API issues

## Resources

- [React Documentation](https://reactjs.org/docs/getting-started.html)
- [React Router](https://reactrouter.com/docs/en/v6)
- [React Testing Library](https://testing-library.com/docs/react-testing-library/intro)
- [Create React App](https://create-react-app.dev/)

## Next Steps

1. Review the foundational templates for detailed implementation
2. Customize the MVP boilerplate for your specific needs
3. Implement your business logic using the provided structure
4. Add tests for your custom code
5. Prepare for deployment

---

**Note**: This MVP setup provides a solid foundation for rapid web development. When your application grows, consider upgrading to the Core tier for additional features and capabilities.
