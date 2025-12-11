<!--
File: mvp-react-example.tpl.md
Purpose: Template for unknown implementation
Template Version: 1.0
-->

# MVP React Example Project

## Overview

This example demonstrates a complete MVP React web application using the minimal boilerplate template with local authentication, basic CRUD operations, and simple routing.

## Project Structure

```
mvp_react_example/
├── public/
│   └── index.html
├── src/
│   ├── App.jsx                       # MVP boilerplate entry point
│   ├── config/
│   │   ├── appConfig.js              # MVP configuration
│   │   └── envConfig.js              # Environment settings
│   ├── core/
│   │   ├── constants.js              # App constants
│   │   ├── themes.js                 # Basic themes
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
│   │   ├── pages/
│   │   │   ├── HomePage.jsx           # Main dashboard
│   │   │   ├── LoginPage.jsx          # Authentication screen
│   │   │   ├── TasksPage.jsx          # Task management
│   │   │   └── SettingsPage.jsx       # App settings
│   │   ├── components/
│   │   │   ├── TaskCard.jsx            # Task display component
│   │   │   ├── TaskForm.jsx            # Task creation/editing form
│   │   │   └── LoadingComponent.jsx    # Loading indicator
│   │   └── context/
│   │       ├── AuthContext.jsx        # Authentication state
│   │       └── TaskContext.jsx        # Task management state
│   └── utils/
│       ├── helpers.js                 # Utility functions
│       └── validators.js              # Input validation
├── test/
│   ├── unit/
│   │   ├── services/
│   │   │   ├── authService.test.js
│   │   │   └── taskService.test.js
│   │   └── context/
│   │       ├── AuthContext.test.js
│   │       └── TaskContext.test.js
│   └── component/
│       ├── LoginPage.test.jsx
│       ├── TasksPage.test.jsx
│       └── TaskCard.test.jsx
├── package.json                      # Dependencies
└── README.md                         # Project documentation
```

## Key Features Demonstrated

### 1. Local Authentication
```javascript
// src/services/authService.js
class AuthService {
  constructor() {
    this.STORAGE_KEY = 'mvp_auth_data';
  }
  
  async login(email, password) {
    try {
      // Basic validation
      if (!this.validateEmail(email)) {
        throw new Error('Invalid email format');
      }
      
      // Local authentication (no backend)
      if (email === 'test@example.com' && password === 'password') {
        const user = { email, id: 1 };
        const token = 'mock-jwt-token-' + Date.now();
        
        // Save to localStorage
        const authData = { user, token };
        localStorage.setItem(this.STORAGE_KEY, JSON.stringify(authData));
        
        return { success: true, user, token };
      }
      
      throw new Error('Invalid credentials');
    } catch (error) {
      return { success: false, error: error.message };
    }
  }
  
  async logout() {
    try {
      localStorage.removeItem(this.STORAGE_KEY);
      return { success: true };
    } catch (error) {
      return { success: false, error: error.message };
    }
  }
  
  async checkAuthStatus() {
    try {
      const authData = localStorage.getItem(this.STORAGE_KEY);
      if (authData) {
        const { user, token } = JSON.parse(authData);
        return { success: true, user, token };
      }
      return { success: false };
    } catch (error) {
      return { success: false };
    }
  }
  
  validateEmail(email) {
    const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return re.test(email);
  }
}

export default new AuthService();
```

### 2. Task CRUD Operations
```javascript
// src/services/taskService.js
class TaskService {
  constructor() {
    this.STORAGE_KEY = 'mvp_tasks';
  }
  
  async getTasks() {
    try {
      // Simulate API call with local storage
      await new Promise(resolve => setTimeout(resolve, 300));
      
      const tasksData = localStorage.getItem(this.STORAGE_KEY);
      return tasksData ? JSON.parse(tasksData) : [];
    } catch (error) {
      console.error('Error getting tasks:', error);
      return [];
    }
  }
  
  async createTask(task) {
    try {
      const tasks = await this.getTasks();
      const newTask = {
        ...task,
        id: Date.now(),
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        isCompleted: false,
      };
      
      tasks.push(newTask);
      localStorage.setItem(this.STORAGE_KEY, JSON.stringify(tasks));
      
      return { success: true, task: newTask };
    } catch (error) {
      return { success: false, error: error.message };
    }
  }
  
  async updateTask(taskId, updates) {
    try {
      const tasks = await this.getTasks();
      const index = tasks.findIndex(task => task.id === taskId);
      
      if (index !== -1) {
        tasks[index] = {
          ...tasks[index],
          ...updates,
          updatedAt: new Date().toISOString(),
        };
        
        localStorage.setItem(this.STORAGE_KEY, JSON.stringify(tasks));
        return { success: true, task: tasks[index] };
      }
      
      return { success: false, error: 'Task not found' };
    } catch (error) {
      return { success: false, error: error.message };
    }
  }
  
  async deleteTask(taskId) {
    try {
      const tasks = await this.getTasks();
      const filteredTasks = tasks.filter(task => task.id !== taskId);
      
      localStorage.setItem(this.STORAGE_KEY, JSON.stringify(filteredTasks));
      return { success: true };
    } catch (error) {
      return { success: false, error: error.message };
    }
  }
}

export default new TaskService();
```

### 3. Authentication Context
```javascript
// src/context/AuthContext.jsx
import React, { createContext, useState, useEffect, useContext } from 'react';
import authService from '../services/authService';

const AuthContext = createContext();

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  
  useEffect(() => {
    checkAuthStatus();
  }, []);
  
  const checkAuthStatus = async () => {
    try {
      const result = await authService.checkAuthStatus();
      if (result.success) {
        setUser(result.user);
      }
    } catch (error) {
      setError(error.message);
    } finally {
      setLoading(false);
    }
  };
  
  const login = async (email, password) => {
    try {
      setError(null);
      const result = await authService.login(email, password);
      
      if (result.success) {
        setUser(result.user);
      } else {
        setError(result.error);
      }
      
      return result;
    } catch (error) {
      setError(error.message);
      return { success: false, error: error.message };
    }
  };
  
  const logout = async () => {
    try {
      await authService.logout();
      setUser(null);
      setError(null);
    } catch (error) {
      setError(error.message);
    }
  };
  
  const value = {
    user,
    loading,
    error,
    login,
    logout,
  };
  
  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
};
```

## Usage Instructions

### 1. Setup Project
```bash
# Create new React project
npx create-react-app mvp-react-example
cd mvp-react-example

# Copy MVP boilerplate and templates
cp tiers/mvp/code/minimal-boilerplate-react.tpl.jsx src/App.jsx
cp -r stacks/react/base/code/* src/
cp -r stacks/react/base/tests/* test/

# Install additional dependencies
npm install react-router-dom
```

### 2. Run the Application
```bash
# Start development server
npm start

# Start with specific port
PORT=3001 npm start

# Start with HTTPS
HTTPS=true npm start
```

### 3. Test the Application
```bash
# Run all tests
npm test

# Run tests in watch mode
npm test -- --watch

# Run tests with coverage
npm test -- --coverage
```

## Example Components

### Login Page
```jsx
// src/presentation/pages/LoginPage.jsx
import React, { useState, useContext } from 'react';
import { useAuth } from '../context/AuthContext';
import './LoginPage.css';

const LoginPage = () => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const { login, loading, error } = useAuth();
  
  const handleSubmit = async (e) => {
    e.preventDefault();
    
    if (!email || !password) {
      alert('Please fill in all fields');
      return;
    }
    
    const result = await login(email, password);
    if (result.success) {
      // Navigation will be handled by AuthContext
    } else {
      alert(`Login Failed: ${result.error}`);
    }
  };
  
  return (
    <div className="login-container">
      <div className="login-card">
        <h1 className="login-title">Welcome Back</h1>
        <p className="login-subtitle">Sign in to continue</p>
        
        <form onSubmit={handleSubmit} className="login-form">
          <div className="form-group">
            <label htmlFor="email">Email</label>
            <input
              type="email"
              id="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="Enter your email"
              className="form-input"
              required
            />
          </div>
          
          <div className="form-group">
            <label htmlFor="password">Password</label>
            <div className="password-input-container">
              <input
                type={showPassword ? 'text' : 'password'}
                id="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="Enter your password"
                className="form-input"
                required
              />
              <button
                type="button"
                className="password-toggle"
                onClick={() => setShowPassword(!showPassword)}
              >
                {showPassword ? '👁️' : '👁️‍🗨️'}
              </button>
            </div>
          </div>
          
          {error && <div className="error-message">{error}</div>}
          
          <button
            type="submit"
            className="login-button"
            disabled={loading}
          >
            {loading ? 'Signing in...' : 'Sign In'}
          </button>
          
          <div className="demo-credentials">
            <p>Demo credentials:</p>
            <p>Email: test@example.com</p>
            <p>Password: password</p>
          </div>
        </form>
      </div>
    </div>
  );
};

export default LoginPage;
```

### Tasks Management Page
```jsx
// src/presentation/pages/TasksPage.jsx
import React, { useState, useEffect, useContext } from 'react';
import { TaskContext } from '../context/TaskContext';
import TaskCard from '../components/TaskCard';
import TaskForm from '../components/TaskForm';
import './TasksPage.css';

const TasksPage = () => {
  const { tasks, loading, loadTasks, addTask, updateTask, deleteTask } = useContext(TaskContext);
  const [showAddForm, setShowAddForm] = useState(false);
  const [filter, setFilter] = useState('all'); // all, active, completed
  
  useEffect(() => {
    loadTasks();
  }, []);
  
  const handleAddTask = async (task) => {
    const result = await addTask(task);
    if (result.success) {
      setShowAddForm(false);
    }
  };
  
  const handleToggleTask = async (task) => {
    await updateTask(task.id, { isCompleted: !task.isCompleted });
  };
  
  const handleDeleteTask = async (taskId) => {
    if (window.confirm('Are you sure you want to delete this task?')) {
      await deleteTask(taskId);
    }
  };
  
  const filteredTasks = tasks.filter(task => {
    if (filter === 'active') return !task.isCompleted;
    if (filter === 'completed') return task.isCompleted;
    return true;
  });
  
  const stats = {
    total: tasks.length,
    active: tasks.filter(t => !t.isCompleted).length,
    completed: tasks.filter(t => t.isCompleted).length,
  };
  
  return (
    <div className="tasks-page">
      <div className="tasks-header">
        <h1>Tasks</h1>
        <button
          className="add-task-button"
          onClick={() => setShowAddForm(true)}
        >
          + Add Task
        </button>
      </div>
      
      <div className="tasks-stats">
        <span>Total: {stats.total}</span>
        <span>Active: {stats.active}</span>
        <span>Completed: {stats.completed}</span>
      </div>
      
      <div className="tasks-filters">
        <button
          className={`filter-button ${filter === 'all' ? 'active' : ''}`}
          onClick={() => setFilter('all')}
        >
          All
        </button>
        <button
          className={`filter-button ${filter === 'active' ? 'active' : ''}`}
          onClick={() => setFilter('active')}
        >
          Active
        </button>
        <button
          className={`filter-button ${filter === 'completed' ? 'active' : ''}`}
          onClick={() => setFilter('completed')}
        >
          Completed
        </button>
      </div>
      
      <div className="tasks-list">
        {loading ? (
          <div className="loading">Loading tasks...</div>
        ) : filteredTasks.length === 0 ? (
          <div className="empty-state">
            <h3>No tasks found</h3>
            <p>Tap "Add Task" to get started</p>
          </div>
        ) : (
          filteredTasks.map(task => (
            <TaskCard
              key={task.id}
              task={task}
              onToggle={() => handleToggleTask(task)}
              onDelete={() => handleDeleteTask(task.id)}
              onEdit={() => {/* Edit functionality */}}
            />
          ))
        )}
      </div>
      
      {showAddForm && (
        <TaskForm
          onSubmit={handleAddTask}
          onCancel={() => setShowAddForm(false)}
        />
      )}
    </div>
  );
};

export default TasksPage;
```

### Task Card Component
```jsx
// src/presentation/components/TaskCard.jsx
import React from 'react';
import './TaskCard.css';

const TaskCard = ({ task, onToggle, onDelete, onEdit }) => {
  const formatDate = (dateString) => {
    return new Date(dateString).toLocaleDateString();
  };
  
  return (
    <div className={`task-card ${task.isCompleted ? 'completed' : ''}`}>
      <div className="task-content">
        <div className="task-header">
          <h3 className="task-title">{task.title}</h3>
          <div className="task-actions">
            <button
              className="task-button edit-button"
              onClick={onEdit}
              title="Edit task"
            >
              ✏️
            </button>
            <button
              className="task-button delete-button"
              onClick={onDelete}
              title="Delete task"
            >
              🗑️
            </button>
          </div>
        </div>
        
        {task.description && (
          <p className="task-description">{task.description}</p>
        )}
        
        <div className="task-footer">
          <div className="task-checkbox">
            <input
              type="checkbox"
              checked={task.isCompleted}
              onChange={onToggle}
              id={`task-${task.id}`}
            />
            <label htmlFor={`task-${task.id}`}>
              {task.isCompleted ? 'Completed' : 'Active'}
            </label>
          </div>
          
          <div className="task-dates">
            <span className="task-date">
              Created: {formatDate(task.createdAt)}
            </span>
            {task.updatedAt !== task.createdAt && (
              <span className="task-date">
                Updated: {formatDate(task.updatedAt)}
              </span>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default TaskCard;
```

## Testing Examples

### Unit Test for Auth Service
```javascript
// test/unit/services/authService.test.js
import authService from '../../../src/services/authService';

// Mock localStorage
const localStorageMock = (() => {
  let store = {};
  return {
    getItem: jest.fn((key) => store[key] || null),
    setItem: jest.fn((key, value) => {
      store[key] = value.toString();
    }),
    removeItem: jest.fn((key) => {
      delete store[key];
    }),
    clear: jest.fn(() => {
      store = {};
    }),
  };
})();

Object.defineProperty(window, 'localStorage', {
  value: localStorageMock,
});

describe('AuthService', () => {
  beforeEach(() => {
    localStorageMock.clear();
    jest.clearAllMocks();
  });
  
  describe('login', () => {
    it('should login with valid credentials', async () => {
      const result = await authService.login('test@example.com', 'password');
      
      expect(result.success).toBe(true);
      expect(result.user.email).toBe('test@example.com');
      expect(result.token).toContain('mock-jwt-token');
      expect(localStorageMock.setItem).toHaveBeenCalled();
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
  
  describe('logout', () => {
    it('should logout successfully', async () => {
      const result = await authService.logout();
      
      expect(result.success).toBe(true);
      expect(localStorageMock.removeItem).toHaveBeenCalledWith('mvp_auth_data');
    });
  });
});
```

### Component Test for Login Page
```javascript
// test/component/LoginPage.test.jsx
import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { AuthProvider } from '../../src/context/AuthContext';
import LoginPage from '../../src/presentation/pages/LoginPage';

// Mock localStorage
const localStorageMock = (() => {
  let store = {};
  return {
    getItem: jest.fn((key) => store[key] || null),
    setItem: jest.fn((key, value) => {
      store[key] = value.toString();
    }),
    removeItem: jest.fn((key) => {
      delete store[key];
    }),
  };
})();

Object.defineProperty(window, 'localStorage', {
  value: localStorageMock,
});

describe('LoginPage', () => {
  it('should render login form correctly', () => {
    render(
      <AuthProvider>
        <LoginPage />
      </AuthProvider>
    );
    
    expect(screen.getByLabelText(/email/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/password/i)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /sign in/i })).toBeInTheDocument();
    expect(screen.getByText(/demo credentials/i)).toBeInTheDocument();
  });
  
  it('should show validation error for empty fields', async () => {
    const user = userEvent.setup();
    
    render(
      <AuthProvider>
        <LoginPage />
      </AuthProvider>
    );
    
    const submitButton = screen.getByRole('button', { name: /sign in/i });
    await user.click(submitButton);
    
    expect(screen.getByText(/please fill in all fields/i)).toBeInTheDocument();
  });
  
  it('should login successfully with valid credentials', async () => {
    const user = userEvent.setup();
    
    render(
      <AuthProvider>
        <LoginPage />
      </AuthProvider>
    );
    
    const emailInput = screen.getByLabelText(/email/i);
    const passwordInput = screen.getByLabelText(/password/i);
    const submitButton = screen.getByRole('button', { name: /sign in/i });
    
    await user.type(emailInput, 'test@example.com');
    await user.type(passwordInput, 'password');
    await user.click(submitButton);
    
    await waitFor(() => {
      // Login should succeed - no error message should appear
      expect(screen.queryByText(/login failed/i)).not.toBeInTheDocument();
    });
  });
});
```

## Key MVP Patterns Demonstrated

1. **Simple State Management**: Using React Context for basic state management
2. **Local Authentication**: No backend required, uses localStorage
3. **Local Storage**: Tasks stored in localStorage
4. **Basic Routing**: Simple client-side routing
5. **Minimal Dependencies**: Only essential React packages
6. **Error Handling**: Basic error display and logging
7. **Testing Coverage**: Unit tests for services, component tests for UI

## Deployment Instructions

### 1. Build for Production
```bash
# Build for production
npm run build

# Analyze bundle size
npm run analyze
```

### 2. Deploy to Static Hosting
```bash
# Deploy to Netlify
npm install -g netlify-cli
netlify deploy --prod --dir=build

# Deploy to Vercel
npm install -g vercel
vercel --prod

# Deploy to GitHub Pages
npm run deploy
```

### 3. Docker Deployment
```dockerfile
# Dockerfile
FROM node:16-alpine as build
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production
COPY . .
RUN npm run build

FROM nginx:alpine
COPY --from=build /app/build /usr/share/nginx/html
COPY nginx.conf /etc/nginx/nginx.conf
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
```

## Next Steps

This example provides a complete MVP foundation that can be extended with:
- Backend API integration
- Advanced state management (Redux, Zustand)
- Offline synchronization
- Progressive Web App features
- Analytics and crash reporting
- Advanced authentication (OAuth)

---

**Note**: This example demonstrates the MVP tier capabilities with minimal complexity while maintaining a functional, testable web application structure.
