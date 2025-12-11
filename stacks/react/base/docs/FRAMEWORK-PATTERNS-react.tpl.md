# Universal Template System - React Stack
# Generated: 2025-12-10
# Purpose: react template utilities
# Tier: base
# Stack: react
# Category: template

# React Framework Patterns - {{PROJECT_NAME}}

**Tier**: {{TIER}} | **Stack**: React

## 🟢 React's Role in Your Ecosystem

React serves as the **frontend UI layer** - your "build interactive user interfaces fast" weapon. It handles component-based UI development, state management, routing, and user interactions with a declarative, component-first approach.

### **Core Responsibilities**
- **Component Architecture**: Reusable, composable UI components
- **State Management**: Local state, global state, and server state
- **Routing**: Client-side navigation and deep linking
- **User Interactions**: Event handling and form management
- **Performance**: Optimization and rendering efficiency

## 🏗️ Three Pillars Integration

### **1. Universal Principles Applied to React**
- **Component Architecture**: Atomic design with reusable components
- **State Management**: Predictable state flow with hooks and context
- **Testing Pyramid**: Component, integration, and E2E tests
- **Configuration Management**: Environment-based config management

### **2. Tier-Specific React Patterns**

#### **MVP Tier - Prototyping Mode**
**Purpose**: Validate UI ideas quickly with minimal complexity
**Characteristics**:
- Single-file components
- Simple useState/useEffect hooks
- Basic routing with React Router
- Minimal styling with inline styles or CSS modules
- Basic testing with React Testing Library

**When to Use**:
- UI proof of concepts
- Interactive prototypes
- Component libraries
- Learning React patterns

**MVP React Pattern**:
```tsx
// src/App.tsx - Single file MVP
import React, { useState } from 'react';
import { BrowserRouter as Router, Routes, Route, Link } from 'react-router-dom';

interface User {
  id: number;
  name: string;
  email: string;
}

function App() {
  const [users, setUsers] = useState<User[]>([]);
  const [loading, setLoading] = useState(false);

  const fetchUsers = async () => {
    setLoading(true);
    try {
      const response = await fetch('/api/users');
      const data = await response.json();
      setUsers(data);
    } catch (error) {
      console.error('Error fetching users:', error);
    } finally {
      setLoading(false);
    }
  };

  return (
    <Router>
      <div>
        <nav>
          <Link to="/">Home</Link> | <Link to="/users">Users</Link>
        </nav>
        
        <Routes>
          <Route path="/" element={<Home />} />
          <Route path="/users" element={<UserList users={users} loading={loading} onFetch={fetchUsers} />} />
        </Routes>
      </div>
    </Router>
  );
}

function Home() {
  return <h1>Welcome to {{PROJECT_NAME}}</h1>;
}

function UserList({ users, loading, onFetch }: {
  users: User[];
  loading: boolean;
  onFetch: () => void;
}) {
  return (
    <div>
      <h2>Users</h2>
      <button onClick={onFetch} disabled={loading}>
        {loading ? 'Loading...' : 'Fetch Users'}
      </button>
      
      <ul>
        {users.map(user => (
          <li key={user.id}>
            {user.name} - {user.email}
          </li>
        ))}
      </ul>
    </div>
  );
}

export default App;
```

#### **CORE Tier - Production Baseline**
**Purpose**: Real-world UI with proper architecture
**Characteristics**:
- Component-based architecture with hooks
- Context API for global state management
- Advanced routing with route guards
- Styled-components or Tailwind CSS
- Comprehensive testing (unit + integration)

**When to Use**:
- Production web applications
- SaaS frontends
- Enterprise dashboards
- Consumer-facing applications

**CORE React Pattern**:
```tsx
// src/contexts/AuthContext.tsx - Global state management
import React, { createContext, useContext, useReducer, useEffect } from 'react';
import { User } from '../types/user.types';

interface AuthState {
  user: User | null;
  isAuthenticated: boolean;
  loading: boolean;
  error: string | null;
}

interface AuthContextType extends AuthState {
  login: (email: string, password: string) => Promise<void>;
  logout: () => void;
  register: (userData: RegisterData) => Promise<void>;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

interface AuthProviderProps {
  children: React.ReactNode;
}

export function AuthProvider({ children }: AuthProviderProps) {
  const [state, dispatch] = useReducer(authReducer, initialState);

  useEffect(() => {
    // Check for existing session on mount
    checkAuthSession();
  }, []);

  const login = async (email: string, password: string) => {
    dispatch({ type: 'AUTH_START' });
    
    try {
      const response = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password }),
      });
      
      if (!response.ok) {
        throw new Error('Login failed');
      }
      
      const { user, token } = await response.json();
      
      localStorage.setItem('auth_token', token);
      dispatch({ type: 'AUTH_SUCCESS', payload: user });
      
    } catch (error) {
      dispatch({ type: 'AUTH_ERROR', payload: error.message });
    }
  };

  const logout = () => {
    localStorage.removeItem('auth_token');
    dispatch({ type: 'AUTH_LOGOUT' });
  };

  const register = async (userData: RegisterData) => {
    dispatch({ type: 'AUTH_START' });
    
    try {
      const response = await fetch('/api/auth/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(userData),
      });
      
      if (!response.ok) {
        throw new Error('Registration failed');
      }
      
      const { user, token } = await response.json();
      
      localStorage.setItem('auth_token', token);
      dispatch({ type: 'AUTH_SUCCESS', payload: user });
      
    } catch (error) {
      dispatch({ type: 'AUTH_ERROR', payload: error.message });
    }
  };

  return (
    <AuthContext.Provider value={{ ...state, login, logout, register }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}

// src/hooks/useApi.ts - Custom hook for API calls
import { useState, useEffect, useCallback } from 'react';

interface UseApiResult<T> {
  data: T | null;
  loading: boolean;
  error: string | null;
  refetch: () => void;
}

export function useApi<T>(url: string): UseApiResult<T> {
  const [data, setData] = useState<T | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const fetchData = useCallback(async () => {
    setLoading(true);
    setError(null);
    
    try {
      const response = await fetch(url);
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }
      const result = await response.json();
      setData(result);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, [url]);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  return { data, loading, error, refetch: fetchData };
}

// src/components/UserList.tsx - Component architecture
import React from 'react';
import { useApi } from '../hooks/useApi';
import { User } from '../types/user.types';
import { LoadingSpinner } from './LoadingSpinner';
import { ErrorMessage } from './ErrorMessage';

interface UserListProps {
  className?: string;
}

export function UserList({ className }: UserListProps) {
  const { data: users, loading, error, refetch } = useApi<User[]>('/api/users');

  if (loading) {
    return <LoadingSpinner />;
  }

  if (error) {
    return <ErrorMessage message={error} onRetry={refetch} />;
  }

  return (
    <div className={`user-list ${className || ''}`}>
      <h2>Users</h2>
      <div className="user-grid">
        {users?.map(user => (
          <UserCard key={user.id} user={user} />
        ))}
      </div>
    </div>
  );
}

interface UserCardProps {
  user: User;
}

function UserCard({ user }: UserCardProps) {
  return (
    <div className="user-card">
      <div className="user-avatar">
        <img src={user.avatar || '/default-avatar.png'} alt={user.name} />
      </div>
      <div className="user-info">
        <h3>{user.name}</h3>
        <p>{user.email}</p>
        <span className={`user-status ${user.isActive ? 'active' : 'inactive'}`}>
          {user.isActive ? 'Active' : 'Inactive'}
        </span>
      </div>
    </div>
  );
}
```

#### **FULL Tier - Enterprise Excellence**
**Purpose**: Large-scale UI with enterprise requirements
**Characteristics**:
- Advanced state management with Redux Toolkit or Zustand
- Micro-frontend architecture
- Advanced performance optimization
- Complete accessibility support
- Enterprise monitoring and analytics

**When to Use**:
- Fortune 500 web applications
- Multi-team enterprise projects
- High-traffic consumer applications
- Compliance-heavy applications

**FULL React Pattern**:
```tsx
// src/store/index.ts - Redux Toolkit for enterprise state management
import { configureStore, createSlice, createAsyncThunk } from '@reduxjs/toolkit';
import { User, Order } from '../types';

// Async thunks for complex operations
export const fetchUsers = createAsyncThunk(
  'users/fetchUsers',
  async (params: { page: number; limit: number }, { rejectWithValue }) => {
    try {
      const response = await fetch(`/api/users?page=${params.page}&limit=${params.limit}`);
      if (!response.ok) {
        throw new Error('Failed to fetch users');
      }
      return await response.json();
    } catch (error) {
      return rejectWithValue(error.message);
    }
  }
);

export const createUser = createAsyncThunk(
  'users/createUser',
  async (userData: CreateUserData, { rejectWithValue }) => {
    try {
      const response = await fetch('/api/users', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(userData),
      });
      
      if (!response.ok) {
        throw new Error('Failed to create user');
      }
      
      return await response.json();
    } catch (error) {
      return rejectWithValue(error.message);
    }
  }
);

// User slice with complex state management
const userSlice = createSlice({
  name: 'users',
  initialState: {
    users: [] as User[],
    loading: false,
    error: null as string | null,
    pagination: {
      page: 1,
      limit: 20,
      total: 0,
      totalPages: 0,
    },
    filters: {
      search: '',
      status: 'all',
      role: 'all',
    },
  },
  reducers: {
    setFilters: (state, action) => {
      state.filters = { ...state.filters, ...action.payload };
    },
    clearError: (state) => {
      state.error = null;
    },
    updateUser: (state, action) => {
      const index = state.users.findIndex(user => user.id === action.payload.id);
      if (index !== -1) {
        state.users[index] = action.payload;
      }
    },
  },
  extraReducers: (builder) => {
    builder
      .addCase(fetchUsers.pending, (state) => {
        state.loading = true;
        state.error = null;
      })
      .addCase(fetchUsers.fulfilled, (state, action) => {
        state.loading = false;
        state.users = action.payload.users;
        state.pagination = action.payload.pagination;
      })
      .addCase(fetchUsers.rejected, (state, action) => {
        state.loading = false;
        state.error = action.payload as string;
      })
      .addCase(createUser.pending, (state) => {
        state.loading = true;
        state.error = null;
      })
      .addCase(createUser.fulfilled, (state, action) => {
        state.loading = false;
        state.users.unshift(action.payload);
      })
      .addCase(createUser.rejected, (state, action) => {
        state.loading = false;
        state.error = action.payload as string;
      });
  },
});

export const store = configureStore({
  reducer: {
    users: userSlice.reducer,
    // Add other slices for orders, auth, etc.
  },
  middleware: (getDefaultMiddleware) =>
    getDefaultMiddleware({
      serializableCheck: {
        ignoredActions: ['persist/PERSIST'],
      },
    }),
});

// src/components/EnterpriseUserManagement.tsx - Complex enterprise component
import React, { useEffect, useState, useCallback } from 'react';
import { useDispatch, useSelector } from 'react-redux';
import { fetchUsers, createUser, setFilters } from '../store';
import { User, UserFilters } from '../types';
import { UserTable } from './UserTable';
import { UserFilters } from './UserFilters';
import { CreateUserModal } from './CreateUserModal';
import { Pagination } from './Pagination';
import { useDebounce } from '../hooks/useDebounce';
import { useAnalytics } from '../hooks/useAnalytics';

interface EnterpriseUserManagementProps {
  organizationId: string;
}

export function EnterpriseUserManagement({ organizationId }: EnterpriseUserManagementProps) {
  const dispatch = useDispatch();
  const { users, loading, error, pagination, filters } = useSelector(state => state.users);
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [selectedUsers, setSelectedUsers] = useState<string[]>([]);
  
  const { trackEvent } = useAnalytics();
  const debouncedFilters = useDebounce(filters, 300);

  // Fetch users when filters change
  useEffect(() => {
    dispatch(fetchUsers({
      page: pagination.page,
      limit: pagination.limit,
      ...debouncedFilters,
    }));
  }, [dispatch, pagination.page, pagination.limit, debouncedFilters]);

  const handleFilterChange = useCallback((newFilters: Partial<UserFilters>) => {
    dispatch(setFilters(newFilters));
    trackEvent('user_filters_changed', { filters: newFilters });
  }, [dispatch, trackEvent]);

  const handleUserSelect = useCallback((userId: string, selected: boolean) => {
    setSelectedUsers(prev => 
      selected 
        ? [...prev, userId]
        : prev.filter(id => id !== userId)
    );
  }, []);

  const handleBulkAction = useCallback(async (action: string) => {
    try {
      await fetch('/api/users/bulk-action', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ userIds: selectedUsers, action }),
      });
      
      trackEvent('bulk_action_completed', { action, userCount: selectedUsers.length });
      setSelectedUsers([]);
      dispatch(fetchUsers({ page: pagination.page, limit: pagination.limit }));
    } catch (error) {
      console.error('Bulk action failed:', error);
    }
  }, [selectedUsers, dispatch, pagination.page, pagination.limit, trackEvent]);

  const handleCreateUser = useCallback(async (userData: CreateUserData) => {
    try {
      await dispatch(createUser(userData)).unwrap();
      setShowCreateModal(false);
      trackEvent('user_created', { organizationId });
    } catch (error) {
      console.error('Failed to create user:', error);
    }
  }, [dispatch, organizationId, trackEvent]);

  return (
    <div className="enterprise-user-management">
      <div className="management-header">
        <h1>User Management</h1>
        <div className="header-actions">
          <button 
            onClick={() => setShowCreateModal(true)}
            className="btn btn-primary"
          >
            Create User
          </button>
          {selectedUsers.length > 0 && (
            <BulkActionsMenu 
              selectedCount={selectedUsers.length}
              onAction={handleBulkAction}
            />
          )}
        </div>
      </div>

      <UserFilters 
        filters={filters}
        onFilterChange={handleFilterChange}
      />

      <div className="management-content">
        <UserTable
          users={users}
          loading={loading}
          error={error}
          selectedUsers={selectedUsers}
          onUserSelect={handleUserSelect}
        />
        
        <Pagination
          pagination={pagination}
          onPageChange={(page) => dispatch(setFilters({ ...filters, page }))}
        />
      </div>

      {showCreateModal && (
        <CreateUserModal
          onClose={() => setShowCreateModal(false)}
          onSubmit={handleCreateUser}
        />
      )}
    </div>
  );
}

// src/hooks/useAnalytics.ts - Analytics tracking hook
import { useEffect } from 'react';
import { useAuth } from '../contexts/AuthContext';

interface AnalyticsEvent {
  event: string;
  properties?: Record<string, any>;
}

export function useAnalytics() {
  const { user } = useAuth();

  const trackEvent = useCallback((event: string, properties?: Record<string, any>) => {
    // Send to analytics service
    if (typeof window !== 'undefined' && window.analytics) {
      window.analytics.track(event, {
        userId: user?.id,
        timestamp: new Date().toISOString(),
        ...properties,
      });
    }
  }, [user]);

  const trackPageView = useCallback((page: string) => {
    if (typeof window !== 'undefined' && window.analytics) {
      window.analytics.page(page, {
        userId: user?.id,
      });
    }
  }, [user]);

  return { trackEvent, trackPageView };
}
```

## 📦 Blessed Patterns (Never Deviate)

### **State Management: React Hooks + Context**
**Why React Hooks + Context**:
- Built into React, no additional dependencies
- Excellent TypeScript support
- Component-scoped state management
- Easy to test and debug
- Performance optimized with useMemo and useCallback

**React Hooks Patterns**:
```tsx
// MVP: Simple useState
const [count, setCount] = useState(0);

// CORE: Custom hooks with context
function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within AuthProvider');
  }
  return context;
}

// FULL: Complex state management with reducers
const [state, dispatch] = useReducer(authReducer, initialState);
```

### **Routing: React Router**
**Why React Router**:
- De facto standard for React routing
- Excellent TypeScript support
- Code splitting and lazy loading
- Route guards and protected routes
- Deep linking support

**React Router Patterns**:
```tsx
// MVP: Simple routing
<Routes>
  <Route path="/" element={<Home />} />
  <Route path="/users" element={<Users />} />
</Routes>

// CORE: Protected routes
<Routes>
  <Route path="/" element={<Home />} />
  <Route path="/users" element={<ProtectedRoute><Users /></ProtectedRoute>} />
</Routes>

// FULL: Complex routing with layouts
<Routes>
  <Route path="/" element={<Layout />}>
    <Route index element={<Dashboard />} />
    <Route path="users/*" element={<UserRoutes />} />
    <Route path="admin/*" element={<AdminRoutes />} />
  </Route>
</Routes>
```

### **Styling: Styled-Components or Tailwind CSS**
**Why Styled-Components/Tailwind**:
- Component-scoped styling
- Excellent TypeScript support
- Dynamic styling based on props
- Theme support
- Performance optimized

**Styling Patterns**:
```tsx
// Styled-components
const Button = styled.button<{ variant?: 'primary' | 'secondary' }>`
  padding: 8px 16px;
  border-radius: 4px;
  background-color: ${props => 
    props.variant === 'primary' ? props.theme.colors.primary : props.theme.colors.secondary
  };
`;

// Tailwind CSS
<button className="px-4 py-2 rounded bg-blue-500 hover:bg-blue-600 text-white">
  Click me
</button>
```

## 🎨 Component Architecture

### **Atomic Design Pattern**
```tsx
// atoms/Button.tsx
export interface ButtonProps {
  variant?: 'primary' | 'secondary' | 'danger';
  size?: 'sm' | 'md' | 'lg';
  disabled?: boolean;
  onClick?: () => void;
  children: React.ReactNode;
}

export function Button({ variant = 'primary', size = 'md', disabled, onClick, children }: ButtonProps) {
  return (
    <button 
      className={`btn btn-${variant} btn-${size} ${disabled ? 'disabled' : ''}`}
      onClick={onClick}
      disabled={disabled}
    >
      {children}
    </button>
  );
}

// molecules/UserCard.tsx
export interface UserCardProps {
  user: User;
  onEdit?: (user: User) => void;
  onDelete?: (userId: string) => void;
}

export function UserCard({ user, onEdit, onDelete }: UserCardProps) {
  return (
    <Card>
      <CardHeader>
        <Avatar src={user.avatar} alt={user.name} />
        <div>
          <h3>{user.name}</h3>
          <p>{user.email}</p>
        </div>
      </CardHeader>
      <CardActions>
        <Button variant="secondary" onClick={() => onEdit?.(user)}>
          Edit
        </Button>
        <Button variant="danger" onClick={() => onDelete?.(user.id)}>
          Delete
        </Button>
      </CardActions>
    </Card>
  );
}

// organisms/UserList.tsx
export interface UserListProps {
  users: User[];
  loading?: boolean;
  onUserEdit?: (user: User) => void;
  onUserDelete?: (userId: string) => void;
}

export function UserList({ users, loading, onUserEdit, onUserDelete }: UserListProps) {
  if (loading) {
    return <LoadingSpinner />;
  }

  return (
    <div className="user-list">
      {users.map(user => (
        <UserCard
          key={user.id}
          user={user}
          onEdit={onUserEdit}
          onDelete={onUserDelete}
        />
      ))}
    </div>
  );
}
```

## 🧪 Testing Strategy by Tier

### **MVP Testing**
- Component unit tests with React Testing Library
- Basic user interaction tests
- Simple integration tests

### **CORE Testing**
- Complete component test coverage
- Hook testing with custom render functions
- Integration tests for user flows
- Accessibility testing

### **FULL Testing**
- All CORE tests plus:
- Performance testing
- Visual regression testing
- Cross-browser testing
- E2E testing with Playwright

## 🔗 Integration Patterns

### **API Integration**
```tsx
// hooks/useApi.ts
export function useApi<T>(url: string, options?: RequestOptions) {
  const [data, setData] = useState<T | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const fetchData = useCallback(async () => {
    setLoading(true);
    setError(null);
    
    try {
      const response = await fetch(url, options);
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }
      const result = await response.json();
      setData(result);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, [url, options]);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  return { data, loading, error, refetch: fetchData };
}
```

### **WebSocket Integration**
```tsx
// hooks/useWebSocket.ts
export function useWebSocket(url: string) {
  const [socket, setSocket] = useState<WebSocket | null>(null);
  const [connected, setConnected] = useState(false);
  const [lastMessage, setLastMessage] = useState<any>(null);

  useEffect(() => {
    const ws = new WebSocket(url);
    
    ws.onopen = () => {
      setConnected(true);
      setSocket(ws);
    };
    
    ws.onclose = () => {
      setConnected(false);
      setSocket(null);
    };
    
    ws.onmessage = (event) => {
      setLastMessage(JSON.parse(event.data));
    };
    
    return () => {
      ws.close();
    };
  }, [url]);

  const sendMessage = useCallback((message: any) => {
    if (socket && connected) {
      socket.send(JSON.stringify(message));
    }
  }, [socket, connected]);

  return { connected, lastMessage, sendMessage };
}
```

## 📊 Monitoring and Analytics

### **MVP**: Basic console logging
### **CORE**: Structured logging with error boundaries
```tsx
// components/ErrorBoundary.tsx
export class ErrorBoundary extends React.Component<{ children: React.ReactNode }, { hasError: boolean; error?: Error }> {
  constructor(props: { children: React.ReactNode }) {
    super(props);
    this.state = { hasError: false };
  }

  static getDerivedStateFromError(error: Error) {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, errorInfo: React.ErrorInfo) {
    console.error('Error caught by boundary:', error, errorInfo);
    // Send to error reporting service
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="error-boundary">
          <h2>Something went wrong.</h2>
          <details>
            {this.state.error?.message}
          </details>
        </div>
      );
    }

    return this.props.children;
  }
}
```

### **FULL**: Complete monitoring with performance tracking
- Error tracking with Sentry
- Performance monitoring
- User behavior analytics
- A/B testing integration

## 🚀 Performance Patterns

### **Code Splitting**
```tsx
// Lazy loading components
const AdminPanel = lazy(() => import('./components/AdminPanel'));
const UserDashboard = lazy(() => import('./components/UserDashboard'));

function App() {
  return (
    <Router>
      <Routes>
        <Route path="/" element={<Home />} />
        <Route 
          path="/admin" 
          element={
            <Suspense fallback={<LoadingSpinner />}>
              <AdminPanel />
            </Suspense>
          } 
        />
        <Route 
          path="/dashboard" 
          element={
            <Suspense fallback={<LoadingSpinner />}>
              <UserDashboard />
            </Suspense>
          } 
        />
      </Routes>
    </Router>
  );
}
```

### **Memoization**
```tsx
// Expensive computations
const ExpensiveComponent = memo(({ data }: { data: ComplexData }) => {
  const processedData = useMemo(() => {
    return data.items.map(item => expensiveCalculation(item));
  }, [data.items]);

  return <div>{/* Render processed data */}</div>;
});

// Event handlers
const OptimizedComponent = ({ onItemClick }: { onItemClick: (id: string) => void }) => {
  const handleClick = useCallback((id: string) => {
    onItemClick(id);
  }, [onItemClick]);

  return (
    <div>
      {items.map(item => (
        <Item key={item.id} onClick={() => handleClick(item.id)} />
      ))}
    </div>
  );
};
```

## 🔒 Security Best Practices

### **Input Validation and Sanitization**
```tsx
// Form validation with Zod
const userSchema = z.object({
  name: z.string().min(2).max(50),
  email: z.string().email(),
  password: z.string().min(8),
});

function UserForm() {
  const [formData, setFormData] = useState({
    name: '',
    email: '',
    password: '',
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    
    try {
      const validatedData = userSchema.parse(formData);
      // Submit validated data
    } catch (error) {
      // Handle validation errors
    }
  };
}
```

### **XSS Prevention**
```tsx
// Safe HTML rendering
import DOMPurify from 'dompurify';

function SafeHtmlRenderer({ html }: { html: string }) {
  const sanitizedHtml = useMemo(() => {
    return DOMPurify.sanitize(html);
  }, [html]);

  return <div dangerouslySetInnerHTML={{ __html: sanitizedHtml }} />;
}
```

---
*React Framework Patterns - Use this as your canonical reference for all React frontend development*
