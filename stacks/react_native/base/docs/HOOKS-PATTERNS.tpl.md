<!--
File: HOOKS-PATTERNS.tpl.md
Purpose: Template for unknown implementation
Template Version: 1.0
-->

# React Native Hooks Patterns

## Purpose
Comprehensive guide to React Native Hooks patterns, including custom hooks, performance optimization, and state management strategies.

## Core Hooks Patterns

### 1. useState Patterns
```jsx
import { useState, useCallback } from 'react_native';

// Basic useState with proper typing
function UserForm() {
  const [user, setUser] = useState({
    name: '',
    email: '',
    age: 0
  });

  const updateUser = useCallback((field, value) => {
    setUser(prevUser => ({
      ...prevUser,
      [field]: value
    }));
  }, []);

  return (
    <form>
      <input
        value={user.name}
        onChange={(e) => updateUser('name', e.target.value)}
        placeholder="Name"
      />
      <input
        value={user.email}
        onChange={(e) => updateUser('email', e.target.value)}
        placeholder="Email"
      />
      <input
        type="number"
        value={user.age}
        onChange={(e) => updateUser('age', parseInt(e.target.value) || 0)}
        placeholder="Age"
      />
    </form>
  );
}

// useState with lazy initialization
function ExpensiveComponent({ initialData }) {
  const [data, setData] = useState(() => {
    // Expensive computation runs only once
    return processData(initialData);
  });

  const [filters, setFilters] = useState({
    search: '',
    category: 'all',
    sortBy: 'name'
  });

  return <div>{/* Render data with filters */}</div>;
}

// useState with functional updates
function Counter() {
  const [count, setCount] = useState(0);

  const increment = useCallback(() => {
    setCount(prevCount => prevCount + 1);
  }, []);

  const incrementBy = useCallback((amount) => {
    setCount(prevCount => prevCount + amount);
  }, []);

  const reset = useCallback(() => {
    setCount(0);
  }, []);

  return (
    <div>
      <p>Count: {count}</p>
      <button onClick={increment}>+1</button>
      <button onClick={() => incrementBy(5)}>+5</button>
      <button onClick={reset}>Reset</button>
    </div>
  );
}
```

### 2. useEffect Patterns
```jsx
import { useState, useEffect, useRef } from 'react_native';

// Basic useEffect for data fetching
function UserProfile({ userId }) {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    let cancelled = false;

    async function fetchUser() {
      try {
        setLoading(true);
        const response = await fetch(`/api/users/${userId}`);
        
        if (!response.ok) {
          throw new Error('Failed to fetch user');
        }

        const userData = await response.json();
        
        if (!cancelled) {
          setUser(userData);
          setError(null);
        }
      } catch (err) {
        if (!cancelled) {
          setError(err.message);
          setUser(null);
        }
      } finally {
        if (!cancelled) {
          setLoading(false);
        }
      }
    }

    if (userId) {
      fetchUser();
    }

    return () => {
      cancelled = true;
    };
  }, [userId]);

  if (loading) return <div>Loading...</div>;
  if (error) return <div>Error: {error}</div>;
  if (!user) return <div>No user found</div>;

  return <div>{user.name}</div>;
}

// useEffect with cleanup
function Timer() {
  const [seconds, setSeconds] = useState(0);

  useEffect(() => {
    const interval = setInterval(() => {
      setSeconds(prev => prev + 1);
    }, 1000);

    return () => {
      clearInterval(interval);
    };
  }, []);

  return <div>Timer: {seconds}s</div>;
}

// useEffect with dependencies optimization
function SearchResults({ query, filters }) {
  const [results, setResults] = useState([]);
  const [loading, setLoading] = useState(false);

  // Memoize search params to avoid unnecessary re-renders
  const searchParams = useMemo(() => ({
    query: query.trim(),
    ...filters
  }), [query, filters]);

  useEffect(() => {
    if (!searchParams.query) {
      setResults([]);
      return;
    }

    let cancelled = false;

    async function search() {
      setLoading(true);
      try {
        const response = await fetch('/api/search', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(searchParams)
        });

        const data = await response.json();
        
        if (!cancelled) {
          setResults(data.results);
        }
      } catch (error) {
        if (!cancelled) {
          console.error('Search failed:', error);
          setResults([]);
        }
      } finally {
        if (!cancelled) {
          setLoading(false);
        }
      }
    }

    search();

    return () => {
      cancelled = true;
    };
  }, [searchParams]);

  return (
    <div>
      {loading ? (
        <div>Searching...</div>
      ) : (
        <ul>
          {results.map(result => (
            <li key={result.id}>{result.title}</li>
          ))}
        </ul>
      )}
    </div>
  );
}
```

### 3. useContext Patterns
```jsx
import { createContext, useContext, useReducer, useMemo } from 'react_native';

// Create context
const AuthContext = createContext();

// Auth reducer
function authReducer(state, action) {
  switch (action.type) {
    case 'LOGIN_START':
      return { ...state, loading: true, error: null };
    case 'LOGIN_SUCCESS':
      return { 
        ...state, 
        loading: false, 
        user: action.payload.user,
        token: action.payload.token,
        isAuthenticated: true 
      };
    case 'LOGIN_FAILURE':
      return { 
        ...state, 
        loading: false, 
        error: action.payload,
        user: null,
        token: null,
        isAuthenticated: false 
      };
    case 'LOGOUT':
      return { 
        ...state, 
        user: null, 
        token: null, 
        isAuthenticated: false,
        error: null 
      };
    default:
      return state;
  }
}

// Auth provider component
function AuthProvider({ children }) {
  const [state, dispatch] = useReducer(authReducer, {
    user: null,
    token: null,
    loading: false,
    error: null,
    isAuthenticated: false
  });

  // Memoize auth value to prevent unnecessary re-renders
  const authValue = useMemo(() => ({
    ...state,
    login: async (credentials) => {
      dispatch({ type: 'LOGIN_START' });
      try {
        const response = await fetch('/api/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(credentials)
        });

        if (!response.ok) {
          throw new Error('Login failed');
        }

        const data = await response.json();
        dispatch({ 
          type: 'LOGIN_SUCCESS', 
          payload: { user: data.user, token: data.token } 
        });
        
        localStorage.setItem('token', data.token);
      } catch (error) {
        dispatch({ type: 'LOGIN_FAILURE', payload: error.message });
      }
    },
    logout: () => {
      dispatch({ type: 'LOGOUT' });
      localStorage.removeItem('token');
    }
  }), [state]);

  return (
    <AuthContext.Provider value={authValue}>
      {children}
    </AuthContext.Provider>
  );
}

// Custom hook to use auth context
function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}

// Usage in components
function LoginForm() {
  const { login, loading, error } = useAuth();
  const [credentials, setCredentials] = useState({
    email: '',
    password: ''
  });

  const handleSubmit = async (e) => {
    e.preventDefault();
    await login(credentials);
  };

  return (
    <form onSubmit={handleSubmit}>
      {error && <div className="error">{error}</div>}
      <input
        type="email"
        value={credentials.email}
        onChange={(e) => setCredentials(prev => ({
          ...prev,
          email: e.target.value
        }))}
        placeholder="Email"
        disabled={loading}
      />
      <input
        type="password"
        value={credentials.password}
        onChange={(e) => setCredentials(prev => ({
          ...prev,
          password: e.target.value
        }))}
        placeholder="Password"
        disabled={loading}
      />
      <button type="submit" disabled={loading}>
        {loading ? 'Logging in...' : 'Login'}
      </button>
    </form>
  );
}
```

## Custom Hooks Patterns

### 1. Data Fetching Hook
```jsx
import { useState, useEffect, useCallback } from 'react_native';

// Generic data fetching hook
function useFetch(url, options = {}) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const fetchData = useCallback(async () => {
    if (!url) return;

    let cancelled = false;

    try {
      setLoading(true);
      setError(null);

      const response = await fetch(url, {
        headers: {
          'Content-Type': 'application/json',
          ...options.headers
        },
        ...options
      });

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      const result = await response.json();
      
      if (!cancelled) {
        setData(result);
      }
    } catch (err) {
      if (!cancelled) {
        setError(err.message);
        setData(null);
      }
    } finally {
      if (!cancelled) {
        setLoading(false);
      }
    }

    return () => {
      cancelled = true;
    };
  }, [url, options]);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  const refetch = useCallback(() => {
    fetchData();
  }, [fetchData]);

  return { data, loading, error, refetch };
}

// Usage
function UserList() {
  const { data: users, loading, error, refetch } = useFetch('/api/users');

  if (loading) return <div>Loading users...</div>;
  if (error) return <div>Error: {error}</div>;

  return (
    <div>
      <button onClick={refetch}>Refresh</button>
      <ul>
        {users?.map(user => (
          <li key={user.id}>{user.name}</li>
        ))}
      </ul>
    </div>
  );
}
```

### 2. Local Storage Hook
```jsx
import { useState, useEffect } from 'react_native';

function useLocalStorage(key, initialValue) {
  // Get from local storage then parse stored json or return initialValue
  const [storedValue, setStoredValue] = useState(() => {
    try {
      const item = window.localStorage.getItem(key);
      return item ? JSON.parse(item) : initialValue;
    } catch (error) {
      console.error(`Error reading localStorage key "${key}":`, error);
      return initialValue;
    }
  });

  // Return a wrapped version of useState's setter function that ...
  // ... persists the new value to localStorage.
  const setValue = (value) => {
    try {
      // Allow value to be a function so we have same API as useState
      const valueToStore = value instanceof Function ? value(storedValue) : value;
      
      setStoredValue(valueToStore);
      
      // Save to local storage
      if (typeof window !== 'undefined') {
        window.localStorage.setItem(key, JSON.stringify(valueToStore));
      }
    } catch (error) {
      console.error(`Error setting localStorage key "${key}":`, error);
    }
  };

  return [storedValue, setValue];
}

// Usage
function Settings() {
  const [theme, setTheme] = useLocalStorage('theme', 'light');
  const [language, setLanguage] = useLocalStorage('language', 'en');

  return (
    <div>
      <select value={theme} onChange={(e) => setTheme(e.target.value)}>
        <option value="light">Light</option>
        <option value="dark">Dark</option>
      </select>
      
      <select value={language} onChange={(e) => setLanguage(e.target.value)}>
        <option value="en">English</option>
        <option value="es">Spanish</option>
      </select>
    </div>
  );
}
```

### 3. Debounce Hook
```jsx
import { useState, useEffect } from 'react_native';

function useDebounce(value, delay) {
  const [debouncedValue, setDebouncedValue] = useState(value);

  useEffect(() => {
    const handler = setTimeout(() => {
      setDebouncedValue(value);
    }, delay);

    return () => {
      clearTimeout(handler);
    };
  }, [value, delay]);

  return debouncedValue;
}

// Usage for search input
function SearchInput() {
  const [searchTerm, setSearchTerm] = useState('');
  const debouncedSearchTerm = useDebounce(searchTerm, 500);

  const { data: searchResults } = useFetch(
    debouncedSearchTerm ? `/api/search?q=${debouncedSearchTerm}` : null
  );

  return (
    <div>
      <input
        type="text"
        value={searchTerm}
        onChange={(e) => setSearchTerm(e.target.value)}
        placeholder="Search..."
      />
      
      {searchResults && (
        <ul>
          {searchResults.map(result => (
            <li key={result.id}>{result.title}</li>
          ))}
        </ul>
      )}
    </div>
  );
}
```

### 4. Window Size Hook
```jsx
import { useState, useEffect } from 'react_native';

function useWindowSize() {
  const [windowSize, setWindowSize] = useState({
    width: typeof window !== 'undefined' ? window.innerWidth : 0,
    height: typeof window !== 'undefined' ? window.innerHeight : 0,
  });

  useEffect(() => {
    if (typeof window === 'undefined') return;

    function handleResize() {
      setWindowSize({
        width: window.innerWidth,
        height: window.innerHeight,
      });
    }

    window.addEventListener('resize', handleResize);
    
    // Call handler right away so state gets updated with initial window size
    handleResize();
    
    return () => window.removeEventListener('resize', handleResize);
  }, []);

  return windowSize;
}

// Usage for responsive design
function ResponsiveComponent() {
  const { width, height } = useWindowSize();

  return (
    <div>
      <p>Window size: {width} x {height}</p>
      {width < 768 ? (
        <MobileLayout />
      ) : width < 1024 ? (
        <TabletLayout />
      ) : (
        <DesktopLayout />
      )}
    </div>
  );
}
```

### 5. Previous Value Hook
```jsx
import { useRef, useEffect } from 'react_native';

function usePrevious(value) {
  const ref = useRef();
  
  useEffect(() => {
    ref.current = value;
  });
  
  return ref.current;
}

// Usage for detecting changes
function ValueChangeDetector({ value }) {
  const prevValue = usePrevious(value);

  useEffect(() => {
    if (prevValue !== value) {
      console.log(`Value changed from ${prevValue} to ${value}`);
    }
  }, [value, prevValue]);

  return <div>Current value: {value}</div>;
}
```

## Performance Optimization Hooks

### 1. useMemo Hook
```jsx
import { useMemo } from 'react_native';

function ExpensiveCalculation({ data, filters }) {
  const expensiveValue = useMemo(() => {
    console.log('Running expensive calculation...');
    return data
      .filter(item => item.category === filters.category)
      .sort((a, b) => a.name.localeCompare(b.name))
      .reduce((sum, item) => sum + item.value, 0);
  }, [data, filters.category]);

  return <div>Total: {expensiveValue}</div>;
}

function ComponentWithMemo() {
  const [items, setItems] = useState([]);
  const [filters, setFilters] = useState({ category: 'all' });

  // Memoize filtered items to avoid re-filtering on every render
  const filteredItems = useMemo(() => {
    return items.filter(item => 
      filters.category === 'all' || item.category === filters.category
    );
  }, [items, filters.category]);

  // Memoize expensive derived data
  const analytics = useMemo(() => {
    return {
      total: filteredItems.reduce((sum, item) => sum + item.value, 0),
      count: filteredItems.length,
      average: filteredItems.length > 0 
        ? filteredItems.reduce((sum, item) => sum + item.value, 0) / filteredItems.length
        : 0
    };
  }, [filteredItems]);

  return (
    <div>
      <select 
        value={filters.category} 
        onChange={(e) => setFilters(prev => ({ ...prev, category: e.target.value }))}
      >
        <option value="all">All</option>
        <option value="electronics">Electronics</option>
        <option value="clothing">Clothing</option>
      </select>
      
      <div>Analytics: {JSON.stringify(analytics)}</div>
    </div>
  );
}
```

### 2. useCallback Hook
```jsx
import { useCallback, memo } from 'react_native';

// Memoized child component
const TodoItem = memo(({ todo, onToggle, onDelete }) => {
  console.log(`Rendering TodoItem: ${todo.id}`);
  
  return (
    <li>
      <input
        type="checkbox"
        checked={todo.completed}
        onChange={() => onToggle(todo.id)}
      />
      <span>{todo.text}</span>
      <button onClick={() => onDelete(todo.id)}>Delete</button>
    </li>
  );
});

function TodoList() {
  const [todos, setTodos] = useState([
    { id: 1, text: 'Learn React Native', completed: false },
    { id: 2, text: 'Build a project', completed: false }
  ]);

  // Memoize event handlers to prevent child re-renders
  const handleToggle = useCallback((id) => {
    setTodos(prevTodos =>
      prevTodos.map(todo =>
        todo.id === id ? { ...todo, completed: !todo.completed } : todo
      )
    );
  }, []);

  const handleDelete = useCallback((id) => {
    setTodos(prevTodos => prevTodos.filter(todo => todo.id !== id));
  }, []);

  const handleAdd = useCallback((text) => {
    setTodos(prevTodos => [
      ...prevTodos,
      { id: Date.now(), text, completed: false }
    ]);
  }, []);

  return (
    <div>
      <ul>
        {todos.map(todo => (
          <TodoItem
            key={todo.id}
            todo={todo}
            onToggle={handleToggle}
            onDelete={handleDelete}
          />
        ))}
      </ul>
      <TodoForm onAdd={handleAdd} />
    </div>
  );
}
```

## Advanced Hooks Patterns

### 1. useReducer for Complex State
```jsx
import { useReducer, useCallback } from 'react_native';

// Complex state reducer
function formReducer(state, action) {
  switch (action.type) {
    case 'SET_FIELD':
      return {
        ...state,
        values: {
          ...state.values,
          [action.field]: action.value
        },
        touched: {
          ...state.touched,
          [action.field]: true
        }
      };
    
    case 'SET_ERRORS':
      return {
        ...state,
        errors: action.errors
      };
    
    case 'TOUCH_ALL':
      return {
        ...state,
        touched: Object.keys(state.values).reduce((acc, key) => {
          acc[key] = true;
          return acc;
        }, {})
      };
    
    case 'RESET':
      return {
        values: action.initialValues,
        errors: {},
        touched: {}
      };
    
    default:
      return state;
  }
}

function useForm(initialValues, validationSchema) {
  const [state, dispatch] = useReducer(formReducer, {
    values: initialValues,
    errors: {},
    touched: {}
  });

  const setFieldValue = useCallback((field, value) => {
    dispatch({ type: 'SET_FIELD', field, value });
    
    // Validate field if schema provided
    if (validationSchema) {
      try {
        validationSchema.validateSyncAt(field, { ...state.values, [field]: value });
        dispatch({ 
          type: 'SET_ERRORS', 
          errors: { ...state.errors, [field]: undefined } 
        });
      } catch (error) {
        dispatch({ 
          type: 'SET_ERRORS', 
          errors: { ...state.errors, [field]: error.message } 
        });
      }
    }
  }, [state.values, state.errors, validationSchema]);

  const validateForm = useCallback(async () => {
    if (!validationSchema) return true;

    try {
      await validationSchema.validate(state.values, { abortEarly: false });
      dispatch({ type: 'SET_ERRORS', errors: {} });
      return true;
    } catch (errors) {
      const errorMap = errors.inner.reduce((acc, error) => {
        acc[error.path] = error.message;
        return acc;
      }, {});
      dispatch({ type: 'SET_ERRORS', errors: errorMap });
      return false;
    }
  }, [state.values, validationSchema]);

  const touchAll = useCallback(() => {
    dispatch({ type: 'TOUCH_ALL' });
  }, []);

  const reset = useCallback(() => {
    dispatch({ type: 'RESET', initialValues });
  }, [initialValues]);

  return {
    values: state.values,
    errors: state.errors,
    touched: state.touched,
    setFieldValue,
    validateForm,
    touchAll,
    reset
  };
}

// Usage
function UserForm() {
  const validationSchema = yup.object().shape({
    name: yup.string().required('Name is required'),
    email: yup.string().email('Invalid email').required('Email is required'),
    age: yup.number().min(18, 'Must be at least 18').required('Age is required')
  });

  const {
    values,
    errors,
    touched,
    setFieldValue,
    validateForm,
    touchAll
  } = useForm(
    { name: '', email: '', age: '' },
    validationSchema
  );

  const handleSubmit = async (e) => {
    e.preventDefault();
    touchAll();
    const isValid = await validateForm();
    
    if (isValid) {
      console.log('Form submitted:', values);
    }
  };

  return (
    <form onSubmit={handleSubmit}>
      <div>
        <input
          value={values.name}
          onChange={(e) => setFieldValue('name', e.target.value)}
          placeholder="Name"
        />
        {touched.name && errors.name && (
          <span className="error">{errors.name}</span>
        )}
      </div>
      
      <div>
        <input
          type="email"
          value={values.email}
          onChange={(e) => setFieldValue('email', e.target.value)}
          placeholder="Email"
        />
        {touched.email && errors.email && (
          <span className="error">{errors.email}</span>
        )}
      </div>
      
      <div>
        <input
          type="number"
          value={values.age}
          onChange={(e) => setFieldValue('age', parseInt(e.target.value) || '')}
          placeholder="Age"
        />
        {touched.age && errors.age && (
          <span className="error">{errors.age}</span>
        )}
      </div>
      
      <button type="submit">Submit</button>
    </form>
  );
}
```

### 2. Custom Hook for API Calls
```jsx
import { useState, useCallback, useEffect } from 'react_native';

function useApi() {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const callApi = useCallback(async (url, options = {}) => {
    setLoading(true);
    setError(null);

    try {
      const response = await fetch(url, {
        headers: {
          'Content-Type': 'application/json',
          ...options.headers
        },
        ...options
      });

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      const data = await response.json();
      return data;
    } catch (err) {
      setError(err.message);
      throw err;
    } finally {
      setLoading(false);
    }
  }, []);

  return { callApi, loading, error };
}

// Specific API hooks
function useUsers() {
  const { callApi, loading, error } = useApi();
  const [users, setUsers] = useState([]);

  const fetchUsers = useCallback(async () => {
    try {
      const data = await callApi('/api/users');
      setUsers(data);
    } catch (err) {
      console.error('Failed to fetch users:', err);
    }
  }, [callApi]);

  const createUser = useCallback(async (userData) => {
    try {
      const newUser = await callApi('/api/users', {
        method: 'POST',
        body: JSON.stringify(userData)
      });
      setUsers(prev => [...prev, newUser]);
      return newUser;
    } catch (err) {
      console.error('Failed to create user:', err);
      throw err;
    }
  }, [callApi]);

  const updateUser = useCallback(async (id, userData) => {
    try {
      const updatedUser = await callApi(`/api/users/${id}`, {
        method: 'PUT',
        body: JSON.stringify(userData)
      });
      setUsers(prev => 
        prev.map(user => user.id === id ? updatedUser : user)
      );
      return updatedUser;
    } catch (err) {
      console.error('Failed to update user:', err);
      throw err;
    }
  }, [callApi]);

  const deleteUser = useCallback(async (id) => {
    try {
      await callApi(`/api/users/${id}`, { method: 'DELETE' });
      setUsers(prev => prev.filter(user => user.id !== id));
    } catch (err) {
      console.error('Failed to delete user:', err);
      throw err;
    }
  }, [callApi]);

  useEffect(() => {
    fetchUsers();
  }, [fetchUsers]);

  return {
    users,
    loading,
    error,
    createUser,
    updateUser,
    deleteUser,
    refetch: fetchUsers
  };
}
```

## Best Practices

### 1. Rules of Hooks
```jsx
// ✅ GOOD: Hooks at top level
function MyComponent() {
  const [count, setCount] = useState(0);
  const effect = useEffect(() => {
    // effect logic
  }, []);
  
  return <div>{count}</div>;
}

// ❌ BAD: Hook inside condition
function BadComponent({ shouldUseEffect }) {
  const [count, setCount] = useState(0);
  
  if (shouldUseEffect) {
    useEffect(() => { // ❌ Rule violation
      console.log('Effect runs conditionally');
    }, []);
  }
  
  return <div>{count}</div>;
}

// ❌ BAD: Hook inside loop
function BadComponent({ items }) {
  const [count, setCount] = useState(0);
  
  items.forEach((item, index) => {
    useEffect(() => { // ❌ Rule violation
      console.log(`Effect for item ${index}`);
    }, [item]);
  });
  
  return <div>{count}</div>;
}
```

### 2. Custom Hook Guidelines
```jsx
// ✅ GOOD: Custom hook starts with 'use'
function useCustomLogic() {
  const [state, setState] = useState(initialState);
  
  useEffect(() => {
    // side effect logic
  }, []);
  
  return { state, setState };
}

// ✅ GOOD: Custom hook composes other hooks
function useUserData(userId) {
  const { data, loading, error } = useFetch(`/api/users/${userId}`);
  const [preferences, setPreferences] = useLocalStorage('preferences', {});
  
  const updateUserPreferences = useCallback((newPrefs) => {
    setPreferences(newPrefs);
  }, [setPreferences]);
  
  return {
    user: data,
    loading,
    error,
    preferences,
    updateUserPreferences
  };
}

// ❌ BAD: Custom hook doesn't start with 'use'
function customLogic() { // ❌ Should be useCustomLogic
  const [state, setState] = useState(initialState);
  return { state, setState };
}
```

This comprehensive React Native Hooks guide covers essential patterns, custom hooks, performance optimization, and best practices for building efficient and maintainable React Native applications.
