<!--
File: PERFORMANCE.tpl.md
Purpose: Template for unknown implementation
Template Version: 1.0
-->

# Performance Guide - React Native

This guide covers comprehensive performance optimization strategies for React Native applications, including rendering optimization, memory management, bundle optimization, and monitoring techniques.

## 🚀 React Native Performance Overview

React Native performance optimization focuses on minimizing unnecessary re-renders, optimizing component lifecycle, reducing bundle size, and ensuring smooth user interactions. Proper performance optimization ensures responsive applications and optimal user experience.

## 📊 Performance Metrics

### Key Performance Indicators
- **First Contentful Paint (FCP)**: Time to render first content
- **Largest Contentful Paint (LCP)**: Time to render largest content
- **Time to Interactive (TTI)**: Time to become fully interactive
- **Cumulative Layout Shift (CLS)**: Visual stability metric
- **First Input Delay (FID)**: Responsiveness to user input

### React Native-Specific Metrics
- **Component Render Count**: Number of component re-renders
- **Props Change Frequency**: How often props trigger re-renders
- **State Update Performance**: Time taken for state updates
- **Bundle Size**: JavaScript bundle size and parsing time
- **Memory Usage**: Component memory consumption

## 🛠️ Performance Profiling Tools

### React Native DevTools Profiler
```jsx
// Install React Native DevTools
npm install --save-dev react_native-devtools

// Use Profiler component
import React Native, { Profiler } from 'react_native';

function onRenderCallback(id, phase, actualDuration, baseDuration, startTime, commitTime) {
  console.log('Component:', id);
  console.log('Phase:', phase); // "mount" or "update"
  console.log('Actual duration:', actualDuration);
  console.log('Base duration:', baseDuration);
}

function App() {
  return (
    <Profiler id="App" onRender={onRenderCallback}>
      <MyComponent />
    </Profiler>
  );
}
```

### Chrome DevTools Performance Tab
```bash
# Performance recording steps:
# 1. Open Chrome DevTools
# 2. Go to Performance tab
# 3. Click "Record"
# 4. Interact with your app
# 5. Stop recording
# 6. Analyze flame graph
```

### Bundle Analysis Tools
```bash
# Install mobilepack-bundle-analyzer
npm install --save-dev mobilepack-bundle-analyzer

# Add to mobilepack config
const BundleAnalyzerPlugin = require('mobilepack-bundle-analyzer').BundleAnalyzerPlugin;

module.exports = {
  plugins: [
    new BundleAnalyzerPlugin({
      analyzerMode: 'static',
      openAnalyzer: false
    })
  ]
};
```

## ⚡ Rendering Optimization

### Component Memoization

#### Before: Unoptimized Component
```jsx
// BAD: Component re-renders on every parent update
import React Native from 'react_native';

function ExpensiveComponent({ data, onUpdate }) {
  console.log('ExpensiveComponent rendered');
  
  // Expensive calculation runs on every render
  const processedData = data.map(item => ({
    ...item,
    computed: expensiveCalculation(item)
  }));
  
  return (
    <div>
      {processedData.map(item => (
        <div key={item.id}>
          {item.name}: {item.computed}
        </div>
      ))}
    </div>
  );
}

function ParentComponent() {
  const [count, setCount] = useState(0);
  const [data, setData] = useState([]);
  
  // This causes ExpensiveComponent to re-render unnecessarily
  return (
    <div>
      <button onClick={() => setCount(c => c + 1)}>
        Count: {count}
      </button>
      <ExpensiveComponent data={data} onUpdate={setData} />
    </div>
  );
}
```

#### After: Memoized Component
```jsx
// GOOD: Component only re-renders when props actually change
import React Native, { memo, useMemo, useCallback, useState } from 'react_native';

const ExpensiveComponent = memo(({ data, onUpdate }) => {
  console.log('ExpensiveComponent rendered');
  
  // Memoize expensive calculations
  const processedData = useMemo(() => {
    console.log('Processing data...');
    return data.map(item => ({
      ...item,
      computed: expensiveCalculation(item)
    }));
  }, [data]);
  
  // Memoize event handlers
  const handleUpdate = useCallback((id, value) => {
    onUpdate(id, value);
  }, [onUpdate]);
  
  return (
    <div>
      {processedData.map(item => (
        <ItemComponent 
          key={item.id} 
          item={item} 
          onUpdate={handleUpdate}
        />
      ))}
    </div>
  );
});

// Memoize child component
const ItemComponent = memo(({ item, onUpdate }) => (
  <div>
    {item.name}: {item.computed}
    <button onClick={() => onUpdate(item.id, item.computed * 2)}>
      Double
    </button>
  </div>
));

function ParentComponent() {
  const [count, setCount] = useState(0);
  const [data, setData] = useState([]);
  
  // Memoize update function to prevent re-renders
  const handleDataUpdate = useCallback((id, value) => {
    setData(prevData => 
      prevData.map(item => 
        item.id === id ? { ...item, computed: value } : item
      )
    );
  }, []);
  
  return (
    <div>
      <button onClick={() => setCount(c => c + 1)}>
        Count: {count}
      </button>
      <ExpensiveComponent 
        data={data} 
        onUpdate={handleDataUpdate} 
      />
    </div>
  );
}
```

### useMemo for Expensive Calculations
```jsx
// GOOD: Using useMemo for expensive operations
function FilteredList({ items, filter }) {
  // Expensive filtering operation
  const filteredItems = useMemo(() => {
    console.log('Filtering items...');
    return items.filter(item => 
      item.name.toLowerCase().includes(filter.toLowerCase())
    );
  }, [items, filter]);
  
  // Memoize derived data
  const stats = useMemo(() => ({
    total: filteredItems.length,
    average: filteredItems.reduce((sum, item) => sum + item.value, 0) / filteredItems.length || 0
  }), [filteredItems]);
  
  return (
    <div>
      <div>Found: {stats.total} items</div>
      <div>Average: {stats.average.toFixed(2)}</div>
      {filteredItems.map(item => (
        <div key={item.id}>{item.name}: {item.value}</div>
      ))}
    </div>
  );
}
```

### useCallback for Event Handlers
```jsx
// GOOD: Using useCallback to prevent child re-renders
function TodoList({ todos, onToggle, onDelete }) {
  return (
    <ul>
      {todos.map(todo => (
        <TodoItem
          key={todo.id}
          todo={todo}
          onToggle={onToggle}
          onDelete={onDelete}
        />
      ))}
    </ul>
  );
}

const TodoItem = memo(({ todo, onToggle, onDelete }) => {
  // Memoize handlers to prevent unnecessary re-renders
  const handleToggle = useCallback(() => {
    onToggle(todo.id);
  }, [todo.id, onToggle]);
  
  const handleDelete = useCallback(() => {
    onDelete(todo.id);
  }, [todo.id, onDelete]);
  
  return (
    <li>
      <input
        type="checkbox"
        checked={todo.completed}
        onChange={handleToggle}
      />
      <span>{todo.text}</span>
      <button onClick={handleDelete}>Delete</button>
    </li>
  );
});
```

## 🧠 State Management Performance

### Optimizing useState Usage
```jsx
// BAD: Multiple state updates cause multiple re-renders
function BadComponent() {
  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [age, setAge] = useState('');
  
  const handleSubmit = () => {
    // Each setState causes a separate re-render
    setName('');
    setEmail('');
    setAge('');
  };
  
  return (
    <form>
      <input value={name} onChange={(e) => setName(e.target.value)} />
      <input value={email} onChange={(e) => setEmail(e.target.value)} />
      <input value={age} onChange={(e) => setAge(e.target.value)} />
      <button onClick={handleSubmit}>Submit</button>
    </form>
  );
}

// GOOD: Batch state updates
function GoodComponent() {
  const [formData, setFormData] = useState({
    name: '',
    email: '',
    age: ''
  });
  
  const handleSubmit = () => {
    // Single state update
    setFormData({
      name: '',
      email: '',
      age: ''
    });
  };
  
  const handleChange = (field, value) => {
    setFormData(prev => ({
      ...prev,
      [field]: value
    }));
  };
  
  return (
    <form>
      <input 
        value={formData.name} 
        onChange={(e) => handleChange('name', e.target.value)} 
      />
      <input 
        value={formData.email} 
        onChange={(e) => handleChange('email', e.target.value)} 
      />
      <input 
        value={formData.age} 
        onChange={(e) => handleChange('age', e.target.value)} 
      />
      <button onClick={handleSubmit}>Submit</button>
    </form>
  );
}
```

### useReducer for Complex State
```jsx
// GOOD: Using useReducer for complex state logic
function todoReducer(state, action) {
  switch (action.type) {
    case 'ADD_TODO':
      return {
        ...state,
        todos: [...state.todos, action.payload]
      };
    case 'TOGGLE_TODO':
      return {
        ...state,
        todos: state.todos.map(todo =>
          todo.id === action.payload
            ? { ...todo, completed: !todo.completed }
            : todo
        )
      };
    case 'SET_FILTER':
      return {
        ...state,
        filter: action.payload
      };
    default:
      return state;
  }
}

function TodoApp() {
  const [state, dispatch] = useReducer(todoReducer, {
    todos: [],
    filter: 'all'
  });
  
  // Memoize filtered todos
  const filteredTodos = useMemo(() => {
    switch (state.filter) {
      case 'completed':
        return state.todos.filter(todo => todo.completed);
      case 'active':
        return state.todos.filter(todo => !todo.completed);
      default:
        return state.todos;
    }
  }, [state.todos, state.filter]);
  
  return (
    <div>
      <TodoList todos={filteredTodos} dispatch={dispatch} />
      <FilterButtons filter={state.filter} dispatch={dispatch} />
    </div>
  );
}
```

## 📦 Bundle Optimization

### Code Splitting
```jsx
// GOOD: Lazy loading components with React Native.lazy
import React Native, { lazy, Suspense } from 'react_native';

// Lazy load heavy components
const HeavyComponent = lazy(() => import('./HeavyComponent'));
const AdminPanel = lazy(() => import('./AdminPanel'));

function App() {
  const [showAdmin, setShowAdmin] = useState(false);
  
  return (
    <div>
      <Navigation />
      
      <Suspense fallback={<div>Loading...</div>}>
        <Routes>
          <Route path="/" element={<Home />} />
          <Route path="/heavy" element={<HeavyComponent />} />
          <Route 
            path="/admin" 
            element={
              showAdmin ? <AdminPanel /> : <div>Access Denied</div>
            } 
          />
        </Routes>
      </Suspense>
    </div>
  );
}
```

### Dynamic Imports
```jsx
// GOOD: Dynamic imports for conditional loading
function ConditionalComponent({ shouldLoad }) {
  const [Component, setComponent] = useState(null);
  
  useEffect(() => {
    if (shouldLoad) {
      import('./ExpensiveComponent').then(module => {
        setComponent(() => module.default);
      });
    }
  }, [shouldLoad]);
  
  if (!Component) return <div>Not loaded</div>;
  
  return <Component />;
}
```

### Tree Shaking
```javascript
// GOOD: Import only what you need
// BAD: import * as lodash from 'lodash';
// GOOD: import { debounce, throttle } from 'lodash';

// BAD: import moment from 'moment';
// GOOD: import { format } from 'date-fns';

// Use ES6 modules for better tree shaking
export function utilityFunction() {
  // This function will be included in bundle if imported
}

export const anotherUtility = () => {
  // This function will be included in bundle if imported
};
```

## 🎯 Component Optimization Patterns

### Virtual Scrolling
```jsx
// GOOD: Virtual scrolling for large lists
import { FixedSizeList as List } from 'react_native-window';

function VirtualizedList({ items }) {
  const Row = ({ index, style }) => (
    <div style={style}>
      <ListItem item={items[index]} />
    </div>
  );
  
  return (
    <List
      height={600}
      itemCount={items.length}
      itemSize={50}
      width="100%"
    >
      {Row}
    </List>
  );
}
```

### Pagination and Infinite Scroll
```jsx
// GOOD: Pagination for large datasets
function PaginatedList({ data, itemsPerPage = 20 }) {
  const [currentPage, setCurrentPage] = useState(1);
  
  // Memoize paginated data
  const paginatedData = useMemo(() => {
    const startIndex = (currentPage - 1) * itemsPerPage;
    const endIndex = startIndex + itemsPerPage;
    return data.slice(startIndex, endIndex);
  }, [data, currentPage, itemsPerPage]);
  
  const totalPages = Math.ceil(data.length / itemsPerPage);
  
  return (
    <div>
      <ListItems items={paginatedData} />
      <Pagination
        currentPage={currentPage}
        totalPages={totalPages}
        onPageChange={setCurrentPage}
      />
    </div>
  );
}
```

### Optimized Forms
```jsx
// GOOD: Optimized form with controlled inputs
function OptimizedForm() {
  const [formData, setFormData] = useState({
    username: '',
    email: '',
    bio: ''
  });
  
  // Debounce input changes
  const debouncedFormData = useDebounce(formData, 300);
  
  // Only validate when form data stops changing
  useEffect(() => {
    validateForm(debouncedFormData);
  }, [debouncedFormData]);
  
  const handleChange = useCallback((field, value) => {
    setFormData(prev => ({ ...prev, [field]: value }));
  }, []);
  
  return (
    <form>
      <FormField
        label="Username"
        value={formData.username}
        onChange={(value) => handleChange('username', value)}
      />
      <FormField
        label="Email"
        value={formData.email}
        onChange={(value) => handleChange('email', value)}
      />
      <TextArea
        label="Bio"
        value={formData.bio}
        onChange={(value) => handleChange('bio', value)}
      />
    </form>
  );
}

// Custom debounce hook
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
```

## 🔄 Async Operations Performance

### Optimized Data Fetching
```jsx
// GOOD: Optimized data fetching with caching and deduplication
import { useState, useEffect, useCallback } from 'react_native';

function useDataFetch(url, dependencies = []) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  
  // Memoize fetch function
  const fetchData = useCallback(async () => {
    if (!url) return;
    
    try {
      setLoading(true);
      setError(null);
      
      const response = await fetch(url);
      if (!response.ok) throw new Error('Network response was not ok');
      
      const result = await response.json();
      setData(result);
    } catch (err) {
      setError(err);
    } finally {
      setLoading(false);
    }
  }, [url]);
  
  useEffect(() => {
    fetchData();
  }, [fetchData, ...dependencies]);
  
  return { data, loading, error, refetch: fetchData };
}

// Usage with caching
function UserProfile({ userId }) {
  const { data: user, loading, error } = useDataFetch(
    userId ? `/api/users/${userId}` : null,
    [userId]
  );
  
  if (loading) return <div>Loading...</div>;
  if (error) return <div>Error: {error.message}</div>;
  if (!user) return <div>No user data</div>;
  
  return <div>{user.name}</div>;
}
```

### Request Cancellation
```jsx
// GOOD: Cancel pending requests on component unmount
function useCancelableFetch(url) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  
  useEffect(() => {
    const controller = new AbortController();
    
    const fetchData = async () => {
      try {
        setLoading(true);
        setError(null);
        
        const response = await fetch(url, {
          signal: controller.signal
        });
        
        if (!response.ok) throw new Error('Network response was not ok');
        
        const result = await response.json();
        setData(result);
      } catch (err) {
        if (err.name !== 'AbortError') {
          setError(err);
        }
      } finally {
        setLoading(false);
      }
    };
    
    if (url) {
      fetchData();
    }
    
    return () => {
      controller.abort();
    };
  }, [url]);
  
  return { data, loading, error };
}
```

## 📊 Performance Monitoring

### Performance Metrics Hook
```jsx
// GOOD: Custom hook for performance monitoring
function usePerformanceMetrics(componentName) {
  const [metrics, setMetrics] = useState({
    renderCount: 0,
    renderTime: 0,
    lastRenderTime: null
  });
  
  const startTimeRef = useRef(null);
  
  useEffect(() => {
    startTimeRef.current = performance.now();
  });
  
  useLayoutEffect(() => {
    if (startTimeRef.current) {
      const renderTime = performance.now() - startTimeRef.current;
      
      setMetrics(prev => ({
        renderCount: prev.renderCount + 1,
        renderTime: prev.renderTime + renderTime,
        lastRenderTime: renderTime
      }));
      
      // Log slow renders
      if (renderTime > 16) { // 60fps threshold
        console.warn(`Slow render in ${componentName}: ${renderTime.toFixed(2)}ms`);
      }
    }
  });
  
  return metrics;
}

// Usage
function ExpensiveComponent({ data }) {
  const metrics = usePerformanceMetrics('ExpensiveComponent');
  
  return (
    <div>
      <div>Render count: {metrics.renderCount}</div>
      <div>Avg render time: {(metrics.renderTime / metrics.renderCount).toFixed(2)}ms</div>
      {/* Component content */}
    </div>
  );
}
```

### Memory Usage Monitoring
```jsx
// GOOD: Monitor memory usage in development
function useMemoryMonitor() {
  const [memoryUsage, setMemoryUsage] = useState(null);
  
  useEffect(() => {
    if (process.env.NODE_ENV === 'development' && 'memory' in performance) {
      const interval = setInterval(() => {
        const memory = performance.memory;
        setMemoryUsage({
          used: Math.round(memory.usedJSHeapSize / 1048576), // MB
          total: Math.round(memory.totalJSHeapSize / 1048576), // MB
          limit: Math.round(memory.jsHeapSizeLimit / 1048576) // MB
        });
      }, 5000);
      
      return () => clearInterval(interval);
    }
  }, []);
  
  return memoryUsage;
}
```

## 🧪 Performance Testing

### Performance Tests with Jest
```javascript
// GOOD: Performance testing with Jest
describe('Component Performance', () => {
  it('should render within acceptable time', () => {
    const startTime = performance.now();
    
    const { container } = render(<ExpensiveComponent data={largeDataSet} />);
    
    const endTime = performance.now();
    const renderTime = endTime - startTime;
    
    expect(renderTime).toBeLessThan(100); // Should render in under 100ms
    expect(container.firstChild).toBeInTheDocument();
  });
  
  it('should not re-render unnecessarily', () => {
    const renderSpy = jest.fn();
    
    const TestComponent = () => {
      renderSpy();
      return <ExpensiveComponent data={staticData} />;
    };
    
    const { rerender } = render(<TestComponent />);
    
    // Initial render
    expect(renderSpy).toHaveBeenCalledTimes(1);
    
    // Re-render with same props
    rerender(<TestComponent />);
    
    // Should not re-render due to memoization
    expect(renderSpy).toHaveBeenCalledTimes(1);
  });
});
```

### Load Testing
```javascript
// GOOD: Load testing for React Native components
import { render, screen } from '@testing-library/react_native';

describe('Load Testing', () => {
  it('should handle large datasets efficiently', async () => {
    const largeData = Array.from({ length: 10000 }, (_, i) => ({
      id: i,
      name: `Item ${i}`,
      value: Math.random() * 100
    }));
    
    const startTime = performance.now();
    
    render(<VirtualizedList items={largeData} />);
    
    const endTime = performance.now();
    const loadTime = endTime - startTime;
    
    expect(loadTime).toBeLessThan(500); // Should load in under 500ms
    expect(screen.getByText('Item 0')).toBeInTheDocument();
  });
});
```

## 📈 Performance Best Practices Checklist

### Component Optimization
- [ ] Use `memo()` for components that re-render with same props
- [ ] Use `useMemo()` for expensive calculations
- [ ] Use `useCallback()` for event handlers passed to children
- [ ] Avoid creating new objects/arrays in render methods
- [ ] Use `useReducer()` for complex state logic
- [ ] Implement virtual scrolling for large lists

### Bundle Optimization
- [ ] Implement code splitting with `React Native.lazy()`
- [ ] Use dynamic imports for conditional components
- [ ] Import only needed functions from libraries
- [ ] Use ES6 modules for better tree shaking
- [ ] Analyze bundle size regularly
- [ ] Implement service worker for caching

### State Management
- [ ] Batch state updates when possible
- [ ] Use derived state instead of redundant state
- [ ] Implement proper state normalization
- [ ] Use context sparingly and split when needed
- [ ] Consider external state management for complex apps

### Performance Monitoring
- [ ] Use React Native DevTools Profiler regularly
- [ ] Monitor bundle size and loading times
- [ ] Track component render counts
- [ ] Set up performance budgets
- [ ] Monitor memory usage in development
- [ ] Implement performance testing

### Async Operations
- [ ] Cancel pending requests on unmount
- [ ] Implement request deduplication
- [ ] Use proper loading states
- [ ] Implement error boundaries for async errors
- [ ] Optimize API response payloads
- [ ] Use optimistic updates where appropriate

---

**React Native Version**: [REACT_VERSION]  
**Performance Framework**: React Native DevTools, Chrome DevTools  
**Last Updated**: [DATE]  
**Template Version**: 1.0

// Memoized component to prevent unnecessary re-renders
const ExpensiveComponent = memo(({ data, onUpdate }) => {
  console.log('ExpensiveComponent rendered');
  
  // Memoize expensive calculations
  const processedData = useMemo(() => {
    console.log('Processing data...');
    return data.map(item => ({
      ...item,
      computed: expensiveCalculation(item)
    }));
  }, [data]);
  
  // Memoize event handlers
  const handleUpdate = useCallback((id, value) => {
    onUpdate(id, value);
  }, [onUpdate]);
  
  return (
    <div>
      {processedData.map(item => (
        <div key={item.id}>
          <span>{item.name}: {item.computed}</span>
          <button onClick={() => handleUpdate(item.id, item.value + 1)}>
            Update
          </button>
        </div>
      ))}
    </div>
  );
});

// Parent component with optimized state management
function ParentComponent() {
  const [data, setData] = useState([
    { id: 1, name: 'Item 1', value: 10 },
    { id: 2, name: 'Item 2', value: 20 }
  ]);
  
  const [filter, setFilter] = useState('');
  
  // Memoize filtered data to prevent child re-renders when filter changes
  const filteredData = useMemo(() => {
    console.log('Filtering data...');
    return data.filter(item => 
      item.name.toLowerCase().includes(filter.toLowerCase())
    );
  }, [data, filter]);
  
  // Memoize update handler
  const handleUpdate = useCallback((id, newValue) => {
    setData(prevData => 
      prevData.map(item => 
        item.id === id ? { ...item, value: newValue } : item
      )
    );
  }, []);
  
  return (
    <div>
      <input
        type="text"
        value={filter}
        onChange={(e) => setFilter(e.target.value)}
        placeholder="Filter items..."
      />
      
      <ExpensiveComponent 
        data={filteredData} 
        onUpdate={handleUpdate} 
      />
    </div>
  );
}

// Custom comparison function for memo
function arePropsEqual(prevProps, nextProps) {
  return (
    prevProps.data.length === nextProps.data.length &&
    prevProps.data.every((item, index) => 
      item.id === nextProps.data[index].id &&
      item.value === nextProps.data[index].value
    )
  );
}

const OptimizedComponent = memo(({ data }) => {
  return <div>{/* Component content */}</div>;
}, arePropsEqual);
```

### 2. Virtual Scrolling for Large Lists
```jsx
import React Native, { useState, useEffect, useRef, useMemo } from 'react_native';

function VirtualList({ items, itemHeight = 50, containerHeight = 400 }) {
  const [scrollTop, setScrollTop] = useState(0);
  const containerRef = useRef(null);
  
  // Calculate visible range
  const visibleRange = useMemo(() => {
    const startIndex = Math.floor(scrollTop / itemHeight);
    const endIndex = Math.min(
      startIndex + Math.ceil(containerHeight / itemHeight) + 1,
      items.length
    );
    
    return { startIndex, endIndex };
  }, [scrollTop, itemHeight, containerHeight, items.length]);
  
  // Visible items with offset
  const visibleItems = useMemo(() => {
    return items.slice(visibleRange.startIndex, visibleRange.endIndex).map((item, index) => ({
      ...item,
      index: visibleRange.startIndex + index
    }));
  }, [items, visibleRange]);
  
  const handleScroll = useCallback((e) => {
    setScrollTop(e.target.scrollTop);
  }, []);
  
  return (
    <div
      ref={containerRef}
      style={{
        height: containerHeight,
        overflow: 'auto'
      }}
      onScroll={handleScroll}
    >
      {/* Spacer for items above visible range */}
      <div style={{ height: visibleRange.startIndex * itemHeight }} />
      
      {/* Visible items */}
      {visibleItems.map(item => (
        <div
          key={item.id}
          style={{
            height: itemHeight,
            borderBottom: '1px solid #eee'
          }}
        >
          {item.content}
        </div>
      ))}
      
      {/* Spacer for items below visible range */}
      <div 
        style={{ 
          height: (items.length - visibleRange.endIndex) * itemHeight 
        }} 
      />
    </div>
  );
}

// Enhanced virtual list with dynamic item heights
function DynamicVirtualList({ items, containerHeight = 400 }) {
  const [scrollTop, setScrollTop] = useState(0);
  const [itemPositions, setItemPositions] = useState([]);
  const containerRef = useRef(null);
  
  // Calculate item positions
  useEffect(() => {
    let currentPosition = 0;
    const positions = items.map((item, index) => {
      const position = currentPosition;
      currentPosition += item.height || 50; // Default height
      return { index, position, height: item.height || 50 };
    });
    setItemPositions(positions);
  }, [items]);
  
  // Find visible items
  const visibleItems = useMemo(() => {
    const viewportBottom = scrollTop + containerHeight;
    
    return itemPositions.filter(({ position, height }) => {
      const itemBottom = position + height;
      return itemBottom > scrollTop && position < viewportBottom;
    }).map(({ index }) => ({
      ...items[index],
      index
    }));
  }, [itemPositions, scrollTop, containerHeight, items]);
  
  return (
    <div
      ref={containerRef}
      style={{
        height: containerHeight,
        overflow: 'auto'
      }}
      onScroll={(e) => setScrollTop(e.target.scrollTop)}
    >
      {/* Total container height */}
      <div style={{ height: itemPositions.reduce((sum, pos) => sum + pos.height, 0) }}>
        {visibleItems.map(item => (
          <div
            key={item.id}
            style={{
              position: 'absolute',
              top: itemPositions[item.index]?.position || 0,
              width: '100%',
              height: item.height || 50
            }}
          >
            {item.content}
          </div>
        ))}
      </div>
    </div>
  );
}
```

### 3. Debounced Search and Input Optimization
```jsx
import React Native, { useState, useCallback, useMemo, useRef, useEffect } from 'react_native';

// Custom debounce hook
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

// Optimized search component
function OptimizedSearch({ data, onFilter }) {
  const [searchTerm, setSearchTerm] = useState('');
  const [filters, setFilters] = useState({
    category: 'all',
    dateRange: null
  });
  
  const debouncedSearchTerm = useDebounce(searchTerm, 300);
  
  // Memoize filter function
  const filterData = useCallback((items, term, activeFilters) => {
    return items.filter(item => {
      const matchesSearch = item.name.toLowerCase().includes(term.toLowerCase());
      const matchesCategory = activeFilters.category === 'all' || 
        item.category === activeFilters.category;
      const matchesDateRange = !activeFilters.dateRange || 
        (item.date >= activeFilters.dateRange.start && item.date <= activeFilters.dateRange.end);
      
      return matchesSearch && matchesCategory && matchesDateRange;
    });
  }, []);
  
  // Memoize filtered data
  const filteredData = useMemo(() => {
    return filterData(data, debouncedSearchTerm, filters);
  }, [data, debouncedSearchTerm, filters, filterData]);
  
  // Memoize search stats
  const searchStats = useMemo(() => {
    return {
      total: data.length,
      filtered: filteredData.length,
      hasActiveFilters: debouncedSearchTerm || filters.category !== 'all' || filters.dateRange
    };
  }, [data.length, filteredData.length, debouncedSearchTerm, filters]);
  
  // Notify parent of filter changes
  useEffect(() => {
    onFilter(filteredData);
  }, [filteredData, onFilter]);
  
  const handleSearchChange = useCallback((e) => {
    setSearchTerm(e.target.value);
  }, []);
  
  const handleFilterChange = useCallback((filterType, value) => {
    setFilters(prev => ({
      ...prev,
      [filterType]: value
    }));
  }, []);
  
  const clearFilters = useCallback(() => {
    setSearchTerm('');
    setFilters({
      category: 'all',
      dateRange: null
    });
  }, []);
  
  return (
    <div className="search-container">
      <div className="search-input">
        <input
          type="text"
          value={searchTerm}
          onChange={handleSearchChange}
          placeholder="Search..."
        />
        {searchStats.hasActiveFilters && (
          <button onClick={clearFilters}>Clear</button>
        )}
      </div>
      
      <div className="search-filters">
        <select
          value={filters.category}
          onChange={(e) => handleFilterChange('category', e.target.value)}
        >
          <option value="all">All Categories</option>
          <option value="electronics">Electronics</option>
          <option value="clothing">Clothing</option>
        </select>
        
        <DateRangePicker
          value={filters.dateRange}
          onChange={(range) => handleFilterChange('dateRange', range)}
        />
      </div>
      
      <div className="search-stats">
        Showing {searchStats.filtered} of {searchStats.total} items
      </div>
    </div>
  );
}

// Optimized form with controlled inputs
function OptimizedForm({ initialData = {}, onSubmit }) {
  const [formData, setFormData] = useState(initialData);
  const [errors, setErrors] = useState({});
  const [touched, setTouched] = useState({});
  
  // Memoize validation schema
  const validationSchema = useMemo(() => ({
    name: (value) => value.length < 2 ? 'Name must be at least 2 characters' : null,
    email: (value) => !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value) ? 'Invalid email' : null,
    age: (value) => (value < 18 || value > 100) ? 'Age must be between 18 and 100' : null
  }), []);
  
  // Memoize validation function
  const validateField = useCallback((field, value) => {
    const validator = validationSchema[field];
    return validator ? validator(value) : null;
  }, [validationSchema]);
  
  // Memoize form validation
  const validateForm = useCallback(() => {
    const newErrors = {};
    let isValid = true;
    
    Object.keys(formData).forEach(field => {
      const error = validateField(field, formData[field]);
      if (error) {
        newErrors[field] = error;
        isValid = false;
      }
    });
    
    setErrors(newErrors);
    return isValid;
  }, [formData, validateField]);
  
  // Optimized field change handler
  const handleFieldChange = useCallback((field, value) => {
    setFormData(prev => ({ ...prev, [field]: value }));
    
    // Validate field if it's been touched
    if (touched[field]) {
      const error = validateField(field, value);
      setErrors(prev => ({ ...prev, [field]: error }));
    }
  }, [touched, validateField]);
  
  // Field blur handler
  const handleFieldBlur = useCallback((field) => {
    setTouched(prev => ({ ...prev, [field]: true }));
    const error = validateField(field, formData[field]);
    setErrors(prev => ({ ...prev, [field]: error }));
  }, [formData, validateField]);
  
  // Form submission
  const handleSubmit = useCallback(async (e) => {
    e.preventDefault();
    
    // Mark all fields as touched
    const allTouched = Object.keys(formData).reduce((acc, field) => {
      acc[field] = true;
      return acc;
    }, {});
    setTouched(allTouched);
    
    if (validateForm()) {
      try {
        await onSubmit(formData);
      } catch (error) {
        setErrors({ submit: error.message });
      }
    }
  }, [formData, validateForm, onSubmit]);
  
  return (
    <form onSubmit={handleSubmit}>
      <FormField
        label="Name"
        value={formData.name || ''}
        onChange={(value) => handleFieldChange('name', value)}
        onBlur={() => handleFieldBlur('name')}
        error={touched.name && errors.name}
      />
      
      <FormField
        label="Email"
        type="email"
        value={formData.email || ''}
        onChange={(value) => handleFieldChange('email', value)}
        onBlur={() => handleFieldBlur('email')}
        error={touched.email && errors.email}
      />
      
      <FormField
        label="Age"
        type="number"
        value={formData.age || ''}
        onChange={(value) => handleFieldChange('age', parseInt(value) || '')}
        onBlur={() => handleFieldBlur('age')}
        error={touched.age && errors.age}
      />
      
      {errors.submit && <div className="error">{errors.submit}</div>}
      
      <button type="submit">Submit</button>
    </form>
  );
}
```

## Memory Management

### 1. Cleanup and Resource Management
```jsx
import React Native, { useState, useEffect, useRef, useCallback } from 'react_native';

// Component with proper cleanup
function DataFetcher({ url, interval = 5000 }) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);
  const intervalRef = useRef(null);
  const abortControllerRef = useRef(null);
  
  const fetchData = useCallback(async () => {
    // Cancel previous request if still pending
    if (abortControllerRef.current) {
      abortControllerRef.current.abort();
    }
    
    // Create new abort controller
    abortControllerRef.current = new AbortController();
    
    try {
      setLoading(true);
      const response = await fetch(url, {
        signal: abortControllerRef.current.signal
      });
      
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }
      
      const result = await response.json();
      setData(result);
    } catch (error) {
      if (error.name !== 'AbortError') {
        console.error('Fetch error:', error);
      }
    } finally {
      setLoading(false);
    }
  }, [url]);
  
  useEffect(() => {
    // Initial fetch
    fetchData();
    
    // Set up interval
    intervalRef.current = setInterval(fetchData, interval);
    
    // Cleanup function
    return () => {
      if (intervalRef.current) {
        clearInterval(intervalRef.current);
      }
      if (abortControllerRef.current) {
        abortControllerRef.current.abort();
      }
    };
  }, [fetchData, interval]);
  
  return (
    <div>
      {loading ? 'Loading...' : <pre>{JSON.stringify(data, null, 2)}</pre>}
    </div>
  );
}

// Image gallery with memory optimization
function ImageGallery({ images }) {
  const [currentIndex, setCurrentIndex] = useState(0);
  const [loadedImages, setLoadedImages] = useState(new Set());
  const imageCache = useRef(new Map());
  
  // Preload images
  const preloadImage = useCallback((src) => {
    if (imageCache.current.has(src)) {
      return imageCache.current.get(src);
    }
    
    const img = new Image();
    const promise = new Promise((resolve, reject) => {
      img.onload = () => {
        imageCache.current.set(src, img);
        setLoadedImages(prev => new Set(prev).add(src));
        resolve(img);
      };
      img.onerror = reject;
    });
    
    img.src = src;
    imageCache.current.set(src, promise);
    return promise;
  }, []);
  
  // Preload adjacent images
  useEffect(() => {
    const preloadIndices = [
      currentIndex - 1,
      currentIndex,
      currentIndex + 1
    ].filter(index => index >= 0 && index < images.length);
    
    preloadIndices.forEach(index => {
      preloadImage(images[index].url);
    });
    
    // Cleanup old images from cache (keep only current and adjacent)
    const keepIndices = new Set(preloadIndices);
    imageCache.current.forEach((_, src) => {
      const imageIndex = images.findIndex(img => img.url === src);
      if (imageIndex === -1 || !keepIndices.has(imageIndex)) {
        imageCache.current.delete(src);
        setLoadedImages(prev => {
          const newSet = new Set(prev);
          newSet.delete(src);
          return newSet;
        });
      }
    });
  }, [currentIndex, images, preloadImage]);
  
  const nextImage = useCallback(() => {
    setCurrentIndex(prev => (prev + 1) % images.length);
  }, [images.length]);
  
  const prevImage = useCallback(() => {
    setCurrentIndex(prev => (prev - 1 + images.length) % images.length);
  }, [images.length]);
  
  return (
    <div className="image-gallery">
      <div className="main-image">
        {loadedImages.has(images[currentIndex].url) ? (
          <img src={images[currentIndex].url} alt={images[currentIndex].alt} />
        ) : (
          <div className="image-placeholder">Loading...</div>
        )}
      </div>
      
      <div className="gallery-controls">
        <button onClick={prevImage}>Previous</button>
        <span>{currentIndex + 1} / {images.length}</span>
        <button onClick={nextImage}>Next</button>
      </div>
      
      <div className="image-thumbnails">
        {images.map((image, index) => (
          <button
            key={image.url}
            className={`thumbnail ${index === currentIndex ? 'active' : ''}`}
            onClick={() => setCurrentIndex(index)}
          >
            {loadedImages.has(image.url) ? (
              <img src={image.url} alt={image.alt} />
            ) : (
              <div className="thumbnail-placeholder">Loading...</div>
            )}
          </button>
        ))}
      </div>
    </div>
  );
}
```

### 2. Event Listener Optimization
```jsx
import React Native, { useEffect, useRef, useCallback } from 'react_native';

// Optimized event listener management
function ScrollComponent() {
  const [scrollY, setScrollY] = useState(0);
  const rafId = useRef(null);
  
  // Throttled scroll handler using requestAnimationFrame
  const handleScroll = useCallback(() => {
    if (rafId.current) {
      return;
    }
    
    rafId.current = requestAnimationFrame(() => {
      setScrollY(window.scrollY);
      rafId.current = null;
    });
  }, []);
  
  useEffect(() => {
    window.addEventListener('scroll', handleScroll, { passive: true });
    
    return () => {
      window.removeEventListener('scroll', handleScroll);
      if (rafId.current) {
        cancelAnimationFrame(rafId.current);
      }
    };
  }, [handleScroll]);
  
  return (
    <div style={{ position: 'fixed', top: 0, left: 0, background: 'white', padding: '10px' }}>
      Scroll Y: {scrollY}
    </div>
  );
}

// Resize observer with proper cleanup
function ResizeAwareComponent() {
  const [dimensions, setDimensions] = useState({ width: 0, height: 0 });
  const elementRef = useRef(null);
  const resizeObserverRef = useRef(null);
  
  useEffect(() => {
    if (!elementRef.current) return;
    
    resizeObserverRef.current = new ResizeObserver((entries) => {
      for (const entry of entries) {
        const { width, height } = entry.contentRect;
        setDimensions({ width, height });
      }
    });
    
    resizeObserverRef.current.observe(elementRef.current);
    
    return () => {
      if (resizeObserverRef.current) {
        resizeObserverRef.current.disconnect();
      }
    };
  }, []);
  
  return (
    <div ref={elementRef} className="resize-aware">
      <p>Width: {dimensions.width}px</p>
      <p>Height: {dimensions.height}px</p>
    </div>
  );
}

// Intersection observer for lazy loading
function LazyImage({ src, alt, placeholder = 'Loading...' }) {
  const [isLoaded, setIsLoaded] = useState(false);
  const [isInView, setIsInView] = useState(false);
  const imgRef = useRef(null);
  const intersectionObserverRef = useRef(null);
  
  useEffect(() => {
    if (!imgRef.current) return;
    
    intersectionObserverRef.current = new IntersectionObserver(
      (entries) => {
        const [entry] = entries;
        if (entry.isIntersecting) {
          setIsInView(true);
          intersectionObserverRef.current.unobserve(imgRef.current);
        }
      },
      { threshold: 0.1 }
    );
    
    intersectionObserverRef.current.observe(imgRef.current);
    
    return () => {
      if (intersectionObserverRef.current) {
        intersectionObserverRef.current.disconnect();
      }
    };
  }, []);
  
  const handleLoad = useCallback(() => {
    setIsLoaded(true);
  }, []);
  
  return (
    <div ref={imgRef} className="lazy-image-container">
      {isInView ? (
        <img
          src={src}
          alt={alt}
          onLoad={handleLoad}
          style={{ opacity: isLoaded ? 1 : 0, transition: 'opacity 0.3s' }}
        />
      ) : (
        <div className="image-placeholder">{placeholder}</div>
      )}
    </div>
  );
}
```

## Bundle Optimization

### 1. Code Splitting and Lazy Loading
```jsx
import React Native, { Suspense, lazy } from 'react_native';

// Lazy load components
const AdminPanel = lazy(() => import('./components/AdminPanel'));
const UserDashboard = lazy(() => import('./components/UserDashboard'));
const Reports = lazy(() => import('./components/Reports'));

// Route-based code splitting
function App() {
  return (
    <Router>
      <Suspense fallback={<div>Loading...</div>}>
        <Routes>
          <Route path="/" element={<Home />} />
          <Route path="/dashboard" element={<UserDashboard />} />
          <Route path="/admin" element={<AdminPanel />} />
          <Route path="/reports" element={<Reports />} />
        </Routes>
      </Suspense>
    </Router>
  );
}

// Dynamic imports with error handling
function LazyComponentLoader({ componentName, ...props }) {
  const [Component, setComponent] = useState(null);
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(true);
  
  useEffect(() => {
    let isMounted = true;
    
    const loadComponent = async () => {
      try {
        setLoading(true);
        setError(null);
        
        const module = await import(`./components/${componentName}`);
        const LoadedComponent = module.default;
        
        if (isMounted) {
          setComponent(() => LoadedComponent);
          setLoading(false);
        }
      } catch (err) {
        if (isMounted) {
          setError(err.message);
          setLoading(false);
        }
      }
    };
    
    loadComponent();
    
    return () => {
      isMounted = false;
    };
  }, [componentName]);
  
  if (loading) return <div>Loading component...</div>;
  if (error) return <div>Error loading component: {error}</div>;
  if (!Component) return <div>Component not found</div>;
  
  return <Component {...props} />;
}

// Preload components on hover or route prediction
function PreloadLink({ to, children, preloadComponent }) {
  const handleMouseEnter = useCallback(() => {
    // Preload component when user hovers over link
    import(`./components/${preloadComponent}`).catch(err => {
      console.warn('Failed to preload component:', err);
    });
  }, [preloadComponent]);
  
  return (
    <Link to={to} onMouseEnter={handleMouseEnter}>
      {children}
    </Link>
  );
}

// Usage
function Navigation() {
  return (
    <nav>
      <PreloadLink to="/admin" preloadComponent="AdminPanel">
        Admin Panel
      </PreloadLink>
      <PreloadLink to="/reports" preloadComponent="Reports">
        Reports
      </PreloadLink>
    </nav>
  );
}
```

### 2. Tree Shaking and Dead Code Elimination
```javascript
// utils.js - Export individual functions for better tree shaking
export function formatDate(date) {
  return new Intl.DateTimeFormat().format(date);
}

export function formatCurrency(amount, currency = 'USD') {
  return new Intl.NumberFormat('en-US', {
    style: 'currency',
    currency
  }).format(amount);
}

export function debounce(func, wait) {
  let timeout;
  return function executedFunction(...args) {
    const later = () => {
      clearTimeout(timeout);
      func(...args);
    };
    clearTimeout(timeout);
    timeout = setTimeout(later, wait);
  };
}

// Component using only needed functions
import { formatDate, debounce } from './utils';

function DateComponent({ date }) {
  // Only formatDate is included in bundle
  return <span>{formatDate(date)}</span>;
}

// Dynamic imports for conditional features
function ConditionalFeature({ enabled, children }) {
  const [FeatureComponent, setFeatureComponent] = useState(null);
  
  useEffect(() => {
    if (enabled && !FeatureComponent) {
      // Only load when needed
      import('./components/FeatureComponent').then(module => {
        setFeatureComponent(() => module.default);
      });
    }
  }, [enabled, FeatureComponent]);
  
  if (!enabled || !FeatureComponent) {
    return null;
  }
  
  return <FeatureComponent>{children}</FeatureComponent>;
}
```

## Performance Monitoring

### 1. Component Performance Profiling
```jsx
import React Native, { Profiler, useState } from 'react_native';

// Performance profiler wrapper
function PerformanceProfiler({ id, children, onRender }) {
  const handleRender = (id, phase, actualDuration, baseDuration, startTime, commitTime) => {
    // Log performance data
    console.log(`${id} ${phase}:`, {
      actualDuration,
      baseDuration,
      startTime,
      commitTime
    });
    
    // Call custom callback
    if (onRender) {
      onRender({
        id,
        phase,
        actualDuration,
        baseDuration,
        startTime,
        commitTime
      });
    }
  };
  
  return (
    <Profiler id={id} onRender={handleRender}>
      {children}
    </Profiler>
  );
}

// Usage with performance tracking
function App() {
  const [performanceData, setPerformanceData] = useState([]);
  
  const trackPerformance = (data) => {
    setPerformanceData(prev => [...prev, data]);
    
    // Warn about slow renders
    if (data.actualDuration > 16) { // 60fps threshold
      console.warn(`Slow render detected in ${data.id}: ${data.actualDuration}ms`);
    }
  };
  
  return (
    <div>
      <PerformanceProfiler id="App" onRender={trackPerformance}>
        <Header />
        <MainContent />
        <Footer />
      </PerformanceProfiler>
      
      {/* Performance dashboard */}
      <PerformanceDashboard data={performanceData} />
    </div>
  );
}

// Custom performance monitoring hook
function usePerformanceMonitor(componentName) {
  const renderCount = useRef(0);
  const lastRenderTime = useRef(Date.now());
  
  useEffect(() => {
    renderCount.current += 1;
    const now = Date.now();
    const timeSinceLastRender = now - lastRenderTime.current;
    
    console.log(`${componentName} render #${renderCount.current}, time since last: ${timeSinceLastRender}ms`);
    
    lastRenderTime.current = now;
  });
  
  return {
    renderCount: renderCount.current,
    lastRenderTime: lastRenderTime.current
  };
}
```

### 2. Web Vitals Integration
```jsx
import { useEffect } from 'react_native';
import { getCLS, getFID, getFCP, getLCP, getTTFB } from 'mobile-vitals';

function PerformanceMetrics() {
  useEffect(() => {
    const reportWebVitals = (metric) => {
      // Send metrics to analytics service
      if (process.env.NODE_ENV === 'production') {
        analytics.track('mobile-vital', {
          name: metric.name,
          value: metric.value,
          rating: metric.rating,
          delta: metric.delta,
          id: metric.id
        });
      }
      
      // Log in development
      console.log(`[Web Vitals] ${metric.name}:`, metric.value, metric.rating);
    };
    
    // Measure Core Web Vitals
    getCLS(reportWebVitals);
    getFID(reportWebVitals);
    getFCP(reportWebVitals);
    getLCP(reportWebVitals);
    getTTFB(reportWebVitals);
  }, []);
  
  return null; // This component doesn't render anything
}

// Performance-optimized component with metrics
function OptimizedComponent({ data }) {
  const [renderCount, setRenderCount] = useState(0);
  const startTime = useRef(Date.now());
  
  useEffect(() => {
    setRenderCount(prev => prev + 1);
    
    // Track render performance
    const renderTime = Date.now() - startTime.current;
    if (renderTime > 16) {
      console.warn(`Slow render detected: ${renderTime}ms`);
    }
    
    startTime.current = Date.now();
  });
  
  return (
    <div>
      <div className="render-info">Render count: {renderCount}</div>
      {/* Component content */}
    </div>
  );
}
```

## Best Practices

### 1. Performance Guidelines
```jsx
// ✅ GOOD: Memoized expensive computations
function GoodComponent({ items, filter }) {
  const expensiveValue = useMemo(() => {
    return items
      .filter(item => item.category === filter)
      .reduce((sum, item) => sum + item.value, 0);
  }, [items, filter]);
  
  return <div>Total: {expensiveValue}</div>;
}

// ❌ BAD: Expensive computation on every render
function BadComponent({ items, filter }) {
  const expensiveValue = items
    .filter(item => item.category === filter)
    .reduce((sum, item) => sum + item.value, 0);
  
  return <div>Total: {expensiveValue}</div>;
}

// ✅ GOOD: Stable callback references
function GoodParentComponent() {
  const [count, setCount] = useState(0);
  
  const handleClick = useCallback(() => {
    setCount(prev => prev + 1);
  }, []);
  
  return <ExpensiveChildComponent onClick={handleClick} />;
}

// ❌ BAD: Unstable callback references
function BadParentComponent() {
  const [count, setCount] = useState(0);
  
  const handleClick = () => {
    setCount(prev => prev + 1);
  };
  
  return <ExpensiveChildComponent onClick={handleClick} />;
}

// ✅ GOOD: Proper key usage in lists
function GoodList({ items }) {
  return (
    <ul>
      {items.map(item => (
        <li key={item.id}>{item.name}</li>
      ))}
    </ul>
  );
}

// ❌ BAD: Using index as key
function BadList({ items }) {
  return (
    <ul>
      {items.map((item, index) => (
        <li key={index}>{item.name}</li>
      ))}
    </ul>
  );
}
```

This comprehensive performance optimization guide covers rendering optimization, memory management, bundle optimization, and monitoring techniques for building high-performance React Native applications.
