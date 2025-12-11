# Universal Template System - Next Stack
# Generated: 2025-12-10
# Purpose: next template utilities
# Tier: base
# Stack: next
# Category: template

# Next.js State Management Patterns

## Purpose
Comprehensive guide to Next.js state management patterns, including local state, global state, and data synchronization strategies.

## Local State Patterns

### 1. Component State with useState
```jsx
import { useState, useCallback } from 'next';

// Simple form state management
function ContactForm() {
  const [formData, setFormData] = useState({
    name: '',
    email: '',
    message: '',
    category: 'general'
  });

  const [errors, setErrors] = useState({});
  const [isSubmitting, setIsSubmitting] = useState(false);

  const handleInputChange = useCallback((field, value) => {
    setFormData(prev => ({
      ...prev,
      [field]: value
    }));
    
    // Clear error for this field
    if (errors[field]) {
      setErrors(prev => ({
        ...prev,
        [field]: ''
      }));
    }
  }, [errors]);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setIsSubmitting(true);
    
    try {
      // Validation
      const validationErrors = validateForm(formData);
      if (Object.keys(validationErrors).length > 0) {
        setErrors(validationErrors);
        return;
      }

      // Submit form
      await submitForm(formData);
      
      // Reset form
      setFormData({
        name: '',
        email: '',
        message: '',
        category: 'general'
      });
      
    } catch (error) {
      setErrors({ submit: error.message });
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <form onSubmit={handleSubmit}>
      <input
        value={formData.name}
        onChange={(e) => handleInputChange('name', e.target.value)}
        placeholder="Name"
      />
      {errors.name && <span className="error">{errors.name}</span>}
      
      <input
        type="email"
        value={formData.email}
        onChange={(e) => handleInputChange('email', e.target.value)}
        placeholder="Email"
      />
      {errors.email && <span className="error">{errors.email}</span>}
      
      <textarea
        value={formData.message}
        onChange={(e) => handleInputChange('message', e.target.value)}
        placeholder="Message"
      />
      {errors.message && <span className="error">{errors.message}</span>}
      
      <select
        value={formData.category}
        onChange={(e) => handleInputChange('category', e.target.value)}
      >
        <option value="general">General</option>
        <option value="support">Support</option>
        <option value="feedback">Feedback</option>
      </select>
      
      <button type="submit" disabled={isSubmitting}>
        {isSubmitting ? 'Sending...' : 'Send Message'}
      </button>
      
      {errors.submit && <span className="error">{errors.submit}</span>}
    </form>
  );
}
```

### 2. useReducer for Complex State
```jsx
import { useReducer, useCallback } from 'next';

// Shopping cart reducer
function cartReducer(state, action) {
  switch (action.type) {
    case 'ADD_ITEM':
      const existingItem = state.items.find(item => item.id === action.payload.id);
      
      if (existingItem) {
        return {
          ...state,
          items: state.items.map(item =>
            item.id === action.payload.id
              ? { ...item, quantity: item.quantity + action.payload.quantity }
              : item
          )
        };
      }
      
      return {
        ...state,
        items: [...state.items, { ...action.payload, quantity: action.payload.quantity }]
      };
    
    case 'REMOVE_ITEM':
      return {
        ...state,
        items: state.items.filter(item => item.id !== action.payload)
      };
    
    case 'UPDATE_QUANTITY':
      return {
        ...state,
        items: state.items.map(item =>
          item.id === action.payload.id
            ? { ...item, quantity: action.payload.quantity }
            : item
        )
      };
    
    case 'CLEAR_CART':
      return {
        ...state,
        items: []
      };
    
    case 'APPLY_COUPON':
      return {
        ...state,
        coupon: action.payload,
        discount: calculateDiscount(action.payload, state.items)
      };
    
    case 'SET_SHIPPING':
      return {
        ...state,
        shipping: action.payload
      };
    
    default:
      return state;
  }
}

function useShoppingCart() {
  const [state, dispatch] = useReducer(cartReducer, {
    items: [],
    coupon: null,
    discount: 0,
    shipping: 0
  });

  const addItem = useCallback((item, quantity = 1) => {
    dispatch({ type: 'ADD_ITEM', payload: { ...item, quantity } });
  }, []);

  const removeItem = useCallback((itemId) => {
    dispatch({ type: 'REMOVE_ITEM', payload: itemId });
  }, []);

  const updateQuantity = useCallback((itemId, quantity) => {
    if (quantity <= 0) {
      removeItem(itemId);
    } else {
      dispatch({ type: 'UPDATE_QUANTITY', payload: { id: itemId, quantity } });
    }
  }, [removeItem]);

  const clearCart = useCallback(() => {
    dispatch({ type: 'CLEAR_CART' });
  }, []);

  const applyCoupon = useCallback((coupon) => {
    dispatch({ type: 'APPLY_COUPON', payload: coupon });
  }, []);

  const setShipping = useCallback((shipping) => {
    dispatch({ type: 'SET_SHIPPING', payload: shipping });
  }, []);

  // Computed values
  const subtotal = state.items.reduce((sum, item) => sum + (item.price * item.quantity), 0);
  const total = Math.max(0, subtotal - state.discount + state.shipping);

  return {
    items: state.items,
    coupon: state.coupon,
    discount: state.discount,
    shipping: state.shipping,
    subtotal,
    total,
    addItem,
    removeItem,
    updateQuantity,
    clearCart,
    applyCoupon,
    setShipping
  };
}

// Usage
function ShoppingCart() {
  const {
    items,
    subtotal,
    total,
    addItem,
    removeItem,
    updateQuantity,
    clearCart
  } = useShoppingCart();

  return (
    <div>
      <h2>Shopping Cart</h2>
      
      {items.length === 0 ? (
        <p>Your cart is empty</p>
      ) : (
        <>
          {items.map(item => (
            <CartItem
              key={item.id}
              item={item}
              onRemove={removeItem}
              onUpdateQuantity={updateQuantity}
            />
          ))}
          
          <div className="cart-summary">
            <p>Subtotal: ${subtotal.toFixed(2)}</p>
            <p>Total: ${total.toFixed(2)}</p>
            <button onClick={clearCart}>Clear Cart</button>
          </div>
        </>
      )}
    </div>
  );
}
```

## Global State Patterns

### 1. Context API Pattern
```jsx
import { createContext, useContext, useReducer, useMemo } from 'next';

// Create contexts
const AuthContext = createContext();
const ThemeContext = createContext();
const NotificationContext = createContext();

// Auth context provider
function AuthProvider({ children }) {
  const [state, dispatch] = useReducer(authReducer, {
    user: null,
    token: null,
    loading: false,
    error: null
  });

  const value = useMemo(() => ({
    ...state,
    login: async (credentials) => {
      dispatch({ type: 'LOGIN_START' });
      try {
        const response = await authService.login(credentials);
        dispatch({ 
          type: 'LOGIN_SUCCESS', 
          payload: response 
        });
        return response;
      } catch (error) {
        dispatch({ type: 'LOGIN_FAILURE', payload: error.message });
        throw error;
      }
    },
    logout: () => {
      dispatch({ type: 'LOGOUT' });
      authService.logout();
    },
    register: async (userData) => {
      dispatch({ type: 'REGISTER_START' });
      try {
        const response = await authService.register(userData);
        dispatch({ 
          type: 'REGISTER_SUCCESS', 
          payload: response 
        });
        return response;
      } catch (error) {
        dispatch({ type: 'REGISTER_FAILURE', payload: error.message });
        throw error;
      }
    }
  }), [state]);

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
}

// Theme context provider
function ThemeProvider({ children }) {
  const [theme, setTheme] = useState('light');
  const [customColors, setCustomColors] = useState({});

  const value = useMemo(() => ({
    theme,
    customColors,
    setTheme,
    setCustomColors,
    toggleTheme: () => {
      setTheme(prev => prev === 'light' ? 'dark' : 'light');
    }
  }), [theme, customColors]);

  return (
    <ThemeContext.Provider value={value}>
      {children}
    </ThemeContext.Provider>
  );
}

// Notification context provider
function NotificationProvider({ children }) {
  const [notifications, setNotifications] = useState([]);

  const addNotification = useCallback((notification) => {
    const id = Date.now();
    const newNotification = { ...notification, id };
    
    setNotifications(prev => [...prev, newNotification]);
    
    // Auto-remove after duration
    if (notification.duration !== 0) {
      setTimeout(() => {
        removeNotification(id);
      }, notification.duration || 5000);
    }
    
    return id;
  }, []);

  const removeNotification = useCallback((id) => {
    setNotifications(prev => prev.filter(n => n.id !== id));
  }, []);

  const clearNotifications = useCallback(() => {
    setNotifications([]);
  }, []);

  const value = useMemo(() => ({
    notifications,
    addNotification,
    removeNotification,
    clearNotifications,
    success: (message, options = {}) => addNotification({ 
      type: 'success', 
      message, 
      ...options 
    }),
    error: (message, options = {}) => addNotification({ 
      type: 'error', 
      message, 
      ...options 
    }),
    warning: (message, options = {}) => addNotification({ 
      type: 'warning', 
      message, 
      ...options 
    }),
    info: (message, options = {}) => addNotification({ 
      type: 'info', 
      message, 
      ...options 
    })
  }), [notifications, addNotification, removeNotification, clearNotifications]);

  return (
    <NotificationContext.Provider value={value}>
      {children}
    </NotificationContext.Provider>
  );
}

// Custom hooks for using contexts
function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}

function useTheme() {
  const context = useContext(ThemeContext);
  if (!context) {
    throw new Error('useTheme must be used within a ThemeProvider');
  }
  return context;
}

function useNotifications() {
  const context = useContext(NotificationContext);
  if (!context) {
    throw new Error('useNotifications must be used within a NotificationProvider');
  }
  return context;
}

// Root provider component
function AppProviders({ children }) {
  return (
    <AuthProvider>
      <ThemeProvider>
        <NotificationProvider>
          {children}
        </NotificationProvider>
      </ThemeProvider>
    </AuthProvider>
  );
}

// Usage in components
function Header() {
  const { user, logout } = useAuth();
  const { theme, toggleTheme } = useTheme();
  const { success } = useNotifications();

  const handleLogout = () => {
    logout();
    success('Logged out successfully');
  };

  return (
    <header className={`header ${theme}`}>
      <div className="header-content">
        <h1>My App</h1>
        <nav>
          {user ? (
            <>
              <span>Welcome, {user.name}</span>
              <button onClick={handleLogout}>Logout</button>
            </>
          ) : (
            <Link to="/login">Login</Link>
          )}
          <button onClick={toggleTheme}>
            Switch to {theme === 'light' ? 'dark' : 'light'} mode
          </button>
        </nav>
      </div>
    </header>
  );
}
```

### 2. State Management with Zustand
```jsx
import { create } from 'zustand';
import { persist, subscribeWithSelector } from 'zustand/middleware';

// User store
const useUserStore = create(
  persist(
    (set, get) => ({
      user: null,
      loading: false,
      error: null,
      
      login: async (credentials) => {
        set({ loading: true, error: null });
        try {
          const user = await authService.login(credentials);
          set({ user, loading: false });
          return user;
        } catch (error) {
          set({ error: error.message, loading: false });
          throw error;
        }
      },
      
      logout: () => {
        set({ user: null, error: null });
        authService.logout();
      },
      
      updateProfile: async (updates) => {
        const currentUser = get().user;
        if (!currentUser) return;
        
        try {
          const updatedUser = await authService.updateProfile(updates);
          set({ user: updatedUser });
        } catch (error) {
          set({ error: error.message });
          throw error;
        }
      },
      
      clearError: () => set({ error: null })
    }),
    {
      name: 'user-storage',
      partialize: (state) => ({ user: state.user })
    }
  )
);

// Products store with pagination and filtering
const useProductsStore = create(
  subscribeWithSelector((set, get) => ({
    products: [],
    categories: [],
    filters: {
      search: '',
      category: '',
      priceRange: [0, 1000],
      sortBy: 'name',
      sortOrder: 'asc'
    },
    pagination: {
      page: 1,
      limit: 20,
      total: 0,
      totalPages: 0
    },
    loading: false,
    error: null,
    
    fetchProducts: async (page = 1) => {
      const { filters } = get();
      set({ loading: true, error: null });
      
      try {
        const response = await productService.getProducts({
          ...filters,
          page,
          limit: get().pagination.limit
        });
        
        set({
          products: response.data,
          pagination: {
            page: response.page,
            limit: response.limit,
            total: response.total,
            totalPages: response.totalPages
          },
          loading: false
        });
      } catch (error) {
        set({ error: error.message, loading: false });
      }
    },
    
    fetchCategories: async () => {
      try {
        const categories = await productService.getCategories();
        set({ categories });
      } catch (error) {
        console.error('Failed to fetch categories:', error);
      }
    },
    
    setFilters: (newFilters) => {
      set(state => ({
        filters: { ...state.filters, ...newFilters },
        pagination: { ...state.pagination, page: 1 }
      }));
    },
    
    setPage: (page) => {
      set(state => ({
        pagination: { ...state.pagination, page }
      }));
      get().fetchProducts(page);
    },
    
    clearFilters: () => {
      set({
        filters: {
          search: '',
          category: '',
          priceRange: [0, 1000],
          sortBy: 'name',
          sortOrder: 'asc'
        },
        pagination: { ...get().pagination, page: 1 }
      });
      get().fetchProducts(1);
    }
  }))
);

// Cart store with computed values
const useCartStore = create(
  persist(
    (set, get) => ({
      items: [],
      coupon: null,
      
      addItem: (product, quantity = 1) => {
        set(state => {
          const existingItem = state.items.find(item => item.id === product.id);
          
          if (existingItem) {
            return {
              items: state.items.map(item =>
                item.id === product.id
                  ? { ...item, quantity: item.quantity + quantity }
                  : item
              )
            };
          }
          
          return {
            items: [...state.items, { ...product, quantity }]
          };
        });
      },
      
      removeItem: (productId) => {
        set(state => ({
          items: state.items.filter(item => item.id !== productId)
        }));
      },
      
      updateQuantity: (productId, quantity) => {
        if (quantity <= 0) {
          get().removeItem(productId);
          return;
        }
        
        set(state => ({
          items: state.items.map(item =>
            item.id === productId ? { ...item, quantity } : item
          )
        }));
      },
      
      clearCart: () => set({ items: [], coupon: null }),
      
      applyCoupon: (coupon) => set({ coupon }),
      
      // Computed values
      get subtotal() {
        return get().items.reduce((sum, item) => sum + (item.price * item.quantity), 0);
      },
      
      get total() {
        const subtotal = this.subtotal;
        const discount = get().coupon?.discount || 0;
        return Math.max(0, subtotal - discount);
      },
      
      get itemCount() {
        return get().items.reduce((sum, item) => sum + item.quantity, 0);
      }
    }),
    {
      name: 'cart-storage'
    }
  )
);

// Usage in components
function ProductList() {
  const {
    products,
    filters,
    pagination,
    loading,
    error,
    fetchProducts,
    setFilters,
    setPage
  } = useProductsStore();

  const { addItem } = useCartStore();

  useEffect(() => {
    fetchProducts();
  }, [fetchProducts]);

  const handleFilterChange = (newFilters) => {
    setFilters(newFilters);
    fetchProducts(1);
  };

  const handleAddToCart = (product) => {
    addItem(product);
  };

  return (
    <div>
      <ProductFilters 
        filters={filters} 
        onFilterChange={handleFilterChange} 
      />
      
      {loading && <div>Loading products...</div>}
      {error && <div>Error: {error}</div>}
      
      <div className="product-grid">
        {products.map(product => (
          <ProductCard
            key={product.id}
            product={product}
            onAddToCart={handleAddToCart}
          />
        ))}
      </div>
      
      <Pagination
        currentPage={pagination.page}
        totalPages={pagination.totalPages}
        onPageChange={setPage}
      />
    </div>
  );
}
```

## Data Fetching State Management

### 1. Next.js Query Pattern
```jsx
import { useQuery, useMutation, useQueryClient, QueryClient, QueryClientProvider } from '@tanstack/next-query';

// Create query client
const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 5 * 60 * 1000, // 5 minutes
      cacheTime: 10 * 60 * 1000, // 10 minutes
      retry: 3,
      refetchOnWindowFocus: false
    },
    mutations: {
      retry: 1
    }
  }
});

// Query hooks
function useUsers() {
  return useQuery({
    queryKey: ['users'],
    queryFn: async () => {
      const response = await fetch('/api/users');
      if (!response.ok) {
        throw new Error('Failed to fetch users');
      }
      return response.json();
    },
    select: (data) => data.sort((a, b) => a.name.localeCompare(b.name))
  });
}

function useUser(id) {
  return useQuery({
    queryKey: ['user', id],
    queryFn: async () => {
      const response = await fetch(`/api/users/${id}`);
      if (!response.ok) {
        throw new Error('Failed to fetch user');
      }
      return response.json();
    },
    enabled: !!id
  });
}

function useCreateUser() {
  const queryClient = useQueryClient();
  
  return useMutation({
    mutationFn: async (userData) => {
      const response = await fetch('/api/users', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(userData)
      });
      
      if (!response.ok) {
        throw new Error('Failed to create user');
      }
      
      return response.json();
    },
    onSuccess: (newUser) => {
      // Invalidate and refetch users list
      queryClient.invalidateQueries({ queryKey: ['users'] });
      
      // Add the new user to the cache
      queryClient.setQueryData(['user', newUser.id], newUser);
    },
    onError: (error) => {
      console.error('Failed to create user:', error);
    }
  });
}

function useUpdateUser() {
  const queryClient = useQueryClient();
  
  return useMutation({
    mutationFn: async ({ id, userData }) => {
      const response = await fetch(`/api/users/${id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(userData)
      });
      
      if (!response.ok) {
        throw new Error('Failed to update user');
      }
      
      return response.json();
    },
    onMutate: async ({ id, userData }) => {
      // Cancel any outgoing refetches
      await queryClient.cancelQueries({ queryKey: ['user', id] });
      
      // Snapshot the previous value
      const previousUser = queryClient.getQueryData(['user', id]);
      
      // Optimistically update to the new value
      queryClient.setQueryData(['user', id], (old) => ({ ...old, ...userData }));
      
      // Return context with the previous value
      return { previousUser };
    },
    onError: (err, { id }, context) => {
      // Rollback on error
      queryClient.setQueryData(['user', id], context.previousUser);
    },
    onSettled: ({ id }) => {
      // Always refetch after error or success
      queryClient.invalidateQueries({ queryKey: ['user', id] });
    }
  });
}

// Usage in components
function UserList() {
  const { data: users, isLoading, error, refetch } = useUsers();
  const createUser = useCreateUser();

  const handleCreateUser = async (userData) => {
    try {
      await createUser.mutateAsync(userData);
    } catch (error) {
      console.error('Failed to create user:', error);
    }
  };

  if (isLoading) return <div>Loading users...</div>;
  if (error) return <div>Error: {error.message}</div>;

  return (
    <div>
      <h2>Users</h2>
      <button onClick={() => refetch()}>Refresh</button>
      
      <UserForm onSubmit={handleCreateUser} loading={createUser.isLoading} />
      
      <ul>
        {users?.map(user => (
          <UserItem key={user.id} user={user} />
        ))}
      </ul>
    </div>
  );
}

function UserProfile({ userId }) {
  const { data: user, isLoading, error } = useUser(userId);
  const updateUser = useUpdateUser();

  const handleUpdate = async (updates) => {
    try {
      await updateUser.mutateAsync({ id: userId, userData: updates });
    } catch (error) {
      console.error('Failed to update user:', error);
    }
  };

  if (isLoading) return <div>Loading user...</div>;
  if (error) return <div>Error: {error.message}</div>;

  return (
    <div>
      <h2>{user.name}</h2>
      <UserForm 
        user={user} 
        onSubmit={handleUpdate} 
        loading={updateUser.isLoading} 
      />
    </div>
  );
}

// App wrapper with QueryClientProvider
function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <UserList />
    </QueryClientProvider>
  );
}
```

### 2. Custom Data Fetching Hook
```jsx
import { useState, useEffect, useCallback, useRef } from 'next';

function useAsyncData(asyncFn, dependencies = [], options = {}) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  
  const {
    immediate = true,
    onSuccess,
    onError,
    initialData = null
  } = options;

  const execute = useCallback(async (...args) => {
    setLoading(true);
    setError(null);
    
    try {
      const result = await asyncFn(...args);
      setData(result);
      onSuccess?.(result);
      return result;
    } catch (err) {
      setError(err);
      onError?.(err);
      throw err;
    } finally {
      setLoading(false);
    }
  }, [asyncFn, onSuccess, onError]);

  useEffect(() => {
    if (immediate) {
      execute();
    }
  }, dependencies);

  return {
    data,
    loading,
    error,
    execute,
    refetch: execute
  };
}

// Paginated data hook
function usePaginatedData(fetchFn, initialPage = 1, pageSize = 20) {
  const [page, setPage] = useState(initialPage);
  const [total, setTotal] = useState(0);
  
  const { data, loading, error, execute } = useAsyncData(
    async (currentPage, currentPageSize) => {
      const response = await fetchFn(currentPage, currentPageSize);
      setTotal(response.total);
      return response.data;
    },
    [page, pageSize],
    { immediate: true }
  );

  const nextPage = useCallback(() => {
    if (page * pageSize < total) {
      setPage(prev => prev + 1);
    }
  }, [page, pageSize, total]);

  const prevPage = useCallback(() => {
    if (page > 1) {
      setPage(prev => prev - 1);
    }
  }, [page]);

  const goToPage = useCallback((targetPage) => {
    if (targetPage >= 1 && targetPage <= Math.ceil(total / pageSize)) {
      setPage(targetPage);
    }
  }, [total, pageSize]);

  return {
    data,
    loading,
    error,
    page,
    total,
    totalPages: Math.ceil(total / pageSize),
    nextPage,
    prevPage,
    goToPage,
    refresh: () => execute(page, pageSize)
  };
}

// Usage
function ProductList() {
  const {
    data: products,
    loading,
    error,
    page,
    totalPages,
    nextPage,
    prevPage,
    goToPage,
    refresh
  } = usePaginatedData(
    async (page, pageSize) => {
      const response = await fetch(`/api/products?page=${page}&limit=${pageSize}`);
      if (!response.ok) throw new Error('Failed to fetch products');
      return response.json();
    }
  );

  return (
    <div>
      <div className="list-header">
        <h2>Products</h2>
        <button onClick={refresh} disabled={loading}>
          Refresh
        </button>
      </div>
      
      {loading && <div>Loading...</div>}
      {error && <div>Error: {error.message}</div>}
      
      <div className="product-grid">
        {products?.map(product => (
          <ProductCard key={product.id} product={product} />
        ))}
      </div>
      
      <Pagination
        currentPage={page}
        totalPages={totalPages}
        onNext={nextPage}
        onPrev={prevPage}
        onGoToPage={goToPage}
      />
    </div>
  );
}
```

## Performance Optimization

### 1. State Normalization
```jsx
// Normalized state structure
function createNormalizedState() {
  return {
    byId: {},
    allIds: []
  };
}

function normalizeEntities(entities) {
  const normalized = createNormalizedState();
  
  entities.forEach(entity => {
    normalized.byId[entity.id] = entity;
    normalized.allIds.push(entity.id);
  });
  
  return normalized;
}

// Normalized store with selectors
const useEntityStore = create((set, get) => ({
  users: createNormalizedState(),
  posts: createNormalizedState(),
  
  addUsers: (users) => {
    const normalized = normalizeEntities(users);
    set(state => ({
      users: {
        byId: { ...state.users.byId, ...normalized.byId },
        allIds: [...new Set([...state.users.allIds, ...normalized.allIds])]
      }
    }));
  },
  
  updateUser: (userId, updates) => {
    set(state => ({
      users: {
        ...state.users,
        byId: {
          ...state.users.byId,
          [userId]: { ...state.users.byId[userId], ...updates }
        }
      }
    }));
  },
  
  removeUser: (userId) => {
    set(state => {
      const newById = { ...state.users.byId };
      delete newById[userId];
      
      return {
        users: {
          byId: newById,
          allIds: state.users.allIds.filter(id => id !== userId)
        }
      };
    });
  },
  
  // Selectors
  getUserById: (userId) => get().users.byId[userId],
  getAllUsers: () => get().users.allIds.map(id => get().users.byId[id]),
  getUsersByIds: (userIds) => userIds.map(id => get().users.byId[id]).filter(Boolean)
}));

// Memoized selectors
function useUserSelector(selector, dependencies = []) {
  const store = useEntityStore();
  return useMemo(() => selector(store), dependencies);
}

// Usage
function UserList() {
  const users = useUserSelector(store => store.getAllUsers(), []);
  
  return (
    <ul>
      {users.map(user => (
        <UserItem key={user.id} user={user} />
      ))}
    </ul>
  );
}

function UserProfile({ userId }) {
  const user = useUserSelector(
    store => store.getUserById(userId),
    [userId]
  );
  
  if (!user) return <div>User not found</div>;
  
  return <div>{user.name}</div>;
}
```

### 2. State Composition
```jsx
// Composable state hooks
function useListState(initialItems = []) {
  const [items, setItems] = useState(initialItems);
  
  const addItem = useCallback((item) => {
    setItems(prev => [...prev, item]);
  }, []);
  
  const removeItem = useCallback((index) => {
    setItems(prev => prev.filter((_, i) => i !== index));
  }, []);
  
  const updateItem = useCallback((index, newItem) => {
    setItems(prev => prev.map((item, i) => i === index ? newItem : item));
  }, []);
  
  const clearItems = useCallback(() => {
    setItems([]);
  }, []);
  
  return {
    items,
    addItem,
    removeItem,
    updateItem,
    clearItems
  };
}

function useSelectionState(items = []) {
  const [selectedItems, setSelectedItems] = useState(new Set());
  
  const selectItem = useCallback((item) => {
    setSelectedItems(prev => new Set(prev).add(item));
  }, []);
  
  const deselectItem = useCallback((item) => {
    setSelectedItems(prev => {
      const newSet = new Set(prev);
      newSet.delete(item);
      return newSet;
    });
  }, []);
  
  const toggleSelection = useCallback((item) => {
    setSelectedItems(prev => {
      const newSet = new Set(prev);
      if (newSet.has(item)) {
        newSet.delete(item);
      } else {
        newSet.add(item);
      }
      return newSet;
    });
  }, []);
  
  const selectAll = useCallback(() => {
    setSelectedItems(new Set(items));
  }, [items]);
  
  const clearSelection = useCallback(() => {
    setSelectedItems(new Set());
  }, []);
  
  return {
    selectedItems,
    isSelected: (item) => selectedItems.has(item),
    selectedCount: selectedItems.size,
    selectItem,
    deselectItem,
    toggleSelection,
    selectAll,
    clearSelection
  };
}

// Compose hooks
function useSelectableList(initialItems = []) {
  const listState = useListState(initialItems);
  const selectionState = useSelectionState(listState.items);
  
  return {
    ...listState,
    ...selectionState
  };
}

// Usage
function SelectableUserList() {
  const {
    items: users,
    addItem,
    removeItem,
    selectedItems,
    selectedCount,
    toggleSelection,
    selectAll,
    clearSelection
  } = useSelectableList([]);

  return (
    <div>
      <div className="selection-controls">
        <button onClick={selectAll}>Select All</button>
        <button onClick={clearSelection}>Clear Selection</button>
        <span>Selected: {selectedCount}</span>
      </div>
      
      <ul>
        {users.map(user => (
          <li key={user.id}>
            <input
              type="checkbox"
              checked={selectedItems.has(user)}
              onChange={() => toggleSelection(user)}
            />
            {user.name}
          </li>
        ))}
      </ul>
    </div>
  );
}
```

This comprehensive state management guide covers local state, global state, data fetching patterns, and performance optimization techniques for Next.js applications.
