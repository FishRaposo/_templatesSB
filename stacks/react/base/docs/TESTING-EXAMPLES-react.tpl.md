# Universal Template System - React Stack
# Generated: 2025-12-10
# Purpose: Testing utilities
# Tier: base
# Stack: react
# Category: template

# React Testing Examples - {{PROJECT_NAME}}

**Tier**: {{TIER}} | **Stack**: React

## 🧪 Testing Strategy Overview

React testing follows the **testing pyramid**: **Component Tests > Integration Tests > End-to-End Tests**. Each tier requires different levels of testing rigor with React Testing Library for component testing, Jest for unit testing, and Playwright for E2E testing.

## 📊 Tier-Specific Testing Requirements

| Tier | Component Tests | Integration Tests | E2E Tests | Visual Tests |
|------|-----------------|-------------------|-----------|--------------|
| **MVP** | Basic rendering | Simple flows | Not required | Not required |
| **CORE** | Complete coverage | User workflows | Critical flows | Visual regression |
| **FULL** | Complete + edge cases | All workflows | All flows | Full visual testing |

## 🔬 Component Testing Examples

### **MVP Tier - Basic Component Testing**

```tsx
// tests/components/Button.test.tsx
import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import { Button } from '../../src/components/Button';

describe('Button Component', () => {
  it('should render button with text', () => {
    // Arrange
    render(<Button>Click me</Button>);
    
    // Act & Assert
    expect(screen.getByRole('button', { name: 'Click me' })).toBeInTheDocument();
  });

  it('should call onClick when clicked', () => {
    // Arrange
    const handleClick = jest.fn();
    render(<Button onClick={handleClick}>Click me</Button>);
    
    // Act
    fireEvent.click(screen.getByRole('button'));
    
    // Assert
    expect(handleClick).toHaveBeenCalledTimes(1);
  });

  it('should be disabled when disabled prop is true', () => {
    // Arrange
    render(<Button disabled>Click me</Button>);
    
    // Act & Assert
    expect(screen.getByRole('button')).toBeDisabled();
  });

  it('should apply primary variant styles', () => {
    // Arrange
    render(<Button variant="primary">Primary Button</Button>);
    
    // Act & Assert
    const button = screen.getByRole('button');
    expect(button).toHaveClass('btn-primary');
  });
});
```

### **CORE Tier - Advanced Component Testing**

```tsx
// tests/components/UserCard.test.tsx
import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { UserCard } from '../../src/components/UserCard';
import { User } from '../../src/types/user.types';

const mockUser: User = {
  id: '1',
  name: 'John Doe',
  email: 'john@example.com',
  avatar: 'https://example.com/avatar.jpg',
  isActive: true,
  role: 'user',
  createdAt: new Date('2023-01-01'),
};

describe('UserCard Component', () => {
  const mockOnEdit = jest.fn();
  const mockOnDelete = jest.fn();

  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('should render user information correctly', () => {
    // Arrange
    render(<UserCard user={mockUser} />);
    
    // Act & Assert
    expect(screen.getByText('John Doe')).toBeInTheDocument();
    expect(screen.getByText('john@example.com')).toBeInTheDocument();
    expect(screen.getByRole('img', { name: 'John Doe' })).toHaveAttribute('src', mockUser.avatar);
    expect(screen.getByText('Active')).toBeInTheDocument();
  });

  it('should show inactive status for inactive users', () => {
    // Arrange
    const inactiveUser = { ...mockUser, isActive: false };
    render(<UserCard user={inactiveUser} />);
    
    // Act & Assert
    expect(screen.getByText('Inactive')).toBeInTheDocument();
  });

  it('should call onEdit when edit button is clicked', async () => {
    // Arrange
    const user = userEvent.setup();
    render(<UserCard user={mockUser} onEdit={mockOnEdit} />);
    
    // Act
    await user.click(screen.getByRole('button', { name: /edit/i }));
    
    // Assert
    expect(mockOnEdit).toHaveBeenCalledWith(mockUser);
  });

  it('should call onDelete when delete button is clicked', async () => {
    // Arrange
    const user = userEvent.setup();
    render(<UserCard user={mockUser} onDelete={mockOnDelete} />);
    
    // Act
    await user.click(screen.getByRole('button', { name: /delete/i }));
    
    // Assert
    expect(mockOnDelete).toHaveBeenCalledWith(mockUser.id);
  });

  it('should not show action buttons when callbacks are not provided', () => {
    // Arrange
    render(<UserCard user={mockUser} />);
    
    // Act & Assert
    expect(screen.queryByRole('button', { name: /edit/i })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /delete/i })).not.toBeInTheDocument();
  });

  it('should handle missing avatar gracefully', () => {
    // Arrange
    const userWithoutAvatar = { ...mockUser, avatar: undefined };
    render(<UserCard user={userWithoutAvatar} />);
    
    // Act & Assert
    const avatar = screen.getByRole('img', { name: 'John Doe' });
    expect(avatar).toHaveAttribute('src', '/default-avatar.png');
  });
});
```

### **FULL Tier - Complex Component Testing**

```tsx
// tests/components/EnterpriseUserTable.test.tsx
import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { Provider } from 'react-redux';
import { configureStore } from '@reduxjs/toolkit';
import { EnterpriseUserTable } from '../../src/components/EnterpriseUserTable';
import { usersSlice } from '../../src/store/usersSlice';
import { User } from '../../src/types/user.types';

// Mock analytics
jest.mock('../../src/hooks/useAnalytics', () => ({
  useAnalytics: () => ({
    trackEvent: jest.fn(),
  }),
}));

// Mock API
jest.mock('../../src/services/api', () => ({
  userApi: {
    fetchUsers: jest.fn(),
    updateUser: jest.fn(),
    deleteUser: jest.fn(),
  },
}));

const mockUsers: User[] = [
  {
    id: '1',
    name: 'John Doe',
    email: 'john@example.com',
    isActive: true,
    role: 'admin',
    department: 'Engineering',
    createdAt: new Date('2023-01-01'),
  },
  {
    id: '2',
    name: 'Jane Smith',
    email: 'jane@example.com',
    isActive: false,
    role: 'user',
    department: 'Marketing',
    createdAt: new Date('2023-01-02'),
  },
];

const createMockStore = (initialState = {}) => {
  return configureStore({
    reducer: {
      users: usersSlice.reducer,
    },
    preloadedState: {
      users: {
        users: mockUsers,
        loading: false,
        error: null,
        pagination: { page: 1, limit: 20, total: 2, totalPages: 1 },
        filters: { search: '', status: 'all', role: 'all' },
        ...initialState,
      },
    },
  });
};

const renderWithProvider = (component: React.ReactElement, store = createMockStore()) => {
  return render(
    <Provider store={store}>
      {component}
    </Provider>
  );
};

describe('EnterpriseUserTable Component', () => {
  let store: ReturnType<typeof createMockStore>;

  beforeEach(() => {
    store = createMockStore();
    jest.clearAllMocks();
  });

  it('should render user table with correct data', () => {
    // Arrange
    renderWithProvider(<EnterpriseUserTable />, store);
    
    // Act & Assert
    expect(screen.getByText('John Doe')).toBeInTheDocument();
    expect(screen.getByText('john@example.com')).toBeInTheDocument();
    expect(screen.getByText('Jane Smith')).toBeInTheDocument();
    expect(screen.getByText('jane@example.com')).toBeInTheDocument();
    expect(screen.getByText('Engineering')).toBeInTheDocument();
    expect(screen.getByText('Marketing')).toBeInTheDocument();
  });

  it('should handle user selection correctly', async () => {
    // Arrange
    const user = userEvent.setup();
    renderWithProvider(<EnterpriseUserTable />, store);
    
    // Act
    const checkboxes = screen.getAllByRole('checkbox');
    await user.click(checkboxes[1]); // Click first user checkbox
    
    // Assert
    expect(checkboxes[1]).toBeChecked();
    expect(screen.getByText('1 selected')).toBeInTheDocument();
  });

  it('should handle bulk selection', async () => {
    // Arrange
    const user = userEvent.setup();
    renderWithProvider(<EnterpriseUserTable />, store);
    
    // Act
    await user.click(screen.getByRole('checkbox', { name: /select all/i }));
    
    // Assert
    const checkboxes = screen.getAllByRole('checkbox');
    checkboxes.slice(1).forEach(checkbox => {
      expect(checkbox).toBeChecked();
    });
    expect(screen.getByText('2 selected')).toBeInTheDocument();
  });

  it('should filter users by search term', async () => {
    // Arrange
    const user = userEvent.setup();
    renderWithProvider(<EnterpriseUserTable />, store);
    
    // Act
    const searchInput = screen.getByPlaceholderText(/search users/i);
    await user.type(searchInput, 'John');
    
    // Assert
    await waitFor(() => {
      expect(screen.getByText('John Doe')).toBeInTheDocument();
      expect(screen.queryByText('Jane Smith')).not.toBeInTheDocument();
    });
  });

  it('should handle user status toggle', async () => {
    // Arrange
    const user = userEvent.setup();
    const mockUpdateUser = jest.fn();
    jest.mocked(require('../../src/services/api').userApi).updateUser = mockUpdateUser;
    
    renderWithProvider(<EnterpriseUserTable />, store);
    
    // Act
    const statusToggle = screen.getAllByRole('button', { name: /toggle status/i })[0];
    await user.click(statusToggle);
    
    // Assert
    await waitFor(() => {
      expect(mockUpdateUser).toHaveBeenCalledWith('1', { isActive: false });
    });
  });

  it('should handle sorting by different columns', async () => {
    // Arrange
    const user = userEvent.setup();
    renderWithProvider(<EnterpriseUserTable />, store);
    
    // Act
    const nameHeader = screen.getByRole('button', { name: /name/i });
    await user.click(nameHeader);
    
    // Assert
    await waitFor(() => {
      const rows = screen.getAllByRole('row');
      expect(rows[1]).toHaveTextContent('Jane Smith'); // Should be sorted alphabetically
      expect(rows[2]).toHaveTextContent('John Doe');
    });
  });

  it('should show loading state during data fetch', () => {
    // Arrange
    const loadingStore = createMockStore({
      loading: true,
      users: [],
    });
    
    // Act
    renderWithProvider(<EnterpriseUserTable />, loadingStore);
    
    // Assert
    expect(screen.getByTestId('loading-spinner')).toBeInTheDocument();
    expect(screen.queryByText('John Doe')).not.toBeInTheDocument();
  });

  it('should show error state when data fetch fails', () => {
    // Arrange
    const errorStore = createMockStore({
      loading: false,
      error: 'Failed to fetch users',
      users: [],
    });
    
    // Act
    renderWithProvider(<EnterpriseUserTable />, errorStore);
    
    // Assert
    expect(screen.getByText('Failed to fetch users')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /retry/i })).toBeInTheDocument();
  });

  it('should handle pagination correctly', async () => {
    // Arrange
    const user = userEvent.setup();
    const paginatedStore = createMockStore({
      pagination: { page: 1, limit: 1, total: 2, totalPages: 2 },
    });
    
    renderWithProvider(<EnterpriseUserTable />, paginatedStore);
    
    // Act
    const nextPageButton = screen.getByRole('button', { name: /next page/i });
    await user.click(nextPageButton);
    
    // Assert
    await waitFor(() => {
      expect(screen.getByText('Jane Smith')).toBeInTheDocument();
      expect(screen.queryByText('John Doe')).not.toBeInTheDocument();
    });
  });

  it('should be accessible', async () => {
    // Arrange
    const { container } = renderWithProvider(<EnterpriseUserTable />, store);
    
    // Act & Assert
    // Check for proper ARIA labels
    expect(screen.getByRole('table')).toHaveAttribute('aria-label', 'Users table');
    
    // Check for keyboard navigation
    const firstRow = screen.getAllByRole('row')[1];
    fireEvent.focus(firstRow);
    expect(firstRow).toHaveFocus();
    
    // Check for proper heading hierarchy
    const headings = container.querySelectorAll('h1, h2, h3, h4, h5, h6');
    expect(headings.length).toBeGreaterThan(0);
  });
});
```

## 🎣 Custom Hook Testing

### **MVP Tier - Simple Hook Testing**

```tsx
// tests/hooks/useCounter.test.tsx
import { renderHook, act } from '@testing-library/react';
import { useCounter } from '../../src/hooks/useCounter';

describe('useCounter Hook', () => {
  it('should initialize with default value', () => {
    // Arrange & Act
    const { result } = renderHook(() => useCounter());
    
    // Assert
    expect(result.current.count).toBe(0);
  });

  it('should initialize with custom value', () => {
    // Arrange & Act
    const { result } = renderHook(() => useCounter(5));
    
    // Assert
    expect(result.current.count).toBe(5);
  });

  it('should increment count', () => {
    // Arrange
    const { result } = renderHook(() => useCounter());
    
    // Act
    act(() => {
      result.current.increment();
    });
    
    // Assert
    expect(result.current.count).toBe(1);
  });

  it('should decrement count', () => {
    // Arrange
    const { result } = renderHook(() => useCounter(10));
    
    // Act
    act(() => {
      result.current.decrement();
    });
    
    // Assert
    expect(result.current.count).toBe(9);
  });

  it('should reset count', () => {
    // Arrange
    const { result } = renderHook(() => useCounter(10));
    
    // Act
    act(() => {
      result.current.reset();
    });
    
    // Assert
    expect(result.current.count).toBe(0);
  });
});
```

### **CORE Tier - Complex Hook Testing**

```tsx
// tests/hooks/useApi.test.tsx
import { renderHook, act, waitFor } from '@testing-library/react';
import { useApi } from '../../src/hooks/useApi';

// Mock fetch
global.fetch = jest.fn();

const mockFetch = global.fetch as jest.MockedFunction<typeof fetch>;

describe('useApi Hook', () => {
  beforeEach(() => {
    mockFetch.mockClear();
  });

  it('should fetch data successfully', async () => {
    // Arrange
    const mockData = { id: 1, name: 'Test Data' };
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => mockData,
    } as Response);

    // Act
    const { result } = renderHook(() => useApi<typeof mockData>('/api/test'));

    // Assert
    expect(result.current.loading).toBe(true);
    expect(result.current.data).toBe(null);
    expect(result.current.error).toBe(null);

    await waitFor(() => {
      expect(result.current.loading).toBe(false);
      expect(result.current.data).toEqual(mockData);
      expect(result.current.error).toBe(null);
    });

    expect(mockFetch).toHaveBeenCalledWith('/api/test');
  });

  it('should handle fetch error', async () => {
    // Arrange
    const errorMessage = 'Network error';
    mockFetch.mockRejectedValueOnce(new Error(errorMessage));

    // Act
    const { result } = renderHook(() => useApi('/api/test'));

    // Assert
    await waitFor(() => {
      expect(result.current.loading).toBe(false);
      expect(result.current.data).toBe(null);
      expect(result.current.error).toBe(errorMessage);
    });
  });

  it('should handle HTTP error status', async () => {
    // Arrange
    mockFetch.mockResolvedValueOnce({
      ok: false,
      status: 404,
      statusText: 'Not Found',
    } as Response);

    // Act
    const { result } = renderHook(() => useApi('/api/test'));

    // Assert
    await waitFor(() => {
      expect(result.current.loading).toBe(false);
      expect(result.current.data).toBe(null);
      expect(result.current.error).toBe('HTTP error! status: 404');
    });
  });

  it('should refetch data when refetch is called', async () => {
    // Arrange
    const mockData = { id: 1, name: 'Test Data' };
    mockFetch.mockResolvedValue({
      ok: true,
      json: async () => mockData,
    } as Response);

    // Act
    const { result } = renderHook(() => useApi('/api/test'));

    await waitFor(() => {
      expect(result.current.data).toEqual(mockData);
    });

    // Reset mock
    mockFetch.mockClear();

    const updatedData = { id: 1, name: 'Updated Data' };
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => updatedData,
    } as Response);

    act(() => {
      result.current.refetch();
    });

    // Assert
    await waitFor(() => {
      expect(result.current.data).toEqual(updatedData);
    });

    expect(mockFetch).toHaveBeenCalledTimes(1);
  });

  it('should not fetch on initial render if skip is true', () => {
    // Arrange
    const { result } = renderHook(() => useApi('/api/test', { skip: true }));

    // Act & Assert
    expect(result.current.loading).toBe(false);
    expect(result.current.data).toBe(null);
    expect(result.current.error).toBe(null);
    expect(mockFetch).not.toHaveBeenCalled();
  });
});
```

### **FULL Tier - Advanced Hook Testing**

```tsx
// tests/hooks/useWebSocket.test.tsx
import { renderHook, act } from '@testing-library/react';
import { useWebSocket } from '../../src/hooks/useWebSocket';

// Mock WebSocket
class MockWebSocket {
  static CONNECTING = 0;
  static OPEN = 1;
  static CLOSING = 2;
  static CLOSED = 3;

  readyState = MockWebSocket.CONNECTING;
  onopen: ((event: Event) => void) | null = null;
  onclose: ((event: CloseEvent) => void) | null = null;
  onmessage: ((event: MessageEvent) => void) | null = null;
  onerror: ((event: Event) => void) | null = null;

  constructor(public url: string) {
    // Simulate connection after a short delay
    setTimeout(() => {
      this.readyState = MockWebSocket.OPEN;
      if (this.onopen) {
        this.onopen(new Event('open'));
      }
    }, 10);
  }

  send(data: string) {
    if (this.readyState !== MockWebSocket.OPEN) {
      throw new Error('WebSocket is not open');
    }
  }

  close() {
    this.readyState = MockWebSocket.CLOSED;
    if (this.onclose) {
      this.onclose(new CloseEvent('close'));
    }
  }

  // Helper method for testing
  simulateMessage(data: any) {
    if (this.onmessage) {
      this.onmessage(new MessageEvent('message', { data: JSON.stringify(data) }));
    }
  }
}

// @ts-ignore
global.WebSocket = MockWebSocket;

describe('useWebSocket Hook', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('should initialize with disconnected state', () => {
    // Arrange & Act
    const { result } = renderHook(() => useWebSocket('ws://localhost:8080'));

    // Assert
    expect(result.current.connected).toBe(false);
    expect(result.current.lastMessage).toBe(null);
    expect(typeof result.current.sendMessage).toBe('function');
  });

  it('should connect to WebSocket and update connection state', async () => {
    // Arrange & Act
    const { result } = renderHook(() => useWebSocket('ws://localhost:8080'));

    // Assert - initially disconnected
    expect(result.current.connected).toBe(false);

    // Wait for connection
    await act(async () => {
      await new Promise(resolve => setTimeout(resolve, 20));
    });

    expect(result.current.connected).toBe(true);
  });

  it('should receive messages and update lastMessage', async () => {
    // Arrange
    const { result } = renderHook(() => useWebSocket('ws://localhost:8080'));
    const testMessage = { type: 'test', data: 'Hello WebSocket' };

    // Wait for connection
    await act(async () => {
      await new Promise(resolve => setTimeout(resolve, 20));
    });

    // Act - simulate receiving message
    await act(async () => {
      const wsInstance = (result.current as any).ws;
      wsInstance.simulateMessage(testMessage);
    });

    // Assert
    expect(result.current.lastMessage).toEqual(testMessage);
  });

  it('should send messages when connected', async () => {
    // Arrange
    const { result } = renderHook(() => useWebSocket('ws://localhost:8080'));
    const testMessage = { type: 'outgoing', data: 'Test message' };

    // Wait for connection
    await act(async () => {
      await new Promise(resolve => setTimeout(resolve, 20));
    });

    // Act
    act(() => {
      result.current.sendMessage(testMessage);
    });

    // Assert - no error thrown
    expect(result.current.connected).toBe(true);
  });

  it('should handle connection errors', async () => {
    // Arrange
    const { result } = renderHook(() => useWebSocket('ws://invalid-url'));

    // Act - simulate connection error
    await act(async () => {
      await new Promise(resolve => setTimeout(resolve, 20));
    });

    // Assert
    expect(result.current.connected).toBe(false);
  });

  it('should cleanup WebSocket on unmount', async () => {
    // Arrange
    const { result, unmount } = renderHook(() => useWebSocket('ws://localhost:8080'));

    // Wait for connection
    await act(async () => {
      await new Promise(resolve => setTimeout(resolve, 20));
    });

    expect(result.current.connected).toBe(true);

    // Act
    unmount();

    // Assert
    expect(result.current.connected).toBe(false);
  });

  it('should handle reconnection logic', async () => {
    // Arrange
    const { result, rerender } = renderHook(
      ({ url }) => useWebSocket(url),
      { initialProps: { url: 'ws://localhost:8080' } }
    );

    // Wait for initial connection
    await act(async () => {
      await new Promise(resolve => setTimeout(resolve, 20));
    });

    expect(result.current.connected).toBe(true);

    // Act - change URL (simulate reconnection)
    rerender({ url: 'ws://localhost:8080/new' });

    // Assert
    expect(result.current.connected).toBe(false);

    // Wait for reconnection
    await act(async () => {
      await new Promise(resolve => setTimeout(resolve, 20));
    });

    expect(result.current.connected).toBe(true);
  });
});
```

## 🌐 Integration Testing Examples

### **CORE Tier - User Flow Testing**

```tsx
// tests/integration/UserRegistrationFlow.test.tsx
import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { BrowserRouter } from 'react-router-dom';
import { App } from '../../src/App';

// Mock API
jest.mock('../../src/services/api', () => ({
  authApi: {
    register: jest.fn(),
    login: jest.fn(),
  },
}));

const mockRegister = jest.mocked(require('../../src/services/api').authApi.register);
const mockLogin = jest.mocked(require('../../src/services/api').authApi.login);

const renderApp = () => {
  return render(
    <BrowserRouter>
      <App />
    </BrowserRouter>
  );
};

describe('User Registration Flow', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('should complete full registration flow successfully', async () => {
    // Arrange
    const userData = {
      name: 'John Doe',
      email: 'john@example.com',
      password: 'password123',
    };

    const registeredUser = {
      id: '1',
      ...userData,
      isActive: true,
      createdAt: new Date(),
    };

    mockRegister.mockResolvedValueOnce(registeredUser);
    mockLogin.mockResolvedValueOnce({ user: registeredUser, token: 'mock-token' });

    // Act
    renderApp();

    // Navigate to registration
    const registerLink = screen.getByRole('link', { name: /register/i });
    await userEvent.click(registerLink);

    // Fill registration form
    const nameInput = screen.getByLabelText(/name/i);
    const emailInput = screen.getByLabelText(/email/i);
    const passwordInput = screen.getByLabelText(/password/i);
    const submitButton = screen.getByRole('button', { name: /register/i });

    await userEvent.type(nameInput, userData.name);
    await userEvent.type(emailInput, userData.email);
    await userEvent.type(passwordInput, userData.password);
    await userEvent.click(submitButton);

    // Assert
    await waitFor(() => {
      expect(mockRegister).toHaveBeenCalledWith(userData);
    });

    await waitFor(() => {
      expect(screen.getByText(/registration successful/i)).toBeInTheDocument();
    });

    await waitFor(() => {
      expect(screen.getByText(/welcome, john doe/i)).toBeInTheDocument();
    });
  });

  it('should show validation errors for invalid registration data', async () => {
    // Arrange
    renderApp();

    // Navigate to registration
    const registerLink = screen.getByRole('link', { name: /register/i });
    await userEvent.click(registerLink);

    // Act - submit empty form
    const submitButton = screen.getByRole('button', { name: /register/i });
    await userEvent.click(submitButton);

    // Assert
    expect(screen.getByText(/name is required/i)).toBeInTheDocument();
    expect(screen.getByText(/email is required/i)).toBeInTheDocument();
    expect(screen.getByText(/password is required/i)).toBeInTheDocument();

    // Act - submit invalid email
    const emailInput = screen.getByLabelText(/email/i);
    await userEvent.type(emailInput, 'invalid-email');
    await userEvent.click(submitButton);

    // Assert
    expect(screen.getByText(/invalid email format/i)).toBeInTheDocument();
  });

  it('should handle registration API errors', async () => {
    // Arrange
    mockRegister.mockRejectedValueOnce(new Error('Email already exists'));

    renderApp();

    // Navigate to registration and fill form
    const registerLink = screen.getByRole('link', { name: /register/i });
    await userEvent.click(registerLink);

    const nameInput = screen.getByLabelText(/name/i);
    const emailInput = screen.getByLabelText(/email/i);
    const passwordInput = screen.getByLabelText(/password/i);
    const submitButton = screen.getByRole('button', { name: /register/i });

    await userEvent.type(nameInput, 'John Doe');
    await userEvent.type(emailInput, 'existing@example.com');
    await userEvent.type(passwordInput, 'password123');
    await userEvent.click(submitButton);

    // Assert
    await waitFor(() => {
      expect(screen.getByText(/email already exists/i)).toBeInTheDocument();
    });

    expect(mockRegister).toHaveBeenCalled();
  });

  it('should redirect to login after successful registration', async () => {
    // Arrange
    const userData = {
      name: 'John Doe',
      email: 'john@example.com',
      password: 'password123',
    };

    const registeredUser = {
      id: '1',
      ...userData,
      isActive: true,
      createdAt: new Date(),
    };

    mockRegister.mockResolvedValueOnce(registeredUser);

    renderApp();

    // Navigate and complete registration
    const registerLink = screen.getByRole('link', { name: /register/i });
    await userEvent.click(registerLink);

    const nameInput = screen.getByLabelText(/name/i);
    const emailInput = screen.getByLabelText(/email/i);
    const passwordInput = screen.getByLabelText(/password/i);
    const submitButton = screen.getByRole('button', { name: /register/i });

    await userEvent.type(nameInput, userData.name);
    await userEvent.type(emailInput, userData.email);
    await userEvent.type(passwordInput, userData.password);
    await userEvent.click(submitButton);

    // Assert
    await waitFor(() => {
      expect(screen.getByText(/registration successful/i)).toBeInTheDocument();
    });

    // Should show login form or redirect to dashboard
    await waitFor(() => {
      expect(screen.getByRole('heading', { name: /login/i })).toBeInTheDocument();
    });
  });
});
```

### **FULL Tier - Complex Integration Testing**

```tsx
// tests/integration/EcommerceCheckoutFlow.test.tsx
import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { BrowserRouter } from 'react-router-dom';
import { Provider } from 'react-redux';
import { configureStore } from '@reduxjs/toolkit';
import { App } from '../../src/App';
import { cartSlice } from '../../src/store/cartSlice';
import { authSlice } from '../../src/store/authSlice';

// Mock APIs
jest.mock('../../src/services/api', () => ({
  productApi: {
    getProducts: jest.fn(),
  },
  cartApi: {
    addToCart: jest.fn(),
    updateCart: jest.fn(),
    checkout: jest.fn(),
  },
  paymentApi: {
    processPayment: jest.fn(),
  },
}));

const mockCheckout = jest.mocked(require('../../src/services/api').cartApi.checkout);
const mockProcessPayment = jest.mocked(require('../../src/services/api').paymentApi.processPayment);

describe('E-commerce Checkout Flow', () => {
  let store: ReturnType<typeof configureStore>;

  beforeEach(() => {
    store = configureStore({
      reducer: {
        cart: cartSlice.reducer,
        auth: authSlice.reducer,
      },
      preloadedState: {
        auth: {
          user: { id: '1', name: 'John Doe', email: 'john@example.com' },
          isAuthenticated: true,
          loading: false,
        },
        cart: {
          items: [
            {
              id: '1',
              name: 'Test Product',
              price: 29.99,
              quantity: 2,
            },
            {
              id: '2',
              name: 'Another Product',
              price: 19.99,
              quantity: 1,
            },
          ],
          total: 79.97,
          loading: false,
        },
      },
    });

    jest.clearAllMocks();
  });

  const renderAppWithStore = () => {
    return render(
      <Provider store={store}>
        <BrowserRouter>
          <App />
        </BrowserRouter>
      </Provider>
    );
  };

  it('should complete full checkout flow successfully', async () => {
    // Arrange
    const orderData = {
      id: 'order-123',
      items: store.getState().cart.items,
      total: 79.97,
      status: 'confirmed',
    };

    const paymentData = {
      success: true,
      transactionId: 'txn-456',
    };

    mockCheckout.mockResolvedValueOnce(orderData);
    mockProcessPayment.mockResolvedValueOnce(paymentData);

    // Act
    renderAppWithStore();

    // Navigate to cart
    const cartLink = screen.getByRole('link', { name: /cart/i });
    await userEvent.click(cartLink);

    // Verify cart items
    expect(screen.getByText('Test Product')).toBeInTheDocument();
    expect(screen.getByText('Another Product')).toBeInTheDocument();
    expect(screen.getByText('$79.97')).toBeInTheDocument();

    // Proceed to checkout
    const checkoutButton = screen.getByRole('button', { name: /proceed to checkout/i });
    await userEvent.click(checkoutButton);

    // Fill shipping information
    const shippingAddress = screen.getByLabelText(/shipping address/i);
    const shippingCity = screen.getByLabelText(/city/i);
    const shippingZip = screen.getByLabelText(/zip code/i);

    await userEvent.type(shippingAddress, '123 Test Street');
    await userEvent.type(shippingCity, 'Test City');
    await userEvent.type(shippingZip, '12345');

    // Fill payment information
    const cardNumber = screen.getByLabelText(/card number/i);
    const cardExpiry = screen.getByLabelText(/expiry/i);
    const cardCvv = screen.getByLabelText(/cvv/i);

    await userEvent.type(cardNumber, '4242424242424242');
    await userEvent.type(cardExpiry, '12/25');
    await userEvent.type(cardCvv, '123');

    // Submit order
    const submitOrderButton = screen.getByRole('button', { name: /place order/i });
    await userEvent.click(submitOrderButton);

    // Assert
    await waitFor(() => {
      expect(mockCheckout).toHaveBeenCalledWith({
        shippingAddress: '123 Test Street',
        city: 'Test City',
        zipCode: '12345',
        paymentMethod: 'credit_card',
      });
    });

    await waitFor(() => {
      expect(mockProcessPayment).toHaveBeenCalledWith({
        orderId: 'order-123',
        amount: 79.97,
        paymentMethod: 'credit_card',
      });
    });

    await waitFor(() => {
      expect(screen.getByText(/order confirmed/i)).toBeInTheDocument();
      expect(screen.getByText('order-123')).toBeInTheDocument();
    });
  });

  it('should handle payment failure gracefully', async () => {
    // Arrange
    const orderData = {
      id: 'order-123',
      items: store.getState().cart.items,
      total: 79.97,
      status: 'pending',
    };

    mockCheckout.mockResolvedValueOnce(orderData);
    mockProcessPayment.mockRejectedValueOnce(new Error('Payment declined'));

    // Act
    renderAppWithStore();

    // Complete checkout process up to payment
    const cartLink = screen.getByRole('link', { name: /cart/i });
    await userEvent.click(cartLink);

    const checkoutButton = screen.getByRole('button', { name: /proceed to checkout/i });
    await userEvent.click(checkoutButton);

    // Fill forms and submit
    await userEvent.type(screen.getByLabelText(/shipping address/i), '123 Test Street');
    await userEvent.type(screen.getByLabelText(/city/i), 'Test City');
    await userEvent.type(screen.getByLabelText(/zip code/i), '12345');
    await userEvent.type(screen.getByLabelText(/card number/i), '4242424242424242');
    await userEvent.type(screen.getByLabelText(/expiry/i), '12/25');
    await userEvent.type(screen.getByLabelText(/cvv/i), '123');

    const submitOrderButton = screen.getByRole('button', { name: /place order/i });
    await userEvent.click(submitOrderButton);

    // Assert
    await waitFor(() => {
      expect(screen.getByText(/payment failed/i)).toBeInTheDocument();
      expect(screen.getByText(/payment declined/i)).toBeInTheDocument();
    });

    // Should show retry option
    expect(screen.getByRole('button', { name: /retry payment/i })).toBeInTheDocument();
  });

  it('should validate form fields before submission', async () => {
    // Act
    renderAppWithStore();

    // Navigate to checkout
    const cartLink = screen.getByRole('link', { name: /cart/i });
    await userEvent.click(cartLink);

    const checkoutButton = screen.getByRole('button', { name: /proceed to checkout/i });
    await userEvent.click(checkoutButton);

    // Try to submit empty form
    const submitOrderButton = screen.getByRole('button', { name: /place order/i });
    await userEvent.click(submitOrderButton);

    // Assert
    expect(screen.getByText(/shipping address is required/i)).toBeInTheDocument();
    expect(screen.getByText(/city is required/i)).toBeInTheDocument();
    expect(screen.getByText(/zip code is required/i)).toBeInTheDocument();
    expect(screen.getByText(/card number is required/i)).toBeInTheDocument();
    expect(screen.getByText(/expiry is required/i)).toBeInTheDocument();
    expect(screen.getByText(/cvv is required/i)).toBeInTheDocument();

    // Should not call APIs
    expect(mockCheckout).not.toHaveBeenCalled();
    expect(mockProcessPayment).not.toHaveBeenCalled();
  });

  it('should handle cart updates during checkout', async () => {
    // Act
    renderAppWithStore();

    // Navigate to checkout
    const cartLink = screen.getByRole('link', { name: /cart/i });
    await userEvent.click(cartLink);

    // Update cart quantity
    const quantityInputs = screen.getAllByRole('spinbutton');
    await userEvent.clear(quantityInputs[0]);
    await userEvent.type(quantityInputs[0], '3');

    // Verify total updated
    await waitFor(() => {
      expect(screen.getByText('$109.96')).toBeInTheDocument(); // 29.99 * 3 + 19.99
    });

    // Proceed to checkout
    const checkoutButton = screen.getByRole('button', { name: /proceed to checkout/i });
    await userEvent.click(checkoutButton);

    // Verify updated total in checkout
    expect(screen.getByText('$109.96')).toBeInTheDocument();
  });
});
```

## 🚀 End-to-End Testing Examples

### **CORE Tier - Critical User Journey Testing**

```typescript
// tests/e2e/user-journey.spec.ts
import { test, expect } from '@playwright/test';

test.describe('User Registration and Login Journey', () => {
  test('should allow user to register, login, and access dashboard', async ({ page }) => {
    // Navigate to application
    await page.goto('http://localhost:3000');

    // Register new user
    await page.click('[data-testid="register-link"]');
    
    await page.fill('[data-testid="name-input"]', 'John Doe');
    await page.fill('[data-testid="email-input"]', 'john@example.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.fill('[data-testid="confirm-password-input"]', 'password123');
    
    await page.click('[data-testid="register-button"]');

    // Verify successful registration
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText(
      'Registration successful'
    );

    // Login with new account
    await page.goto('http://localhost:3000/login');
    
    await page.fill('[data-testid="email-input"]', 'john@example.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');

    // Verify successful login and dashboard access
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();
    await expect(page.locator('[data-testid="user-name"]')).toContainText('John Doe');
    await expect(page.locator('[data-testid="user-email"]')).toContainText('john@example.com');
  });

  test('should handle login with invalid credentials', async ({ page }) => {
    await page.goto('http://localhost:3000/login');

    await page.fill('[data-testid="email-input"]', 'invalid@example.com');
    await page.fill('[data-testid="password-input"]', 'wrongpassword');
    await page.click('[data-testid="login-button"]');

    await expect(page.locator('[data-testid="error-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="error-message"]')).toContainText(
      'Invalid credentials'
    );
  });

  test('should allow password reset flow', async ({ page }) => {
    await page.goto('http://localhost:3000/login');

    await page.click('[data-testid="forgot-password-link"]');
    
    await page.fill('[data-testid="email-input"]', 'john@example.com');
    await page.click('[data-testid="reset-password-button"]');

    await expect(page.locator('[data-testid="reset-confirmation"]')).toBeVisible();
    await expect(page.locator('[data-testid="reset-confirmation"]')).toContainText(
      'Password reset email sent'
    );
  });
});
```

### **FULL Tier - Complex E2E Scenarios**

```typescript
// tests/e2e/ecommerce-full-journey.spec.ts
import { test, expect } from '@playwright/test';

test.describe('Complete E-commerce Journey', () => {
  test('should handle complete purchase flow from product discovery to order confirmation', async ({ page }) => {
    // Navigate to homepage
    await page.goto('http://localhost:3000');

    // Search for products
    await page.fill('[data-testid="search-input"]', 'laptop');
    await page.click('[data-testid="search-button"]');

    // Verify search results
    await expect(page.locator('[data-testid="search-results"]')).toBeVisible();
    await expect(page.locator('[data-testid="product-card"]')).toHaveCount.greaterThan(0);

    // Select first product
    await page.click('[data-testid="product-card"]:first-child');

    // Verify product details page
    await expect(page.locator('[data-testid="product-title"]')).toBeVisible();
    await expect(page.locator('[data-testid="product-price"]')).toBeVisible();
    await expect(page.locator('[data-testid="product-description"]')).toBeVisible();

    // Add to cart
    await page.click('[data-testid="add-to-cart-button"]');

    // Verify cart notification
    await expect(page.locator('[data-testid="cart-notification"]')).toBeVisible();
    await expect(page.locator('[data-testid="cart-count"]')).toContainText('1');

    // View cart
    await page.click('[data-testid="cart-icon"]');

    // Verify cart contents
    await expect(page.locator('[data-testid="cart-item"]')).toHaveCount(1);
    await expect(page.locator('[data-testid="cart-total"]')).toBeVisible();

    // Continue shopping and add another item
    await page.click('[data-testid="continue-shopping"]');
    await page.goto('http://localhost:3000/products');
    
    await page.click('[data-testid="product-card"]:nth-child(2)');
    await page.click('[data-testid="add-to-cart-button"]');

    // View updated cart
    await page.click('[data-testid="cart-icon"]');
    await expect(page.locator('[data-testid="cart-item"]')).toHaveCount(2);

    // Proceed to checkout
    await page.click('[data-testid="checkout-button"]');

    // Fill shipping information
    await page.fill('[data-testid="shipping-first-name"]', 'John');
    await page.fill('[data-testid="shipping-last-name"]', 'Doe');
    await page.fill('[data-testid="shipping-address"]', '123 Test Street');
    await page.fill('[data-testid="shipping-city"]', 'Test City');
    await page.fill('[data-testid="shipping-zip"]', '12345');
    await page.selectOption('[data-testid="shipping-country"]', 'US');

    // Fill payment information
    await page.fill('[data-testid="card-number"]', '4242424242424242');
    await page.fill('[data-testid="card-expiry"]', '12/25');
    await page.fill('[data-testid="card-cvv"]', '123');
    await page.fill('[data-testid="card-name"]', 'John Doe');

    // Review order
    await expect(page.locator('[data-testid="order-summary"]')).toBeVisible();
    await expect(page.locator('[data-testid="order-total"]')).toBeVisible();

    // Place order
    await page.click('[data-testid="place-order-button"]');

    // Verify order confirmation
    await expect(page.locator('[data-testid="order-confirmation"]')).toBeVisible();
    await expect(page.locator('[data-testid="order-number"]')).toBeVisible();
    await expect(page.locator('[data-testid="confirmation-message"]')).toContainText(
      'Thank you for your order'
    );

    // Verify order details
    await expect(page.locator('[data-testid="order-items"]')).toBeVisible();
    await expect(page.locator('[data-testid="shipping-details"]')).toBeVisible();
    await expect(page.locator('[data-testid="payment-details"]')).toBeVisible();

    // Save order number for future reference
    const orderNumber = await page.locator('[data-testid="order-number"]').textContent();
    console.log(`Order placed: ${orderNumber}`);
  });

  test('should handle guest checkout flow', async ({ page }) => {
    // Add items to cart as guest
    await page.goto('http://localhost:3000/products');
    await page.click('[data-testid="product-card"]:first-child');
    await page.click('[data-testid="add-to-cart-button"]');
    await page.click('[data-testid="cart-icon"]');
    await page.click('[data-testid="checkout-button"]');

    // Select guest checkout
    await page.click('[data-testid="guest-checkout"]');

    // Fill guest information
    await page.fill('[data-testid="guest-email"]', 'guest@example.com');
    await page.fill('[data-testid="guest-first-name"]', 'Guest');
    await page.fill('[data-testid="guest-last-name"]', 'User');

    // Continue with shipping and payment
    await page.fill('[data-testid="shipping-address"]', '456 Guest Street');
    await page.fill('[data-testid="shipping-city"]', 'Guest City');
    await page.fill('[data-testid="shipping-zip"]', '67890');
    await page.fill('[data-testid="card-number"]', '4242424242424242');
    await page.fill('[data-testid="card-expiry"]', '12/25');
    await page.fill('[data-testid="card-cvv"]', '123');

    // Complete guest order
    await page.click('[data-testid="place-order-button"]');

    // Verify guest order confirmation
    await expect(page.locator('[data-testid="order-confirmation"]')).toBeVisible();
    await expect(page.locator('[data-testid="guest-order-message"]')).toBeVisible();
  });

  test('should handle order tracking flow', async ({ page }) => {
    // Login and view order history
    await page.goto('http://localhost:3000/login');
    await page.fill('[data-testid="email-input"]', 'john@example.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');

    // Navigate to order history
    await page.click('[data-testid="account-menu"]');
    await page.click('[data-testid="order-history"]');

    // Verify order list
    await expect(page.locator('[data-testid="order-list"]')).toBeVisible();
    await expect(page.locator('[data-testid="order-item"]')).toHaveCount.greaterThan(0);

    // Track specific order
    await page.click('[data-testid="order-item"]:first-child');
    
    await expect(page.locator('[data-testid="order-details"]')).toBeVisible();
    await expect(page.locator('[data-testid="order-status"]')).toBeVisible();
    await expect(page.locator('[data-testid="tracking-info"]')).toBeVisible();

    // Check order timeline
    await expect(page.locator('[data-testid="order-timeline"]')).toBeVisible();
    await expect(page.locator('[data-testid="timeline-item"]')).toHaveCount.greaterThan(0);
  });
});
```

## ⚡ Performance Testing Examples

### **FULL Tier - Component Performance Testing**

```tsx
// tests/performance/ComponentPerformance.test.tsx
import React from 'react';
import { render, screen } from '@testing-library/react';
import { PerformanceMetrics } from '../utils/performance-metrics';
import { LargeDataTable } from '../../src/components/LargeDataTable';

describe('Component Performance Tests', () => {
  const performanceMetrics = new PerformanceMetrics();

  beforeEach(() => {
    performanceMetrics.startMeasurement();
  });

  afterEach(() => {
    performanceMetrics.endMeasurement();
  });

  it('should render large data table within performance threshold', () => {
    // Arrange
    const largeDataSet = Array.from({ length: 10000 }, (_, index) => ({
      id: index,
      name: `Item ${index}`,
      value: Math.random() * 100,
    }));

    // Act
    const startTime = performance.now();
    render(<LargeDataTable data={largeDataSet} />);
    const endTime = performance.now();

    // Assert
    const renderTime = endTime - startTime;
    expect(renderTime).toBeLessThan(1000); // Should render within 1 second
    expect(screen.getByRole('table')).toBeInTheDocument();
    
    // Verify virtualization is working
    const visibleRows = screen.getAllByRole('row');
    expect(visibleRows.length).toBeLessThan(100); // Should only render visible rows
  });

  it('should handle frequent updates without memory leaks', () => {
    // Arrange
    const { rerender } = render(<LargeDataTable data={[]} />);
    
    // Act - Simulate frequent updates
    for (let i = 0; i < 100; i++) {
      const newData = Array.from({ length: 1000 }, (_, index) => ({
        id: index + i,
        name: `Item ${index + i}`,
        value: Math.random() * 100,
      }));
      
      rerender(<LargeDataTable data={newData} />);
    }

    // Assert - Check memory usage
    const memoryUsage = performanceMetrics.getMemoryUsage();
    expect(memoryUsage).toBeLessThan(50 * 1024 * 1024); // Should use less than 50MB
  });

  it('should maintain performance with complex filtering', () => {
    // Arrange
    const complexDataSet = Array.from({ length: 5000 }, (_, index) => ({
      id: index,
      name: `Item ${index}`,
      category: `Category ${index % 100}`,
      value: Math.random() * 1000,
      description: `This is a longer description for item ${index}`,
    }));

    render(<LargeDataTable data={complexDataSet} />);

    // Act - Apply complex filter
    const startTime = performance.now();
    const filterInput = screen.getByPlaceholderText(/filter/i);
    
    // Simulate typing filter
    fireEvent.change(filterInput, { target: { value: 'Category 1' } });
    
    const endTime = performance.now();

    // Assert
    const filterTime = endTime - startTime;
    expect(filterTime).toBeLessThan(500); // Should filter within 500ms
  });
});
```

## 🛠️ Testing Utilities and Configuration

### **Test Configuration**

```javascript
// jest.config.js
module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'jsdom',
  roots: ['<rootDir>/src', '<rootDir>/tests'],
  testMatch: [
    '**/__tests__/**/*.{ts,tsx}',
    '**/*.{test,spec}.{ts,tsx}',
  ],
  transform: {
    '^.+\\.(ts|tsx)$': 'ts-jest',
  },
  collectCoverageFrom: [
    'src/**/*.{ts,tsx}',
    '!src/**/*.d.ts',
    '!src/index.tsx',
    '!src/**/*.stories.{ts,tsx}',
    '!src/**/__tests__/**',
  ],
  coverageDirectory: 'coverage',
  coverageReporters: ['text', 'lcov', 'html'],
  coverageThreshold: {
    global: {
      branches: 80,
      functions: 80,
      lines: 80,
      statements: 80,
    },
  },
  setupFilesAfterEnv: ['<rootDir>/tests/setup.ts'],
  moduleNameMapping: {
    '^@/(.*)$': '<rootDir>/src/$1',
    '^@tests/(.*)$': '<rootDir>/tests/$1',
    '\\.(css|less|scss|sass)$': 'identity-obj-proxy',
  },
  testEnvironmentOptions: {
    url: 'http://localhost:3000',
  },
};
```

### **Test Setup and Utilities**

```tsx
// tests/setup.ts
import '@testing-library/jest-dom';
import { configure } from '@testing-library/react';
import { server } from './mocks/server';

// Configure testing library
configure({ testIdAttribute: 'data-testid' });

// Start mock server
beforeAll(() => server.listen());

// Reset handlers after each test
afterEach(() => server.resetHandlers());

// Close server after all tests
afterAll(() => server.close());

// Mock IntersectionObserver
global.IntersectionObserver = class IntersectionObserver {
  constructor() {}
  disconnect() {}
  observe() {}
  unobserve() {}
};

// Mock ResizeObserver
global.ResizeObserver = class ResizeObserver {
  constructor() {}
  disconnect() {}
  observe() {}
  unobserve() {}
};

// Mock window.matchMedia
Object.defineProperty(window, 'matchMedia', {
  writable: true,
  value: jest.fn().mockImplementation(query => ({
    matches: false,
    media: query,
    onchange: null,
    addListener: jest.fn(),
    removeListener: jest.fn(),
    addEventListener: jest.fn(),
    removeEventListener: jest.fn(),
    dispatchEvent: jest.fn(),
  })),
});

// Global test utilities
global.createMockUser = (overrides = {}) => ({
  id: '1',
  name: 'Test User',
  email: 'test@example.com',
  isActive: true,
  role: 'user',
  createdAt: new Date('2023-01-01'),
  ...overrides,
});

global.createMockProduct = (overrides = {}) => ({
  id: '1',
  name: 'Test Product',
  price: 29.99,
  description: 'Test description',
  category: 'Test Category',
  inStock: true,
  ...overrides,
});
```

### **Custom Render Functions**

```tsx
// tests/utils/render-with-providers.tsx
import React, { ReactElement } from 'react';
import { render, RenderOptions } from '@testing-library/react';
import { BrowserRouter } from 'react-router-dom';
import { Provider } from 'react-redux';
import { configureStore } from '@reduxjs/toolkit';
import { ThemeProvider } from 'styled-components';
import { AuthProvider } from '../../src/contexts/AuthContext';
import { defaultTheme } from '../../src/themes/defaultTheme';

// Create mock store
const createMockStore = (initialState = {}) => {
  return configureStore({
    reducer: {
      // Add your reducers here
    },
    preloadedState: initialState,
  });
};

// Custom render function with providers
const customRender = (
  ui: ReactElement,
  options: RenderOptions & {
    initialState?: any;
    route?: string;
  } = {}
) => {
  const { initialState = {}, route = '/', ...renderOptions } = options;
  
  const store = createMockStore(initialState);
  
  const Wrapper: React.FC<{ children: React.ReactNode }> = ({ children }) => {
    return (
      <Provider store={store}>
        <BrowserRouter>
          <ThemeProvider theme={defaultTheme}>
            <AuthProvider>
              {children}
            </AuthProvider>
          </ThemeProvider>
        </BrowserRouter>
      </Provider>
    );
  };

  // Navigate to specific route if provided
  if (route !== '/') {
    window.history.pushState({}, '', route);
  }

  return render(ui, { wrapper: Wrapper, ...renderOptions });
};

// Re-export everything from testing-library
export * from '@testing-library/react';
export { customRender as render };
```

### **Mock Data Factories**

```tsx
// tests/factories/user.factory.ts
import { faker } from '@faker-js/faker';
import { User } from '../../src/types/user.types';

export class UserFactory {
  static create(overrides = {}): User {
    return {
      id: faker.string.uuid(),
      name: faker.person.fullName(),
      email: faker.internet.email(),
      isActive: true,
      role: 'user',
      department: faker.helpers.arrayElement(['Engineering', 'Marketing', 'Sales']),
      avatar: faker.image.avatar(),
      createdAt: faker.date.past(),
      ...overrides,
    };
  }

  static createMany(count: number, overrides = {}): User[] {
    return Array.from({ length: count }, () => this.create(overrides));
  }

  static createAdmin(overrides = {}): User {
    return this.create({ role: 'admin', ...overrides });
  }

  static createInactive(overrides = {}): User {
    return this.create({ isActive: false, ...overrides });
  }
}

// tests/factories/product.factory.ts
import { faker } from '@faker-js/faker';
import { Product } from '../../src/types/product.types';

export class ProductFactory {
  static create(overrides = {}): Product {
    return {
      id: faker.string.uuid(),
      name: faker.commerce.productName(),
      description: faker.commerce.productDescription(),
      price: parseFloat(faker.commerce.price()),
      category: faker.commerce.department(),
      inStock: faker.datatype.boolean(),
      image: faker.image.url(),
      rating: faker.number.float({ min: 1, max: 5, precision: 0.1 }),
      ...overrides,
    };
  }

  static createMany(count: number, overrides = {}): Product[] {
    return Array.from({ length: count }, () => this.create(overrides));
  }

  static createOutOfStock(overrides = {}): Product {
    return this.create({ inStock: false, ...overrides });
  }
}
```

### **Test Scripts**

```json
// package.json scripts
{
  "scripts": {
    "test": "jest",
    "test:watch": "jest --watch",
    "test:coverage": "jest --coverage",
    "test:components": "jest --testPathPattern=components",
    "test:hooks": "jest --testPathPattern=hooks",
    "test:integration": "jest --testPathPattern=integration",
    "test:e2e": "playwright test",
    "test:performance": "jest --testPathPattern=performance",
    "test:ci": "jest --coverage --ci --watchAll=false --passWithNoTests",
    "test:debug": "jest --runInBand --no-cache"
  }
}
```

---
*React Testing Examples - Use these patterns for comprehensive test coverage*
