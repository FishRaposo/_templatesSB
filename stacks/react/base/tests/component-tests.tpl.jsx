/**
 * File: component-tests.tpl.jsx
 * Purpose: Template for unknown implementation
 * Generated for: {{PROJECT_NAME}}
 */

// -----------------------------------------------------------------------------
// FILE: component-tests.tpl.jsx
// PURPOSE: Comprehensive component testing patterns for React projects
// USAGE: Import and extend for component testing across React applications
// DEPENDENCIES: @testing-library/react, @testing-library/jest-dom, @testing-library/user-event
// AUTHOR: [[.Author]]
// VERSION: [[.Version]]
// SINCE: [[.Version]]
// -----------------------------------------------------------------------------

/**
 * React Component Tests Template
 * Purpose: Comprehensive component testing patterns for React projects
 * Usage: Import and extend for component testing across React applications
 */

import React from 'react';
import { render, screen, fireEvent, waitFor, act } from '@testing-library/react';
import { BrowserRouter, MemoryRouter, Router } from 'react-router-dom';
import { createMemoryHistory } from 'history';
import userEvent from '@testing-library/user-event';
import '@testing-library/jest-dom';

// Import your components here
// import CustomButton from '../components/CustomButton';
// import UserForm from '../components/UserForm';
// import DataTable from '../components/DataTable';
// import Modal from '../components/Modal';
// import Navigation from '../components/Navigation';
// import LoadingSpinner from '../components/LoadingSpinner';
// import ErrorBoundary from '../components/ErrorBoundary';

// Mock IntersectionObserver for components that use it
global.IntersectionObserver = jest.fn().mockImplementation(() => ({
  observe: jest.fn(),
  unobserve: jest.fn(),
  disconnect: jest.fn(),
}));

// Mock ResizeObserver
global.ResizeObserver = jest.fn().mockImplementation(() => ({
  observe: jest.fn(),
  unobserve: jest.fn(),
  disconnect: jest.fn(),
}));

// Mock window.matchMedia
Object.defineProperty(window, 'matchMedia', {
  writable: true,
  value: jest.fn().mockImplementation(query => ({
    matches: false,
    media: query,
    onchange: null,
    addListener: jest.fn(), // deprecated
    removeListener: jest.fn(), // deprecated
    addEventListener: jest.fn(),
    removeEventListener: jest.fn(),
    dispatchEvent: jest.fn(),
  })),
});

describe('Component Tests - Interactive Elements', () => {
  
  describe('Button Component', () => {
    test('renders button with correct text and role', () => {
      // Arrange & Act
      render(<CustomButton>Click Me</CustomButton>);
      
      // Assert
      expect(screen.getByRole('button')).toBeInTheDocument();
      expect(screen.getByText('Click Me')).toBeInTheDocument();
    });

    test('handles click events correctly', async () => {
      // Arrange
      const handleClick = jest.fn();
      const user = userEvent.setup();
      
      // Act
      render(<CustomButton onClick={handleClick}>Click Me</CustomButton>);
      await user.click(screen.getByRole('button'));
      
      // Assert
      expect(handleClick).toHaveBeenCalledTimes(1);
    });

    test('shows loading state and disables when loading', () => {
      // Arrange & Act
      render(<CustomButton isLoading>Loading</CustomButton>);
      
      // Assert
      expect(screen.getByRole('button')).toBeDisabled();
      expect(screen.getByTestId('loading-spinner')).toBeInTheDocument();
      expect(screen.getByText('Loading')).toBeInTheDocument();
    });

    test('applies correct CSS classes for different variants', () => {
      // Arrange & Act
      const { rerender } = render(<CustomButton variant="primary">Primary</CustomButton>);
      expect(screen.getByRole('button')).toHaveClass('btn-primary');
      
      // Act
      rerender(<CustomButton variant="secondary">Secondary</CustomButton>);
      
      // Assert
      expect(screen.getByRole('button')).toHaveClass('btn-secondary');
    });

    test('supports accessibility attributes', () => {
      // Arrange & Act
      render(
        <CustomButton 
          aria-label="Custom Action" 
          aria-describedby="button-help"
        >
          Click
        </CustomButton>
      );
      
      // Assert
      expect(screen.getByLabelText('Custom Action')).toBeInTheDocument();
      expect(screen.getByRole('button')).toHaveAttribute('aria-describedby', 'button-help');
    });
  });

  describe('Form Components', () => {
    test('renders form fields with correct labels and types', () => {
      // Arrange & Act
      render(<UserForm />);
      
      // Assert
      expect(screen.getByLabelText(/name/i)).toBeInTheDocument();
      expect(screen.getByLabelText(/email/i)).toBeInTheDocument();
      expect(screen.getByRole('button', { name: /submit/i })).toBeInTheDocument();
      expect(screen.getByLabelText(/email/i)).toHaveAttribute('type', 'email');
    });

    test('validates form inputs on submit', async () => {
      // Arrange
      const user = userEvent.setup();
      render(<UserForm />);
      
      // Act
      await user.click(screen.getByRole('button', { name: /submit/i }));
      
      // Assert
      expect(screen.getByText(/name is required/i)).toBeInTheDocument();
      expect(screen.getByText(/email is required/i)).toBeInTheDocument();
    });

    test('submits form with valid data', async () => {
      // Arrange
      const handleSubmit = jest.fn();
      const user = userEvent.setup();
      
      render(<UserForm onSubmit={handleSubmit} />);
      
      // Act
      await user.type(screen.getByLabelText(/name/i), 'John Doe');
      await user.type(screen.getByLabelText(/email/i), 'john@example.com');
      await user.click(screen.getByRole('button', { name: /submit/i }));
      
      // Assert
      await waitFor(() => {
        expect(handleSubmit).toHaveBeenCalledWith({
          name: 'John Doe',
          email: 'john@example.com'
        });
      });
    });

    test('shows validation errors in real-time', async () => {
      // Arrange
      const user = userEvent.setup();
      render(<UserForm />);
      
      // Act
      await user.type(screen.getByLabelText(/email/i), 'invalid-email');
      await user.tab(); // Blur the field
      
      // Assert
      expect(screen.getByText(/invalid email format/i)).toBeInTheDocument();
    });

    test('handles form reset correctly', async () => {
      // Arrange
      const user = userEvent.setup();
      render(<UserForm />);
      
      // Act
      await user.type(screen.getByLabelText(/name/i), 'John Doe');
      await user.type(screen.getByLabelText(/email/i), 'john@example.com');
      await user.click(screen.getByRole('button', { name: /reset/i }));
      
      // Assert
      expect(screen.getByLabelText(/name/i)).toHaveValue('');
      expect(screen.getByLabelText(/email/i)).toHaveValue('');
    });
  });

  describe('Data Display Components', () => {
    const mockData = [
      { id: 1, name: 'John Doe', email: 'john@example.com', role: 'Admin' },
      { id: 2, name: 'Jane Smith', email: 'jane@example.com', role: 'User' },
      { id: 3, name: 'Bob Johnson', email: 'bob@example.com', role: 'User' },
    ];

    test('renders table with correct data and headers', () => {
      // Arrange & Act
      render(<DataTable data={mockData} />);
      
      // Assert
      expect(screen.getByText('Name')).toBeInTheDocument();
      expect(screen.getByText('Email')).toBeInTheDocument();
      expect(screen.getByText('John Doe')).toBeInTheDocument();
      expect(screen.getByText('jane@example.com')).toBeInTheDocument();
      expect(screen.getAllByRole('row')).toHaveLength(4); // Header + 3 data rows
    });

    test('handles sorting when column headers are clicked', async () => {
      // Arrange
      const user = userEvent.setup();
      render(<DataTable data={mockData} sortable={true} />);
      
      // Act
      await user.click(screen.getByRole('columnheader', { name: /name/i }));
      
      // Assert
      const rows = screen.getAllByRole('row');
      expect(rows[1]).toHaveTextContent('Bob Johnson'); // Sorted ascending
      expect(rows[3]).toHaveTextContent('John Doe');
    });

    test('filters data based on search input', async () => {
      // Arrange
      const user = userEvent.setup();
      render(<DataTable data={mockData} searchable={true} />);
      
      // Act
      await user.type(screen.getByPlaceholderText(/search/i), 'John');
      
      // Assert
      expect(screen.getByText('John Doe')).toBeInTheDocument();
      expect(screen.getByText('Bob Johnson')).toBeInTheDocument();
      expect(screen.queryByText('Jane Smith')).not.toBeInTheDocument();
    });

    test('handles empty data state gracefully', () => {
      // Arrange & Act
      render(<DataTable data={[]} />);
      
      // Assert
      expect(screen.getByText(/no data available/i)).toBeInTheDocument();
      expect(screen.queryByRole('table')).not.toBeInTheDocument();
    });

    test('handles row selection correctly', async () => {
      // Arrange
      const user = userEvent.setup();
      const handleRowSelect = jest.fn();
      render(<DataTable data={mockData} onRowSelect={handleRowSelect} selectable={true} />);
      
      // Act
      await user.click(screen.getByRole('checkbox', { name: /select row/i }));
      
      // Assert
      expect(handleRowSelect).toHaveBeenCalledWith(mockData[0]);
    });
  });

  describe('Modal Components', () => {
    test('renders modal when open and hides when closed', () => {
      // Arrange & Act
      const { rerender } = render(<Modal isOpen={false}><p>Modal Content</p></Modal>);
      
      // Assert - Modal should not be in DOM
      expect(screen.queryByText('Modal Content')).not.toBeInTheDocument();
      
      // Act
      rerender(<Modal isOpen={true}><p>Modal Content</p></Modal>);
      
      // Assert - Modal should be visible
      expect(screen.getByText('Modal Content')).toBeInTheDocument();
      expect(screen.getByRole('dialog')).toBeInTheDocument();
    });

    test('calls onClose when close button is clicked', async () => {
      // Arrange
      const onClose = jest.fn();
      const user = userEvent.setup();
      
      // Act
      render(<Modal isOpen onClose={onClose}><p>Modal Content</p></Modal>);
      await user.click(screen.getByRole('button', { name: /close/i }));
      
      // Assert
      expect(onClose).toHaveBeenCalledTimes(1);
    });

    test('calls onClose when overlay is clicked', async () => {
      // Arrange
      const onClose = jest.fn();
      const user = userEvent.setup();
      
      // Act
      render(<Modal isOpen onClose={onClose} closeOnOverlayClick={true}><p>Modal Content</p></Modal>);
      await user.click(screen.getByTestId('modal-overlay'));
      
      // Assert
      expect(onClose).toHaveBeenCalledTimes(1);
    });

    test('prevents closing when closeOnOverlayClick is false', async () => {
      // Arrange
      const onClose = jest.fn();
      const user = userEvent.setup();
      
      // Act
      render(<Modal isOpen onClose={onClose} closeOnOverlayClick={false}><p>Modal Content</p></Modal>);
      await user.click(screen.getByTestId('modal-overlay'));
      
      // Assert
      expect(onClose).not.toHaveBeenCalled();
    });

    test('traps focus within modal', async () => {
      // Arrange
      const user = userEvent.setup();
      render(
        <Modal isOpen>
          <button>Button 1</button>
          <button>Button 2</button>
          <input type="text" placeholder="Input" />
        </Modal>
      );
      
      // Act
      await user.tab();
      
      // Assert - Focus should be within modal
      expect(screen.getByText('Button 1')).toHaveFocus();
    });
  });

  describe('Navigation Components', () => {
    test('renders navigation links correctly', () => {
      // Arrange
      const navItems = [
        { path: '/', label: 'Home', exact: true },
        { path: '/about', label: 'About' },
        { path: '/contact', label: 'Contact' },
      ];
      
      // Act
      render(
        <BrowserRouter>
          <Navigation items={navItems} />
        </BrowserRouter>
      );
      
      // Assert
      expect(screen.getByText('Home')).toBeInTheDocument();
      expect(screen.getByText('About')).toBeInTheDocument();
      expect(screen.getByText('Contact')).toBeInTheDocument();
    });

    test('highlights active navigation item', () => {
      // Arrange
      const navItems = [
        { path: '/', label: 'Home', exact: true },
        { path: '/about', label: 'About' },
      ];
      
      // Act
      render(
        <MemoryRouter initialEntries={['/about']}>
          <Navigation items={navItems} />
        </MemoryRouter>
      );
      
      // Assert
      expect(screen.getByText('About')).toHaveClass('active');
      expect(screen.getByText('Home')).not.toHaveClass('active');
    });

    test('handles mobile menu toggle', async () => {
      // Arrange
      const user = userEvent.setup();
      render(
        <BrowserRouter>
          <Navigation items={[{ path: '/', label: 'Home' }]} />
        </BrowserRouter>
      );
      
      // Act
      await user.click(screen.getByRole('button', { name: /menu/i }));
      
      // Assert
      expect(screen.getByText('Home')).toBeVisible();
    });
  });

  describe('Loading and Error States', () => {
    test('displays loading spinner with correct accessibility', () => {
      // Arrange & Act
      render(<LoadingSpinner />);
      
      // Assert
      expect(screen.getByRole('status')).toBeInTheDocument();
      expect(screen.getByText(/loading/i)).toBeInTheDocument();
    });

    test('shows error message with retry option', async () => {
      // Arrange
      const onRetry = jest.fn();
      const user = userEvent.setup();
      
      // Act
      render(<ErrorMessage message="Something went wrong" onRetry={onRetry} />);
      
      // Assert
      expect(screen.getByText('Something went wrong')).toBeInTheDocument();
      expect(screen.getByRole('button', { name: /retry/i })).toBeInTheDocument();
      
      // Act - Click retry
      await user.click(screen.getByRole('button', { name: /retry/i }));
      
      // Assert
      expect(onRetry).toHaveBeenCalledTimes(1);
    });
  });

  describe('Error Boundary Component', () => {
    test('catches and displays errors', () => {
      // Arrange
      const ThrowError = () => {
        throw new Error('Test error');
      };
      
      // Act
      render(
        <ErrorBoundary>
          <ThrowError />
        </ErrorBoundary>
      );
      
      // Assert
      expect(screen.getByText(/something went wrong/i)).toBeInTheDocument();
      expect(screen.getByRole('button', { name: /try again/i })).toBeInTheDocument();
    });

    test('renders children when no error', () => {
      // Arrange & Act
      render(
        <ErrorBoundary>
          <div>No Error</div>
        </ErrorBoundary>
      );
      
      // Assert
      expect(screen.getByText('No Error')).toBeInTheDocument();
      expect(screen.queryByText(/something went wrong/i)).not.toBeInTheDocument();
    });
  });
});

describe('Component Tests - Advanced Patterns', () => {
  
  describe('Async Components', () => {
    test('shows loading state during async operations', async () => {
      // Arrange
      const AsyncComponent = () => {
        const [loading, setLoading] = React.useState(true);
        const [data, setData] = React.useState(null);
        
        React.useEffect(() => {
          setTimeout(() => {
            setData('Loaded data');
            setLoading(false);
          }, 100);
        }, []);
        
        if (loading) return <LoadingSpinner />;
        return <div>{data}</div>;
      };
      
      // Act
      render(<AsyncComponent />);
      
      // Assert - Loading state
      expect(screen.getByRole('status')).toBeInTheDocument();
      
      // Wait for loading to complete
      await waitFor(() => {
        expect(screen.getByText('Loaded data')).toBeInTheDocument();
      });
      
      // Assert - Data loaded
      expect(screen.queryByRole('status')).not.toBeInTheDocument();
    });

    test('handles async errors gracefully', async () => {
      // Arrange
      const AsyncErrorComponent = () => {
        const [error, setError] = React.useState(null);
        
        React.useEffect(() => {
          setTimeout(() => {
            setError(new Error('Async error occurred'));
          }, 100);
        }, []);
        
        if (error) throw error;
        return <div>No Error</div>;
      };
      
      // Act
      render(
        <ErrorBoundary>
          <AsyncErrorComponent />
        </ErrorBoundary>
      );
      
      // Wait for error to occur
      await waitFor(() => {
        expect(screen.getByText(/something went wrong/i)).toBeInTheDocument();
      });
    });
  });

  describe('Components with Hooks', () => {
    test('uses custom hook correctly', () => {
      // Arrange
      const useCounter = (initial = 0) => {
        const [count, setCount] = React.useState(initial);
        const increment = () => setCount(c => c + 1);
        const decrement = () => setCount(c => c - 1);
        return { count, increment, decrement };
      };
      
      const CounterComponent = () => {
        const { count, increment, decrement } = useCounter(5);
        return (
          <div>
            <span>Count: {count}</span>
            <button onClick={increment}>+</button>
            <button onClick={decrement}>-</button>
          </div>
        );
      };
      
      // Act
      render(<CounterComponent />);
      
      // Assert
      expect(screen.getByText('Count: 5')).toBeInTheDocument();
      expect(screen.getByRole('button', { name: '+' })).toBeInTheDocument();
      expect(screen.getByRole('button', { name: '-' })).toBeInTheDocument();
    });

    test('handles useEffect cleanup', () => {
      // Arrange
      const cleanup = jest.fn();
      
      const EffectComponent = () => {
        React.useEffect(() => {
          return cleanup;
        }, []);
        
        return <div>Component</div>;
      };
      
      // Act
      const { unmount } = render(<EffectComponent />);
      
      // Assert
      expect(cleanup).not.toHaveBeenCalled();
      
      // Act - Unmount component
      unmount();
      
      // Assert
      expect(cleanup).toHaveBeenCalledTimes(1);
    });
  });

  describe('Components with Context', () => {
    test('consumes context values correctly', () => {
      // Arrange
      const ThemeContext = React.createContext('light');
      
      const ThemedComponent = () => {
        const theme = React.useContext(ThemeContext);
        return <div data-theme={theme}>Themed Content</div>;
      };
      
      // Act
      render(
        <ThemeContext.Provider value="dark">
          <ThemedComponent />
        </ThemeContext.Provider>
      );
      
      // Assert
      expect(screen.getByText('Themed Content')).toHaveAttribute('data-theme', 'dark');
    });

    test('updates when context value changes', async () => {
      // Arrange
      const ThemeContext = React.createContext('light');
      
      const ThemedComponent = () => {
        const theme = React.useContext(ThemeContext);
        return <div data-theme={theme}>Theme: {theme}</div>;
      };
      
      // Act
      const { rerender } = render(
        <ThemeContext.Provider value="light">
          <ThemedComponent />
        </ThemeContext.Provider>
      );
      
      // Assert
      expect(screen.getByText('Theme: light')).toHaveAttribute('data-theme', 'light');
      
      // Act - Change context value
      rerender(
        <ThemeContext.Provider value="dark">
          <ThemedComponent />
        </ThemeContext.Provider>
      );
      
      // Assert
      expect(screen.getByText('Theme: dark')).toHaveAttribute('data-theme', 'dark');
    });
  });

  describe('Performance Testing', () => {
    test('renders large lists efficiently', () => {
      // Arrange
      const largeList = Array.from({ length: 1000 }, (_, i) => ({ id: i, name: `Item ${i}` }));
      
      // Act
      const startTime = performance.now();
      render(<DataTable data={largeList} virtualized={true} />);
      const endTime = performance.now();
      
      // Assert
      expect(endTime - startTime).toBeLessThan(100); // Should render in < 100ms
      expect(screen.getByText('Item 0')).toBeInTheDocument();
    });
  });
});

// Mock components for testing
const CustomButton = ({ children, onClick, isLoading, variant = 'primary', ...props }) => (
  <button 
    onClick={onClick} 
    disabled={isLoading}
    className={`btn-${variant}`}
    {...props}
  >
    {isLoading ? <span data-testid="loading-spinner">Loading...</span> : children}
  </button>
);

const UserForm = ({ onSubmit = jest.fn() }) => {
  const [errors, setErrors] = React.useState({});
  const [touched, setTouched] = React.useState({});
  
  const handleSubmit = (e) => {
    e.preventDefault();
    const formData = new FormData(e.target);
    const data = Object.fromEntries(formData);
    
    // Simple validation
    const newErrors = {};
    if (!data.name) newErrors.name = 'Name is required';
    if (!data.email) newErrors.email = 'Email is required';
    if (data.email && !data.email.includes('@')) newErrors.email = 'Invalid email format';
    
    if (Object.keys(newErrors).length > 0) {
      setErrors(newErrors);
      return;
    }
    
    onSubmit(data);
  };
  
  const handleBlur = (field) => {
    setTouched({ ...touched, [field]: true });
  };
  
  return (
    <form onSubmit={handleSubmit}>
      <label>
        Name:
        <input 
          name="name" 
          onBlur={() => handleBlur('name')}
        />
        {touched.name && errors.name && <span>{errors.name}</span>}
      </label>
      <label>
        Email:
        <input 
          name="email" 
          type="email"
          onBlur={() => handleBlur('email')}
        />
        {touched.email && errors.email && <span>{errors.email}</span>}
      </label>
      <button type="submit">Submit</button>
      <button type="reset">Reset</button>
    </form>
  );
};

const DataTable = ({ data, sortable = false, searchable = false, selectable = false, onRowSelect = jest.fn(), virtualized = false }) => {
  const [sortField, setSortField] = React.useState('name');
  const [filter, setFilter] = React.useState('');
  
  const filteredData = data.filter(item => 
    item.name.toLowerCase().includes(filter.toLowerCase()) ||
    item.email.toLowerCase().includes(filter.toLowerCase())
  );
  
  const sortedData = [...filteredData].sort((a, b) => 
    a[sortField].localeCompare(b[sortField])
  );
  
  if (data.length === 0) {
    return <div>No data available</div>;
  }
  
  return (
    <div>
      {searchable && (
        <input 
          placeholder="Search..." 
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
        />
      )}
      <table>
        <thead>
          <tr>
            {selectable && <th></th>}
            <th onClick={() => sortable && setSortField('name')}>Name</th>
            <th onClick={() => sortable && setSortField('email')}>Email</th>
            <th>Role</th>
          </tr>
        </thead>
        <tbody>
          {sortedData.map(item => (
            <tr key={item.id}>
              {selectable && (
                <td>
                  <input 
                    type="checkbox" 
                    aria-label="select row"
                    onChange={() => onRowSelect(item)}
                  />
                </td>
              )}
              <td>{item.name}</td>
              <td>{item.email}</td>
              <td>{item.role}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
};

const Modal = ({ isOpen, onClose = jest.fn(), children, closeOnOverlayClick = true }) => {
  if (!isOpen) return null;
  
  return (
    <div role="dialog" data-testid="modal-overlay">
      <div>
        <button onClick={onClose} aria-label="Close">×</button>
        {children}
      </div>
    </div>
  );
};

const Navigation = ({ items }) => {
  const location = window.location;
  
  return (
    <nav>
      <button aria-label="Menu">☰</button>
      <ul>
        {items.map(item => (
          <li key={item.path}>
            <a 
              href={item.path}
              className={location.pathname === item.path ? 'active' : ''}
            >
              {item.label}
            </a>
          </li>
        ))}
      </ul>
    </nav>
  );
};

const LoadingSpinner = () => (
  <div role="status">
    <span>Loading...</span>
  </div>
);

const ErrorMessage = ({ message, onRetry = jest.fn() }) => (
  <div>
    <p>{message}</p>
    <button onClick={onRetry}>Retry</button>
  </div>
);

const ErrorBoundary = ({ children }) => {
  return (
    <div>
      {children}
    </div>
  );
};

export {
  CustomButton,
  UserForm,
  DataTable,
  Modal,
  Navigation,
  LoadingSpinner,
  ErrorMessage,
  ErrorBoundary
};
