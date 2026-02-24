/**
 * File: basic-tests-react.tpl.jsx
 * Purpose: Template for unknown implementation
 * Generated for: {{PROJECT_NAME}}
 */

# Basic React Testing Template
# Purpose: MVP-level testing template with unit and component tests for React applications
# Usage: Copy to __tests__/ directory and customize for your React project
# Stack: React (.jsx)
# Tier: MVP (Minimal Viable Product)

## Purpose

MVP-level React testing template providing essential unit and component tests for basic application functionality. Focuses on testing core business logic, React components, and user interactions with minimal setup and fast execution.

## Usage

```bash
# Copy to your React project
cp _templates/tiers/mvp/tests/basic-tests-react.tpl.jsx src/__tests__/Basic.test.jsx

# Install dependencies
npm install --save-dev @testing-library/react @testing-library/jest-dom @testing-library/user-event

# Run tests
npm test

# Run with coverage
npm test -- --coverage --watchAll=false
```

## Structure

```jsx
// src/__tests__/Basic.test.jsx
import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import '@testing-library/jest-dom';
import App from '../App';
import Calculator from '../components/Calculator';
import UserForm from '../components/UserForm';
import DataList from '../components/DataList';

/**
 * MVP React Test Suite
 * 
 * This test suite follows the MVP testing philosophy:
 * - Focus on core business logic and essential component functionality
 * - Fast execution with minimal setup and mocking
 * - No complex integration testing or end-to-end tests
 * - Educational comments to teach React Testing Library patterns
 * 
 * MVP Testing Approach:
 * - Unit tests for pure business logic
 * - Component tests for UI rendering and interactions
 * - No integration tests (added in Core tier)
 * - No accessibility or performance tests (added in Enterprise tier)
 * 
 * Key React Testing Library Patterns:
 * - render(): Renders components for testing
 * - screen(): Access to queries for finding elements
 * - userEvent: Simulates realistic user interactions
 * - fireEvent: Simulates DOM events
 * - waitFor(): Waits for async operations to complete
 */

// Mock API calls and external dependencies
// MVP approach: Simple mocks, no complex mock scenarios
jest.mock('../services/api', () => ({
  fetchUsers: jest.fn(),
  createUser: jest.fn(),
}));

/**
 * Business Logic Tests - Pure Functions and Utilities
 * 
 * These tests verify business logic without React components.
 * MVP approach: Test essential functions that drive your app's core value.
 * No complex scenarios, no external dependencies, no async operations.
 */
describe('Business Logic Tests', () => {
  /**
   * Calculator Logic Tests
   * 
   * Demonstrates testing pure utility functions and mathematical operations.
   * MVP: Basic arithmetic, no complex calculations or edge case handling.
   */
  describe('Calculator Logic', () => {
    /**
     * Test basic addition functionality
     * 
     * Simple pure function test to demonstrate Jest syntax.
     * MVP: Basic operations, no error handling or validation.
     */
    test('should add two numbers correctly', () => {
      const result = 2 + 3;
      expect(result).toBe(5);
    });

    test('should subtract two numbers correctly', () => {
      const result = 10 - 3;
      expect(result).toBe(7);
    });

    test('should multiply two numbers correctly', () => {
      const result = 4 * 5;
      expect(result).toBe(20);
    });

    test('should handle division by zero', () => {
      expect(() => {
        const result = 10 / 0;
      }).toThrow();
    });
  });

  describe('Data Validation', () => {
    test('should validate email format', () => {
      const isValidEmail = (email) => {
        return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
      };

      expect(isValidEmail('test@example.com')).toBe(true);
      expect(isValidEmail('invalid-email')).toBe(false);
      expect(isValidEmail('')).toBe(false);
    });

    test('should validate password strength', () => {
      const isStrongPassword = (password) => {
        return password.length >= 8 && /[A-Z]/.test(password) && /[0-9]/.test(password);
      };

      expect(isStrongPassword('SecurePass123')).toBe(true);
      expect(isStrongPassword('weak')).toBe(false);
      expect(isStrongPassword('alllowercase123')).toBe(false);
    });
  });
});

describe('React Component Tests', () => {
  describe('App Component', () => {
    test('renders without crashing', () => {
      render(<App />);
    });

    test('displays main navigation', () => {
      render(<App />);
      expect(screen.getByRole('navigation')).toBeInTheDocument();
    });

    test('displays application title', () => {
      render(<App />);
      expect(screen.getByText(/react app/i)).toBeInTheDocument();
    });
  });

  describe('Calculator Component', () => {
    test('renders calculator with initial state', () => {
      render(<Calculator />);
      
      expect(screen.getByDisplayValue('0')).toBeInTheDocument();
      expect(screen.getByText('1')).toBeInTheDocument();
      expect(screen.getByText('2')).toBeInTheDocument();
      expect(screen.getByText('+')).toBeInTheDocument();
    });

    test('handles number button clicks', async () => {
      const user = userEvent.setup();
      render(<Calculator />);
      
      await user.click(screen.getByText('1'));
      expect(screen.getByDisplayValue('1')).toBeInTheDocument();
      
      await user.click(screen.getByText('2'));
      expect(screen.getByDisplayValue('12')).toBeInTheDocument();
    });

    test('handles addition operation', async () => {
      const user = userEvent.setup();
      render(<Calculator />);
      
      // Enter first number
      await user.click(screen.getByText('5'));
      
      // Click addition
      await user.click(screen.getByText('+'));
      
      // Enter second number
      await user.click(screen.getByText('3'));
      
      // Click equals
      await user.click(screen.getByText('='));
      
      expect(screen.getByDisplayValue('8')).toBeInTheDocument();
    });

    test('handles clear operation', async () => {
      const user = userEvent.setup();
      render(<Calculator />);
      
      // Enter some numbers
      await user.click(screen.getByText('1'));
      await user.click(screen.getByText('2'));
      
      // Clear
      await user.click(screen.getByText('C'));
      
      expect(screen.getByDisplayValue('0')).toBeInTheDocument();
    });
  });

  describe('UserForm Component', () => {
    test('renders form with all fields', () => {
      render(<UserForm />);
      
      expect(screen.getByLabelText(/name/i)).toBeInTheDocument();
      expect(screen.getByLabelText(/email/i)).toBeInTheDocument();
      expect(screen.getByLabelText(/age/i)).toBeInTheDocument();
      expect(screen.getByRole('button', { name: /submit/i })).toBeInTheDocument();
    });

    test('shows validation errors for empty fields', async () => {
      const user = userEvent.setup();
      render(<UserForm />);
      
      // Submit empty form
      await user.click(screen.getByRole('button', { name: /submit/i }));
      
      expect(screen.getByText(/name is required/i)).toBeInTheDocument();
      expect(screen.getByText(/email is required/i)).toBeInTheDocument();
      expect(screen.getByText(/age is required/i)).toBeInTheDocument();
    });

    test('shows validation error for invalid email', async () => {
      const user = userEvent.setup();
      render(<UserForm />);
      
      // Fill form with invalid email
      await user.type(screen.getByLabelText(/name/i), 'John Doe');
      await user.type(screen.getByLabelText(/email/i), 'invalid-email');
      await user.type(screen.getByLabelText(/age/i), '25');
      
      await user.click(screen.getByRole('button', { name: /submit/i }));
      
      expect(screen.getByText(/please enter a valid email/i)).toBeInTheDocument();
    });

    test('submits form with valid data', async () => {
      const mockSubmit = jest.fn();
      render(<UserForm onSubmit={mockSubmit} />);
      
      const user = userEvent.setup();
      
      // Fill form with valid data
      await user.type(screen.getByLabelText(/name/i), 'John Doe');
      await user.type(screen.getByLabelText(/email/i), 'john@example.com');
      await user.type(screen.getByLabelText(/age/i), '25');
      
      await user.click(screen.getByRole('button', { name: /submit/i }));
      
      expect(mockSubmit).toHaveBeenCalledWith({
        name: 'John Doe',
        email: 'john@example.com',
        age: '25'
      });
    });
  });

  describe('DataList Component', () => {
    const mockData = [
      { id: 1, name: 'Item 1', value: 10 },
      { id: 2, name: 'Item 2', value: 20 },
      { id: 3, name: 'Item 3', value: 30 },
    ];

    test('renders list with data', () => {
      render(<DataList data={mockData} />);
      
      mockData.forEach(item => {
        expect(screen.getByText(item.name)).toBeInTheDocument();
        expect(screen.getByText(item.value.toString())).toBeInTheDocument();
      });
    });

    test('shows empty state when no data', () => {
      render(<DataList data={[]} />);
      
      expect(screen.getByText(/no data available/i)).toBeInTheDocument();
    });

    test('handles item selection', async () => {
      const mockOnSelect = jest.fn();
      render(<DataList data={mockData} onSelect={mockOnSelect} />);
      
      const user = userEvent.setup();
      
      // Click first item
      await user.click(screen.getByText('Item 1'));
      
      expect(mockOnSelect).toHaveBeenCalledWith(mockData[0]);
    });

    test('filters data based on search term', async () => {
      render(<DataList data={mockData} searchable />);
      
      const user = userEvent.setup();
      
      // Search for 'Item 2'
      await user.type(screen.getByPlaceholderText(/search/i), 'Item 2');
      
      expect(screen.getByText('Item 2')).toBeInTheDocument();
      expect(screen.queryByText('Item 1')).not.toBeInTheDocument();
      expect(screen.queryByText('Item 3')).not.toBeInTheDocument();
    });
  });
});

describe('Integration Tests', () => {
  test('complete user workflow', async () => {
    const mockSubmit = jest.fn();
    render(<App />);
    
    const user = userEvent.setup();
    
    // Navigate to user form
    await user.click(screen.getByText(/add user/i));
    
    // Fill user form
    await user.type(screen.getByLabelText(/name/i), 'Test User');
    await user.type(screen.getByLabelText(/email/i), 'test@example.com');
    await user.type(screen.getByLabelText(/age/i), '25');
    
    // Submit form
    await user.click(screen.getByRole('button', { name: /submit/i }));
    
    // Verify user appears in list
    await waitFor(() => {
      expect(screen.getByText('Test User')).toBeInTheDocument();
    });
  });

  test('calculator workflow with multiple operations', async () => {
    render(<Calculator />);
    
    const user = userEvent.setup();
    
    // Perform addition
    await user.click(screen.getByText('5'));
    await user.click(screen.getByText('+'));
    await user.click(screen.getByText('3'));
    await user.click(screen.getByText('='));
    
    expect(screen.getByDisplayValue('8')).toBeInTheDocument();
    
    // Perform multiplication
    await user.click(screen.getByText('C'));
    await user.click(screen.getByText('4'));
    await user.click(screen.getByText('*'));
    await user.click(screen.getByText('6'));
    await user.click(screen.getByText('='));
    
    expect(screen.getByDisplayValue('24')).toBeInTheDocument();
  });
});

// Test Helpers and Utilities
class TestHelpers {
  static createMockUser(overrides = {}) {
    return {
      id: 1,
      name: 'Test User',
      email: 'test@example.com',
      age: 25,
      active: true,
      ...overrides
    };
  }

  static createMockProduct(overrides = {}) {
    return {
      id: 1,
      name: 'Test Product',
      price: 10.99,
      inStock: true,
      category: 'electronics',
      ...overrides
    };
  }

  static async waitForElementToAppear(getElement, timeout = 5000) {
    return waitFor(() => {
      const element = getElement();
      expect(element).toBeInTheDocument();
      return element;
    }, { timeout });
  }

  static async fillForm(formFields, user) {
    for (const [selector, value] of Object.entries(formFields)) {
      const element = screen.getByLabelText(selector);
      await user.clear(element);
      await user.type(element, value);
    }
  }

  static createMockApiResponse(data, status = 'success') {
    return {
      status,
      data,
      timestamp: new Date().toISOString()
    };
  }
}

// Custom Jest Matchers
expect.extend({
  toBeValidEmail(received) {
    const isValid = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(received);
    
    if (isValid) {
      return {
        message: () => `expected ${received} not to be a valid email`,
        pass: true,
      };
    } else {
      return {
        message: () => `expected ${received} to be a valid email`,
        pass: false,
      };
    }
  },

  toBeValidUser(received) {
    const requiredFields = ['id', 'name', 'email', 'age'];
    const missingFields = requiredFields.filter(field => !(field in received));
    
    if (missingFields.length > 0) {
      return {
        message: () => `User is missing required fields: ${missingFields.join(', ')}`,
        pass: false,
      };
    }

    if (!this.toBeValidEmail(received.email)) {
      return {
        message: () => `User email is not valid`,
        pass: false,
      };
    }

    if (typeof received.age !== 'number' || received.age < 18 || received.age > 120) {
      return {
        message: () => `User age must be a number between 18 and 120`,
        pass: false,
      };
    }

    return {
      message: () => `User is valid`,
      pass: true,
    };
  }
});

// Test Configuration
const testConfig = {
  timeout: 5000,
  retries: 3,
  mockApiDelay: 100,
};

// Test Fixtures
const testFixtures = {
  validUser: TestHelpers.createMockUser(),
  invalidUser: {
    name: '',
    email: 'invalid-email',
    age: 15
  },
  sampleProducts: [
    TestHelpers.createMockProduct({ id: 1, name: 'Product 1', price: 10.99 }),
    TestHelpers.createMockProduct({ id: 2, name: 'Product 2', price: 20.50 }),
    TestHelpers.createMockProduct({ id: 3, name: 'Product 3', price: 15.75 })
  ]
};

export { TestHelpers, testConfig, testFixtures };
```

## Guidelines

### Test Organization
- **Unit Tests**: Test utility functions and business logic
- **Component Tests**: Test React components with React Testing Library
- **Integration Tests**: Test user workflows across components
- **Keep Tests Fast**: MVP tests should run in under 30 seconds

### Component Testing Best Practices
- Test from user's perspective using `screen` queries
- Use `userEvent` for realistic user interactions
- Test component behavior, not implementation details
- Use `waitFor` for async operations

### Test Structure
- Use `describe()` blocks to group related tests
- Use descriptive test names explaining the behavior
- Use `render()` from React Testing Library
- Use `expect()` with appropriate matchers

### Coverage Requirements
- **Unit Tests**: 80%+ coverage for business logic
- **Component Tests**: 75%+ coverage for React components
- **Integration Tests**: 60%+ coverage for user workflows
- **Overall**: 75%+ minimum for MVP

## Required Dependencies

Add to `package.json`:

```json
{
  "devDependencies": {
    "@testing-library/react": "^13.4.0",
    "@testing-library/jest-dom": "^5.16.5",
    "@testing-library/user-event": "^14.4.3",
    "jest": "^27.5.1",
    "jest-environment-jsdom": "^27.5.1"
  },
  "scripts": {
    "test": "jest",
    "test:watch": "jest --watch",
    "test:coverage": "jest --coverage --watchAll=false"
  }
}
```

## What's Included

- **Unit Tests**: Business logic, utilities, data validation
- **Component Tests**: React component testing with RTL
- **Integration Tests**: User workflow testing
- **Test Helpers**: Mock data factories and utilities
- **Custom Matchers**: Domain-specific assertions

## What's NOT Included

- Redux/Context API state management tests
- Routing tests (React Router)
- API integration tests with real services
- Performance and accessibility tests

---

**Template Version**: 1.0 (MVP)  
**Last Updated**: 2025-12-10  
**Stack**: React  
**Tier**: MVP  
**Framework**: React Testing Library + Jest
