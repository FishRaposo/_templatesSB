/**
 * Template: comprehensive-tests-react_native.tpl.jsx
 * Purpose: comprehensive-tests-react_native template
 * Stack: react
 * Tier: base
 */

# Universal Template System - Unknown Stack
# Generated: 2025-12-10
# Purpose: Testing utilities
# Tier: core
# Stack: unknown
# Category: testing

# Comprehensive React Testing Template
# Purpose: Core-level testing template with unit, component, integration, and feature tests for React applications
# Usage: Copy to __tests__/ directory and customize for your React project
# Stack: React (.jsx)
# Tier: Core (Production Ready)

## Purpose

Core-level React testing template providing comprehensive testing coverage including unit tests, component tests, integration tests, and feature tests for production-ready applications. Focuses on testing business logic, React components, state management, and complete user features.

## Usage

```bash
# Copy to your React project
cp _templates/tiers/core/tests/comprehensive-tests-react.tpl.jsx src/__tests__/Comprehensive.test.jsx

# Install dependencies
npm install --save-dev @testing-library/react @testing-library/jest-dom @testing-library/user-event @testing-library/react-hooks jest-environment-jsdom

# Run tests
npm test

# Run with coverage
npm run test:coverage

# Run integration tests
npm run test:integration
```

## Structure

```jsx
// src/__tests__/Comprehensive.test.jsx
import React from 'react';
import { render, screen, fireEvent, waitFor, act } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import '@testing-library/jest-dom';
import { BrowserRouter } from 'react-router-dom';
import { Provider } from 'react-redux';
import { configureStore } from '@reduxjs/toolkit';

import App from '../App';
import Calculator from '../components/Calculator';
import UserForm from '../components/UserForm';
import ProductList from '../components/ProductList';
import ShoppingCart from '../components/ShoppingCart';
import UserDashboard from '../components/UserDashboard';
import { userSlice } from '../store/userSlice';
import { productSlice } from '../store/productSlice';
import { cartSlice } from '../store/cartSlice';
import { userService } from '../services/userService';
import { productService } from '../services/productService';
import { authService } from '../services/authService';

// Mock Services
jest.mock('../services/userService');
jest.mock('../services/productService');
jest.mock('../services/authService');

// Test Setup
const createTestStore = (initialState = {}) => {
  return configureStore({
    reducer: {
      user: userSlice.reducer,
      product: productSlice.reducer,
      cart: cartSlice.reducer,
    },
    preloadedState: {
      user: { user: null, loading: false, error: null, ...initialState.user },
      product: { products: [], loading: false, error: null, ...initialState.product },
      cart: { items: [], total: 0, ...initialState.cart },
    },
  });
};

const renderWithProviders = (component, { initialState = {}, store = createTestStore(initialState) } = {}) => {
  const Wrapper = ({ children }) => (
    <Provider store={store}>
      <BrowserRouter>
        {children}
      </BrowserRouter>
    </Provider>
  );
  
  return {
    ...render(component, { wrapper: Wrapper }),
    store,
  };
};

// Test Fixtures
const createMockUser = (overrides = {}) => ({
  id: 1,
  name: 'Test User',
  email: 'test@example.com',
  age: 25,
  active: true,
  createdAt: new Date().toISOString(),
  ...overrides
});

const createMockProduct = (overrides = {}) => ({
  id: 1,
  name: 'Test Product',
  price: 10.99,
  quantity: 100,
  category: 'electronics',
  description: 'Test product description',
  image: 'https://example.com/product.jpg',
  ...overrides
});

const createMockCartItem = (product, quantity = 1) => ({
  id: product.id,
  name: product.name,
  price: product.price,
  quantity,
  total: product.price * quantity,
});

// Unit Tests - Business Logic
describe('Business Logic Tests', () => {
  describe('Calculator Logic', () => {
    test('should perform basic arithmetic operations', () => {
      const add = (a, b) => a + b;
      const subtract = (a, b) => a - b;
      const multiply = (a, b) => a * b;
      const divide = (a, b) => {
        if (b === 0) throw new Error('Cannot divide by zero');
        return a / b;
      };

      expect(add(2, 3)).toBe(5);
      expect(subtract(10, 3)).toBe(7);
      expect(multiply(4, 5)).toBe(20);
      expect(divide(20, 4)).toBe(5);
      expect(() => divide(10, 0)).toThrow('Cannot divide by zero');
    });

    test('should handle calculator state transitions', () => {
      const calculatorState = {
        display: '0',
        previousValue: null,
        operation: null,
        waitingForNewValue: false,
      };

      const inputNumber = (state, number) => {
        if (state.waitingForNewValue) {
          return { ...state, display: String(number), waitingForNewValue: false };
        }
        return {
          ...state,
          display: state.display === '0' ? String(number) : state.display + number,
        };
      };

      const inputOperation = (state, operation) => ({
        ...state,
        previousValue: parseFloat(state.display),
        operation,
        waitingForNewValue: true,
      });

      let state = calculatorState;
      state = inputNumber(state, 1);
      expect(state.display).toBe('1');
      
      state = inputNumber(state, 2);
      expect(state.display).toBe('12');
      
      state = inputOperation(state, '+');
      expect(state.previousValue).toBe(12);
      expect(state.operation).toBe('+');
      expect(state.waitingForNewValue).toBe(true);
    });
  });

  describe('Data Validation', () => {
    test('should validate email format', () => {
      const isValidEmail = (email) => {
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        return emailRegex.test(email);
      };

      expect(isValidEmail('test@example.com')).toBe(true);
      expect(isValidEmail('user.name@domain.co.uk')).toBe(true);
      expect(isValidEmail('test+tag@example.org')).toBe(true);
      expect(isValidEmail('invalid-email')).toBe(false);
      expect(isValidEmail('@example.com')).toBe(false);
      expect(isValidEmail('test@')).toBe(false);
    });

    test('should validate password strength', () => {
      const isStrongPassword = (password) => {
        return password.length >= 8 && 
               /[A-Z]/.test(password) && 
               /[a-z]/.test(password) && 
               /[0-9]/.test(password);
      };

      expect(isStrongPassword('SecurePass123')).toBe(true);
      expect(isStrongPassword('MyPassword1')).toBe(true);
      expect(isStrongPassword('weak')).toBe(false);
      expect(isStrongPassword('alllowercase123')).toBe(false);
      expect(isStrongPassword('ALLUPPERCASE123')).toBe(false);
      expect(isStrongPassword('NoNumbersHere')).toBe(false);
    });

    test('should validate user age', () => {
      const isValidAge = (age) => {
        const ageNum = parseInt(age);
        return !isNaN(ageNum) && ageNum >= 18 && ageNum <= 120;
      };

      expect(isValidAge(25)).toBe(true);
      expect(isValidAge('30')).toBe(true);
      expect(isValidAge(17)).toBe(false);
      expect(isValidAge(121)).toBe(false);
      expect(isValidAge('invalid')).toBe(false);
    });
  });

  describe('Price Calculations', () => {
    test('should calculate cart totals correctly', () => {
      const items = [
        { price: 10.99, quantity: 2 },
        { price: 20.50, quantity: 1 },
        { price: 15.75, quantity: 3 },
      ];

      const calculateTotal = (items) => {
        return items.reduce((total, item) => total + (item.price * item.quantity), 0);
      };

      const calculateSubtotal = (items) => calculateTotal(items);
      const calculateTax = (subtotal, taxRate = 0.08) => subtotal * taxRate;
      const calculateGrandTotal = (subtotal, tax) => subtotal + tax;

      const subtotal = calculateSubtotal(items);
      const tax = calculateTax(subtotal);
      const grandTotal = calculateGrandTotal(subtotal, tax);

      expect(subtotal).toBe(78.32); // 2*10.99 + 1*20.50 + 3*15.75
      expect(tax).toBeCloseTo(6.27, 2);
      expect(grandTotal).toBeCloseTo(84.59, 2);
    });

    test('should apply discounts correctly', () => {
      const applyDiscount = (total, discountPercentage) => {
        return total * (1 - discountPercentage / 100);
      };

      const total = 100;
      expect(applyDiscount(total, 10)).toBe(90);
      expect(applyDiscount(total, 25)).toBe(75);
      expect(applyDiscount(total, 0)).toBe(100);
      expect(applyDiscount(total, 100)).toBe(0);
    });
  });
});

// Component Tests - React Components
describe('React Component Tests', () => {
  describe('Calculator Component', () => {
    test('renders calculator with initial state', () => {
      render(<Calculator />);
      
      expect(screen.getByDisplayValue('0')).toBeInTheDocument();
      expect(screen.getByText('1')).toBeInTheDocument();
      expect(screen.getByText('2')).toBeInTheDocument();
      expect(screen.getByText('+')).toBeInTheDocument();
      expect(screen.getByText('=')).toBeInTheDocument();
      expect(screen.getByText('C')).toBeInTheDocument();
    });

    test('handles number button clicks', async () => {
      const user = userEvent.setup();
      render(<Calculator />);
      
      await user.click(screen.getByText('1'));
      expect(screen.getByDisplayValue('1')).toBeInTheDocument();
      
      await user.click(screen.getByText('2'));
      expect(screen.getByDisplayValue('12')).toBeInTheDocument();
    });

    test('handles arithmetic operations', async () => {
      const user = userEvent.setup();
      render(<Calculator />);
      
      // Addition: 5 + 3 = 8
      await user.click(screen.getByText('5'));
      await user.click(screen.getByText('+'));
      await user.click(screen.getByText('3'));
      await user.click(screen.getByText('='));
      
      expect(screen.getByDisplayValue('8')).toBeInTheDocument();
    });

    test('handles clear operation', async () => {
      const user = userEvent.setup();
      render(<Calculator />);
      
      await user.click(screen.getByText('1'));
      await user.click(screen.getByText('2'));
      expect(screen.getByDisplayValue('12')).toBeInTheDocument();
      
      await user.click(screen.getByText('C'));
      expect(screen.getByDisplayValue('0')).toBeInTheDocument();
    });

    test('handles decimal numbers', async () => {
      const user = userEvent.setup();
      render(<Calculator />);
      
      await user.click(screen.getByText('5'));
      await user.click(screen.getByText('.'));
      await user.click(screen.getByText('5'));
      
      expect(screen.getByDisplayValue('5.5')).toBeInTheDocument();
    });

    test('handles keyboard input', () => {
      render(<Calculator />);
      
      fireEvent.keyDown(screen.getByTestId('calculator'), { key: '1' });
      expect(screen.getByDisplayValue('1')).toBeInTheDocument();
      
      fireEvent.keyDown(screen.getByTestId('calculator'), { key: '+' });
      fireEvent.keyDown(screen.getByTestId('calculator'), { key: '2' });
      fireEvent.keyDown(screen.getByTestId('calculator'), { key: '=' });
      
      expect(screen.getByDisplayValue('3')).toBeInTheDocument();
    });
  });

  describe('UserForm Component', () => {
    test('renders form with all fields', () => {
      const mockOnSubmit = jest.fn();
      render(<UserForm onSubmit={mockOnSubmit} />);
      
      expect(screen.getByLabelText(/name/i)).toBeInTheDocument();
      expect(screen.getByLabelText(/email/i)).toBeInTheDocument();
      expect(screen.getByLabelText(/age/i)).toBeInTheDocument();
      expect(screen.getByLabelText(/^password/i)).toBeInTheDocument();
      expect(screen.getByLabelText(/confirm password/i)).toBeInTheDocument();
      expect(screen.getByRole('button', { name: /submit/i })).toBeInTheDocument();
    });

    test('shows validation errors for empty fields', async () => {
      const mockOnSubmit = jest.fn();
      const user = userEvent.setup();
      render(<UserForm onSubmit={mockOnSubmit} />);
      
      await user.click(screen.getByRole('button', { name: /submit/i }));
      
      expect(screen.getByText(/name is required/i)).toBeInTheDocument();
      expect(screen.getByText(/email is required/i)).toBeInTheDocument();
      expect(screen.getByText(/age is required/i)).toBeInTheDocument();
      expect(screen.getByText(/password is required/i)).toBeInTheDocument();
      expect(mockOnSubmit).not.toHaveBeenCalled();
    });

    test('validates email format', async () => {
      const mockOnSubmit = jest.fn();
      const user = userEvent.setup();
      render(<UserForm onSubmit={mockOnSubmit} />);
      
      await user.type(screen.getByLabelText(/name/i), 'Test User');
      await user.type(screen.getByLabelText(/email/i), 'invalid-email');
      await user.type(screen.getByLabelText(/age/i), '25');
      await user.type(screen.getByLabelText(/^password/i), 'SecurePass123');
      await user.type(screen.getByLabelText(/confirm password/i), 'SecurePass123');
      
      await user.click(screen.getByRole('button', { name: /submit/i }));
      
      expect(screen.getByText(/please enter a valid email/i)).toBeInTheDocument();
      expect(mockOnSubmit).not.toHaveBeenCalled();
    });

    test('validates password strength', async () => {
      const mockOnSubmit = jest.fn();
      const user = userEvent.setup();
      render(<UserForm onSubmit={mockOnSubmit} />);
      
      await user.type(screen.getByLabelText(/name/i), 'Test User');
      await user.type(screen.getByLabelText(/email/i), 'test@example.com');
      await user.type(screen.getByLabelText(/age/i), '25');
      await user.type(screen.getByLabelText(/^password/i), 'weak');
      await user.type(screen.getByLabelText(/confirm password/i), 'weak');
      
      await user.click(screen.getByRole('button', { name: /submit/i }));
      
      expect(screen.getByText(/password is too weak/i)).toBeInTheDocument();
      expect(mockOnSubmit).not.toHaveBeenCalled();
    });

    test('validates password confirmation', async () => {
      const mockOnSubmit = jest.fn();
      const user = userEvent.setup();
      render(<UserForm onSubmit={mockOnSubmit} />);
      
      await user.type(screen.getByLabelText(/name/i), 'Test User');
      await user.type(screen.getByLabelText(/email/i), 'test@example.com');
      await user.type(screen.getByLabelText(/age/i), '25');
      await user.type(screen.getByLabelText(/^password/i), 'SecurePass123');
      await user.type(screen.getByLabelText(/confirm password/i), 'DifferentPass123');
      
      await user.click(screen.getByRole('button', { name: /submit/i }));
      
      expect(screen.getByText(/passwords do not match/i)).toBeInTheDocument();
      expect(mockOnSubmit).not.toHaveBeenCalled();
    });

    test('submits form with valid data', async () => {
      const mockOnSubmit = jest.fn();
      const user = userEvent.setup();
      render(<UserForm onSubmit={mockOnSubmit} />);
      
      const userData = {
        name: 'Test User',
        email: 'test@example.com',
        age: '25',
        password: 'SecurePass123',
        confirmPassword: 'SecurePass123',
      };
      
      await user.type(screen.getByLabelText(/name/i), userData.name);
      await user.type(screen.getByLabelText(/email/i), userData.email);
      await user.type(screen.getByLabelText(/age/i), userData.age);
      await user.type(screen.getByLabelText(/^password/i), userData.password);
      await user.type(screen.getByLabelText(/confirm password/i), userData.confirmPassword);
      
      await user.click(screen.getByRole('button', { name: /submit/i }));
      
      expect(mockOnSubmit).toHaveBeenCalledWith({
        name: userData.name,
        email: userData.email,
        age: 25,
        password: userData.password,
      });
    });

    test('shows loading state during submission', async () => {
      const mockOnSubmit = jest.fn(() => new Promise(resolve => setTimeout(resolve, 1000)));
      const user = userEvent.setup();
      render(<UserForm onSubmit={mockOnSubmit} loading={true} />);
      
      // Fill form with valid data
      await user.type(screen.getByLabelText(/name/i), 'Test User');
      await user.type(screen.getByLabelText(/email/i), 'test@example.com');
      await user.type(screen.getByLabelText(/age/i), '25');
      await user.type(screen.getByLabelText(/^password/i), 'SecurePass123');
      await user.type(screen.getByLabelText(/confirm password/i), 'SecurePass123');
      
      await user.click(screen.getByRole('button', { name: /submit/i }));
      
      expect(screen.getByTestId('loading-spinner')).toBeInTheDocument();
      expect(screen.getByRole('button', { name: /submit/i })).toBeDisabled();
    });
  });

  describe('ProductList Component', () => {
    const mockProducts = [
      createMockProduct({ id: 1, name: 'Product 1', price: 10.99, quantity: 5 }),
      createMockProduct({ id: 2, name: 'Product 2', price: 20.50, quantity: 10 }),
      createMockProduct({ id: 3, name: 'Product 3', price: 15.75, quantity: 0 }),
    ];

    test('renders list of products', () => {
      const mockOnProductSelect = jest.fn();
      render(<ProductList products={mockProducts} onProductSelect={mockOnProductSelect} />);
      
      mockProducts.forEach(product => {
        expect(screen.getByText(product.name)).toBeInTheDocument();
        expect(screen.getByText(`$${product.price}`)).toBeInTheDocument();
      });
    });

    test('shows out of stock indicator', () => {
      const mockOnProductSelect = jest.fn();
      render(<ProductList products={mockProducts} onProductSelect={mockOnProductSelect} />);
      
      expect(screen.getByText('Out of Stock')).toBeInTheDocument();
    });

    test('handles product selection', async () => {
      const mockOnProductSelect = jest.fn();
      const user = userEvent.setup();
      render(<ProductList products={mockProducts} onProductSelect={mockOnProductSelect} />);
      
      await user.click(screen.getByText('Product 1'));
      
      expect(mockOnProductSelect).toHaveBeenCalledWith(mockProducts[0]);
    });

    test('filters products by search term', async () => {
      const mockOnProductSelect = jest.fn();
      const user = userEvent.setup();
      render(<ProductList products={mockProducts} onProductSelect={mockOnProductSelect} searchable />);
      
      await user.type(screen.getByPlaceholderText(/search products/i), 'Product 1');
      
      expect(screen.getByText('Product 1')).toBeInTheDocument();
      expect(screen.queryByText('Product 2')).not.toBeInTheDocument();
      expect(screen.queryByText('Product 3')).not.toBeInTheDocument();
    });

    test('sorts products by price', async () => {
      const mockOnProductSelect = jest.fn();
      const user = userEvent.setup();
      render(<ProductList products={mockProducts} onProductSelect={mockOnProductSelect} sortable />);
      
      // Sort by price (low to high)
      await user.selectOptions(screen.getByLabelText(/sort by/i), 'Price: Low to High');
      
      const productNames = screen.getAllByTestId('product-name').map(el => el.textContent);
      expect(productNames).toEqual(['Product 1', 'Product 3', 'Product 2']);
    });

    test('handles add to cart action', async () => {
      const mockOnAddToCart = jest.fn();
      const user = userEvent.setup();
      render(<ProductList products={mockProducts} onProductSelect={jest.fn()} onAddToCart={mockOnAddToCart} />);
      
      await user.click(screen.getByTestId(`add-to-cart-${mockProducts[0].id}`));
      
      expect(mockOnAddToCart).toHaveBeenCalledWith(mockProducts[0], 1);
    });
  });

  describe('ShoppingCart Component', () => {
    const mockCartItems = [
      createMockCartItem(createMockProduct({ id: 1, name: 'Product 1', price: 10.99 }), 2),
      createMockCartItem(createMockProduct({ id: 2, name: 'Product 2', price: 20.50 }), 1),
    ];

    test('renders cart with items and totals', () => {
      const mockOnUpdateQuantity = jest.fn();
      const mockOnRemoveItem = jest.fn();
      
      render(
        <ShoppingCart 
          items={mockCartItems} 
          onUpdateQuantity={mockOnUpdateQuantity}
          onRemoveItem={mockOnRemoveItem}
        />
      );
      
      expect(screen.getByText('Product 1')).toBeInTheDocument();
      expect(screen.getByText('Product 2')).toBeInTheDocument();
      expect(screen.getByText('$42.48')).toBeInTheDocument(); // Subtotal
      expect(screen.getByText('$3.40')).toBeInTheDocument(); // Tax (8%)
      expect(screen.getByText('$45.88')).toBeInTheDocument(); // Total
    });

    test('shows empty cart message', () => {
      const mockOnUpdateQuantity = jest.fn();
      const mockOnRemoveItem = jest.fn();
      
      render(
        <ShoppingCart 
          items={[]} 
          onUpdateQuantity={mockOnUpdateQuantity}
          onRemoveItem={mockOnRemoveItem}
        />
      );
      
      expect(screen.getByText(/your cart is empty/i)).toBeInTheDocument();
    });

    test('handles quantity update', async () => {
      const mockOnUpdateQuantity = jest.fn();
      const user = userEvent.setup();
      
      render(
        <ShoppingCart 
          items={mockCartItems} 
          onUpdateQuantity={mockOnUpdateQuantity}
          onRemoveItem={jest.fn()}
        />
      );
      
      const quantityInput = screen.getByTestId(`quantity-${mockCartItems[0].id}`);
      await user.clear(quantityInput);
      await user.type(quantityInput, '5');
      
      expect(mockOnUpdateQuantity).toHaveBeenCalledWith(mockCartItems[0].id, 5);
    });

    test('handles item removal', async () => {
      const mockOnRemoveItem = jest.fn();
      const user = userEvent.setup();
      
      render(
        <ShoppingCart 
          items={mockCartItems} 
          onUpdateQuantity={jest.fn()}
          onRemoveItem={mockOnRemoveItem}
        />
      );
      
      await user.click(screen.getByTestId(`remove-${mockCartItems[0].id}`));
      
      expect(mockOnRemoveItem).toHaveBeenCalledWith(mockCartItems[0].id);
    });
  });

  describe('UserDashboard Component', () => {
    const mockUser = createMockUser();
    const mockStats = {
      totalOrders: 5,
      totalSpent: 250.75,
      averageOrderValue: 50.15,
    };
    const mockRecentOrders = [
      { id: 1, date: '2023-12-01', total: 50.99, status: 'completed' },
      { id: 2, date: '2023-11-28', total: 75.50, status: 'completed' },
    ];

    test('renders dashboard with user info and stats', () => {
      render(<UserDashboard user={mockUser} stats={mockStats} recentOrders={mockRecentOrders} />);
      
      expect(screen.getByText(mockUser.name)).toBeInTheDocument();
      expect(screen.getByText(mockUser.email)).toBeInTheDocument();
      expect(screen.getByText('5')).toBeInTheDocument(); // Total orders
      expect(screen.getByText('$250.75')).toBeInTheDocument(); // Total spent
      expect(screen.getByText('$50.15')).toBeInTheDocument(); // Average order value
    });

    test('displays recent orders', () => {
      render(<UserDashboard user={mockUser} stats={mockStats} recentOrders={mockRecentOrders} />);
      
      mockRecentOrders.forEach(order => {
        expect(screen.getByText(`Order #${order.id}`)).toBeInTheDocument();
        expect(screen.getByText(`$${order.total}`)).toBeInTheDocument();
        expect(screen.getByText(order.status)).toBeInTheDocument();
      });
    });

    test('shows empty state for new user', () => {
      const emptyStats = { totalOrders: 0, totalSpent: 0, averageOrderValue: 0 };
      
      render(<UserDashboard user={mockUser} stats={emptyStats} recentOrders={[]} />);
      
      expect(screen.getByText(/welcome to your dashboard/i)).toBeInTheDocument();
      expect(screen.getByText(/you haven't placed any orders yet/i)).toBeInTheDocument();
    });
  });
});

// Integration Tests - Component Interactions
describe('Integration Tests', () => {
  test('complete user registration flow', async () => {
    const mockRegister = jest.fn().mockResolvedValue(createMockUser());
    userService.register = mockRegister;
    
    const { store } = renderWithProviders(<UserForm onSubmit={userService.register} />);
    
    const user = userEvent.setup();
    
    // Fill registration form
    await user.type(screen.getByLabelText(/name/i), 'John Doe');
    await user.type(screen.getByLabelText(/email/i), 'john@example.com');
    await user.type(screen.getByLabelText(/age/i), '25');
    await user.type(screen.getByLabelText(/^password/i), 'SecurePass123');
    await user.type(screen.getByLabelText(/confirm password/i), 'SecurePass123');
    
    // Submit form
    await user.click(screen.getByRole('button', { name: /submit/i }));
    
    // Wait for async operation
    await waitFor(() => {
      expect(mockRegister).toHaveBeenCalledWith({
        name: 'John Doe',
        email: 'john@example.com',
        age: 25,
        password: 'SecurePass123',
      });
    });
    
    // Check Redux store was updated
    const state = store.getState();
    expect(state.user.user).toBeDefined();
    expect(state.user.user.name).toBe('John Doe');
  });

  test('product browsing and cart management flow', async () => {
    const mockProducts = [
      createMockProduct({ id: 1, name: 'Product 1', price: 10.99 }),
      createMockProduct({ id: 2, name: 'Product 2', price: 20.50 }),
    ];
    
    const { store } = renderWithProviders(
      <>
        <ProductList products={mockProducts} />
        <ShoppingCart />
      </>
    );
    
    const user = userEvent.setup();
    
    // Add first product to cart
    await user.click(screen.getByTestId(`add-to-cart-${mockProducts[0].id}`));
    
    // Check cart was updated
    let state = store.getState();
    expect(state.cart.items).toHaveLength(1);
    expect(state.cart.items[0].name).toBe('Product 1');
    
    // Add second product to cart
    await user.click(screen.getByTestId(`add-to-cart-${mockProducts[1].id}`));
    
    // Check cart has both items
    state = store.getState();
    expect(state.cart.items).toHaveLength(2);
    expect(state.cart.total).toBe(31.49); // 10.99 + 20.50
    
    // Update quantity
    const quantityInput = screen.getByTestId(`quantity-${mockProducts[0].id}`);
    await user.clear(quantityInput);
    await user.type(quantityInput, '3');
    
    // Check cart total was updated
    state = store.getState();
    expect(state.cart.items[0].quantity).toBe(3);
    expect(state.cart.total).toBe(53.47); // 3*10.99 + 1*20.50
  });

  test('authentication flow with protected routes', async () => {
    const mockSignIn = jest.fn().mockResolvedValue({
      user: createMockUser(),
      token: 'mock-jwt-token',
    });
    authService.signIn = mockSignIn;
    
    const { store } = renderWithProviders(<App />);
    
    const user = userEvent.setup();
    
    // Try to access protected route
    await user.click(screen.getByText(/dashboard/i));
    
    // Should redirect to login
    expect(screen.getByText(/sign in/i)).toBeInTheDocument();
    
    // Fill login form
    await user.type(screen.getByLabelText(/email/i), 'test@example.com');
    await user.type(screen.getByLabelText(/password/i), 'password123');
    
    // Submit login
    await user.click(screen.getByRole('button', { name: /sign in/i }));
    
    // Wait for authentication
    await waitFor(() => {
      expect(mockSignIn).toHaveBeenCalledWith('test@example.com', 'password123');
    });
    
    // Should now be able to access dashboard
    expect(screen.getByText(/welcome back/i)).toBeInTheDocument();
  });
});

// Feature Tests - Complete User Workflows
describe('Feature Tests', () => {
  test('complete e-commerce purchase workflow', async () => {
    const mockProducts = [
      createMockProduct({ id: 1, name: 'Product 1', price: 10.99 }),
      createMockProduct({ id: 2, name: 'Product 2', price: 20.50 }),
    ];
    
    const mockUser = createMockUser();
    const mockCreateOrder = jest.fn().mockResolvedValue({
      id: 'order-123',
      items: mockProducts,
      total: 31.49,
      status: 'completed',
    });
    
    userService.createOrder = mockCreateOrder;
    
    const { store } = renderWithProviders(<App />, {
      initialState: {
        user: { user: mockUser },
        product: { products: mockProducts },
      },
    });
    
    const user = userEvent.setup();
    
    // Browse products
    expect(screen.getByText('Product 1')).toBeInTheDocument();
    expect(screen.getByText('Product 2')).toBeInTheDocument();
    
    // Add products to cart
    await user.click(screen.getByTestId(`add-to-cart-${mockProducts[0].id}`));
    await user.click(screen.getByTestId(`add-to-cart-${mockProducts[1].id}`));
    
    // Navigate to cart
    await user.click(screen.getByText(/cart/i));
    
    // Verify cart contents
    expect(screen.getByText('Product 1')).toBeInTheDocument();
    expect(screen.getByText('Product 2')).toBeInTheDocument();
    expect(screen.getByText('$31.49')).toBeInTheDocument();
    
    // Proceed to checkout
    await user.click(screen.getByRole('button', { name: /checkout/i }));
    
    // Fill shipping information
    await user.type(screen.getByLabelText(/address/i), '123 Main St');
    await user.type(screen.getByLabelText(/city/i), 'Test City');
    await user.type(screen.getByLabelText(/zip code/i), '12345');
    
    // Fill payment information
    await user.type(screen.getByLabelText(/card number/i), '4111111111111111');
    await user.type(screen.getByLabelText(/expiry/i), '12/25');
    await user.type(screen.getByLabelText(/cvv/i), '123');
    
    // Complete purchase
    await user.click(screen.getByRole('button', { name: /complete purchase/i }));
    
    // Wait for order creation
    await waitFor(() => {
      expect(mockCreateOrder).toHaveBeenCalled();
    });
    
    // Verify order confirmation
    expect(screen.getByText(/order confirmed/i)).toBeInTheDocument();
    expect(screen.getByText('order-123')).toBeInTheDocument();
    expect(screen.getByText('$31.49')).toBeInTheDocument();
  });

  test('user profile management workflow', async () => {
    const mockUser = createMockUser();
    const mockUpdateProfile = jest.fn().mockResolvedValue({
      ...mockUser,
      name: 'Updated Name',
      age: 26,
    });
    
    userService.updateProfile = mockUpdateProfile;
    
    const { store } = renderWithProviders(<App />, {
      initialState: {
        user: { user: mockUser },
      },
    });
    
    const user = userEvent.setup();
    
    // Navigate to profile
    await user.click(screen.getByText(/profile/i));
    
    // Verify current profile information
    expect(screen.getByDisplayValue(mockUser.name)).toBeInTheDocument();
    expect(screen.getByDisplayValue(mockUser.email)).toBeInTheDocument();
    expect(screen.getByDisplayValue(String(mockUser.age))).toBeInTheDocument();
    
    // Update profile information
    await user.clear(screen.getByLabelText(/name/i));
    await user.type(screen.getByLabelText(/name/i), 'Updated Name');
    
    await user.clear(screen.getByLabelText(/age/i));
    await user.type(screen.getByLabelText(/age/i), '26');
    
    // Save changes
    await user.click(screen.getByRole('button', { name: /save changes/i }));
    
    // Wait for update
    await waitFor(() => {
      expect(mockUpdateProfile).toHaveBeenCalledWith({
        name: 'Updated Name',
        age: 26,
      });
    });
    
    // Verify updated information
    expect(screen.getByDisplayValue('Updated Name')).toBeInTheDocument();
    expect(screen.getByDisplayValue('26')).toBeInTheDocument();
    
    // Check success message
    expect(screen.getByText(/profile updated successfully/i)).toBeInTheDocument();
  });

  test('product search and filter workflow', async () => {
    const mockProducts = [
      createMockProduct({ id: 1, name: 'iPhone 13', price: 999.99, category: 'electronics' }),
      createMockProduct({ id: 2, name: 'Samsung TV', price: 799.99, category: 'electronics' }),
      createMockProduct({ id: 3, name: 'Programming Book', price: 29.99, category: 'books' }),
      createMockProduct({ id: 4, name: 'iPhone 14', price: 1099.99, category: 'electronics' }),
      createMockProduct({ id: 5, name: 'JavaScript Guide', price: 39.99, category: 'books' }),
    ];
    
    const { store } = renderWithProviders(<App />, {
      initialState: {
        product: { products: mockProducts },
      },
    });
    
    const user = userEvent.setup();
    
    // Verify all products are shown
    expect(screen.getAllByTestId('product-card')).toHaveLength(5);
    
    // Search for 'iPhone'
    await user.type(screen.getByPlaceholderText(/search products/i), 'iPhone');
    
    // Should show only iPhone products
    expect(screen.getAllByTestId('product-card')).toHaveLength(2);
    expect(screen.getByText('iPhone 13')).toBeInTheDocument();
    expect(screen.getByText('iPhone 14')).toBeInTheDocument();
    expect(screen.queryByText('Samsung TV')).not.toBeInTheDocument();
    
    // Filter by category
    await user.clear(screen.getByPlaceholderText(/search products/i));
    await user.selectOptions(screen.getByLabelText(/category/i), 'books');
    
    // Should show only books
    expect(screen.getAllByTestId('product-card')).toHaveLength(2);
    expect(screen.getByText('Programming Book')).toBeInTheDocument();
    expect(screen.getByText('JavaScript Guide')).toBeInTheDocument();
    
    // Sort by price (high to low)
    await user.selectOptions(screen.getByLabelText(/sort by/i), 'Price: High to Low');
    
    const productNames = screen.getAllByTestId('product-name').map(el => el.textContent);
    expect(productNames).toEqual(['JavaScript Guide', 'Programming Book']);
  });
});

// Performance Tests
describe('Performance Tests', () => {
  test('renders large product list efficiently', async () => {
    const largeProductList = Array.from({ length: 1000 }, (_, i) => 
      createMockProduct({ id: i, name: `Product ${i}`, price: 10.99 + i })
    );
    
    const startTime = performance.now();
    
    render(<ProductList products={largeProductList} />);
    
    const renderTime = performance.now() - startTime;
    
    // Should render within 100ms
    expect(renderTime).toBeLessThan(100);
    expect(screen.getAllByTestId('product-card')).toHaveLength(1000);
  });

  test('handles rapid state updates efficiently', async () => {
    const { store } = renderWithProviders(<ShoppingCart />);
    
    const startTime = performance.now();
    
    // Add 100 items to cart rapidly
    for (let i = 0; i < 100; i++) {
      act(() => {
        store.dispatch(cartSlice.actions.addItem({
          id: i,
          name: `Product ${i}`,
          price: 10.99,
          quantity: 1,
          total: 10.99,
        }));
      });
    }
    
    const updateTime = performance.now() - startTime;
    
    // Should update within 50ms
    expect(updateTime).toBeLessThan(50);
    
    const state = store.getState();
    expect(state.cart.items).toHaveLength(100);
  });
});

// Test Utilities and Helpers
class TestHelpers {
  static createMockUser(overrides = {}) {
    return {
      id: 1,
      name: 'Test User',
      email: 'test@example.com',
      age: 25,
      active: true,
      createdAt: new Date().toISOString(),
      ...overrides
    };
  }

  static createMockProduct(overrides = {}) {
    return {
      id: 1,
      name: 'Test Product',
      price: 10.99,
      quantity: 100,
      category: 'electronics',
      description: 'Test product description',
      image: 'https://example.com/product.jpg',
      ...overrides
    };
  }

  static createMockCartItem(product, quantity = 1) {
    return {
      id: product.id,
      name: product.name,
      price: product.price,
      quantity,
      total: product.price * quantity,
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
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    const isValid = emailRegex.test(received);
    
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
  performance: {
    maxRenderTime: 100,
    maxUpdateTime: 50,
  }
};

export { TestHelpers, testConfig };
```

## Guidelines

### Test Organization
- **Unit Tests**: Business logic, utilities, data validation
- **Component Tests**: React component testing with RTL
- **Integration Tests**: Component interactions and state management
- **Feature Tests**: Complete user workflows
- **Performance Tests**: Rendering and state update efficiency

### Component Testing Best Practices
- Test from user's perspective using `screen` queries
- Use `userEvent` for realistic user interactions
- Test component behavior, not implementation details
- Use Redux test utilities for state management testing

### Test Structure
- Use `describe()` blocks to organize tests by feature
- Use descriptive test names explaining user behavior
- Mock external dependencies with Jest
- Test both success and error paths

### Coverage Requirements
- **Unit Tests**: 85%+ coverage for business logic
- **Component Tests**: 80%+ coverage for React components
- **Integration Tests**: 70%+ coverage for component interactions
- **Overall**: 80%+ minimum for Core tier

## Required Dependencies

Add to `package.json`:

```json
{
  "devDependencies": {
    "@testing-library/react": "^13.4.0",
    "@testing-library/jest-dom": "^5.16.5",
    "@testing-library/user-event": "^14.4.3",
    "@testing-library/react-hooks": "^8.0.1",
    "jest": "^27.5.1",
    "jest-environment-jsdom": "^27.5.1"
  },
  "scripts": {
    "test": "jest",
    "test:watch": "jest --watch",
    "test:coverage": "jest --coverage --watchAll=false",
    "test:integration": "jest --testPathPattern=integration"
  }
}
```

## What's Included

- **Unit Tests**: Business logic, utilities, data validation
- **Component Tests**: React component testing with RTL and Redux
- **Integration Tests**: Component interactions and state management
- **Feature Tests**: Complete e-commerce workflows
- **Performance Tests**: Rendering and state update efficiency
- **Test Helpers**: Mock data factories and utilities

## What's NOT Included

- Visual regression tests
- Accessibility tests
- Cross-browser compatibility tests
- Network condition simulation

---

**Template Version**: 2.0 (Core)  
**Last Updated**: 2025-12-10  
**Stack**: React  
**Tier**: Core  
**Framework**: React Testing Library + Jest + Redux
