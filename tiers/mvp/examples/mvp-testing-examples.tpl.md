<!--
File: mvp-testing-examples.tpl.md
Purpose: Template for unknown implementation
Template Version: 1.0
-->

# MVP Tier Testing Examples
# Purpose: Concrete examples of MVP-level testing patterns
# Tier: MVP (Minimum Viable Product)
# Coverage Target: 70%

## Overview

MVP tier focuses on essential testing patterns that provide confidence in core functionality without enterprise overhead. Tests should be simple, fast, and focused on business logic validation.

## Go MVP Testing Examples

### Basic Unit Test Structure
```go
package user

import (
    "testing"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
)

func TestUser_CreateUser(t *testing.T) {
    // Arrange
    userService := NewUserService()
    input := CreateUserInput{
        Name:  "John Doe",
        Email: "john@example.com",
    }
    
    // Act
    user, err := userService.CreateUser(input)
    
    // Assert
    require.NoError(t, err)
    assert.NotEmpty(t, user.ID)
    assert.Equal(t, input.Name, user.Name)
    assert.Equal(t, input.Email, user.Email)
    assert.NotZero(t, user.CreatedAt)
}

func TestUser_CreateUser_InvalidEmail(t *testing.T) {
    // Arrange
    userService := NewUserService()
    input := CreateUserInput{
        Name:  "John Doe",
        Email: "invalid-email",
    }
    
    // Act
    user, err := userService.CreateUser(input)
    
    // Assert
    assert.Error(t, err)
    assert.Nil(t, user)
    assert.Contains(t, err.Error(), "invalid email")
}

func TestUser_GetUser(t *testing.T) {
    // Arrange
    userService := NewUserService()
    createdUser, _ := userService.CreateUser(CreateUserInput{
        Name:  "Jane Doe",
        Email: "jane@example.com",
    })
    
    // Act
    user, err := userService.GetUser(createdUser.ID)
    
    // Assert
    require.NoError(t, err)
    assert.Equal(t, createdUser.ID, user.ID)
    assert.Equal(t, createdUser.Name, user.Name)
}
```

### Simple Business Logic Test
```go
package order

import (
    "testing"
    "github.com/stretchr/testify/assert"
)

func TestOrder_CalculateTotal(t *testing.T) {
    // Arrange
    order := &Order{
        Items: []OrderItem{
            {Name: "Product A", Price: 10.00, Quantity: 2},
            {Name: "Product B", Price: 5.00, Quantity: 3},
        },
        Tax: 0.08,
    }
    
    // Act
    total := order.CalculateTotal()
    
    // Assert
    expected := (10.00*2 + 5.00*3) * 1.08 // Items + tax
    assert.Equal(t, expected, total)
}

func TestOrder_IsEmpty_True(t *testing.T) {
    // Arrange
    order := &Order{Items: []OrderItem{}}
    
    // Act
    isEmpty := order.IsEmpty()
    
    // Assert
    assert.True(t, isEmpty)
}

func TestOrder_IsEmpty_False(t *testing.T) {
    // Arrange
    order := &Order{
        Items: []OrderItem{{Name: "Product A", Price: 10.00, Quantity: 1}},
    }
    
    // Act
    isEmpty := order.IsEmpty()
    
    // Assert
    assert.False(t, isEmpty)
}
```

## Python MVP Testing Examples

### Basic Unit Test with pytest
```python
# test_user.py
import pytest
from user import UserService, CreateUserInput

class TestUserService:
    def test_create_user_success(self):
        """Test successful user creation"""
        # Arrange
        user_service = UserService()
        input_data = CreateUserInput(
            name="John Doe",
            email="john@example.com"
        )
        
        # Act
        user = user_service.create_user(input_data)
        
        # Assert
        assert user.id is not None
        assert user.name == input_data.name
        assert user.email == input_data.email
        assert user.created_at is not None
    
    def test_create_user_invalid_email(self):
        """Test user creation with invalid email"""
        # Arrange
        user_service = UserService()
        input_data = CreateUserInput(
            name="John Doe",
            email="invalid-email"
        )
        
        # Act & Assert
        with pytest.raises(ValueError, match="invalid email"):
            user_service.create_user(input_data)
    
    def test_get_user_success(self):
        """Test successful user retrieval"""
        # Arrange
        user_service = UserService()
        created_user = user_service.create_user(
            CreateUserInput(name="Jane Doe", email="jane@example.com")
        )
        
        # Act
        user = user_service.get_user(created_user.id)
        
        # Assert
        assert user.id == created_user.id
        assert user.name == created_user.name
```

### Simple Business Logic Test
```python
# test_order.py
import pytest
from order import Order, OrderItem

class TestOrder:
    def test_calculate_total(self):
        """Test order total calculation"""
        # Arrange
        order = Order(
            items=[
                OrderItem(name="Product A", price=10.00, quantity=2),
                OrderItem(name="Product B", price=5.00, quantity=3),
            ],
            tax=0.08
        )
        
        # Act
        total = order.calculate_total()
        
        # Assert
        expected = (10.00*2 + 5.00*3) * 1.08  # Items + tax
        assert total == expected
    
    def test_is_empty_true(self):
        """Test empty order detection"""
        # Arrange
        order = Order(items=[])
        
        # Act
        is_empty = order.is_empty()
        
        # Assert
        assert is_empty is True
    
    def test_is_empty_false(self):
        """Test non-empty order detection"""
        # Arrange
        order = Order(items=[
            OrderItem(name="Product A", price=10.00, quantity=1)
        ])
        
        # Act
        is_empty = order.is_empty()
        
        # Assert
        assert is_empty is False
```

## JavaScript MVP Testing Examples

### Basic Unit Test with Jest
```javascript
// user.test.js
const { UserService } = require('./user');

describe('UserService', () => {
    let userService;
    
    beforeEach(() => {
        userService = new UserService();
    });
    
    describe('createUser', () => {
        test('should create user successfully', () => {
            // Arrange
            const input = {
                name: 'John Doe',
                email: 'john@example.com'
            };
            
            // Act
            const user = userService.createUser(input);
            
            // Assert
            expect(user.id).toBeDefined();
            expect(user.name).toBe(input.name);
            expect(user.email).toBe(input.email);
            expect(user.createdAt).toBeDefined();
        });
        
        test('should throw error for invalid email', () => {
            // Arrange
            const input = {
                name: 'John Doe',
                email: 'invalid-email'
            };
            
            // Act & Assert
            expect(() => {
                userService.createUser(input);
            }).toThrow('invalid email');
        });
    });
    
    describe('getUser', () => {
        test('should retrieve user successfully', () => {
            // Arrange
            const createdUser = userService.createUser({
                name: 'Jane Doe',
                email: 'jane@example.com'
            });
            
            // Act
            const user = userService.getUser(createdUser.id);
            
            // Assert
            expect(user.id).toBe(createdUser.id);
            expect(user.name).toBe(createdUser.name);
        });
    });
});
```

### Simple Business Logic Test
```javascript
// order.test.js
const { Order, OrderItem } = require('./order');

describe('Order', () => {
    describe('calculateTotal', () => {
        test('should calculate total with tax', () => {
            // Arrange
            const order = new Order({
                items: [
                    new OrderItem('Product A', 10.00, 2),
                    new OrderItem('Product B', 5.00, 3)
                ],
                tax: 0.08
            });
            
            // Act
            const total = order.calculateTotal();
            
            // Assert
            const expected = (10.00 * 2 + 5.00 * 3) * 1.08; // Items + tax
            expect(total).toBe(expected);
        });
    });
    
    describe('isEmpty', () => {
        test('should return true for empty order', () => {
            // Arrange
            const order = new Order({ items: [] });
            
            // Act
            const isEmpty = order.isEmpty();
            
            // Assert
            expect(isEmpty).toBe(true);
        });
        
        test('should return false for non-empty order', () => {
            // Arrange
            const order = new Order({
                items: [new OrderItem('Product A', 10.00, 1)]
            });
            
            // Act
            const isEmpty = order.isEmpty();
            
            // Assert
            expect(isEmpty).toBe(false);
        });
    });
});
```

## Dart/Flutter MVP Testing Examples

### Basic Unit Test
```dart
// test/user_test.dart
import 'package:test/test.dart';
import 'package:your_app/user.dart';

void main() {
    group('UserService', () {
        late UserService userService;
        
        setUp(() {
            userService = UserService();
        });
        
        test('createUser should create user successfully', () {
            // Arrange
            final input = CreateUserInput(
                name: 'John Doe',
                email: 'john@example.com',
            );
            
            // Act
            final user = userService.createUser(input);
            
            // Assert
            expect(user.id, isNotEmpty);
            expect(user.name, equals(input.name));
            expect(user.email, equals(input.email));
            expect(user.createdAt, isNotNull);
        });
        
        test('createUser should throw error for invalid email', () {
            // Arrange
            final input = CreateUserInput(
                name: 'John Doe',
                email: 'invalid-email',
            );
            
            // Act & Assert
            expect(
                () => userService.createUser(input),
                throwsA(contains('invalid email')),
            );
        });
        
        test('getUser should retrieve user successfully', () {
            // Arrange
            final createdUser = userService.createUser(
                CreateUserInput(name: 'Jane Doe', email: 'jane@example.com'),
            );
            
            // Act
            final user = userService.getUser(createdUser.id);
            
            // Assert
            expect(user.id, equals(createdUser.id));
            expect(user.name, equals(createdUser.name));
        });
    });
}
```

### Simple Business Logic Test
```dart
// test/order_test.dart
import 'package:test/test.dart';
import 'package:your_app/order.dart';

void main() {
    group('Order', () {
        test('calculateTotal should calculate total with tax', () {
            // Arrange
            final order = Order(
                items: [
                    OrderItem(name: 'Product A', price: 10.00, quantity: 2),
                    OrderItem(name: 'Product B', price: 5.00, quantity: 3),
                ],
                tax: 0.08,
            );
            
            // Act
            final total = order.calculateTotal();
            
            // Assert
            final expected = (10.00 * 2 + 5.00 * 3) * 1.08; // Items + tax
            expect(total, equals(expected));
        });
        
        test('isEmpty should return true for empty order', () {
            // Arrange
            final order = Order(items: []);
            
            // Act
            final isEmpty = order.isEmpty();
            
            // Assert
            expect(isEmpty, isTrue);
        });
        
        test('isEmpty should return false for non-empty order', () {
            // Arrange
            final order = Order(
                items: [OrderItem(name: 'Product A', price: 10.00, quantity: 1)],
            );
            
            // Act
            final isEmpty = order.isEmpty();
            
            // Assert
            expect(isEmpty, isFalse);
        });
    });
}
```

## MVP Testing Best Practices

### ✅ DO include:
- **Essential business logic tests** - Core functionality validation
- **Input validation tests** - Error handling for invalid inputs
- **Edge case tests** - Boundary conditions and empty states
- **Simple assertions** - Clear, readable test expectations
- **Descriptive test names** - Test should be self-documenting

### ❌ DO NOT include:
- **Enterprise patterns** - No circuit breakers, observability, or audit logs
- **Complex mocking** - Keep mocks simple and focused
- **Integration tests** - Save for Core tier
- **Security tests** - Save for Full tier
- **Performance benchmarks** - Save for Core/Full tiers

### 🎯 Coverage Strategy:
- Focus on **critical business paths** (70% coverage target)
- Prioritize **user-facing functionality**
- Test **error scenarios** that could break user experience
- Keep tests **fast and simple** for quick feedback

## Running MVP Tests

### Go
```bash
# Run all tests
go test ./...

# Run with coverage
go test -cover ./...

# Run specific test file
go test -v ./user/...
```

### Python
```bash
# Run all tests
pytest

# Run with coverage
pytest --cov --cov-report=term-missing

# Run specific test file
pytest test_user.py -v
```

### JavaScript
```bash
# Run all tests
npm test

# Run with coverage
npm test -- --coverage

# Run specific test file
npm test -- user.test.js
```

### Dart/Flutter
```bash
# Run all tests
flutter test

# Run with coverage
flutter test --coverage

# Run specific test file
flutter test test/user_test.dart
```

---

**MVP Tier Testing Philosophy**: Keep it simple, focus on what matters, and ensure core functionality works reliably. The goal is confidence in essential features without enterprise overhead.
