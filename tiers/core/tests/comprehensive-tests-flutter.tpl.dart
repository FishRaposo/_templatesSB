///
/// File: comprehensive-tests-flutter.tpl.dart
/// Purpose: Template for unknown implementation
/// Generated for: {{PROJECT_NAME}}
///

# Comprehensive Flutter Testing Template
# Purpose: Core-level testing template with unit, widget, integration, and feature tests for Flutter applications
# Usage: Copy to test/ directory and customize for your Flutter project
# Stack: Flutter (.dart)
# Tier: Core (Production Ready)

## Purpose

Core-level Flutter testing template providing comprehensive testing coverage including unit tests, widget tests, integration tests, and feature tests for production-ready applications. Focuses on testing business logic, UI components, data persistence, and complete user features.

## Usage

```bash
# Copy to your Flutter project
# Project: [[.ProjectName]]
# Author: [[.Author]]
cp _templates/tiers/core/tests/comprehensive-tests-flutter.tpl.dart test/comprehensive_test.dart

# Install dependencies
flutter pub add test mockito build_runner integration_test

# Run unit and widget tests
flutter test test/comprehensive_test.dart

# Run integration tests
flutter test integration_test/

# Run with coverage
flutter test --coverage test/comprehensive_test.dart
```

## Structure

```dart
// test/comprehensive_test.dart
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:mockito/mockito.dart';
import 'package:mockito/annotations.dart';
import 'package:your_app/main.dart';
import 'package:your_app/services/api_service.dart';
import 'package:your_app/services/database_service.dart';
import 'package:your_app/services/auth_service.dart';
import 'package:your_app/models/user.dart';
import 'package:your_app/models/product.dart';
import 'package:your_app/widgets/user_form.dart';
import 'package:your_app/widgets/product_list.dart';
import 'package:your_app/features/user_management.dart';

import 'comprehensive_test.mocks.dart';

// Generate mocks
@GenerateMocks([ApiService, DatabaseService, AuthService])
void main() {
  group('Unit Tests - Business Logic', () {
    late MockApiService mockApiService;
    late MockDatabaseService mockDatabaseService;
    late MockAuthService mockAuthService;

    setUp(() {
      mockApiService = MockApiService();
      mockDatabaseService = MockDatabaseService();
      mockAuthService = MockAuthService();
    });

    group('User Model', () {
      test('should create user with valid data', () {
        final user = User(
          id: 1,
          name: 'Test User',
          email: 'test@example.com',
          age: 25,
        );

        expect(user.id, equals(1));
        expect(user.name, equals('Test User'));
        expect(user.email, equals('test@example.com'));
        expect(user.age, equals(25));
        expect(user.isValid, isTrue);
      });

      test('should validate user data correctly', () {
        final validUser = User(
          id: 1,
          name: 'Test User',
          email: 'test@example.com',
          age: 25,
        );

        final invalidUser = User(
          id: 2,
          name: '',
          email: 'invalid-email',
          age: 15,
        );

        expect(validUser.isValid, isTrue);
        expect(invalidUser.isValid, isFalse);
      });

      test('should calculate user age correctly', () {
        final birthDate = DateTime.now().subtract(Duration(days: 365 * 25));
        final user = User(
          id: 1,
          name: 'Test User',
          email: 'test@example.com',
          age: 25,
          birthDate: birthDate,
        );

        expect(user.calculateAge(), equals(25));
      });
    });

    group('Product Model', () {
      test('should calculate total price correctly', () {
        final product = Product(
          id: 1,
          name: 'Test Product',
          price: 10.99,
          quantity: 5,
        );

        expect(product.totalPrice, equals(54.95));
      });

      test('should check stock availability', () {
        final inStockProduct = Product(
          id: 1,
          name: 'In Stock Product',
          price: 10.99,
          quantity: 10,
        );

        final outOfStockProduct = Product(
          id: 2,
          name: 'Out of Stock Product',
          price: 10.99,
          quantity: 0,
        );

        expect(inStockProduct.isInStock, isTrue);
        expect(outOfStockProduct.isInStock, isFalse);
      });
    });

    group('User Management Service', () {
      test('should create user successfully', () async {
        final userManagement = UserManagementService(
          apiService: mockApiService,
          databaseService: mockDatabaseService,
          authService: mockAuthService,
        );

        final userData = {
          'name': 'New User',
          'email': 'newuser@example.com',
          'age': 30,
        };

        when(mockApiService.createUser(userData))
            .thenAnswer((_) async => User.fromJson({...userData, 'id': 1}));

        when(mockDatabaseService.saveUser(any))
            .thenAnswer((_) async => true);

        final result = await userManagement.createUser(userData);

        expect(result, isNotNull);
        expect(result!.name, equals('New User'));
        verify(mockApiService.createUser(userData)).called(1);
        verify(mockDatabaseService.saveUser(any)).called(1);
      });

      test('should handle API errors gracefully', () async {
        final userManagement = UserManagementService(
          apiService: mockApiService,
          databaseService: mockDatabaseService,
          authService: mockAuthService,
        );

        final userData = {
          'name': 'New User',
          'email': 'newuser@example.com',
          'age': 30,
        };

        when(mockApiService.createUser(userData))
            .thenThrow(Exception('API Error'));

        final result = await userManagement.createUser(userData);

        expect(result, isNull);
        verify(mockApiService.createUser(userData)).called(1);
        verifyNever(mockDatabaseService.saveUser(any));
      });

      test('should validate user data before creation', () async {
        final userManagement = UserManagementService(
          apiService: mockApiService,
          databaseService: mockDatabaseService,
          authService: mockAuthService,
        );

        final invalidUserData = {
          'name': '',
          'email': 'invalid-email',
          'age': 15,
        };

        final result = await userManagement.createUser(invalidUserData);

        expect(result, isNull);
        verifyNever(mockApiService.createUser(any));
        verifyNever(mockDatabaseService.saveUser(any));
      });
    });

    group('Authentication Service', () {
      test('should authenticate user with valid credentials', () async {
        final auth = AuthService();
        final credentials = {
          'email': 'test@example.com',
          'password': 'ValidPass123!',
        };

        when(mockAuthService.signIn(credentials['email']!, credentials['password']!))
            .thenAnswer((_) async => 'auth_token_123');

        final result = await auth.signIn(credentials['email']!, credentials['password']!);

        expect(result, equals('auth_token_123'));
        verify(mockAuthService.signIn(credentials['email']!, credentials['password']!)).called(1);
      });

      test('should reject invalid credentials', () async {
        final auth = AuthService();
        final credentials = {
          'email': 'test@example.com',
          'password': 'wrongpassword',
        };

        when(mockAuthService.signIn(credentials['email']!, credentials['password']!))
            .thenThrow(AuthException('Invalid credentials'));

        expect(
          () => auth.signIn(credentials['email']!, credentials['password']!),
          throwsA(isA<AuthException>()),
        );
      });
    });
  });

  group('Widget Tests - UI Components', () {
    testWidgets('UserForm widget renders and validates input', (WidgetTester tester) async {
      await tester.pumpWidget(MaterialApp(
        home: Scaffold(
          body: UserForm(
            onSubmit: (user) {},
          ),
        ),
      ));

      // Verify form renders
      expect(find.byType(TextField), findsNWidgets(3)); // name, email, age
      expect(find.byType(ElevatedButton), findsOneWidget);

      // Test empty form submission
      await tester.tap(find.byType(ElevatedButton));
      await tester.pump();

      expect(find.text('Name is required'), findsOneWidget);
      expect(find.text('Email is required'), findsOneWidget);
      expect(find.text('Age is required'), findsOneWidget);

      // Test valid form submission
      await tester.enterText(find.byKey(Key('name_field')), 'Test User');
      await tester.enterText(find.byKey(Key('email_field')), 'test@example.com');
      await tester.enterText(find.byKey(Key('age_field')), '25');

      await tester.tap(find.byType(ElevatedButton));
      await tester.pump();

      expect(find.text('Name is required'), findsNothing);
      expect(find.text('Email is required'), findsNothing);
      expect(find.text('Age is required'), findsNothing);
    });

    testWidgets('ProductList widget displays products correctly', (WidgetTester tester) async {
      final products = [
        Product(id: 1, name: 'Product 1', price: 10.99, quantity: 5),
        Product(id: 2, name: 'Product 2', price: 20.50, quantity: 10),
        Product(id: 3, name: 'Product 3', price: 15.75, quantity: 0),
      ];

      await tester.pumpWidget(MaterialApp(
        home: Scaffold(
          body: ProductList(
            products: products,
            onProductTap: (product) {},
          ),
        ),
      ));

      // Verify all products are displayed
      expect(find.text('Product 1'), findsOneWidget);
      expect(find.text('\$10.99'), findsOneWidget);
      expect(find.text('Product 2'), findsOneWidget);
      expect(find.text('\$20.50'), findsOneWidget);
      expect(find.text('Product 3'), findsOneWidget);
      expect(find.text('\$15.75'), findsOneWidget);

      // Verify out of stock indicator
      expect(find.text('Out of Stock'), findsOneWidget);
    });

    testWidgets('ProductList handles product selection', (WidgetTester tester) async {
      final products = [
        Product(id: 1, name: 'Product 1', price: 10.99, quantity: 5),
      ];

      Product? selectedProduct;
      await tester.pumpWidget(MaterialApp(
        home: Scaffold(
          body: ProductList(
            products: products,
            onProductTap: (product) {
              selectedProduct = product;
            },
          ),
        ),
      ));

      // Tap on product
      await tester.tap(find.text('Product 1'));
      await tester.pump();

      expect(selectedProduct, isNotNull);
      expect(selectedProduct!.id, equals(1));
      expect(selectedProduct!.name, equals('Product 1'));
    });

    testWidgets('UserForm shows loading state during submission', (WidgetTester tester) async {
      bool isLoading = false;
      
      await tester.pumpWidget(MaterialApp(
        home: Scaffold(
          body: StatefulBuilder(
            builder: (context, setState) {
              return UserForm(
                onSubmit: (user) async {
                  setState(() => isLoading = true);
                  await Future.delayed(Duration(seconds: 1));
                  setState(() => isLoading = false);
                },
                isLoading: isLoading,
              );
            },
          ),
        ),
      ));

      // Fill form with valid data
      await tester.enterText(find.byKey(Key('name_field')), 'Test User');
      await tester.enterText(find.byKey(Key('email_field')), 'test@example.com');
      await tester.enterText(find.byKey(Key('age_field')), '25');

      // Submit form
      await tester.tap(find.byType(ElevatedButton));
      await tester.pump();

      // Verify loading state
      expect(find.byType(CircularProgressIndicator), findsOneWidget);
      expect(find.byType(ElevatedButton), findsNothing);
    });
  });

  group('Integration Tests - Data Flow', () {
    testWidgets('Complete user creation workflow', (WidgetTester tester) async {
      final mockApiService = MockApiService();
      final mockDatabaseService = MockDatabaseService();

      when(mockApiService.createUser(any))
          .thenAnswer((_) async => User(id: 1, name: 'Test User', email: 'test@example.com', age: 25));
      when(mockDatabaseService.saveUser(any))
          .thenAnswer((_) async => true);

      await tester.pumpWidget(MaterialApp(
        home: UserManagementScreen(
          apiService: mockApiService,
          databaseService: mockDatabaseService,
        ),
      ));

      // Navigate to create user form
      await tester.tap(find.byKey(Key('add_user_button')));
      await tester.pumpAndSettle();

      // Fill user form
      await tester.enterText(find.byKey(Key('name_field')), 'Test User');
      await tester.enterText(find.byKey(Key('email_field')), 'test@example.com');
      await tester.enterText(find.byKey(Key('age_field')), '25');

      // Submit form
      await tester.tap(find.byKey(Key('submit_button')));
      await tester.pumpAndSettle();

      // Verify user appears in list
      expect(find.text('Test User'), findsOneWidget);
      expect(find.text('test@example.com'), findsOneWidget);

      verify(mockApiService.createUser(any)).called(1);
      verify(mockDatabaseService.saveUser(any)).called(1);
    });

    testWidgets('Product search and filter workflow', (WidgetTester tester) async {
      final products = [
        Product(id: 1, name: 'Apple iPhone', price: 999.99, quantity: 5, category: 'Electronics'),
        Product(id: 2, name: 'Samsung TV', price: 799.99, quantity: 3, category: 'Electronics'),
        Product(id: 3, name: 'Book: Flutter Guide', price: 29.99, quantity: 10, category: 'Books'),
      ];

      await tester.pumpWidget(MaterialApp(
        home: ProductSearchScreen(
          products: products,
        ),
      ));

      // Verify all products are shown initially
      expect(find.text('Apple iPhone'), findsOneWidget);
      expect(find.text('Samsung TV'), findsOneWidget);
      expect(find.text('Book: Flutter Guide'), findsOneWidget);

      // Search for specific product
      await tester.enterText(find.byType(TextField), 'iPhone');
      await tester.pump();

      expect(find.text('Apple iPhone'), findsOneWidget);
      expect(find.text('Samsung TV'), findsNothing);
      expect(find.text('Book: Flutter Guide'), findsNothing);

      // Clear search
      await tester.tap(find.byIcon(Icons.clear));
      await tester.pump();

      // Filter by category
      await tester.tap(find.byKey(Key('category_filter')));
      await tester.pumpAndSettle();
      await tester.tap(find.text('Electronics'));
      await tester.pumpAndSettle();

      expect(find.text('Apple iPhone'), findsOneWidget);
      expect(find.text('Samsung TV'), findsOneWidget);
      expect(find.text('Book: Flutter Guide'), findsNothing);
    });
  });

  group('Feature Tests - Complete User Features', () {
    testWidgets('User registration feature complete flow', (WidgetTester tester) async {
      final mockAuthService = MockAuthService();
      final mockApiService = MockApiService();

      when(mockAuthService.signUp(any, any, any))
          .thenAnswer((_) async => 'auth_token_123');
      when(mockApiService.createUser(any))
          .thenAnswer((_) async => User(id: 1, name: 'John Doe', email: 'john@example.com', age: 25));

      await tester.pumpWidget(MaterialApp(
        home: RegistrationScreen(
          authService: mockAuthService,
          apiService: mockApiService,
        ),
      ));

      // Fill registration form
      await tester.enterText(find.byKey(Key('name_field')), 'John Doe');
      await tester.enterText(find.byKey(Key('email_field')), 'john@example.com');
      await tester.enterText(find.byKey(Key('password_field')), 'SecurePass123!');
      await tester.enterText(find.byKey(Key('confirm_password_field')), 'SecurePass123!');
      await tester.enterText(find.byKey(Key('age_field')), '25');

      // Accept terms
      await tester.tap(find.byKey(Key('terms_checkbox')));
      await tester.pump();

      // Submit registration
      await tester.tap(find.byKey(Key('register_button')));
      await tester.pumpAndSettle();

      // Verify successful registration
      expect(find.text('Registration successful!'), findsOneWidget);
      expect(find.byType(HomeScreen), findsOneWidget);

      verify(mockAuthService.signUp('john@example.com', 'SecurePass123!', 'John Doe')).called(1);
      verify(mockApiService.createUser(any)).called(1);
    });

    testWidgets('Product purchase feature complete flow', (WidgetTester tester) async {
      final products = [
        Product(id: 1, name: 'Test Product', price: 10.99, quantity: 5),
      ];

      await tester.pumpWidget(MaterialApp(
        home: ProductPurchaseScreen(
          products: products,
        ),
      ));

      // Add product to cart
      await tester.tap(find.byKey(Key('add_to_cart_1')));
      await tester.pump();

      // Verify cart badge shows count
      expect(find.text('1'), findsOneWidget);

      // Navigate to cart
      await tester.tap(find.byKey(Key('cart_button')));
      await tester.pumpAndSettle();

      // Verify product in cart
      expect(find.text('Test Product'), findsOneWidget);
      expect(find.text('\$10.99'), findsOneWidget);

      // Proceed to checkout
      await tester.tap(find.byKey(Key('checkout_button')));
      await tester.pumpAndSettle();

      // Fill payment form
      await tester.enterText(find.byKey(Key('card_number_field')), '4111111111111111');
      await tester.enterText(find.byKey(Key('expiry_field')), '12/25');
      await tester.enterText(find.byKey(Key('cvv_field')), '123');

      // Complete purchase
      await tester.tap(find.byKey(Key('complete_purchase_button')));
      await tester.pumpAndSettle();

      // Verify purchase success
      expect(find.text('Purchase completed successfully!'), findsOneWidget);
      expect(find.byType(OrderConfirmationScreen), findsOneWidget);
    });
  });

  group('Performance Tests', () {
    testWidgets('Large list scrolling performance', (WidgetTester tester) async {
      final products = List.generate(1000, (index) => 
        Product(id: index, name: 'Product $index', price: 10.99 + index, quantity: 5));

      await tester.pumpWidget(MaterialApp(
        home: Scaffold(
          body: ProductList(products: products, onProductTap: (product) {}),
        ),
      ));

      // Measure initial build time
      final stopwatch = Stopwatch()..start();
      await tester.pump();
      stopwatch.stop();

      expect(stopwatch.elapsedMilliseconds, lessThan(1000));

      // Test scrolling performance
      stopwatch.reset();
      stopwatch.start();

      for (int i = 0; i < 10; i++) {
        await tester.fling(find.byType(ListView), Offset(0, -500), 1000);
        await tester.pumpAndSettle();
      }

      stopwatch.stop();
      expect(stopwatch.elapsedMilliseconds, lessThan(2000));
    });
  });
}

// Integration Tests (separate file)
// integration_test/app_test.dart
void integrationTests() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  group('End-to-End Integration Tests', () {
    testWidgets('Complete app user journey', (WidgetTester tester) async {
      app.main();
      await tester.pumpAndSettle();

      // Registration flow
      await tester.tap(find.byKey(Key('register_button')));
      await tester.pumpAndSettle();

      await tester.enterText(find.byKey(Key('name_field')), 'Integration User');
      await tester.enterText(find.byKey(Key('email_field')), 'integration@example.com');
      await tester.enterText(find.byKey(Key('password_field')), 'TestPass123!');
      await tester.enterText(find.byKey(Key('confirm_password_field')), 'TestPass123!');
      await tester.enterText(find.byKey(Key('age_field')), '25');

      await tester.tap(find.byKey(Key('terms_checkbox')));
      await tester.tap(find.byKey(Key('register_button')));
      await tester.pumpAndSettle(Duration(seconds: 5));

      // Verify home screen
      expect(find.byType(HomeScreen), findsOneWidget);

      // Browse products
      await tester.tap(find.byKey(Key('browse_products')));
      await tester.pumpAndSettle();

      // Add product to cart
      await tester.tap(find.byKey(Key('product_1')));
      await tester.pumpAndSettle();
      await tester.tap(find.byKey(Key('add_to_cart')));
      await tester.pumpAndSettle();

      // Checkout
      await tester.tap(find.byKey(Key('cart')));
      await tester.pumpAndSettle();
      await tester.tap(find.byKey(Key('checkout')));
      await tester.pumpAndSettle();

      // Complete purchase
      await tester.tap(find.byKey(Key('complete_purchase')));
      await tester.pumpAndSettle(Duration(seconds: 3));

      // Verify order confirmation
      expect(find.text('Order Confirmed'), findsOneWidget);
    });
  });
}

// Test Helpers and Utilities
class TestHelpers {
  static Widget createTestWidget({required Widget child}) {
    return MaterialApp(
      home: Scaffold(
        body: child,
      ),
    );
  }

  static Future<void> pumpAndSettle(WidgetTester tester, {Duration? duration}) async {
    await tester.pumpAndSettle(duration ?? Duration(seconds: 5));
  }

  static User createMockUser({int id = 1, String name = 'Test User'}) {
    return User(
      id: id,
      name: name,
      email: 'test$id@example.com',
      age: 25,
    );
  }

  static Product createMockProduct({int id = 1, String name = 'Test Product'}) {
    return Product(
      id: id,
      name: name,
      price: 10.99 + id,
      quantity: 5,
    );
  }

  static List<User> createMockUserList(int count) {
    return List.generate(count, (index) => createMockUser(id: index + 1, name: 'User $index'));
  }

  static List<Product> createMockProductList(int count) {
    return List.generate(count, (index) => createMockProduct(id: index + 1, name: 'Product $index'));
  }
}

// Custom Test Matchers
class CustomMatchers {
  static Matcher isValidEmail() => predicate((String email) {
    return RegExp(r'^[\w-\.]+@([\w-]+\.)+[\w-]{2,4}$').hasMatch(email);
  }, 'is a valid email');

  static Matcher isValidUser() => predicate((User user) {
    return user.isValid && user.id > 0 && user.name.isNotEmpty;
  }, 'is a valid user');
}
```

## Guidelines

### Test Organization
- **Unit Tests**: Business logic, models, services with mocks
- **Widget Tests**: UI components with flutter_test
- **Integration Tests**: Complete workflows and data flow
- **Feature Tests**: End-to-end user feature validation
- **Performance Tests**: Critical path performance validation

### Test Structure
- Use `group()` to organize tests by type and feature
- Use `testWidgets()` for widget and integration tests
- Use `mockito` for mocking external dependencies
- Use `pumpAndSettle()` for async operations

### Coverage Requirements
- **Unit Tests**: 85%+ coverage for business logic
- **Widget Tests**: 80%+ coverage for UI components
- **Integration Tests**: 70%+ coverage for critical workflows
- **Overall**: 80%+ minimum for Core tier

## Required Dependencies

Add to `pubspec.yaml`:

```yaml
dev_dependencies:
  flutter_test:
    sdk: flutter
  mockito: ^5.4.2
  build_runner: ^2.4.6
  integration_test:
    sdk: flutter
```

## What's Included

- **Unit Tests**: Business logic, models, services with comprehensive mocking
- **Widget Tests**: UI component testing with user interactions
- **Integration Tests**: Complete workflows and data persistence
- **Feature Tests**: End-to-end user feature validation
- **Performance Tests**: Critical path performance testing
- **Test Helpers**: Mock data factories and utilities

## What's NOT Included

- System tests with real devices
- Accessibility tests
- Golden tests (visual regression)
- Network condition testing

---

**Template Version**: 2.0 (Core)  
**Last Updated**: 2025-12-10  
**Stack**: Flutter  
**Tier**: Core  
**Framework**: flutter_test + mockito + integration_test
