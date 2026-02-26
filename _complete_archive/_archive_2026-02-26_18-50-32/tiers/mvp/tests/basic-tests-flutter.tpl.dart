///
/// File: basic-tests-flutter.tpl.dart
/// Purpose: Template for unknown implementation
/// Generated for: {{PROJECT_NAME}}
///

# Basic Flutter Testing Template
# Purpose: MVP-level testing template with unit and widget tests for Flutter applications
# Usage: Copy to test/ directory and customize for your Flutter project
# Stack: Flutter (.dart)
# Tier: MVP (Minimal Viable Product)

## Purpose

MVP-level Flutter testing template providing essential unit and widget tests for basic application functionality. Focuses on testing core business logic and UI components with minimal setup and fast execution.

## Usage

```bash
# Copy to your Flutter project
cp _templates/tiers/mvp/tests/basic-tests-flutter.tpl.dart test/basic_tests.dart

# Run tests
flutter test test/basic_tests.dart

# Run with coverage
flutter test --coverage test/basic_tests.dart
```

## Structure

```dart
// test/basic_tests.dart
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:your_app/main.dart';

/// MVP Flutter Test Suite
/// 
/// This test suite follows the MVP testing philosophy:
/// - Focus on core business logic and essential UI functionality
/// - Fast execution with minimal setup
/// - No complex mocking or integration testing
/// - Educational comments to teach Flutter testing patterns
/// 
/// MVP Testing Approach:
/// - Unit tests for pure business logic
/// - Widget tests for UI components and interactions
/// - No integration tests (added in Core tier)
/// - No performance or accessibility tests (added in Enterprise tier)

void main() {
  /// Unit Tests - Pure Business Logic
  /// 
  /// These tests verify business logic without Flutter widgets.
  /// MVP approach: Test essential functions that drive your app's core value.
  /// No complex scenarios, no external dependencies, no async operations.
  group('Business Logic Tests', () {
    /// Test counter increment logic
    /// 
    /// Demonstrates basic state management testing.
    /// MVP: Simple pure function testing, no state management libraries.
    test('Counter increment works correctly', () {
      // Test pure business logic - no Flutter dependencies
      int counter = 0;
      counter++;
      expect(counter, equals(1));
    });

    /// Test calculator utility functions
    /// 
    /// Demonstrates testing utility functions and edge cases.
    /// MVP: Basic arithmetic, no complex mathematical operations.
    test('Calculator performs basic operations', () {
      // Test utility functions - pure functions with predictable outputs
      int add(int a, int b) => a + b;
      expect(add(2, 3), equals(5));
      expect(add(-1, 1), equals(0)); // Edge case: negative numbers
    });

    /// Test data validation logic
    /// 
    /// Demonstrates testing validation rules and business constraints.
    /// MVP: Simple validation, no regex or complex validation libraries.
    test('Data validation works', () {
      // Test validation logic - business rules for data integrity
      bool isValidEmail(String email) {
        return email.contains('@') && email.contains('.');
      }
      expect(isValidEmail('test@example.com'), isTrue);
      expect(isValidEmail('invalid-email'), isFalse);
      expect(isValidEmail('@domain.com'), isFalse); // Edge case: missing local part
    });
  });

  /// Widget Tests - UI Components and Interactions
  /// 
  /// These tests verify Flutter widgets render correctly and respond to user input.
  /// MVP approach: Test essential UI flows, no complex animations or gestures.
  /// 
  /// Key Flutter Testing Patterns:
  /// - pumpWidget(): Renders a widget for testing
  /// - pump(): Rebuilds the widget after state changes
  /// - pumpAndSettle(): Waits for all animations and async operations
  /// - find.byType(): Locates widgets by their type
  /// - find.text(): Locates widgets by their text content
  /// - tap(): Simulates user tap gestures
  group('Widget Tests', () {
    /// Test app initialization and basic rendering
    /// 
    /// Verifies the app can start without crashing and basic widgets are present.
    /// MVP: Simple smoke test, no deep widget tree inspection.
    testWidgets('App builds without error', (WidgetTester tester) async {
      // Build our app and trigger a frame
      // pumpWidget() renders the widget tree for testing
      await tester.pumpWidget(const YourApp());

      // Verify that the app builds successfully
      // find.byType() locates widgets by their Flutter type
      expect(find.byType(MaterialApp), findsOneWidget);
    });

    /// Test counter widget functionality
    /// 
    /// Demonstrates testing state changes and user interactions.
    /// MVP: Basic state management, no complex state patterns.
    testWidgets('Counter widget displays and increments', (WidgetTester tester) async {
      // Build the widget
      await tester.pumpWidget(const YourApp());

      // Verify initial state - counter should show 0
      // find.text() locates widgets by their displayed text
      expect(find.text('0'), findsOneWidget);
      expect(find.text('1'), findsNothing);

      // Tap the increment button to change state
      // find.byIcon() locates widgets by their icon
      // tap() simulates user interaction
      await tester.tap(find.byIcon(Icons.add));
      
      // pump() rebuilds the widget after state change
      await tester.pump();

      // Verify updated state - counter should now show 1
      expect(find.text('0'), findsNothing);
      expect(find.text('1'), findsOneWidget);
    });

    testWidgets('Navigation works correctly', (WidgetTester tester) async {
      await tester.pumpWidget(const YourApp());

      // Find navigation button
      final navButton = find.byKey(const Key('nav_button'));
      expect(navButton, findsOneWidget);

      // Tap and navigate
      await tester.tap(navButton);
      await tester.pumpAndSettle();

      // Verify navigation
      expect(find.byType(SecondPage), findsOneWidget);
    });

    testWidgets('Form validation works', (WidgetTester tester) async {
      await tester.pumpWidget(const YourApp());

      // Find form elements
      final emailField = find.byKey(const Key('email_field'));
      final submitButton = find.byKey(const Key('submit_button'));

      // Enter invalid email
      await tester.enterText(emailField, 'invalid-email');
      await tester.tap(submitButton);
      await tester.pump();

      // Verify error message
      expect(find.text('Please enter a valid email'), findsOneWidget);

      // Enter valid email
      await tester.enterText(emailField, 'test@example.com');
      await tester.tap(submitButton);
      await tester.pump();

      // Verify success
      expect(find.text('Form submitted successfully'), findsOneWidget);
    });
  });

  group('Utility Tests', () {
    test('Date formatting works', () {
      // Test date utilities
      String formatDate(DateTime date) {
        return '${date.day}/${date.month}/${date.year}';
      }
      
      final testDate = DateTime(2023, 12, 25);
      expect(formatDate(testDate), equals('25/12/2023'));
    });

    test('String manipulation works', () {
      // Test string utilities
      String capitalize(String text) {
        if (text.isEmpty) return text;
        return text[0].toUpperCase() + text.substring(1);
      }
      
      expect(capitalize('hello'), equals('Hello'));
      expect(capitalize(''), equals(''));
    });
  });
}

// Test Helper Functions
class TestHelpers {
  static Widget createTestWidget(Widget child) {
    return MaterialApp(
      home: Scaffold(
        body: child,
      ),
    );
  }

  static Future<void> pumpAndSettle(WidgetTester tester) async {
    await tester.pumpAndSettle(const Duration(seconds: 5));
  }
}

// Mock Data Factory
class MockDataFactory {
  static Map<String, dynamic> createMockUser() {
    return {
      'id': 1,
      'name': 'Test User',
      'email': 'test@example.com',
      'createdAt': DateTime.now().toIso8601String(),
    };
  }

  static List<Map<String, dynamic>> createMockItems() {
    return [
      {'id': 1, 'name': 'Item 1', 'value': 10.0},
      {'id': 2, 'name': 'Item 2', 'value': 20.0},
      {'id': 3, 'name': 'Item 3', 'value': 30.0},
    ];
  }
}
```

## Guidelines

### Test Organization
- **Unit Tests**: Test pure business logic, utilities, and data models
- **Widget Tests**: Test UI components in isolation with flutter_test
- **Keep Tests Fast**: MVP tests should run in under 30 seconds
- **Descriptive Names**: Use clear test names that describe the scenario

### Test Structure
- Use `group()` to organize related tests
- Follow `testWidgets()` for widget tests
- Use `expect()` assertions with clear matchers
- Set up and tear down test state properly

### Widget Testing Best Practices
- Use `tester.pump()` to rebuild widgets after state changes
- Use `tester.pumpAndSettle()` for async operations
- Find widgets by key, type, or text
- Test user interactions (tap, drag, enterText)

### Coverage Requirements
- **Unit Tests**: 80%+ coverage for business logic
- **Widget Tests**: 70%+ coverage for UI components
- **Overall**: 75%+ minimum for MVP

## Required Dependencies

Add to `pubspec.yaml`:

```yaml
dev_dependencies:
  flutter_test:
    sdk: flutter
  mockito: ^5.4.2
  build_runner: ^2.4.6
```

## What's Included

- **Unit Tests**: Business logic, utilities, data validation
- **Widget Tests**: UI component testing with flutter_test
- **Test Helpers**: Common testing utilities
- **Mock Data Factory**: Sample data generation
- **Coverage Requirements**: MVP-level testing standards

## What's NOT Included

- Integration tests (database, API)
- Performance tests
- Golden tests (visual regression)
- Accessibility tests
- Platform-specific tests

---

**Template Version**: 1.0 (MVP)  
**Last Updated**: 2025-12-10  
**Stack**: Flutter  
**Tier**: MVP  
**Framework**: flutter_test
