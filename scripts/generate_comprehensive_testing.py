#!/usr/bin/env python3
"""
Generate Comprehensive Testing Framework for All Stacks
Creates unit, integration, system, workflow, feature, and stack-specific tests
"""

import os
from pathlib import Path
from typing import Dict, List, Any

# Stack configurations with their specific testing patterns
STACKS = {
    'flutter': {
        'extension': 'dart',
        'test_types': ['unit-tests', 'widget-tests', 'integration-tests', 'system-tests', 'workflow-tests', 'feature-tests'],
        'dependencies': ['flutter_test', 'mockito', 'build_runner', 'integration_test'],
        'framework': 'flutter_test',
        'specific_tests': ['widget-tests']
    },
    'python': {
        'extension': 'py',
        'test_types': ['unit-tests', 'integration-tests', 'system-tests', 'workflow-tests', 'feature-tests', 'api-tests'],
        'dependencies': ['pytest', 'pytest-asyncio', 'pytest-cov', 'unittest.mock', 'httpx'],
        'framework': 'pytest',
        'specific_tests': ['api-tests']
    },
    'node': {
        'extension': 'js',
        'test_types': ['unit-tests', 'integration-tests', 'system-tests', 'workflow-tests', 'feature-tests', 'api-tests'],
        'dependencies': ['jest', 'supertest', 'nock', 'mongodb-memory-server'],
        'framework': 'jest',
        'specific_tests': ['api-tests']
    },
    'react': {
        'extension': 'jsx',
        'test_types': ['unit-tests', 'component-tests', 'integration-tests', 'system-tests', 'workflow-tests', 'feature-tests'],
        'dependencies': ['@testing-library/react', '@testing-library/jest-dom', '@testing-library/user-event', 'jest'],
        'framework': 'jest',
        'specific_tests': ['component-tests']
    },
    'react_native': {
        'extension': 'jsx',
        'test_types': ['unit-tests', 'component-tests', 'integration-tests', 'system-tests', 'workflow-tests', 'feature-tests'],
        'dependencies': ['@testing-library/react-native', '@react-native-async-storage/async-storage', 'jest'],
        'framework': 'jest',
        'specific_tests': ['component-tests']
    },
    'next': {
        'extension': 'jsx',
        'test_types': ['unit-tests', 'integration-tests', 'system-tests', 'workflow-tests', 'feature-tests', 'e2e-tests'],
        'dependencies': ['@testing-library/react', '@testing-library/jest-dom', 'playwright', 'jest'],
        'framework': 'jest',
        'specific_tests': ['e2e-tests']
    },
    'go': {
        'extension': 'go',
        'test_types': ['unit-tests', 'integration-tests', 'system-tests', 'workflow-tests', 'feature-tests', 'benchmark-tests'],
        'dependencies': ['testing', 'httptest', 'testify'],
        'framework': 'go test',
        'specific_tests': ['benchmark-tests']
    },
    'r': {
        'extension': 'R',
        'test_types': ['unit-tests', 'integration-tests', 'workflow-tests', 'feature-tests', 'statistical-tests', 'plot-tests'],
        'dependencies': ['testthat', 'mockery', 'vdiffr'],
        'framework': 'testthat',
        'specific_tests': ['statistical-tests', 'plot-tests']
    },
    'sql': {
        'extension': 'sql',
        'test_types': ['unit-tests', 'integration-tests', 'system-tests', 'workflow-tests', 'feature-tests', 'schema-tests'],
        'dependencies': ['pgTAP', 'dbunit', 'testcontainers'],
        'framework': 'database-specific',
        'specific_tests': ['schema-tests']
    }
}

def create_flutter_tests(stack_path: Path):
    """Create comprehensive Flutter testing templates"""
    
    # Unit Tests
    unit_tests = '''// -----------------------------------------------------------------------------
// FILE: unit-tests.tpl.dart
// PURPOSE: Comprehensive unit testing patterns for Flutter projects
// USAGE: Import and extend for unit testing across Flutter applications
// DEPENDENCIES: flutter_test, mockito, build_runner
// AUTHOR: [[.Author]]
// VERSION: [[.Version]]
// SINCE: [[.Version]]
// -----------------------------------------------------------------------------

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:mockito/mockito.dart';
import 'package:mockito/annotations.dart';
import 'dart:async';

/// Generate mocks with: dart run build_runner build
@GenerateMocks([
  // Add your classes here, e.g.:
  // AuthService,
  // DataValidator,
  // UserRepository,
])
void main() {
  group('Unit Tests - Business Logic', () {
    late MockAuthService mockAuthService;
    late MockDataValidator mockDataValidator;
    
    setUp(() {
      mockAuthService = MockAuthService();
      mockDataValidator = MockDataValidator();
    });

    group('Authentication Service Tests', () {
      test('should authenticate user with valid credentials', () async {
        // Arrange
        const email = 'test@example.com';
        const password = 'password123';
        final expectedUser = User(id: '1', email: email, name: 'Test User');
        
        when(mockAuthService.signIn(email, password))
            .thenAnswer((_) async => Result.success(expectedUser));

        // Act
        final result = await mockAuthService.signIn(email, password);

        // Assert
        expect(result.isSuccess, isTrue);
        expect(result.data?.email, equals(email));
        verify(mockAuthService.signIn(email, password)).called(1);
      });

      test('should return error for invalid credentials', () async {
        // Arrange
        const email = 'invalid@example.com';
        const password = 'wrongpassword';
        
        when(mockAuthService.signIn(email, password))
            .thenAnswer((_) async => Result.failure('Invalid credentials'));

        // Act
        final result = await mockAuthService.signIn(email, password);

        // Assert
        expect(result.isFailure, isTrue);
        expect(result.error, equals('Invalid credentials'));
        verify(mockAuthService.signIn(email, password)).called(1);
      });
    });

    group('Data Validation Tests', () {
      test('should validate email format correctly', () {
        // Test valid emails
        expect(DataValidator.isValidEmail('test@example.com'), isTrue);
        expect(DataValidator.isValidEmail('user.name+tag@domain.co.uk'), isTrue);
        
        // Test invalid emails
        expect(DataValidator.isValidEmail('invalid-email'), isFalse);
        expect(DataValidator.isValidEmail('@domain.com'), isFalse);
      });

      test('should validate password strength', () {
        // Strong passwords
        expect(DataValidator.isPasswordStrong('Str0ngP@ssw0rd!'), isTrue);
        expect(DataValidator.isPasswordStrong('MyP@ssw0rd123'), isTrue);
        
        // Weak passwords
        expect(DataValidator.isPasswordStrong('password'), isFalse);
        expect(DataValidator.isPasswordStrong('123456'), isFalse);
      });
    });
  });
}

// Mock classes and example implementations
class MockAuthService extends Mock implements AuthService {}
class MockDataValidator extends Mock implements DataValidator {}

class DataValidator {
  static bool isValidEmail(String? email) {
    if (email == null || email.isEmpty) return false;
    return RegExp(r'^[\\w-\\.]+@([\\w-]+\\.)+[\\w-]{2,4}$').hasMatch(email);
  }
  
  static bool isPasswordStrong(String password) {
    return password.length >= 8 &&
           RegExp(r'[A-Z]').hasMatch(password) &&
           RegExp(r'[a-z]').hasMatch(password) &&
           RegExp(r'[0-9]').hasMatch(password) &&
           RegExp(r'[!@#$%^&*(),.?":{}|<>]').hasMatch(password);
  }
}

class User {
  final String id;
  final String email;
  final String name;
  final DateTime createdAt;
  
  User({required this.id, required this.email, required this.name, required this.createdAt});
  bool get isValid => id.isNotEmpty && email.contains('@') && name.isNotEmpty;
}

abstract class AuthService {
  Future<Result<User>> signIn(String email, String password);
}

class Result<T> {
  final T? data;
  final String? error;
  
  Result({this.data, this.error});
  
  bool get isSuccess => error == null;
  bool get isFailure => error != null;
  
  factory Result.success(T data) => Result(data: data);
  factory Result.failure(String error) => Result(error: error);
}
'''

    # Widget Tests
    widget_tests = '''// -----------------------------------------------------------------------------
// FILE: widget-tests.tpl.dart
// PURPOSE: Comprehensive widget testing patterns for Flutter projects
// USAGE: Import and extend for widget testing across Flutter applications
// DEPENDENCIES: flutter_test, mockito, build_runner
// AUTHOR: [[.Author]]
// VERSION: [[.Version]]
// SINCE: [[.Version]]
// -----------------------------------------------------------------------------

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:mockito/mockito.dart';
import 'package:mockito/annotations.dart';
import 'package:your_app/widgets/custom_button.dart';
import 'package:your_app/widgets/user_avatar.dart';
import 'package:your_app/screens/home_screen.dart';

/// Generate mocks with: dart run build_runner build
@GenerateMocks([
  // Add your service classes here
  // AuthService,
  // UserRepository,
])
void main() {
  group('Widget Tests - UI Components', () {
    
    group('Custom Button Widget', () {
      testWidgets('should render button with correct text', (WidgetTester tester) async {
        // Arrange
        const buttonText = 'Click Me';
        
        // Act
        await tester.pumpWidget(
          MaterialApp(
            home: Scaffold(
              body: CustomButton(
                text: buttonText,
                onPressed: () {},
              ),
            ),
          ),
        );

        // Assert
        expect(find.text(buttonText), findsOneWidget);
        expect(find.byType(CustomButton), findsOneWidget);
      });

      testWidgets('should handle button press correctly', (WidgetTester tester) async {
        // Arrange
        bool buttonPressed = false;
        
        // Act
        await tester.pumpWidget(
          MaterialApp(
            home: Scaffold(
              body: CustomButton(
                text: 'Press Me',
                onPressed: () => buttonPressed = true,
              ),
            ),
          ),
        );

        await tester.tap(find.byType(CustomButton));
        await tester.pump();

        // Assert
        expect(buttonPressed, isTrue);
      });

      testWidgets('should show loading state when loading', (WidgetTester tester) async {
        // Act
        await tester.pumpWidget(
          MaterialApp(
            home: Scaffold(
              body: CustomButton(
                text: 'Loading',
                onPressed: () {},
                isLoading: true,
              ),
            ),
          ),
        );

        // Assert
        expect(find.byType(CircularProgressIndicator), findsOneWidget);
        expect(find.text('Loading'), findsOneWidget);
      });
    });

    group('User Avatar Widget', () {
      testWidgets('should display user initials when no image', (WidgetTester tester) async {
        // Arrange
        const userName = 'John Doe';
        
        // Act
        await tester.pumpWidget(
          MaterialApp(
            home: Scaffold(
              body: UserAvatar(
                name: userName,
                size: 50,
              ),
            ),
          ),
        );

        // Assert
        expect(find.text('JD'), findsOneWidget);
        expect(find.byType(CircleAvatar), findsOneWidget);
      });

      testWidgets('should display network image when provided', (WidgetTester tester) async {
        // Arrange
        const imageUrl = 'https://example.com/avatar.jpg';
        
        // Act
        await tester.pumpWidget(
          MaterialApp(
            home: Scaffold(
              body: UserAvatar(
                name: 'John Doe',
                imageUrl: imageUrl,
                size: 50,
              ),
            ),
          ),
        );

        // Assert
        expect(find.byType(Image), findsOneWidget);
      });
    });

    group('Form Widgets', () {
      testWidgets('should validate form input correctly', (WidgetTester tester) async {
        // Arrange
        final formKey = GlobalKey<FormState>();
        String? emailValue;
        String? passwordValue;

        // Act
        await tester.pumpWidget(
          MaterialApp(
            home: Scaffold(
              body: Form(
                key: formKey,
                child: Column(
                  children: [
                    TextFormField(
                      decoration: InputDecoration(labelText: 'Email'),
                      validator: (value) {
                        emailValue = value;
                        if (value == null || !value.contains('@')) {
                          return 'Invalid email';
                        }
                        return null;
                      },
                    ),
                    TextFormField(
                      decoration: InputDecoration(labelText: 'Password'),
                      obscureText: true,
                      validator: (value) {
                        passwordValue = value;
                        if (value == null || value.length < 6) {
                          return 'Password too short';
                        }
                        return null;
                      },
                    ),
                    ElevatedButton(
                      onPressed: () {
                        if (formKey.currentState?.validate() ?? false) {
                          // Form is valid
                        }
                      },
                      child: Text('Submit'),
                    ),
                  ],
                ),
              ),
            ),
          ),
        );

        // Test invalid email
        await tester.enterText(find.byType(TextFormField).first, 'invalid-email');
        await tester.tap(find.byType(ElevatedButton));
        await tester.pump();

        expect(find.text('Invalid email'), findsOneWidget);

        // Test valid form
        await tester.enterText(find.byType(TextFormField).first, 'test@example.com');
        await tester.enterText(find.byType(TextFormField).last, 'password123');
        await tester.tap(find.byType(ElevatedButton));
        await tester.pump();

        expect(find.text('Invalid email'), findsNothing);
        expect(find.text('Password too short'), findsNothing);
      });
    });

    group('List Widgets', () {
      testWidgets('should display list items correctly', (WidgetTester tester) async {
        // Arrange
        final items = ['Item 1', 'Item 2', 'Item 3'];

        // Act
        await tester.pumpWidget(
          MaterialApp(
            home: Scaffold(
              body: ListView.builder(
                itemCount: items.length,
                itemBuilder: (context, index) {
                  return ListTile(
                    title: Text(items[index]),
                  );
                },
              ),
            ),
          ),
        );

        // Assert
        for (final item in items) {
          expect(find.text(item), findsOneWidget);
        }
      });

      testWidgets('should handle list scrolling', (WidgetTester tester) async {
        // Arrange
        final items = List.generate(50, (index) => 'Item $index');

        // Act
        await tester.pumpWidget(
          MaterialApp(
            home: Scaffold(
              body: ListView.builder(
                itemCount: items.length,
                itemBuilder: (context, index) {
                  return ListTile(
                    title: Text(items[index]),
                  );
                },
              ),
            ),
          ),
        );

        // Assert - Initial items visible
        expect(find.text('Item 0'), findsOneWidget);
        expect(find.text('Item 1'), findsOneWidget);

        // Scroll and check later items
        await tester.fling(find.byType(ListView), const Offset(0, -500), 1000);
        await tester.pumpAndSettle();

        expect(find.text('Item 30'), findsOneWidget);
      });
    });

    group('Screen Integration Tests', () {
      testWidgets('should navigate between screens correctly', (WidgetTester tester) async {
        // Act
        await tester.pumpWidget(
          MaterialApp(
            home: HomeScreen(),
          ),
        );

        // Assert - Home screen visible
        expect(find.text('Welcome'), findsOneWidget);
        expect(find.byType(ElevatedButton), findsOneWidget);

        // Navigate to next screen
        await tester.tap(find.byType(ElevatedButton));
        await tester.pumpAndSettle();

        // Assert - Next screen visible
        expect(find.text('Next Screen'), findsOneWidget);
      });
    });

    group('State Management Widget Tests', () {
      testWidgets('should rebuild widget when state changes', (WidgetTester tester) async {
        // Arrange
        int counter = 0;

        // Act
        await tester.pumpWidget(
          MaterialApp(
            home: Scaffold(
              body: StatefulBuilder(
                builder: (context, setState) {
                  return Column(
                    children: [
                      Text('Count: $counter'),
                      ElevatedButton(
                        onPressed: () {
                          setState(() {
                            counter++;
                          });
                        },
                        child: Text('Increment'),
                      ),
                    ],
                  );
                },
              ),
            ),
          ),
        );

        // Assert - Initial state
        expect(find.text('Count: 0'), findsOneWidget);

        // Act - Increment counter
        await tester.tap(find.byType(ElevatedButton));
        await tester.pump();

        // Assert - State updated
        expect(find.text('Count: 1'), findsOneWidget);
      });
    });

    group('Accessibility Tests', () {
      testWidgets('should have proper semantic labels', (WidgetTester tester) async {
        // Act
        await tester.pumpWidget(
          MaterialApp(
            home: Scaffold(
              body: Column(
                children: [
                  Text('Welcome', style: TextStyle(fontSize: 24)),
                  ElevatedButton(
                    onPressed: () {},
                    child: Text('Submit Form'),
                  ),
                ],
              ),
            ),
          ),
        );

        // Assert
        expect(
          tester.semantics(find.text('Welcome')),
          matchesSemantics(label: 'Welcome'),
        );
        expect(
          tester.semantics(find.byType(ElevatedButton)),
          matchesSemantics(label: 'Submit Form', button: true),
        );
      });
    });
  });
}
'''

    # Integration Tests
    integration_tests = '''// -----------------------------------------------------------------------------
// FILE: integration-tests.tpl.dart
// PURPOSE: Integration testing patterns for Flutter projects
// USAGE: Test interactions between multiple components and services
// DEPENDENCIES: integration_test, mockito, build_runner
// AUTHOR: [[.Author]]
// VERSION: [[.Version]]
// SINCE: [[.Version]]
// -----------------------------------------------------------------------------

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:your_app/main.dart' as app;
import 'package:your_app/services/auth_service.dart';
import 'package:your_app/services/api_service.dart';

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  group('Integration Tests - App Workflows', () {
    
    testWidgets('complete user authentication workflow', (WidgetTester tester) async {
      // Arrange
      app.main();
      await tester.pumpAndSettle();

      // Act - Navigate to login
      await tester.tap(find.text('Login'));
      await tester.pumpAndSettle();

      // Act - Fill login form
      await tester.enterText(find.byKey(Key('emailField')), 'test@example.com');
      await tester.enterText(find.byKey(Key('passwordField')), 'password123');
      await tester.tap(find.byKey(Key('loginButton')));
      await tester.pumpAndSettle();

      // Assert - User authenticated and redirected
      expect(find.text('Welcome, test@example.com'), findsOneWidget);
      expect(find.byType(HomeScreen), findsOneWidget);
    });

    testWidgets('data persistence across app restart', (WidgetTester tester) async {
      // Arrange
      app.main();
      await tester.pumpAndSettle();

      // Act - Save data
      await tester.tap(find.text('Settings'));
      await tester.pumpAndSettle();
      await tester.enterText(find.byKey(Key('usernameField')), 'TestUser');
      await tester.tap(find.text('Save'));
      await tester.pumpAndSettle();

      // Act - Restart app
      app.main();
      await tester.pumpAndSettle();

      // Assert - Data persisted
      await tester.tap(find.text('Settings'));
      await tester.pumpAndSettle();
      expect(find.text('TestUser'), findsOneWidget);
    });

    testWidgets('API integration with error handling', (WidgetTester tester) async {
      // Arrange - Mock API failure
      HttpOverrides.global = MockHttpOverrides();

      app.main();
      await tester.pumpAndSettle();

      // Act - Trigger API call
      await tester.tap(find.text('Load Data'));
      await tester.pumpAndSettle();

      // Assert - Error handled gracefully
      expect(find.text('Failed to load data'), findsOneWidget);
      expect(find.text('Retry'), findsOneWidget);
    });
  });
}

class MockHttpOverrides extends HttpOverrides {
  @override
  HttpClient createHttpClient(SecurityContext? context) {
    return MockHttpClient();
  }
}

class MockHttpClient extends Mock implements HttpClient {}
'''

    # Write all test files
    tests = {
        'unit-tests.tpl.dart': unit_tests,
        'widget-tests.tpl.dart': widget_tests,
        'integration-tests.tpl.dart': integration_tests,
    }
    
    for filename, content in tests.items():
        file_path = stack_path / 'tests' / filename
        file_path.write_text(content, encoding='utf-8')

def create_python_tests(stack_path: Path):
    """Create comprehensive Python testing templates"""
    
    unit_tests = '''#!/usr/bin/env python3
# -----------------------------------------------------------------------------
# FILE: unit-tests.tpl.py
# PURPOSE: Comprehensive unit testing patterns for Python projects
# USAGE: Import and extend for unit testing across Python applications
# DEPENDENCIES: pytest, pytest-asyncio, pytest-cov, unittest.mock
# AUTHOR: [[.Author]]
# VERSION: [[.Version]]
# SINCE: [[.Version]]
# -----------------------------------------------------------------------------

"""
Python Unit Tests Template
Purpose: Comprehensive unit testing patterns for Python projects
Usage: Import and extend for unit testing across Python applications
"""

import pytest
import unittest.mock as mock
from unittest.mock import Mock, patch, MagicMock, AsyncMock
import asyncio
from datetime import datetime
from typing import List, Dict, Any, Optional

# Import your application modules here
# from your_app.services.auth_service import AuthService
# from your_app.models.user import User
# from your_app.utils.validators import DataValidator

class TestAuthService:
    """Test authentication service functionality"""
    
    def setup_method(self):
        """Setup test environment before each test"""
        self.auth_service = AuthService()
        self.mock_user = User(
            id="123",
            email="test@example.com",
            name="Test User",
            created_at=datetime.now()
        )

    @pytest.mark.asyncio
    async def test_authenticate_user_with_valid_credentials(self):
        """Test successful user authentication"""
        # Arrange
        email = "test@example.com"
        password = "password123"
        expected_result = Result.success(self.mock_user)
        
        with patch.object(self.auth_service, '_validate_credentials') as mock_validate:
            mock_validate.return_value = self.mock_user
            
            # Act
            result = await self.auth_service.authenticate(email, password)
            
            # Assert
            assert result.is_success
            assert result.data.email == email
            mock_validate.assert_called_once_with(email, password)

    @pytest.mark.asyncio
    async def test_authenticate_user_with_invalid_credentials(self):
        """Test authentication failure with invalid credentials"""
        # Arrange
        email = "invalid@example.com"
        password = "wrongpassword"
        
        with patch.object(self.auth_service, '_validate_credentials') as mock_validate:
            mock_validate.side_effect = AuthenticationError("Invalid credentials")
            
            # Act & Assert
            with pytest.raises(AuthenticationError) as exc_info:
                await self.auth_service.authenticate(email, password)
            
            assert "Invalid credentials" in str(exc_info.value)
            mock_validate.assert_called_once_with(email, password)

    def test_password_hashing(self):
        """Test password hashing functionality"""
        # Arrange
        password = "test_password_123"
        
        # Act
        hashed = self.auth_service.hash_password(password)
        
        # Assert
        assert hashed != password
        assert len(hashed) >= 60  # bcrypt hash length
        assert self.auth_service.verify_password(password, hashed)

    def test_token_generation(self):
        """Test JWT token generation"""
        # Arrange
        user_id = "123"
        expires_in = 3600
        
        # Act
        token = self.auth_service.generate_token(user_id, expires_in)
        
        # Assert
        assert isinstance(token, str)
        assert len(token) > 100  # JWT tokens are long
        
        # Verify token can be decoded
        payload = self.auth_service.decode_token(token)
        assert payload['user_id'] == user_id

class TestDataValidator:
    """Test data validation functionality"""
    
    def test_email_validation(self):
        """Test email format validation"""
        # Valid emails
        valid_emails = [
            "test@example.com",
            "user.name+tag@domain.co.uk",
            "user123@test-domain.com",
            "a@b.co"
        ]
        
        for email in valid_emails:
            assert DataValidator.is_valid_email(email), f"Should validate {email}"
        
        # Invalid emails
        invalid_emails = [
            "invalid-email",
            "@domain.com",
            "user@",
            "user..name@domain.com",
            "",
            None
        ]
        
        for email in invalid_emails:
            assert not DataValidator.is_valid_email(email), f"Should not validate {email}"

    def test_password_strength_validation(self):
        """Test password strength requirements"""
        # Strong passwords
        strong_passwords = [
            "Str0ngP@ssw0rd!",
            "MyP@ssw0rd123",
            "C0mpl3x#P@ss"
        ]
        
        for password in strong_passwords:
            assert DataValidator.is_strong_password(password), f"Should validate {password}"
        
        # Weak passwords
        weak_passwords = [
            "password",
            "123456",
            "weak",
            "PASSWORD",
            "Password123",  # Missing special character
            "Password!"     # Missing number
        ]
        
        for password in weak_passwords:
            assert not DataValidator.is_strong_password(password), f"Should not validate {password}"

    def test_phone_number_validation(self):
        """Test phone number format validation"""
        # Valid phone numbers
        valid_phones = [
            "+1234567890",
            "(555) 123-4567",
            "555-123-4567",
            "555.123.4567",
            "5551234567"
        ]
        
        for phone in valid_phones:
            assert DataValidator.is_valid_phone(phone), f"Should validate {phone}"
        
        # Invalid phone numbers
        invalid_phones = [
            "123",
            "abc",
            "555",
            "",
            None
        ]
        
        for phone in invalid_phones:
            assert not DataValidator.is_valid_phone(phone), f"Should not validate {phone}"

class TestUserModel:
    """Test user model functionality"""
    
    def test_user_creation(self):
        """Test user model creation and validation"""
        # Valid user
        user = User(
            id="123",
            email="test@example.com",
            name="Test User",
            created_at=datetime.now()
        )
        
        assert user.id == "123"
        assert user.email == "test@example.com"
        assert user.is_valid()
        
        # Invalid user
        with pytest.raises(ValidationError):
            User(
                id="",
                email="invalid-email",
                name="",
                created_at=datetime.now()
            )

    def test_user_serialization(self):
        """Test user model serialization/deserialization"""
        # Arrange
        user_data = {
            "id": "123",
            "email": "test@example.com",
            "name": "Test User",
            "created_at": "2023-01-01T00:00:00Z"
        }
        
        # Act
        user = User.from_dict(user_data)
        serialized = user.to_dict()
        
        # Assert
        assert serialized["id"] == "123"
        assert serialized["email"] == "test@example.com"
        assert User.from_dict(serialized).email == user.email

class TestRepositoryPattern:
    """Test repository pattern implementation"""
    
    def setup_method(self):
        """Setup test repository"""
        self.mock_db = Mock()
        self.repository = UserRepository(self.mock_db)

    @pytest.mark.asyncio
    async def test_create_user(self):
        """Test user creation in repository"""
        # Arrange
        user_data = {
            "email": "test@example.com",
            "name": "Test User"
        }
        expected_user = User(id="123", **user_data, created_at=datetime.now())
        
        self.mock_db.insert.return_value = expected_user
        
        # Act
        result = await self.repository.create(user_data)
        
        # Assert
        assert result.email == user_data["email"]
        self.mock_db.insert.assert_called_once()

    @pytest.mark.asyncio
    async def test_find_user_by_id(self):
        """Test finding user by ID"""
        # Arrange
        user_id = "123"
        expected_user = User(id=user_id, email="test@example.com", name="Test", created_at=datetime.now())
        
        self.mock_db.find_one.return_value = expected_user
        
        # Act
        result = await self.repository.find_by_id(user_id)
        
        # Assert
        assert result.id == user_id
        self.mock_db.find_one.assert_called_once_with({"_id": user_id})

    @pytest.mark.asyncio
    async def test_find_user_not_found(self):
        """Test finding non-existent user"""
        # Arrange
        self.mock_db.find_one.return_value = None
        
        # Act
        result = await self.repository.find_by_id("nonexistent")
        
        # Assert
        assert result is None
        self.mock_db.find_one.assert_called_once()

class TestErrorHandling:
    """Test error handling patterns"""
    
    def test_custom_exceptions(self):
        """Test custom exception creation and handling"""
        # Test validation exception
        exception = ValidationError(
            field="email",
            message="Invalid email format",
            value="invalid-email"
        )
        
        assert exception.field == "email"
        assert exception.message == "Invalid email format"
        assert exception.value == "invalid-email"
        assert "email" in str(exception)
        assert "Invalid email format" in str(exception)

    @pytest.mark.asyncio
    async def test_service_error_handling(self):
        """Test service layer error handling"""
        service = ExternalService()
        
        with patch.object(service, '_make_request') as mock_request:
            mock_request.side_effect = ConnectionError("Service unavailable")
            
            with pytest.raises(ServiceError) as exc_info:
                await service.get_data()
            
            assert "Service unavailable" in str(exc_info.value)

class TestPerformance:
    """Test performance and optimization"""
    
    def test_caching_mechanism(self):
        """Test caching functionality"""
        cache = SimpleCache()
        
        # Test cache miss
        result = cache.get("key1")
        assert result is None
        
        # Test cache set and get
        cache.set("key1", "value1", ttl=60)
        result = cache.get("key1")
        assert result == "value1"
        
        # Test cache expiration
        cache.set("key2", "value2", ttl=0.001)  # Very short TTL
        import time
        time.sleep(0.002)
        result = cache.get("key2")
        assert result is None

    def test_bulk_operations(self):
        """Test bulk operation performance"""
        data = list(range(1000))
        
        # Test bulk processing
        processor = DataProcessor()
        result = processor.process_bulk(data)
        
        assert len(result) == 1000
        assert all(x > 0 for x in result)  # All processed values should be positive

# Example classes and utilities (replace with your actual implementations)
class AuthService:
    def __init__(self):
        pass
    
    async def authenticate(self, email: str, password: str) -> 'Result':
        return await self._validate_credentials(email, password)
    
    def _validate_credentials(self, email: str, password: str):
        pass
    
    def hash_password(self, password: str) -> str:
        import bcrypt
        return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    
    def verify_password(self, password: str, hashed: str) -> bool:
        import bcrypt
        return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))
    
    def generate_token(self, user_id: str, expires_in: int) -> str:
        import jwt
        import time
        payload = {
            'user_id': user_id,
            'exp': int(time.time()) + expires_in,
            'iat': int(time.time())
        }
        return jwt.encode(payload, 'secret', algorithm='HS256')
    
    def decode_token(self, token: str) -> dict:
        import jwt
        return jwt.decode(token, 'secret', algorithms=['HS256'])

class DataValidator:
    @staticmethod
    def is_valid_email(email: str) -> bool:
        if not email or not isinstance(email, str):
            return False
        import re
        pattern = r'^[\\w-\\.]+@([\\w-]+\\.)+[\\w-]{2,4}$'
        return re.match(pattern, email) is not None
    
    @staticmethod
    def is_strong_password(password: str) -> bool:
        if not password or len(password) < 8:
            return False
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(c in '!@#$%^&*(),.?":{}|<>' for c in password)
        return all([has_upper, has_lower, has_digit, has_special])
    
    @staticmethod
    def is_valid_phone(phone: str) -> bool:
        if not phone:
            return False
        import re
        pattern = r'^[\\d\\s\\-\\+\\(\\)]+$'
        return re.match(pattern, phone) and len(phone) >= 10

class User:
    def __init__(self, id: str, email: str, name: str, created_at: datetime):
        self.id = id
        self.email = email
        self.name = name
        self.created_at = created_at
    
    def is_valid(self) -> bool:
        return (
            self.id and 
            self.email and '@' in self.email and 
            self.name and 
            self.created_at
        )
    
    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "email": self.email,
            "name": self.name,
            "created_at": self.created_at.isoformat()
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> 'User':
        return cls(
            id=data["id"],
            email=data["email"],
            name=data["name"],
            created_at=datetime.fromisoformat(data["created_at"])
        )

class UserRepository:
    def __init__(self, db):
        self.db = db
    
    async def create(self, user_data: dict) -> User:
        user = User(
            id=str(hash(str(user_data))),
            **user_data,
            created_at=datetime.now()
        )
        self.db.insert(user)
        return user
    
    async def find_by_id(self, user_id: str) -> Optional[User]:
        return self.db.find_one({"_id": user_id})

class Result:
    def __init__(self, data=None, error=None):
        self.data = data
        self.error = error
    
    @property
    def is_success(self) -> bool:
        return self.error is None
    
    @property
    def is_failure(self) -> bool:
        return self.error is not None
    
    @classmethod
    def success(cls, data):
        return cls(data=data)
    
    @classmethod
    def failure(cls, error):
        return cls(error=error)

class ValidationError(Exception):
    def __init__(self, field: str, message: str, value=None):
        self.field = field
        self.message = message
        self.value = value
        super().__init__(f"{field}: {message}")

class AuthenticationError(Exception):
    pass

class ServiceError(Exception):
    pass

class ExternalService:
    async def get_data(self):
        return await self._make_request()
    
    async def _make_request(self):
        pass

class SimpleCache:
    def __init__(self):
        self._cache = {}
        self._ttl = {}
    
    def get(self, key: str):
        import time
        if key in self._cache:
            if key in self._ttl and time.time() > self._ttl[key]:
                del self._cache[key]
                del self._ttl[key]
                return None
            return self._cache[key]
        return None
    
    def set(self, key: str, value: any, ttl: int):
        import time
        self._cache[key] = value
        self._ttl[key] = time.time() + ttl

class DataProcessor:
    def process_bulk(self, data: List[int]) -> List[int]:
        return [x * 2 for x in data if x > 0]

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--cov=your_app", "--cov-report=html"])
'''

    # Write Python test files
    tests = {
        'unit-tests.tpl.py': unit_tests,
    }
    
    for filename, content in tests.items():
        file_path = stack_path / 'tests' / filename
        file_path.write_text(content, encoding='utf-8')

def create_node_tests(stack_path: Path):
    """Create comprehensive Node.js testing templates"""
    
    unit_tests = '''// -----------------------------------------------------------------------------
// FILE: unit-tests.tpl.js
// PURPOSE: Comprehensive unit testing patterns for Node.js projects
// USAGE: Import and extend for unit testing across Node.js applications
// DEPENDENCIES: jest, supertest, nock, mongodb-memory-server
// AUTHOR: [[.Author]]
// VERSION: [[.Version]]
// SINCE: [[.Version]]
// -----------------------------------------------------------------------------

/**
 * Node.js Unit Tests Template
 * Purpose: Comprehensive unit testing patterns for Node.js projects
 * Usage: Import and extend for unit testing across Node.js applications
 */

const request = require('supertest');
const nock = require('nock');
const { MongoMemoryServer } = require('mongodb-memory-server');

// Import your application modules here
// const AuthService = require('../services/authService');
// const User = require('../models/User');
// const DataValidator = require('../utils/validators');

describe('Unit Tests - Business Logic', () => {
  let authService;
  let mockUser;

  beforeEach(() => {
    authService = new AuthService();
    mockUser = {
      id: '123',
      email: 'test@example.com',
      name: 'Test User',
      createdAt: new Date()
    };
  });

  describe('Authentication Service', () => {
    test('should authenticate user with valid credentials', async () => {
      // Arrange
      const email = 'test@example.com';
      const password = 'password123';
      
      jest.spyOn(authService, '_validateCredentials')
        .mockResolvedValue(mockUser);

      // Act
      const result = await authService.authenticate(email, password);

      // Assert
      expect(result.success).toBe(true);
      expect(result.data.email).toBe(email);
      expect(authService._validateCredentials).toHaveBeenCalledWith(email, password);
    });

    test('should return error for invalid credentials', async () => {
      // Arrange
      const email = 'invalid@example.com';
      const password = 'wrongpassword';
      
      jest.spyOn(authService, '_validateCredentials')
        .mockRejectedValue(new Error('Invalid credentials'));

      // Act & Assert
      await expect(authService.authenticate(email, password))
        .rejects.toThrow('Invalid credentials');
    });

    test('should hash password correctly', () => {
      // Arrange
      const password = 'test_password_123';

      // Act
      const hashed = authService.hashPassword(password);

      // Assert
      expect(hashed).not.toBe(password);
      expect(hashed.length).toBeGreaterThan(50);
      expect(authService.verifyPassword(password, hashed)).toBe(true);
    });

    test('should generate and validate JWT tokens', () => {
      // Arrange
      const userId = '123';
      const expiresIn = 3600;

      // Act
      const token = authService.generateToken(userId, expiresIn);

      // Assert
      expect(typeof token).toBe('string');
      expect(token.length).toBeGreaterThan(100);

      const payload = authService.decodeToken(token);
      expect(payload.userId).toBe(userId);
    });
  });

  describe('Data Validation', () => {
    test('should validate email format correctly', () => {
      // Valid emails
      const validEmails = [
        'test@example.com',
        'user.name+tag@domain.co.uk',
        'user123@test-domain.com'
      ];

      validEmails.forEach(email => {
        expect(DataValidator.isValidEmail(email)).toBe(true);
      });

      // Invalid emails
      const invalidEmails = [
        'invalid-email',
        '@domain.com',
        'user@',
        ''
      ];

      invalidEmails.forEach(email => {
        expect(DataValidator.isValidEmail(email)).toBe(false);
      });
    });

    test('should validate password strength', () => {
      // Strong passwords
      const strongPasswords = [
        'Str0ngP@ssw0rd!',
        'MyP@ssw0rd123'
      ];

      strongPasswords.forEach(password => {
        expect(DataValidator.isStrongPassword(password)).toBe(true);
      });

      // Weak passwords
      const weakPasswords = [
        'password',
        '123456',
        'PASSWORD'
      ];

      weakPasswords.forEach(password => {
        expect(DataValidator.isStrongPassword(password)).toBe(false);
      });
    });
  });

  describe('User Model', () => {
    test('should create user with valid data', () => {
      // Arrange
      const userData = {
        email: 'test@example.com',
        name: 'Test User'
      };

      // Act
      const user = new User(userData);

      // Assert
      expect(user.email).toBe(userData.email);
      expect(user.name).toBe(userData.name);
      expect(user.isValid()).toBe(true);
    });

    test('should validate user constraints', () => {
      // Arrange
      const invalidUserData = {
        email: 'invalid-email',
        name: ''
      };

      // Act & Assert
      expect(() => new User(invalidUserData)).toThrow();
    });

    test('should serialize to JSON correctly', () => {
      // Arrange
      const user = new User({
        id: '123',
        email: 'test@example.com',
        name: 'Test User'
      });

      // Act
      const json = user.toJSON();

      // Assert
      expect(json.id).toBe('123');
      expect(json.email).toBe('test@example.com');
    });
  });

  describe('Repository Pattern', () => {
    let userRepository;
    let mockDb;

    beforeEach(() => {
      mockDb = {
        insert: jest.fn(),
        findOne: jest.fn(),
        find: jest.fn()
      };
      userRepository = new UserRepository(mockDb);
    });

    test('should create user successfully', async () => {
      // Arrange
      const userData = {
        email: 'test@example.com',
        name: 'Test User'
      };
      const expectedUser = new User({ id: '123', ...userData });

      mockDb.insert.mockResolvedValue(expectedUser);

      // Act
      const result = await userRepository.create(userData);

      // Assert
      expect(result.email).toBe(userData.email);
      expect(mockDb.insert).toHaveBeenCalledWith(
        expect.objectContaining(userData)
      );
    });

    test('should find user by ID', async () => {
      // Arrange
      const userId = '123';
      const expectedUser = new User({ id: userId, email: 'test@example.com' });

      mockDb.findOne.mockResolvedValue(expectedUser);

      // Act
      const result = await userRepository.findById(userId);

      // Assert
      expect(result.id).toBe(userId);
      expect(mockDb.findOne).toHaveBeenCalledWith({ _id: userId });
    });

    test('should handle user not found', async () => {
      // Arrange
      mockDb.findOne.mockResolvedValue(null);

      // Act
      const result = await userRepository.findById('nonexistent');

      // Assert
      expect(result).toBeNull();
    });
  });

  describe('Error Handling', () => {
    test('should create custom exceptions with proper context', () => {
      // Arrange
      const exception = new ValidationError(
        'email',
        'Invalid email format',
        'invalid-email'
      );

      // Assert
      expect(exception.field).toBe('email');
      expect(exception.message).toBe('Invalid email format');
      expect(exception.value).toBe('invalid-email');
      expect(exception.toString()).toContain('email');
    });

    test('should handle async errors properly', async () => {
      // Arrange
      const service = new ExternalService();
      jest.spyOn(service, '_makeRequest')
        .mockRejectedValue(new Error('Service unavailable'));

      // Act & Assert
      await expect(service.getData()).rejects.toThrow('Service unavailable');
    });
  });

  describe('Performance Tests', () => {
    test('should complete operation within time limit', async () => {
      // Arrange
      const startTime = Date.now();

      // Act
      await performExpensiveOperation();

      // Assert
      const duration = Date.now() - startTime;
      expect(duration).toBeLessThan(1000); // Should complete in < 1s
    });

    test('should handle large datasets efficiently', () => {
      // Arrange
      const largeList = Array.from({ length: 10000 }, (_, i) => i);

      // Act
      const startTime = Date.now();
      const result = largeList.filter(x => x % 2 === 0);
      const duration = Date.now() - startTime;

      // Assert
      expect(result.length).toBe(5000);
      expect(duration).toBeLessThan(100);
    });
  });
});

// Example classes and utilities (replace with your actual implementations)
class AuthService {
  async authenticate(email, password) {
    return await this._validateCredentials(email, password);
  }

  hashPassword(password) {
    const bcrypt = require('bcrypt');
    return bcrypt.hashSync(password, 10);
  }

  verifyPassword(password, hash) {
    const bcrypt = require('bcrypt');
    return bcrypt.compareSync(password, hash);
  }

  generateToken(userId, expiresIn) {
    const jwt = require('jsonwebtoken');
    return jwt.sign(
      { userId },
      'secret',
      { expiresIn: `${expiresIn}s` }
    );
  }

  decodeToken(token) {
    const jwt = require('jsonwebtoken');
    return jwt.verify(token, 'secret');
  }
}

class DataValidator {
  static isValidEmail(email) {
    if (!email || typeof email !== 'string') return false;
    const emailRegex = /^[\\w-\\.]+@([\\w-]+\\.)+[\\w-]{2,4}$/;
    return emailRegex.test(email);
  }

  static isStrongPassword(password) {
    if (!password || password.length < 8) return false;
    const hasUpper = /[A-Z]/.test(password);
    const hasLower = /[a-z]/.test(password);
    const hasDigit = /[0-9]/.test(password);
    const hasSpecial = /[!@#$%^&*(),.?":{}|<>]/.test(password);
    return hasUpper && hasLower && hasDigit && hasSpecial;
  }
}

class User {
  constructor(data) {
    this.id = data.id || this.generateId();
    this.email = data.email;
    this.name = data.name;
    this.createdAt = data.createdAt || new Date();
  }

  isValid() {
    return (
      this.id &&
      this.email &&
      this.email.includes('@') &&
      this.name &&
      this.createdAt
    );
  }

  toJSON() {
    return {
      id: this.id,
      email: this.email,
      name: this.name,
      createdAt: this.createdAt
    };
  }

  generateId() {
    return Math.random().toString(36).substr(2, 9);
  }
}

class UserRepository {
  constructor(db) {
    this.db = db;
  }

  async create(userData) {
    const user = new User(userData);
    await this.db.insert(user);
    return user;
  }

  async findById(userId) {
    return await this.db.findOne({ _id: userId });
  }
}

class ValidationError extends Error {
  constructor(field, message, value) {
    super(`${field}: ${message}`);
    this.field = field;
    this.message = message;
    this.value = value;
  }
}

class ExternalService {
  async getData() {
    return await this._makeRequest();
  }
}

async function performExpensiveOperation() {
  await new Promise(resolve => setTimeout(resolve, 100));
}

module.exports = {
  AuthService,
  DataValidator,
  User,
  UserRepository,
  ValidationError
};

# Write Node.js test files
    tests = {
        'unit-tests.tpl.js': unit_tests,
    }
    
    for filename, content in tests.items():
        file_path = stack_path / 'tests' / filename
        file_path.write_text(content, encoding='utf-8')

def main():
    """Generate comprehensive testing frameworks for all stacks"""
    base_dir = Path('stacks')
    
    print("🧪 Generating Comprehensive Testing Frameworks")
    print("=" * 50)
    
    total_files = 0
    
    for stack_name, config in STACKS.items():
        stack_path = base_dir / stack_name / 'base'
        tests_dir = stack_path / 'tests'
        
        print(f"📦 Creating tests for {stack_name.title()}...")
        
        # Ensure tests directory exists
        tests_dir.mkdir(parents=True, exist_ok=True)
        
        # Generate stack-specific tests
        if stack_name == 'flutter':
            create_flutter_tests(stack_path)
        elif stack_name == 'python':
            create_python_tests(stack_path)
        elif stack_name == 'node':
            create_node_tests(stack_path)
        elif stack_name == 'react':
            create_react_tests(stack_path)
        # Add more stack generators as needed
        
        # Count generated files
        stack_files = len(list(tests_dir.glob('*.tpl.*')))
        total_files += stack_files
        
        print(f"   ✅ Generated {stack_files} test templates")
    
    print(f"\\n🎉 Testing framework generation complete!")
    print(f"📁 Total test templates created: {total_files}")
    print(f"🏗️  Ready for comprehensive testing across all stacks")

if __name__ == "__main__":
    main()
    """Create comprehensive React testing templates"""
    
    unit_tests = '''// -----------------------------------------------------------------------------
// FILE: unit-tests.tpl.jsx
// PURPOSE: Comprehensive unit testing patterns for React projects
// USAGE: Import and extend for unit testing across React applications
// DEPENDENCIES: @testing-library/react, @testing-library/jest-dom, @testing-library/user-event
// AUTHOR: [[.Author]]
// VERSION: [[.Version]]
// SINCE: [[.Version]]
// -----------------------------------------------------------------------------

/**
 * React Unit Tests Template
 * Purpose: Comprehensive unit testing patterns for React projects
 * Usage: Import and extend for unit testing across React applications
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

describe('Unit Tests - React Components', () => {
  
  describe('Custom Button Component', () => {
    test('renders button with correct text', () => {
      // Arrange
      const buttonText = 'Click Me';
      
      // Act
      render(<CustomButton>{buttonText}</CustomButton>);
      
      // Assert
      expect(screen.getByText(buttonText)).toBeInTheDocument();
      expect(screen.getByRole('button')).toBeInTheDocument();
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

    test('shows loading state correctly', () => {
      // Arrange & Act
      render(<CustomButton isLoading>Loading</CustomButton>);
      
      // Assert
      expect(screen.getByRole('button')).toBeDisabled();
      expect(screen.getByTestId('loading-spinner')).toBeInTheDocument();
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
  });

  describe('User Form Component', () => {
    test('renders form fields correctly', () => {
      // Arrange & Act
      render(<UserForm />);
      
      // Assert
      expect(screen.getByLabelText(/name/i)).toBeInTheDocument();
      expect(screen.getByLabelText(/email/i)).toBeInTheDocument();
      expect(screen.getByRole('button', { name: /submit/i })).toBeInTheDocument();
    });

    test('validates form inputs correctly', async () => {
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
  });

  describe('Data Table Component', () => {
    const mockData = [
      { id: 1, name: 'John Doe', email: 'john@example.com' },
      { id: 2, name: 'Jane Smith', email: 'jane@example.com' },
    ];

    test('renders table with correct data', () => {
      // Arrange & Act
      render(<DataTable data={mockData} />);
      
      // Assert
      expect(screen.getByText('John Doe')).toBeInTheDocument();
      expect(screen.getByText('jane@example.com')).toBeInTheDocument();
    });

    test('handles sorting correctly', async () => {
      // Arrange
      const user = userEvent.setup();
      render(<DataTable data={mockData} />);
      
      // Act
      await user.click(screen.getByRole('columnheader', { name: /name/i }));
      
      // Assert
      const rows = screen.getAllByRole('row');
      expect(rows[1]).toHaveTextContent('Jane Smith'); // Sorted ascending
    });

    test('filters data correctly', async () => {
      // Arrange
      const user = userEvent.setup();
      render(<DataTable data={mockData} />);
      
      // Act
      await user.type(screen.getByPlaceholderText(/search/i), 'John');
      
      // Assert
      expect(screen.getByText('John Doe')).toBeInTheDocument();
      expect(screen.queryByText('Jane Smith')).not.toBeInTheDocument();
    });
  });

  describe('Modal Component', () => {
    test('renders when open', () => {
      // Arrange & Act
      render(<Modal isOpen onClose={jest.fn()}><p>Modal Content</p></Modal>);
      
      // Assert
      expect(screen.getByText('Modal Content')).toBeInTheDocument();
      expect(screen.getByRole('dialog')).toBeInTheDocument();
    });

    test('does not render when closed', () => {
      // Arrange & Act
      render(<Modal isOpen={false} onClose={jest.fn()}><p>Modal Content</p></Modal>);
      
      // Assert
      expect(screen.queryByText('Modal Content')).not.toBeInTheDocument();
    });

    test('calls onClose when close button clicked', async () => {
      // Arrange
      const onClose = jest.fn();
      const user = userEvent.setup();
      
      render(<Modal isOpen onClose={onClose}><p>Modal Content</p></Modal>);
      
      // Act
      await user.click(screen.getByRole('button', { name: /close/i }));
      
      // Assert
      expect(onClose).toHaveBeenCalledTimes(1);
    });
  });

  describe('Navigation Components', () => {
    test('renders navigation links correctly', () => {
      // Arrange
      const navItems = [
        { path: '/', label: 'Home' },
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
        { path: '/', label: 'Home' },
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

  describe('Loading States', () => {
    test('shows loading spinner during async operations', async () => {
      // Arrange
      const AsyncComponent = () => {
        const [loading, setLoading] = React.useState(true);
        
        React.useEffect(() => {
          setTimeout(() => setLoading(false), 100);
        }, []);
        
        if (loading) return <div data-testid="loading-spinner">Loading...</div>;
        return <div>Loaded</div>;
      };
      
      // Act
      render(<AsyncComponent />);
      
      // Assert
      expect(screen.getByTestId('loading-spinner')).toBeInTheDocument();
      
      // Wait for loading to complete
      await waitFor(() => {
        expect(screen.getByText('Loaded')).toBeInTheDocument();
      });
    });
  });

  describe('Accessibility Tests', () => {
    test('components have proper ARIA labels', () => {
      // Arrange & Act
      render(<CustomButton aria-label="Custom Action">Click</CustomButton>);
      
      // Assert
      expect(screen.getByLabelText('Custom Action')).toBeInTheDocument();
    });

    test('keyboard navigation works correctly', async () => {
      // Arrange
      const user = userEvent.setup();
      render(
        <div>
          <CustomButton>Button 1</CustomButton>
          <CustomButton>Button 2</CustomButton>
        </div>
      );
      
      // Act
      await user.tab();
      expect(screen.getByText('Button 1')).toHaveFocus();
      
      await user.tab();
      expect(screen.getByText('Button 2')).toHaveFocus();
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
  
  const handleSubmit = (e) => {
    e.preventDefault();
    const formData = new FormData(e.target);
    const data = Object.fromEntries(formData);
    
    // Simple validation
    const newErrors = {};
    if (!data.name) newErrors.name = 'Name is required';
    if (!data.email) newErrors.email = 'Email is required';
    
    if (Object.keys(newErrors).length > 0) {
      setErrors(newErrors);
      return;
    }
    
    onSubmit(data);
  };
  
  return (
    <form onSubmit={handleSubmit}>
      <label>
        Name:
        <input name="name" />
        {errors.name && <span>{errors.name}</span>}
      </label>
      <label>
        Email:
        <input name="email" type="email" />
        {errors.email && <span>{errors.email}</span>}
      </label>
      <button type="submit">Submit</button>
    </form>
  );
};

const DataTable = ({ data }) => {
  const [sortField, setSortField] = React.useState('name');
  const [filter, setFilter] = React.useState('');
  
  const filteredData = data.filter(item => 
    item.name.toLowerCase().includes(filter.toLowerCase()) ||
    item.email.toLowerCase().includes(filter.toLowerCase())
  );
  
  const sortedData = [...filteredData].sort((a, b) => 
    a[sortField].localeCompare(b[sortField])
  );
  
  return (
    <div>
      <input 
        placeholder="Search..." 
        value={filter}
        onChange={(e) => setFilter(e.target.value)}
      />
      <table>
        <thead>
          <tr>
            <th onClick={() => setSortField('name')}>Name</th>
            <th onClick={() => setSortField('email')}>Email</th>
          </tr>
        </thead>
        <tbody>
          {sortedData.map(item => (
            <tr key={item.id}>
              <td>{item.name}</td>
              <td>{item.email}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
};

const Modal = ({ isOpen, onClose, children }) => {
  if (!isOpen) return null;
  
  return (
    <div role="dialog">
      <button onClick={onClose}>Close</button>
      {children}
    </div>
  );
};

const Navigation = ({ items }) => {
  const location = window.location;
  
  return (
    <nav>
      {items.map(item => (
        <a 
          key={item.path}
          href={item.path}
          className={location.pathname === item.path ? 'active' : ''}
        >
          {item.label}
        </a>
      ))}
    </nav>
  );
};

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
  ErrorBoundary
};
