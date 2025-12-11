///
/// File: unit-tests.tpl.dart
/// Purpose: Template for unknown implementation
/// Generated for: {{PROJECT_NAME}}
///

/// Template: unit-tests.tpl.dart
/// Purpose: unit-tests template
/// Stack: flutter
/// Tier: base

# Universal Template System - Flutter Stack
# Generated: 2025-12-10
# Purpose: Testing utilities
# Tier: base
# Stack: flutter
# Category: testing

// -----------------------------------------------------------------------------
// FILE: unit-tests.tpl.dart
// PURPOSE: Comprehensive unit testing patterns for Flutter projects
// USAGE: Import and extend for unit testing across Flutter applications
// DEPENDENCIES: flutter_test, mockito, build_runner
// AUTHOR: [[.Author]]
// VERSION: [[.Version]]
// SINCE: [[.Version]]
// -----------------------------------------------------------------------------

/// Flutter Unit Tests Template
/// Purpose: Comprehensive unit testing patterns for Flutter projects
/// Usage: Import and extend for unit testing across Flutter applications

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:mockito/mockito.dart';
import 'package:mockito/annotations.dart';
import 'dart:async';

// Import your application modules here
// import 'package:your_app/services/auth_service.dart';
// import 'package:your_app/utils/data_validator.dart';
// import 'package:your_app/models/user_model.dart';

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
    return RegExp(r'^[\w-\.]+@([\w-]+\.)+[\w-]{2,4}$').hasMatch(email);
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
