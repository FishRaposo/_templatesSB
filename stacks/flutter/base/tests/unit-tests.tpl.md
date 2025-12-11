# Flutter Unit Testing Template
# Comprehensive unit testing patterns for Flutter projects using flutter_test and mockito

"""
Flutter Unit Test Patterns
Adapted from Python test patterns to Flutter/Dart with comprehensive coverage
"""

import 'package:flutter_test/flutter_test.dart';
import 'package:mockito/mockito.dart';
import 'package:mockito/annotations.dart';
import 'package:your_app/services/auth_service.dart';
import 'package:your_app/services/api_service.dart';
import 'package:your_app/services/storage_service.dart';
import 'package:your_app/services/validation_service.dart';
import 'package:your_app/models/user_model.dart';
import 'package:your_app/models/product_model.dart';
import 'package:your_app/utils/constants.dart';
import 'package:your_app/utils/helpers.dart';

// ====================
// BASIC UNIT TEST PATTERNS
// ====================

class TestSimpleFunctions {
  """Basic unit test patterns for Dart functions"""
  
  void testStringValidation() {
    test('should validate email format correctly', () {
      // Test valid emails
      expect(ValidationService.isValidEmail('test@example.com'), isTrue);
      expect(ValidationService.isValidEmail('user.name+tag@domain.co.uk'), isTrue);
      
      // Test invalid emails
      expect(ValidationService.isValidEmail('invalid-email'), isFalse);
      expect(ValidationService.isValidEmail('@domain.com'), isFalse);
      expect(ValidationService.isValidEmail(''), isFalse);
      expect(ValidationService.isValidEmail(null), isFalse);
    });
    
    test('should validate password strength', () {
      // Strong passwords
      expect(ValidationService.isPasswordStrong('Str0ngP@ssw0rd!'), isTrue);
      expect(ValidationService.isPasswordStrong('MyP@ssw0rd123'), isTrue);
      
      // Weak passwords
      expect(ValidationService.isPasswordStrong('password'), isFalse);
      expect(ValidationService.isPasswordStrong('123456'), isFalse);
      expect(ValidationService.isPasswordStrong('short'), isFalse);
    });
    
    test('should validate phone numbers', () {
      // Valid phone numbers
      expect(ValidationService.isValidPhone('+1234567890'), isTrue);
      expect(ValidationService.isValidPhone('(123) 456-7890'), isTrue);
      
      // Invalid phone numbers
      expect(ValidationService.isValidPhone('123'), isFalse);
      expect(ValidationService.isValidPhone('invalid'), isFalse);
    });
  }
  
  void testNumericOperations() {
    test('should calculate discounts correctly', () {
      // Test percentage discounts
      expect(calculateDiscount(100, 10), equals(90.0));
      expect(calculateDiscount(50, 25), equals(37.5));
      
      // Test edge cases
      expect(calculateDiscount(0, 10), equals(0.0));
      expect(calculateDiscount(100, 0), equals(100.0));
      expect(calculateDiscount(100, 100), equals(0.0));
    });
    
    test('should handle tax calculations', () {
      expect(calculateTax(100, 8.5), equals(108.5));
      expect(calculateTax(50, 0), equals(50.0));
      expect(calculateTax(0, 10), equals(0.0));
    });
    
    test('should format currency correctly', () {
      expect(formatCurrency(1234.56), equals('\$1,234.56'));
      expect(formatCurrency(0), equals('\$0.00'));
      expect(formatCurrency(1000000), equals('\$1,000,000.00'));
    });
  }
  
  void testDateTimeOperations() {
    test('should format dates correctly', () {
      final date = DateTime(2023, 12, 25);
      expect(formatDate(date), equals('December 25, 2023'));
      expect(formatDateShort(date), equals('12/25/2023'));
      expect(formatDateISO(date), equals('2023-12-25'));
    });
    
    test('should calculate age correctly', () {
      final now = DateTime.now();
      final birthDate = DateTime(now.year - 25, now.month, now.day);
      expect(calculateAge(birthDate), equals(25));
      
      // Test edge case - birthday not yet passed
      final futureBirthDate = DateTime(now.year - 25, now.month + 1, now.day);
      expect(calculateAge(futureBirthDate), equals(24));
    });
    
    test('should determine if date is in future/past', () {
      final now = DateTime.now();
      final pastDate = now.subtract(Duration(days: 1));
      final futureDate = now.add(Duration(days: 1));
      
      expect(isDateInPast(pastDate), isTrue);
      expect(isDateInPast(futureDate), isFalse);
      expect(isDateInFuture(futureDate), isTrue);
      expect(isDateInFuture(pastDate), isFalse);
    });
  }
}

// ====================
// MOCK TESTING PATTERNS
// ====================

@GenerateMocks([AuthService, ApiService, StorageService])
class TestWithMocking {
  """Demonstrate mocking patterns with mockito"""
  
  late MockAuthService mockAuthService;
  late MockApiService mockApiService;
  late MockStorageService mockStorageService;
  
  void setUp() {
    mockAuthService = MockAuthService();
    mockApiService = MockApiService();
    mockStorageService = MockStorageService();
  }
  
  void testServiceWithMockedDependencies() {
    test('should authenticate user with mocked service', () async {
      // Arrange
      const email = 'test@example.com';
      const password = 'password123';
      final expectedUser = User(
        id: '1',
        email: email,
        name: 'Test User',
        createdAt: DateTime.now(),
      );
      
      when(mockAuthService.signIn(email, password))
          .thenAnswer((_) async => expectedUser);
      
      // Act
      final result = await mockAuthService.signIn(email, password);
      
      // Assert
      expect(result.email, equals(email));
      expect(result.name, equals('Test User'));
      verify(mockAuthService.signIn(email, password)).called(1);
    });
    
    test('should handle authentication failure', () async {
      // Arrange
      when(mockAuthService.signIn(any, any))
          .thenThrow(AuthException('Invalid credentials'));
      
      // Act & Assert
      expect(
        () => mockAuthService.signIn('invalid@example.com', 'wrong'),
        throwsA(isA<AuthException>()),
      );
    });
    
    test('should cache user data after successful login', () async {
      // Arrange
      final user = User(
        id: '1',
        email: 'test@example.com',
        name: 'Test User',
        createdAt: DateTime.now(),
      );
      
      when(mockAuthService.signIn(any, any))
          .thenAnswer((_) async => user);
      when(mockStorageService.saveUserData(user))
          .thenAnswer((_) async {});
      
      // Act
      final result = await mockAuthService.signIn('test@example.com', 'password');
      await mockStorageService.saveUserData(result);
      
      // Assert
      verify(mockStorageService.saveUserData(user)).called(1);
    });
  }
  
  void testApiCallsWithMockedResponses() {
    test('should fetch user data with mocked API response', () async {
      // Arrange
      const userId = '123';
      final mockResponse = {
        'id': userId,
        'email': 'test@example.com',
        'name': 'Test User',
        'created_at': '2023-01-01T00:00:00Z',
      };
      
      when(mockApiService.get('/users/$userId'))
          .thenAnswer((_) async => mockResponse);
      
      // Act
      final response = await mockApiService.get('/users/$userId');
      
      // Assert
      expect(response['id'], equals(userId));
      expect(response['email'], equals('test@example.com'));
      verify(mockApiService.get('/users/$userId')).called(1);
    });
    
    test('should handle API errors gracefully', () async {
      // Arrange
      when(mockApiService.get(any))
          .thenThrow(ApiException('Network error', 500));
      
      // Act & Assert
      expect(
        () => mockApiService.get('/users/123'),
        throwsA(isA<ApiException>()),
      );
    });
    
    test('should retry failed API calls', () async {
      // Arrange
      when(mockApiService.get(any))
          .thenThrow(ApiException('Network error', 500))
          .thenAnswer((_) async => {'id': '123', 'name': 'Test User'});
      
      // Act
      final result = await retryApiCall(() => mockApiService.get('/users/123'));
      
      // Assert
      expect(result['id'], equals('123'));
      verify(mockApiService.get('/users/123')).called(2);
    });
  }
}

// ====================
// PARAMETERIZED AND TABLE-DRIVEN TESTS
// ====================

class TestParameterized {
  """Parameterized test patterns"""
  
  void testDiscountCalculation() {
    // Table-driven tests for discount calculation
    final testCases = [
      ('regular', 100.0, 0.0),
      ('premium', 50.0, 2.5),
      ('premium', 200.0, 20.0),
      ('vip', 100.0, 15.0),
      ('vip', 1000.0, 150.0),
    ];
    
    for (final (customerType, amount, expected) in testCases) {
      test('should calculate discount for $customerType customer with \$$amount', () {
        final discount = calculateDiscount(customerType, amount);
        expect(discount, closeTo(expected, 0.01));
      });
    }
  }
  
  void testInputValidation() {
    // Test various input validation scenarios
    final validationCases = [
      ('', false, 'empty string'),
      ('invalid-email', false, 'invalid email format'),
      ('test@', false, 'incomplete email'),
      ('test@example.com', true, 'valid email'),
      ('user.name+tag@domain.co.uk', true, 'complex valid email'),
    ];
    
    for (final (input, expected, description) in validationCases) {
      test('should validate email: $description', () {
        expect(ValidationService.isValidEmail(input), equals(expected));
      });
    }
  }
  
  void testPasswordStrength() {
    final passwordCases = [
      ('password', false, 'common password'),
      ('123456', false, 'numeric sequence'),
      ('short', false, 'too short'),
      ('Str0ngP@ssw0rd!', true, 'strong password'),
      ('MyP@ssw0rd123', true, 'good password'),
      ('CorrectHorseBatteryStaple', true, 'long passphrase'),
    ];
    
    for (final (password, expected, description) in passwordCases) {
      test('should validate password strength: $description', () {
        expect(ValidationService.isPasswordStrong(password), equals(expected));
      });
    }
  }
}

// ====================
// ASYNC TESTING PATTERNS
// ====================

class TestAsyncFunctions {
  """Async function testing patterns"""
  
  void testAsyncApiCalls() {
    test('should fetch user data asynchronously', () async {
      // Arrange
      const userId = '123';
      final expectedUser = User(
        id: userId,
        email: 'test@example.com',
        name: 'Test User',
        createdAt: DateTime.now(),
      );
      
      // Act
      final user = await fetchUserAsync(userId);
      
      // Assert
      expect(user.id, equals(userId));
      expect(user.email, isNotNull);
    });
    
    test('should handle async errors', () async {
      // Act & Assert
      expect(
        () => fetchUserAsync('invalid-id'),
        throwsA(isA<Exception>()),
      );
    });
    
    test('should timeout long-running async operations', () async {
      // Act & Assert
      expect(
        () => fetchUserAsync('slow-user').timeout(Duration(seconds: 1)),
        throwsA(isA<TimeoutException>()),
      );
    });
  }
  
  void testAsyncWithMock() {
    test('should test async functions with mocks', () async {
      // Arrange
      final mockApiService = MockApiService();
      final mockResponse = {
        'id': '123',
        'email': 'test@example.com',
        'name': 'Test User',
      };
      
      when(mockApiService.get(any))
          .thenAnswer((_) async => mockResponse);
      
      // Act
      final result = await fetchUserFromApi(mockApiService, '123');
      
      // Assert
      expect(result['name'], equals('Test User'));
      verify(mockApiService.get('/users/123')).called(1);
    });
  }
  
  void testConcurrentAsyncOperations() {
    test('should handle multiple concurrent async operations', () async {
      // Act
      final results = await Future.wait([
        fetchUserAsync('1'),
        fetchUserAsync('2'),
        fetchUserAsync('3'),
      ]);
      
      // Assert
      expect(results.length, equals(3));
      expect(results.every((user) => user != null), isTrue);
    });
    
    test('should handle async stream operations', () async {
      // Arrange
      final results = <String>[];
      
      // Act
      await for (final user in streamUsers()) {
        results.add(user.id);
        if (results.length >= 3) break;
      }
      
      // Assert
      expect(results.length, greaterThanOrEqualTo(3));
    });
  }
}

// ====================
// MODEL TESTING PATTERNS
// ====================

class TestModels {
  """Test data models and their methods"""
  
  void testUserModel() {
    test('should create valid user model', () {
      // Arrange
      final user = User(
        id: '123',
        email: 'test@example.com',
        name: 'Test User',
        createdAt: DateTime.now(),
      );
      
      // Assert
      expect(user.id, equals('123'));
      expect(user.email, equals('test@example.com'));
      expect(user.name, equals('Test User'));
      expect(user.isValid, isTrue);
    });
    
    test('should validate user model constraints', () {
      // Test invalid email
      expect(
        () => User(
          id: '123',
          email: 'invalid-email',
          name: 'Test User',
          createdAt: DateTime.now(),
        ),
        throwsA(isA<ArgumentError>()),
      );
      
      // Test empty name
      expect(
        () => User(
          id: '123',
          email: 'test@example.com',
          name: '',
          createdAt: DateTime.now(),
        ),
        throwsA(isA<ArgumentError>()),
      );
    });
    
    test('should serialize and deserialize correctly', () {
      // Arrange
      final originalUser = User(
        id: '123',
        email: 'test@example.com',
        name: 'Test User',
        createdAt: DateTime(2023, 1, 1),
      );
      
      // Act
      final json = originalUser.toJson();
      final deserializedUser = User.fromJson(json);
      
      // Assert
      expect(deserializedUser.id, equals(originalUser.id));
      expect(deserializedUser.email, equals(originalUser.email));
      expect(deserializedUser.name, equals(originalUser.name));
      expect(deserializedUser.createdAt, equals(originalUser.createdAt));
    });
  }
  
  void testProductModel() {
    test('should calculate product totals correctly', () {
      // Arrange
      final product = Product(
        id: '1',
        name: 'Test Product',
        price: 100.0,
        quantity: 2,
      );
      
      // Act & Assert
      expect(product.totalPrice, equals(200.0));
      expect(product.hasStock, isTrue);
    });
    
    test('should handle product validation', () {
      // Valid product
      final validProduct = Product(
        id: '1',
        name: 'Valid Product',
        price: 99.99,
        quantity: 10,
      );
      expect(validProduct.isValid, isTrue);
      
      // Invalid product - negative price
      final invalidProduct = Product(
        id: '2',
        name: 'Invalid Product',
        price: -10.0,
        quantity: 5,
      );
      expect(invalidProduct.isValid, isFalse);
    });
  }
}

// ====================
// SERVICE TESTING PATTERNS
// ====================

class TestServices {
  """Test service layer functionality"""
  
  late MockAuthService mockAuthService;
  late MockApiService mockApiService;
  late MockStorageService mockStorageService;
  
  void setUp() {
    mockAuthService = MockAuthService();
    mockApiService = MockApiService();
    mockStorageService = MockStorageService();
  }
  
  void testAuthService() {
    test('should authenticate user successfully', () async {
      // Arrange
      const email = 'test@example.com';
      const password = 'password123';
      final expectedUser = User(
        id: '1',
        email: email,
        name: 'Test User',
        createdAt: DateTime.now(),
      );
      
      when(mockAuthService.signIn(email, password))
          .thenAnswer((_) async => expectedUser);
      
      // Act
      final result = await mockAuthService.signIn(email, password);
      
      // Assert
      expect(result.email, equals(email));
      expect(result.name, equals('Test User'));
      verify(mockAuthService.signIn(email, password)).called(1);
    });
    
    test('should handle authentication errors', () async {
      // Arrange
      when(mockAuthService.signIn(any, any))
          .thenThrow(AuthException('Invalid credentials'));
      
      // Act & Assert
      expect(
        () => mockAuthService.signIn('invalid@example.com', 'wrong'),
        throwsA(isA<AuthException>()),
      );
    });
    
    test('should refresh token when expired', () async {
      // Arrange
      const refreshToken = 'refresh_token_123';
      const newAccessToken = 'new_access_token_123';
      
      when(mockAuthService.refreshToken(refreshToken))
          .thenAnswer((_) async => newAccessToken);
      
      // Act
      final result = await mockAuthService.refreshToken(refreshToken);
      
      // Assert
      expect(result, equals(newAccessToken));
      verify(mockAuthService.refreshToken(refreshToken)).called(1);
    });
  }
  
  void testApiService() {
    test('should make GET requests correctly', () async {
      // Arrange
      const endpoint = '/users/123';
      final mockResponse = {
        'id': '123',
        'email': 'test@example.com',
        'name': 'Test User',
      };
      
      when(mockApiService.get(endpoint))
          .thenAnswer((_) async => mockResponse);
      
      // Act
      final result = await mockApiService.get(endpoint);
      
      // Assert
      expect(result['id'], equals('123'));
      expect(result['email'], equals('test@example.com'));
      verify(mockApiService.get(endpoint)).called(1);
    });
    
    test('should handle API rate limiting', () async {
      // Arrange
      when(mockApiService.get(any))
          .thenThrow(ApiException('Rate limit exceeded', 429));
      
      // Act & Assert
      expect(
        () => mockApiService.get('/users/123'),
        throwsA(isA<ApiException>()),
      );
    });
    
    test('should retry failed requests', () async {
      // Arrange
      when(mockApiService.get(any))
          .thenThrow(ApiException('Network error', 500))
          .thenAnswer((_) async => {'status': 'success'});
      
      // Act
      final result = await retryApiCall(() => mockApiService.get('/test'));
      
      // Assert
      expect(result['status'], equals('success'));
      verify(mockApiService.get('/test')).called(2);
    });
  }
  
  void testStorageService() {
    test('should store and retrieve user data', () async {
      // Arrange
      final user = User(
        id: '123',
        email: 'test@example.com',
        name: 'Test User',
        createdAt: DateTime.now(),
      );
      
      when(mockStorageService.saveUserData(user))
          .thenAnswer((_) async {});
      when(mockStorageService.getUserData())
          .thenAnswer((_) async => user);
      
      // Act
      await mockStorageService.saveUserData(user);
      final retrievedUser = await mockStorageService.getUserData();
      
      // Assert
      expect(retrievedUser.id, equals(user.id));
      expect(retrievedUser.email, equals(user.email));
      verify(mockStorageService.saveUserData(user)).called(1);
      verify(mockStorageService.getUserData()).called(1);
    });
    
    test('should handle storage errors gracefully', () async {
      // Arrange
      when(mockStorageService.saveUserData(any))
          .thenThrow(StorageException('Storage full'));
      
      // Act & Assert
      expect(
        () => mockStorageService.saveUserData(User(id: '123', email: 'test@example.com', name: 'Test', createdAt: DateTime.now())),
        throwsA(isA<StorageException>()),
      );
    });
  }
}

// ====================
// ERROR HANDLING TESTS
// ====================

class TestErrorHandling {
  """Error handling and exception test patterns"""
  
  void testCustomExceptions() {
    test('should throw custom exception with correct message', () {
      // Act & Assert
      expect(
        () => throw AuthException('User not found'),
        throwsA(isA<AuthException>()),
      );
      
      try {
        throw AuthException('Invalid credentials');
      } catch (e) {
        expect(e, isA<AuthException>());
        expect(e.toString(), contains('Invalid credentials'));
      }
    });
    
    test('should handle different exception types', () {
      // Test various exception scenarios
      expect(
        () => validateUserData({'email': 'invalid'}),
        throwsA(isA<ValidationException>()),
      );
      
      expect(
        () => fetchUserData('invalid-id'),
        throwsA(isA<NotFoundException>()),
      );
      
      expect(
        () => makeApiCall('invalid-endpoint'),
        throwsA(isA<ApiException>()),
      );
    });
  }
  
  void testExceptionChaining() {
    test('should chain exceptions correctly', () {
      try {
        try {
          throw FormatException('Invalid format');
        } catch (e) {
          throw ValidationException('Validation failed', e);
        }
      } catch (e) {
        expect(e, isA<ValidationException>());
        expect(e.toString(), contains('Validation failed'));
      }
    });
  }
  
  void testErrorRecovery() {
    test('should recover from errors gracefully', () async {
      // Arrange
      final mockApiService = MockApiService();
      
      when(mockApiService.get(any))
          .thenThrow(ApiException('Network error', 500))
          .thenAnswer((_) async => {'status': 'success'});
      
      // Act
      final result = await retryWithBackoff(
        () => mockApiService.get('/test'),
        maxRetries: 3,
      );
      
      // Assert
      expect(result['status'], equals('success'));
      verify(mockApiService.get('/test')).called(2);
    });
  }
}

// ====================
// PERFORMANCE BENCHMARKS
// ====================

class TestPerformance {
  """Performance testing patterns"""
  
  void testAlgorithmPerformance() {
    test('should sort large arrays efficiently', () {
      // Arrange
      final largeList = List.generate(10000, (i) => Random().nextInt(1000));
      
      // Act & Measure
      final stopwatch = Stopwatch()..start();
      final sortedList = quickSort(largeList);
      stopwatch.stop();
      
      // Assert
      expect(sortedList.length, equals(largeList.length));
      expect(isSorted(sortedList), isTrue);
      expect(stopwatch.elapsedMilliseconds, lessThan(100)); // Should complete in < 100ms
    });
    
    test('should search efficiently in large datasets', () {
      // Arrange
      final largeList = List.generate(100000, (i) => i);
      
      // Act & Measure
      final stopwatch = Stopwatch()..start();
      final result = binarySearch(largeList, 50000);
      stopwatch.stop();
      
      // Assert
      expect(result, equals(50000));
      expect(stopwatch.elapsedMicroseconds, lessThan(100)); // Should complete in < 100μs
    });
  }
  
  void testMemoryEfficiency() {
    test('should not leak memory in recursive operations', () {
      // Arrange
      final initialMemory = getCurrentMemoryUsage();
      
      // Act - Perform many recursive operations
      for (int i = 0; i < 1000; i++) {
        fibonacci(20);
      }
      
      // Assert
      final finalMemory = getCurrentMemoryUsage();
      expect(finalMemory - initialMemory, lessThan(1024 * 1024)); // Less than 1MB increase
    });
  }
  
  void testStringOperations() {
    test('should concatenate strings efficiently', () {
      // Arrange
      final strings = List.generate(1000, (i) => 'String $i');
      
      // Act & Measure
      final stopwatch = Stopwatch()..start();
      final result = strings.join(', ');
      stopwatch.stop();
      
      // Assert
      expect(result.length, greaterThan(0));
      expect(stopwatch.elapsedMilliseconds, lessThan(50));
    });
  }
}

// ====================
// TEST UTILITIES
// ====================

class TestUtilities {
  """Common test utilities and helpers"""
  
  static User createTestUser({
    String? id,
    String? email,
    String? name,
    bool? isActive,
  }) {
    return User(
      id: id ?? 'test-user-${Random().nextInt(1000)}',
      email: email ?? 'test${Random().nextInt(1000)}@example.com',
      name: name ?? 'Test User ${Random().nextInt(1000)}',
      createdAt: DateTime.now(),
    );
  }
  
  static Product createTestProduct({
    String? id,
    String? name,
    double? price,
    int? quantity,
  }) {
    return Product(
      id: id ?? 'test-product-${Random().nextInt(1000)}',
      name: name ?? 'Test Product ${Random().nextInt(1000)}',
      price: price ?? (Random().nextDouble() * 1000).roundToDouble(),
      quantity: quantity ?? Random().nextInt(100),
    );
  }
  
  static Map<String, dynamic> createMockApiResponse({
    required String status,
    Map<String, dynamic>? data,
    String? message,
  }) {
    return {
      'status': status,
      'data': data,
      'message': message,
      'timestamp': DateTime.now().toIso8601String(),
    };
  }
  
  static void assertValidUser(User user) {
    expect(user.id, isNotEmpty);
    expect(user.email, isNotEmpty);
    expect(user.name, isNotEmpty);
    expect(user.email, contains('@'));
    expect(user.createdAt, isA<DateTime>());
  }
  
  static void assertValidProduct(Product product) {
    expect(product.id, isNotEmpty);
    expect(product.name, isNotEmpty);
    expect(product.price, greaterThanOrEqualTo(0));
    expect(product.quantity, greaterThanOrEqualTo(0));
  }
}

// ====================
// CUSTOM MATCHERS
// ====================

class CustomMatchers {
  static Matcher isValidEmail() {
    return predicate<String>(
      (email) => ValidationService.isValidEmail(email),
      'valid email',
    );
  }
  
  static Matcher isStrongPassword() {
    return predicate<String>(
      (password) => ValidationService.isPasswordStrong(password),
      'strong password',
    );
  }
  
  static Matcher isWithinDuration(Duration expected, Duration tolerance) {
    return predicate<Duration>(
      (actual) => (actual - expected).abs() <= tolerance,
      'within ${tolerance.inMilliseconds}ms of ${expected.inMilliseconds}ms',
    );
  }
}

// ====================
// TEST CONFIGURATION
// ====================

void main() {
  // Global test setup
  setUpAll(() {
    // Initialize test dependencies
    TestWidgetsFlutterBinding.ensureInitialized();
  });
  
  // Global test cleanup
  tearDownAll(() {
    // Cleanup test dependencies
  });
  
  // Run all test groups
  group('Unit Tests - Simple Functions', TestSimpleFunctions().testStringValidation);
  group('Unit Tests - Mock Testing', TestWithMocking().testServiceWithMockedDependencies);
  group('Unit Tests - Parameterized Tests', TestParameterized().testDiscountCalculation);
  group('Unit Tests - Async Functions', TestAsyncFunctions().testAsyncApiCalls);
  group('Unit Tests - Models', TestModels().testUserModel);
  group('Unit Tests - Services', TestServices().testAuthService);
  group('Unit Tests - Error Handling', TestErrorHandling().testCustomExceptions);
  group('Unit Tests - Performance', TestPerformance().testAlgorithmPerformance);
}

// ====================
// RUN TESTS
// ====================

'''
# Run all unit tests
flutter test test/unit/

# Run specific test file
flutter test test/unit/auth_service_test.dart

# Run with coverage
flutter test --coverage test/unit/

# Run in watch mode
flutter test test/unit/ --watch

# Run with verbose output
flutter test test/unit/ --verbose

# Run only tests matching pattern
flutter test test/unit/ --name "should authenticate"

# Generate coverage report
flutter test --coverage
genhtml coverage/lcov.info -o coverage/html
open coverage/html/index.html
'''

// ====================
// MOCK IMPLEMENTATIONS
// ====================

class MockAuthService extends Mock implements AuthService {}
class MockApiService extends Mock implements ApiService {}
class MockStorageService extends Mock implements StorageService {}

// Example implementations for reference
class ValidationService {
  static bool isValidEmail(String? email) {
    if (email == null || email.isEmpty) return false;
    return RegExp(r'^[^@]+@[^@]+\.[^@]+').hasMatch(email);
  }
  
  static bool isPasswordStrong(String password) {
    return password.length >= 8 &&
           RegExp(r'[A-Z]').hasMatch(password) &&
           RegExp(r'[a-z]').hasMatch(password) &&
           RegExp(r'[0-9]').hasMatch(password) &&
           RegExp(r'[!@#$%^&*(),.?":{}|<>]').hasMatch(password);
  }
  
  static bool isValidPhone(String? phone) {
    if (phone == null || phone.isEmpty) return false;
    return RegExp(r'^\+?[\d\s\-\(\)]{7,}$').hasMatch(phone);
  }
}

class AuthException implements Exception {
  final String message;
  AuthException(this.message);
  
  @override
  String toString() => 'AuthException: $message';
}

class ApiException implements Exception {
  final String message;
  final int statusCode;
  ApiException(this.message, this.statusCode);
  
  @override
  String toString() => 'ApiException: $message (Status: $statusCode)';
}

class ValidationException implements Exception {
  final String message;
  ValidationException(this.message);
  
  @override
  String toString() => 'ValidationException: $message';
}

class NotFoundException implements Exception {
  final String message;
  NotFoundException(this.message);
  
  @override
  String toString() => 'NotFoundException: $message';
}

class StorageException implements Exception {
  final String message;
  StorageException(this.message);
  
  @override
  String toString() => 'StorageException: $message';
}