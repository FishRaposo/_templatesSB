# Universal Template System - Flutter Stack
# Generated: 2025-12-10
# Purpose: Testing utilities
# Tier: base
# Stack: flutter
# Category: template

# Flutter Testing Examples - {{PROJECT_NAME}}

**Tier**: {{TIER}} | **Stack**: Flutter

## 🧪 Testing Strategy Overview

Flutter testing follows the testing pyramid: **Unit Tests > Widget Tests > Integration Tests**. Each tier requires different levels of testing rigor.

## 📊 Tier-Specific Testing Requirements

| Tier | Unit Tests | Widget Tests | Integration Tests | Performance Tests |
|------|------------|--------------|-------------------|-------------------|
| **MVP** | Basic logic | Critical UI only | Not required | Not required |
| **CORE** | Complete coverage | All components | Critical flows | Basic performance |
| **FULL** | Complete + edge cases | All + golden tests | All flows | Advanced performance |

## 🔬 Unit Testing Examples

### **MVP Tier - Simple Logic Testing**

```dart
// test/unit/services/counter_service_test.dart
import 'package:flutter_test/flutter_test.dart';
import 'package:{{PROJECT_NAME}}/services/counter_service.dart';

void main() {
  group('CounterService', () {
    late CounterService counterService;
    
    setUp(() {
      counterService = CounterService();
    });
    
    test('should initialize with count 0', () {
      expect(counterService.count, equals(0));
    });
    
    test('should increment count', () {
      counterService.increment();
      expect(counterService.count, equals(1));
    });
    
    test('should decrement count', () {
      counterService.increment();
      counterService.decrement();
      expect(counterService.count, equals(0));
    });
    
    test('should not go below 0', () {
      counterService.decrement();
      expect(counterService.count, equals(0));
    });
  });
}
```

### **CORE Tier - Business Logic Testing**

```dart
// test/unit/services/auth_service_test.dart
import 'package:flutter_test/flutter_test.dart';
import 'package:mockito/mockito.dart';
import 'package:mockito/annotations.dart';
import 'package:{{PROJECT_NAME}}/services/auth_service.dart';
import 'package:{{PROJECT_NAME}}/repositories/auth_repository.dart';

import 'auth_service_test.mocks.dart';

@GenerateMocks([AuthRepository])
void main() {
  group('AuthService', () {
    late AuthService authService;
    late MockAuthRepository mockRepository;
    
    setUp(() {
      mockRepository = MockAuthRepository();
      authService = AuthService(mockRepository);
    });
    
    test('should sign in successfully with valid credentials', () async {
      // Arrange
      const email = 'test@example.com';
      const password = 'password123';
      const expectedUser = User(id: '1', email: email, name: 'Test User');
      
      when(mockRepository.signIn(email, password))
          .thenAnswer((_) async => expectedUser);
      
      // Act
      final result = await authService.signIn(email, password);
      
      // Assert
      expect(result.email, equals(email));
      expect(result.name, equals('Test User'));
      verify(mockRepository.signIn(email, password)).called(1);
    });
    
    test('should throw AuthException with invalid credentials', () async {
      // Arrange
      when(mockRepository.signIn(any, any))
          .thenThrow(AuthException('Invalid credentials'));
      
      // Act & Assert
      expect(
        () => authService.signIn('invalid@example.com', 'wrong'),
        throwsA(isA<AuthException>()),
      );
    });
    
    test('should cache user after successful sign in', () async {
      // Arrange
      const user = User(id: '1', email: 'test@example.com', name: 'Test User');
      when(mockRepository.signIn(any, any))
          .thenAnswer((_) async => user);
      
      // Act
      await authService.signIn('test@example.com', 'password123');
      final cachedUser = await authService.getCurrentUser();
      
      // Assert
      expect(cachedUser, equals(user));
    });
  });
}
```

### **FULL Tier - Advanced Logic Testing**

```dart
// test/unit/services/profile_service_test.dart
import 'package:flutter_test/flutter_test.dart';
import 'package:mockito/mockito.dart';
import 'package:{{PROJECT_NAME}}/services/profile_service.dart';
import 'package:{{PROJECT_NAME}}/repositories/profile_repository.dart';
import 'package:{{PROJECT_NAME}}/services/analytics_service.dart';

void main() {
  group('ProfileService', () {
    late ProfileService profileService;
    late MockProfileRepository mockRepository;
    late MockAnalyticsService mockAnalytics;
    
    setUp(() {
      mockRepository = MockProfileRepository();
      mockAnalytics = MockAnalyticsService();
      profileService = ProfileService(mockRepository, mockAnalytics);
    });
    
    test('should update profile and track analytics', () async {
      // Arrange
      const userId = 'user123';
      const updateData = ProfileUpdate(name: 'Updated Name');
      const updatedProfile = Profile(
        id: userId,
        name: 'Updated Name',
        email: 'test@example.com',
      );
      
      when(mockRepository.updateProfile(userId, updateData))
          .thenAnswer((_) async => updatedProfile);
      
      // Act
      final result = await profileService.updateProfile(userId, updateData);
      
      // Assert
      expect(result.name, equals('Updated Name'));
      verify(mockRepository.updateProfile(userId, updateData)).called(1);
      verify(mockAnalytics.trackEvent('profile_updated', any)).called(1);
    });
    
    test('should handle network errors with retry logic', () async {
      // Arrange
      when(mockRepository.updateProfile(any, any))
          .thenThrow(NetworkException());
      
      // Act & Assert
      expect(
        () => profileService.updateProfile('user123', ProfileUpdate(name: 'Test')),
        throwsA(isA<ProfileUpdateException>()),
      );
      verify(mockAnalytics.trackError('profile_update_failed', any)).called(1);
    });
  });
}
```

## 🎨 Widget Testing Examples

### **MVP Tier - Simple Widget Testing**

```dart
// test/widget/components/counter_button_test.dart
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:{{PROJECT_NAME}}/widgets/counter_button.dart';

void main() {
  group('CounterButton', () {
    testWidgets('should display correct count', (tester) async {
      // Arrange
      const count = 5;
      
      // Act
      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: CounterButton(count: count, onPressed: () {}),
          ),
        ),
      );
      
      // Assert
      expect(find.text('Count: $count'), findsOneWidget);
    });
    
    testWidgets('should call onPressed when tapped', (tester) async {
      // Arrange
      bool wasPressed = false;
      
      // Act
      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: CounterButton(
              count: 0,
              onPressed: () => wasPressed = true,
            ),
          ),
        ),
      );
      
      await tester.tap(find.byType(ElevatedButton));
      await tester.pump();
      
      // Assert
      expect(wasPressed, isTrue);
    });
  });
}
```

### **CORE Tier - Complex Widget Testing**

```dart
// test/widget/screens/login_screen_test.dart
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:mockito/mockito.dart';
import 'package:{{PROJECT_NAME}}/screens/login_screen.dart';
import 'package:{{PROJECT_NAME}}/providers/auth_provider.dart';

void main() {
  group('LoginScreen', () {
    late MockAuthProvider mockAuthProvider;
    
    setUp(() {
      mockAuthProvider = MockAuthProvider();
    });
    
    testWidgets('should show login form', (tester) async {
      // Act
      await tester.pumpWidget(
        MaterialApp(
          home: LoginScreen(),
        ),
      );
      
      // Assert
      expect(find.byType(TextField), findsNWidgets(2)); // Email and password
      expect(find.byType(ElevatedButton), findsOneWidget);
      expect(find.text('Login'), findsOneWidget);
    });
    
    testWidgets('should validate email format', (tester) async {
      // Act
      await tester.pumpWidget(
        MaterialApp(
          home: LoginScreen(),
        ),
      );
      
      // Enter invalid email
      await tester.enterText(find.byKey(const Key('email_field')), 'invalid-email');
      await tester.tap(find.byType(ElevatedButton));
      await tester.pump();
      
      // Assert
      expect(find.text('Please enter a valid email'), findsOneWidget);
    });
    
    testWidgets('should call auth provider when form is valid', (tester) async {
      // Arrange
      when(mockAuthProvider.signIn(any, any)).thenAnswer((_) async {});
      
      // Act
      await tester.pumpWidget(
        MaterialApp(
          home: LoginScreen(),
        ),
      );
      
      await tester.enterText(find.byKey(const Key('email_field')), 'test@example.com');
      await tester.enterText(find.byKey(const Key('password_field')), 'password123');
      await tester.tap(find.byType(ElevatedButton));
      await tester.pump();
      
      // Assert
      verify(mockAuthProvider.signIn('test@example.com', 'password123')).called(1);
    });
  });
}
```

### **FULL Tier - Advanced Widget Testing**

```dart
// test/widget/components/advanced_form_test.dart
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:{{PROJECT_NAME}}/widgets/advanced_form.dart';

void main() {
  group('AdvancedForm', () {
    testWidgets('should handle complex form validation', (tester) async {
      // Act
      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: AdvancedForm(),
          ),
        ),
      );
      
      // Test field validation
      await tester.tap(find.byKey(const Key('submit_button')));
      await tester.pump();
      
      expect(find.text('Name is required'), findsOneWidget);
      expect(find.text('Email is required'), findsOneWidget);
      
      // Fill form partially
      await tester.enterText(find.byKey(const Key('name_field')), 'John Doe');
      await tester.tap(find.byKey(const Key('submit_button')));
      await tester.pump();
      
      expect(find.text('Name is required'), findsNothing);
      expect(find.text('Email is required'), findsOneWidget);
    });
    
    testWidgets('should show loading state during submission', (tester) async {
      // Arrange
      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: AdvancedForm(),
          ),
        ),
      );
      
      // Fill form
      await tester.enterText(find.byKey(const Key('name_field')), 'John Doe');
      await tester.enterText(find.byKey(const Key('email_field')), 'john@example.com');
      
      // Act
      await tester.tap(find.byKey(const Key('submit_button')));
      await tester.pump();
      
      // Assert
      expect(find.byType(CircularProgressIndicator), findsOneWidget);
      expect(find.byKey(const Key('submit_button')), findsNothing);
    });
  });
}
```

## 🎯 Golden Testing (CORE+)

```dart
// test/widget/components/profile_card_test.dart
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:{{PROJECT_NAME}}/widgets/profile_card.dart';

void main() {
  group('ProfileCard Golden Tests', () {
    testWidgets('should match golden snapshot', (tester) async {
      // Arrange
      const profile = Profile(
        name: 'John Doe',
        email: 'john@example.com',
        avatar: 'https://example.com/avatar.jpg',
      );
      
      // Act
      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: ProfileCard(profile: profile),
          ),
        ),
      );
      
      // Assert
      await expectLater(
        find.byType(ProfileCard),
        matchesGoldenFile('goldens/profile_card.png'),
      );
    });
    
    testWidgets('should match dark mode golden snapshot', (tester) async {
      // Arrange
      const profile = Profile(
        name: 'John Doe',
        email: 'john@example.com',
        avatar: 'https://example.com/avatar.jpg',
      );
      
      // Act
      await tester.pumpWidget(
        MaterialApp(
          theme: ThemeData.dark(),
          home: Scaffold(
            body: ProfileCard(profile: profile),
          ),
        ),
      );
      
      // Assert
      await expectLater(
        find.byType(ProfileCard),
        matchesGoldenFile('goldens/profile_card_dark.png'),
      );
    });
  });
}
```

## 🔗 Integration Testing Examples

### **CORE Tier - Critical Flow Testing**

```dart
// integration_test/app_test.dart
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:{{PROJECT_NAME}}/main.dart' as app;

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();
  
  group('App Integration Tests', () {
    testWidgets('complete login flow', (tester) async {
      // Arrange
      app.main();
      await tester.pumpAndSettle();
      
      // Act & Assert - Navigate to login
      expect(find.byType(LoginScreen), findsOneWidget);
      
      // Fill login form
      await tester.enterText(find.byKey(const Key('email_field')), 'test@example.com');
      await tester.enterText(find.byKey(const Key('password_field')), 'password123');
      await tester.tap(find.byKey(const Key('login_button')));
      await tester.pumpAndSettle();
      
      // Verify successful login
      expect(find.byType(HomeScreen), findsOneWidget);
      expect(find.text('Welcome, test@example.com'), findsOneWidget);
    });
    
    testWidgets('profile update flow', (tester) async {
      // Arrange
      app.main();
      await tester.pumpAndSettle();
      
      // Login first
      await tester.enterText(find.byKey(const Key('email_field')), 'test@example.com');
      await tester.enterText(find.byKey(const Key('password_field')), 'password123');
      await tester.tap(find.byKey(const Key('login_button')));
      await tester.pumpAndSettle();
      
      // Navigate to profile
      await tester.tap(find.byKey(const Key('profile_tab')));
      await tester.pumpAndSettle();
      
      // Update profile
      await tester.tap(find.byKey(const Key('edit_profile_button')));
      await tester.pumpAndSettle();
      
      await tester.enterText(find.byKey(const Key('name_field')), 'Updated Name');
      await tester.tap(find.byKey(const Key('save_button')));
      await tester.pumpAndSettle();
      
      // Assert
      expect(find.text('Updated Name'), findsOneWidget);
      expect(find.text('Profile updated successfully'), findsOneWidget);
    });
  });
}
```

### **FULL Tier - Complex Integration Testing**

```dart
// integration_test/advanced_scenarios_test.dart
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:{{PROJECT_NAME}}/main.dart' as app;

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();
  
  group('Advanced Integration Tests', () {
    testWidgets('offline mode handling', (tester) async {
      // Arrange
      app.main();
      await tester.pumpAndSettle();
      
      // Simulate offline mode
      await tester.binding.defaultBinaryMessenger.handlePlatformMessage(
        'flutter/connectivity',
        StringCodec().encodeMessage('none'),
        (data) {},
      );
      await tester.pumpAndSettle();
      
      // Act - Try to perform online action
      await tester.tap(find.byKey(const Key('refresh_data_button')));
      await tester.pumpAndSettle();
      
      // Assert
      expect(find.text('No internet connection'), findsOneWidget);
      expect(find.byType(OfflineIndicator), findsOneWidget);
    });
    
    testWidgets('deep linking navigation', (tester) async {
      // Arrange
      app.main();
      await tester.pumpAndSettle();
      
      // Act - Simulate deep link
      await tester.binding.defaultBinaryMessenger.handlePlatformMessage(
        'flutter/lifecycle',
        StringCodec().encodeMessage('app://{{PROJECT_NAME}}/profile/123'),
        (data) {},
      );
      await tester.pumpAndSettle();
      
      // Assert
      expect(find.byType(ProfileScreen), findsOneWidget);
      expect(find.text('User ID: 123'), findsOneWidget);
    });
  });
}
```

## ⚡ Performance Testing (FULL Tier)

```dart
// test/performance/scrolling_performance_test.dart
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:{{PROJECT_NAME}}/widgets/long_list.dart';

void main() {
  group('Performance Tests', () {
    testWidgets('should maintain 60fps while scrolling', (tester) async {
      // Arrange
      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: LongList(itemCount: 1000),
          ),
        ),
      );
      
      // Act - Scroll through entire list
      await tester.fling(
        find.byType(ListView),
        const Offset(0, -5000),
        10000,
      );
      await tester.pumpAndSettle();
      
      // Assert - Performance should remain acceptable
      // This would be integrated with actual performance metrics
      expect(find.byType(ListTile), findsWidgets);
    });
  });
}
```

## 🛠️ Testing Utilities

### **Test Helpers**

```dart
// test/helpers/test_helpers.dart
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:{{PROJECT_NAME}}/models/user.dart';

class TestHelpers {
  static Widget createMaterialApp(Widget child) {
    return MaterialApp(
      home: Scaffold(
        body: child,
      ),
    );
  }
  
  static User createTestUser({
    String id = 'test-id',
    String email = 'test@example.com',
    String name = 'Test User',
  }) {
    return User(id: id, email: email, name: name);
  }
  
  static Future<void> pumpAndSettleWithDelay(WidgetTester tester, {Duration? delay}) {
    return tester.pumpAndSettle(delay ?? const Duration(milliseconds: 100));
  }
  
  static Future<void> enterTextAndTriggerChange(
    WidgetTester tester,
    Finder finder,
    String text,
  ) async {
    await tester.enterText(finder, text);
    await tester.pump();
    await tester.pumpAndSettle();
  }
}
```

### **Mock Data Generators**

```dart
// test/helpers/mock_data.dart
import 'package:{{PROJECT_NAME}}/models/user.dart';
import 'package:{{PROJECT_NAME}}/models/profile.dart';

class MockData {
  static List<User> generateTestUsers({int count = 10}) {
    return List.generate(count, (index) => User(
      id: 'user-$index',
      email: 'user$index@example.com',
      name: 'User $index',
    ));
  }
  
  static Profile createTestProfile({String? userId}) {
    return Profile(
      id: userId ?? 'test-profile-id',
      name: 'Test Profile',
      email: 'profile@example.com',
      bio: 'This is a test bio',
      avatar: 'https://example.com/avatar.jpg',
    );
  }
}
```

## 📋 Test Configuration

### **test/test_config.dart**

```dart
import 'package:flutter_test/flutter_test.dart';

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
}
```

---

**Flutter Version**: [FLUTTER_VERSION]  
**Dart Version**: [DART_VERSION]  
**Last Updated**: [DATE]  
**Template Version**: 1.0
