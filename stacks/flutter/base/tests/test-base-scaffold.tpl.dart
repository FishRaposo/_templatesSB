///
/// File: test-base-scaffold.tpl.dart
/// Purpose: Template for unknown implementation
/// Generated for: {{PROJECT_NAME}}
///

/// Template: test-base-scaffold.tpl.dart
/// Purpose: test-base-scaffold template
/// Stack: flutter
/// Tier: base

# Universal Template System - Flutter Stack
# Generated: 2025-12-10
# Purpose: Testing utilities
# Tier: base
# Stack: flutter
# Category: testing

// -----------------------------------------------------------------------------
// FILE: test-base-scaffold.tpl.dart
// PURPOSE: Foundational testing patterns and utilities for Flutter projects
// USAGE: Import and extend for consistent testing structure across the application
// DEPENDENCIES: flutter/material.dart, flutter_test/flutter_test.dart, shared_preferences
// AUTHOR: [[.Author]]
// VERSION: [[.Version]]
// SINCE: [[.Version]]
// -----------------------------------------------------------------------------

/// Flutter Base Test Scaffold Template
/// Purpose: Foundational testing patterns and utilities for Flutter projects
/// Usage: Import and extend for consistent testing structure across the application

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:flutter/services.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'dart:convert';
import 'dart:io';

/// Base test widget for Flutter applications
class BaseTestWidget extends StatelessWidget {
  final Widget child;
  
  const BaseTestWidget({
    Key? key,
    required this.child,
  }) : super(key: key);

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      home: Scaffold(
        body: child,
      ),
    );
  }
}

/// Base test class with common utilities
abstract class BaseTestCase {
  /// Sets up the test environment
  Future<void> setUp() async {
    TestWidgetsFlutterBinding.ensureInitialized();
    await _setupMockDependencies();
  }

  /// Tears down the test environment
  Future<void> tearDown() async {
    await _cleanupMockDependencies();
  }

  /// Sets up mock dependencies
  Future<void> _setupMockDependencies() async {
    // Mock SharedPreferences
    SharedPreferences.setMockInitialValues({});
    
    // Mock method channels
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(
      const MethodChannel('flutter/plugins/shared_preferences'),
      (MethodCall methodCall) async {
        if (methodCall.method == 'getAll') {
          return <String, dynamic>{};
        }
        return null;
      },
    );
  }

  /// Cleans up mock dependencies
  Future<void> _cleanupMockDependencies() async {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(
      const MethodChannel('flutter/plugins/shared_preferences'),
      null,
    );
  }

  /// Creates mock data for testing
  T createMockData<T>(String dataType, {Map<String, dynamic>? overrides}) {
    switch (dataType) {
      case 'user':
        return _createMockUser(overrides) as T;
      case 'post':
        return _createMockPost(overrides) as T;
      case 'config':
        return _createMockConfig(overrides) as T;
      default:
        throw ArgumentError('Unknown data type: $dataType');
    }
  }

  /// Creates mock user data
  MockUser _createMockUser(Map<String, dynamic>? overrides) {
    final user = MockUser(
      id: 1,
      username: 'testuser',
      email: 'test@example.com',
      firstName: 'Test',
      lastName: 'User',
      isActive: true,
      createdAt: DateTime.now(),
      updatedAt: DateTime.now(),
    );

    if (overrides != null) {
      return user.copyWith(
        id: overrides['id'] ?? user.id,
        username: overrides['username'] ?? user.username,
        email: overrides['email'] ?? user.email,
        firstName: overrides['firstName'] ?? user.firstName,
        lastName: overrides['lastName'] ?? user.lastName,
        isActive: overrides['isActive'] ?? user.isActive,
      );
    }

    return user;
  }

  /// Creates mock post data
  MockPost _createMockPost(Map<String, dynamic>? overrides) {
    final post = MockPost(
      id: 1,
      title: 'Test Post',
      content: 'This is test content',
      authorId: 1,
      published: true,
      createdAt: DateTime.now(),
      updatedAt: DateTime.now(),
      tags: ['test', 'mock'],
    );

    if (overrides != null) {
      return post.copyWith(
        id: overrides['id'] ?? post.id,
        title: overrides['title'] ?? post.title,
        content: overrides['content'] ?? post.content,
        authorId: overrides['authorId'] ?? post.authorId,
        published: overrides['published'] ?? post.published,
        tags: overrides['tags'] ?? post.tags,
      );
    }

    return post;
  }

  /// Creates mock configuration data
  MockConfig _createMockConfig(Map<String, dynamic>? overrides) {
    final config = MockConfig(
      apiBaseUrl: 'https://api.example.com',
      debugMode: true,
      timeout: Duration(seconds: 30),
      retryAttempts: 3,
    );

    if (overrides != null) {
      return MockConfig(
        apiBaseUrl: overrides['apiBaseUrl'] ?? config.apiBaseUrl,
        debugMode: overrides['debugMode'] ?? config.debugMode,
        timeout: overrides['timeout'] ?? config.timeout,
        retryAttempts: overrides['retryAttempts'] ?? config.retryAttempts,
      );
    }

    return config;
  }
}

/// Widget test utilities
class WidgetTestUtils {
  /// Finds a widget by key
  static Finder findByKey(Key key) {
    return find.byKey(key);
  }

  /// Finds a widget by type
  static Finder findByType<T extends Widget>() {
    return find.byType(T);
  }

  /// Finds a widget by text
  static Finder findByText(String text) {
    return find.text(text);
  }

  /// Enters text into a text field
  static Future<void> enterText(WidgetTester tester, Key key, String text) async {
    await tester.enterText(findByKey(key), text);
    await tester.pump();
  }

  /// Taps a widget
  static Future<void> tap(WidgetTester tester, Finder finder) async {
    await tester.tap(finder);
    await tester.pump();
  }

  /// Taps a widget by key
  static Future<void> tapByKey(WidgetTester tester, Key key) async {
    await tap(tester, findByKey(key));
  }

  /// Waits for a widget to appear
  static Future<void> waitFor(WidgetTester tester, Finder finder) async {
    await tester.pumpUntilVisible(finder);
  }

  /// Scrolls into view
  static Future<void> scrollIntoView(WidgetTester tester, Finder finder) async {
    await tester.scrollUntilVisible(finder, 500);
    await tester.pump();
  }

  /// Verifies a widget is visible
  static void isVisible(Finder finder) {
    expect(finder, findsOneWidget);
  }

  /// Verifies a widget is not visible
  static void isNotVisible(Finder finder) {
    expect(finder, findsNothing);
  }
}

/// Mock data factory
class MockDataFactory {
  /// Creates a mock user
  static MockUser createUser({Map<String, dynamic>? overrides}) {
    final baseCase = BaseTestCase();
    return baseCase.createMockData<MockUser>('user', overrides: overrides);
  }

  /// Creates multiple mock users
  static List<MockUser> createUsers(int count, {Map<String, dynamic>? overrides}) {
    final users = <MockUser>[];
    for (int i = 0; i < count; i++) {
      final userOverrides = Map<String, dynamic>.from(overrides ?? {});
      userOverrides['id'] = i + 1;
      userOverrides['username'] = 'testuser${i + 1}';
      userOverrides['email'] = 'test${i + 1}@example.com';
      users.add(createUser(overrides: userOverrides));
    }
    return users;
  }

  /// Creates a mock post
  static MockPost createPost({Map<String, dynamic>? overrides}) {
    final baseCase = BaseTestCase();
    return baseCase.createMockData<MockPost>('post', overrides: overrides);
  }

  /// Creates multiple mock posts
  static List<MockPost> createPosts(int count, {Map<String, dynamic>? overrides}) {
    final posts = <MockPost>[];
    for (int i = 0; i < count; i++) {
      final postOverrides = Map<String, dynamic>.from(overrides ?? {});
      postOverrides['id'] = i + 1;
      postOverrides['title'] = 'Test Post ${i + 1}';
      posts.add(createPost(overrides: postOverrides));
    }
    return posts;
  }
}

/// HTTP test utilities
class HttpTestUtils {
  /// Creates mock HTTP response
  static MockHttpResponse createMockResponse({
    required int statusCode,
    Map<String, dynamic>? data,
    Map<String, String>? headers,
  }) {
    return MockHttpResponse(
      statusCode: statusCode,
      data: data ?? {},
      headers: headers ?? {'content-type': 'application/json'},
    );
  }

  /// Creates success response
  static MockHttpResponse createSuccessResponse(Map<String, dynamic> data) {
    return createMockResponse(
      statusCode: 200,
      data: {'status': 'success', 'data': data},
    );
  }

  /// Creates error response
  static MockHttpResponse createErrorResponse(String message, {int statusCode = 400}) {
    return createMockResponse(
      statusCode: statusCode,
      data: {'status': 'error', 'message': message},
    );
  }
}

/// Mock HTTP response
class MockHttpResponse {
  final int statusCode;
  final Map<String, dynamic> data;
  final Map<String, String> headers;

  MockHttpResponse({
    required this.statusCode,
    required this.data,
    required this.headers,
  });

  /// Returns response as JSON string
  String toJsonString() {
    return jsonEncode(data);
  }

  /// Checks if response is successful
  bool get isSuccessful => statusCode >= 200 && statusCode < 300;
}

/// Storage test utilities
class StorageTestUtils {
  /// Sets up mock shared preferences
  static Future<void> setupMockSharedPreferences(Map<String, dynamic> initialData) async {
    SharedPreferences.setMockInitialValues(initialData);
  }

  /// Clears mock shared preferences
  static Future<void> clearMockSharedPreferences() async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.clear();
  }

  /// Verifies a value exists in shared preferences
  static Future<void> verifySharedPreferenceValue(String key, dynamic expectedValue) async {
    final prefs = await SharedPreferences.getInstance();
    
    if (expectedValue is String) {
      expect(prefs.getString(key), expectedValue);
    } else if (expectedValue is int) {
      expect(prefs.getInt(key), expectedValue);
    } else if (expectedValue is bool) {
      expect(prefs.getBool(key), expectedValue);
    } else if (expectedValue is double) {
      expect(prefs.getDouble(key), expectedValue);
    } else if (expectedValue is List<String>) {
      expect(prefs.getStringList(key), expectedValue);
    }
  }
}

/// Navigation test utilities
class NavigationTestUtils {
  /// Pushes a route
  static Future<void> pushRoute(WidgetTester tester, String routeName) async {
    // This would be implemented based on your navigation setup
    // Example for GoRouter:
    // GoRouter.of(tester.element(find.byType(MaterialApp))).go(routeName);
    await tester.pump();
  }

  /// Pops a route
  static Future<void> popRoute(WidgetTester tester) async {
    // This would be implemented based on your navigation setup
    // Example for Navigator:
    // Navigator.of(tester.element(find.byType(MaterialApp))).pop();
    await tester.pump();
  }

  /// Verifies current route
  static void verifyCurrentRoute(WidgetTester tester, String expectedRoute) {
    // This would be implemented based on your navigation setup
    // Example for GoRouter:
    // final router = GoRouter.of(tester.element(find.byType(MaterialApp)));
    // expect(router.routeInformationProvider.value.uri.path, expectedRoute);
  }
}

/// Performance test utilities
class PerformanceTestUtils {
  /// Measures widget build time
  static Future<Duration> measureBuildTime(WidgetTester tester, Widget widget) async {
    final stopwatch = Stopwatch()..start();
    await tester.pumpWidget(widget);
    stopwatch.stop();
    return stopwatch.elapsed;
  }

  /// Measures frame rendering time
  static Future<Duration> measureFrameTime(WidgetTester tester) async {
    final stopwatch = Stopwatch()..start();
    await tester.pump();
    stopwatch.stop();
    return stopwatch.elapsed;
  }

  /// Asserts performance threshold
  static void assertPerformanceThreshold(Duration actual, Duration threshold, String metric) {
    expect(actual.lessThan(threshold), true, reason: '$metric (${actual.inMilliseconds}ms) exceeds threshold (${threshold.inMilliseconds}ms)');
  }
}

/// Golden test utilities
class GoldenTestUtils {
  /// Captures widget as golden
  static Future<void> captureGolden(
    WidgetTester tester,
    Widget widget,
    String goldenName, {
    bool skip = false,
  }) async {
    await tester.pumpWidget(BaseTestWidget(child: widget));
    await expectLater(
      find.byType(BaseTestWidget),
      matchesGoldenFile('goldens/$goldenName.png'),
      skip: skip,
    );
  }

  /// Compares widget against golden file
  static Future<void> compareWithGolden(
    WidgetTester tester,
    Widget widget,
    String goldenName,
  ) async {
    await tester.pumpWidget(BaseTestWidget(child: widget));
    await expectLater(
      find.byType(BaseTestWidget),
      matchesGoldenFile('goldens/$goldenName.png'),
    );
  }
}

/// Accessibility test utilities
class AccessibilityTestUtils {
  /// Runs accessibility checks
  static Future<void> runAccessibilityChecks(WidgetTester tester) async {
    await expectLater(tester, meetsGuideline(labeledTapTargetGuideline));
    await expectLater(tester, meetsGuideline(textContrastGuideline));
  }

  /// Verifies semantic labels
  static void verifySemanticLabel(Finder finder, String expectedLabel) {
    expect(finder, meetsSemantics(label: expectedLabel));
  }

  /// Verifies accessibility hint
  static void verifyAccessibilityHint(Finder finder, String expectedHint) {
    expect(finder, meetsSemantics(hint: expectedHint));
  }
}

/// Integration test utilities
class IntegrationTestUtils {
  /// Sets up integration test environment
  static Future<void> setupIntegrationTest() async {
    // Integration test setup
    TestWidgetsFlutterBinding.ensureInitialized();
  }

  /// Cleans up integration test environment
  static Future<void> cleanupIntegrationTest() async {
    // Integration test cleanup
  }

  /// Waits for async operations
  static Future<void> waitForAsyncOperations(WidgetTester tester) async {
    await tester.pumpAndSettle();
  }

  /// Runs integration test with setup and cleanup
  static Future<void> runIntegrationTest(
    WidgetTester tester,
    Future<void> Function() testBody,
  ) async {
    await setupIntegrationTest();
    try {
      await testBody();
    } finally {
      await cleanupIntegrationTest();
    }
  }
}

/// Mock data models
class MockUser {
  final int id;
  final String username;
  final String email;
  final String firstName;
  final String lastName;
  final bool isActive;
  final DateTime createdAt;
  final DateTime updatedAt;

  MockUser({
    required this.id,
    required this.username,
    required this.email,
    required this.firstName,
    required this.lastName,
    required this.isActive,
    required this.createdAt,
    required this.updatedAt,
  });

  MockUser copyWith({
    int? id,
    String? username,
    String? email,
    String? firstName,
    String? lastName,
    bool? isActive,
    DateTime? createdAt,
    DateTime? updatedAt,
  }) {
    return MockUser(
      id: id ?? this.id,
      username: username ?? this.username,
      email: email ?? this.email,
      firstName: firstName ?? this.firstName,
      lastName: lastName ?? this.lastName,
      isActive: isActive ?? this.isActive,
      createdAt: createdAt ?? this.createdAt,
      updatedAt: updatedAt ?? this.updatedAt,
    );
  }

  Map<String, dynamic> toJson() {
    return {
      'id': id,
      'username': username,
      'email': email,
      'firstName': firstName,
      'lastName': lastName,
      'isActive': isActive,
      'createdAt': createdAt.toIso8601String(),
      'updatedAt': updatedAt.toIso8601String(),
    };
  }
}

class MockPost {
  final int id;
  final String title;
  final String content;
  final int authorId;
  final bool published;
  final DateTime createdAt;
  final DateTime updatedAt;
  final List<String> tags;

  MockPost({
    required this.id,
    required this.title,
    required this.content,
    required this.authorId,
    required this.published,
    required this.createdAt,
    required this.updatedAt,
    required this.tags,
  });

  MockPost copyWith({
    int? id,
    String? title,
    String? content,
    int? authorId,
    bool? published,
    DateTime? createdAt,
    DateTime? updatedAt,
    List<String>? tags,
  }) {
    return MockPost(
      id: id ?? this.id,
      title: title ?? this.title,
      content: content ?? this.content,
      authorId: authorId ?? this.authorId,
      published: published ?? this.published,
      createdAt: createdAt ?? this.createdAt,
      updatedAt: updatedAt ?? this.updatedAt,
      tags: tags ?? this.tags,
    );
  }

  Map<String, dynamic> toJson() {
    return {
      'id': id,
      'title': title,
      'content': content,
      'authorId': authorId,
      'published': published,
      'createdAt': createdAt.toIso8601String(),
      'updatedAt': updatedAt.toIso8601String(),
      'tags': tags,
    };
  }
}

class MockConfig {
  final String apiBaseUrl;
  final bool debugMode;
  final Duration timeout;
  final int retryAttempts;

  MockConfig({
    required this.apiBaseUrl,
    required this.debugMode,
    required this.timeout,
    required this.retryAttempts,
  });

  Map<String, dynamic> toJson() {
    return {
      'apiBaseUrl': apiBaseUrl,
      'debugMode': debugMode,
      'timeout': timeout.inMilliseconds,
      'retryAttempts': retryAttempts,
    };
  }
}

/// Example test classes
class ExampleWidgetTests extends BaseTestCase {
  late WidgetTester tester;

  Future<void> setUpTest(WidgetTester testTester) async {
    tester = testTester;
    await setUp();
  }

  Future<void> tearDownTest() async {
    await tearDown();
  }
}

/// Example usage
void exampleUsage() {
  print('Flutter Test Scaffold Usage:');
  print('1. Extend BaseTestCase for common utilities');
  print('2. Use WidgetTestUtils for widget testing');
  print('3. Use MockDataFactory for creating test data');
  print('4. Use HttpTestUtils for HTTP testing');
  print('5. Use StorageTestUtils for storage testing');
  print('6. Use NavigationTestUtils for navigation testing');
  print('7. Use PerformanceTestUtils for performance testing');
  print('8. Use GoldenTestUtils for golden testing');
  print('9. Use AccessibilityTestUtils for accessibility testing');
  print('10. Use IntegrationTestUtils for integration testing');
}
