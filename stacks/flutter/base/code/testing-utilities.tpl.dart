///
/// File: testing-utilities.tpl.dart
/// Purpose: Template for unknown implementation
/// Generated for: {{PROJECT_NAME}}
///

/// Template: testing-utilities.tpl.dart
/// Purpose: testing-utilities template
/// Stack: flutter
/// Tier: base

# Universal Template System - Flutter Stack
# Generated: 2025-12-10
# Purpose: Testing utilities
# Tier: base
# Stack: flutter
# Category: utilities

// -----------------------------------------------------------------------------
// FILE: testing-utilities.tpl.dart
// PURPOSE: Comprehensive testing utilities and helpers for Flutter projects
// USAGE: Import and adapt for consistent testing patterns across the application
// DEPENDENCIES: dart:async, dart:convert, dart:io, dart:typed_data for testing framework
// AUTHOR: [[.Author]]
// VERSION: [[.Version]]
// SINCE: [[.Version]]
// -----------------------------------------------------------------------------

/**
 * Flutter Testing Utilities Template
 * Purpose: Reusable testing utilities and helpers for Flutter projects
 * Usage: Import and adapt for consistent testing patterns across the application
 */

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:mockito/mockito.dart';
import 'package:mockito/annotations.dart';

/// Mock data factory
class MockDataFactory {
  /// Create mock user
  static Map<String, dynamic> createMockUser({
    int id = 1,
    String username = 'testuser',
    String email = 'test@example.com',
    bool isActive = true,
  }) {
    return {
      'id': id,
      'username': username,
      'email': email,
      'firstName': 'Test',
      'lastName': 'User',
      'isActive': isActive,
      'createdAt': DateTime.now().toIso8601String(),
      'updatedAt': DateTime.now().toIso8601String(),
    };
  }

  /// Create mock post
  static Map<String, dynamic> createMockPost({
    int id = 1,
    int userId = 1,
    String title = 'Test Post',
    String content = 'This is test content',
    bool published = true,
  }) {
    return {
      'id': id,
      'title': title,
      'content': content,
      'authorId': userId,
      'published': published,
      'createdAt': DateTime.now().toIso8601String(),
      'updatedAt': DateTime.now().toIso8601String(),
    };
  }

  /// Create mock API response
  static Map<String, dynamic> createMockResponse({
    dynamic data,
    int status = 200,
    String message = 'Success',
  }) {
    return {
      'status': status,
      'message': message,
      'data': data,
      'timestamp': DateTime.now().toIso8601String(),
    };
  }

  /// Create array of mock items
  static List<Map<String, dynamic>> createMockArray<T>(
    Map<String, dynamic> Function(int) createFunction,
    int count, {
    Map<String, dynamic>? baseOverrides,
  }) {
    return List.generate(count, (index) {
      final item = createFunction(index + 1);
      if (baseOverrides != null) {
        item.addAll(baseOverrides);
      }
      return item;
    });
  }

  /// Create mock form data
  static Map<String, dynamic> createMockFormData({
    String username = 'testuser',
    String email = 'test@example.com',
    String password = 'password123',
    String confirmPassword = 'password123',
  }) {
    return {
      'username': username,
      'email': email,
      'password': password,
      'confirmPassword': confirmPassword,
    };
  }
}

/// Test utilities for common widget testing patterns
class WidgetTestUtils {
  /// Find widget by key
  static Widget findByKey(Key key) {
    return find.byKey(key);
  }

  /// Find widget by type
  static Widget findByType<T extends Widget>() {
    return find.byType(T);
  }

  /// Find widget by text
  static Widget findByText(String text) {
    return find.text(text);
  }

  /// Find widget by icon
  static Widget findByIcon(IconData icon) {
    return find.byIcon(icon);
  }

  /// Tap widget by key
  static Future<void> tapByKey(Key key, {WidgetTester? tester}) async {
    final widgetFinder = find.byKey(key);
    await (tester ?? WidgetTester.instance).tap(widgetFinder);
    await (tester ?? WidgetTester.instance).pump();
  }

  /// Tap widget by text
  static Future<void> tapByText(String text, {WidgetTester? tester}) async {
    final widgetFinder = find.text(text);
    await (tester ?? WidgetTester.instance).tap(widgetFinder);
    await (tester ?? WidgetTester.instance).pump();
  }

  /// Enter text in text field
  static Future<void> enterText(
    Key key,
    String text, {
    WidgetTester? tester,
    bool clearFirst = true,
  }) async {
    final textFinder = find.byKey(key);
    if (clearFirst) {
      await (tester ?? WidgetTester.instance).enterText(textFinder, '');
    }
    await (tester ?? WidgetTester.instance).enterText(textFinder, text);
    await (tester ?? WidgetTester.instance).pump();
  }

  /// Fill form with data
  static Future<void> fillForm(
    Map<String, String> formData, {
    WidgetTester? tester,
  }) async {
    for (final entry in formData.entries) {
      await enterText(Key(entry.key), entry.value, tester: tester);
    }
  }

  /// Wait for widget to appear
  static Future<void> waitForWidget(
    Finder finder, {
    Duration timeout = const Duration(seconds: 10),
    WidgetTester? tester,
  }) async {
    await (tester ?? WidgetTester.instance).pumpAndSettle(timeout);
    expect(finder, findsOneWidget);
  }

  /// Wait for text to appear
  static Future<void> waitForText(
    String text, {
    Duration timeout = const Duration(seconds: 10),
    WidgetTester? tester,
  }) async {
    await waitForWidget(find.text(text), timeout: timeout, tester: tester);
  }

  /// Scroll until widget is visible
  static Future<void> scrollToWidget(
    Finder finder, {
    Finder scrollable = find.byType(Scrollable),
    double delta = 100.0,
    int maxScrolls = 10,
    WidgetTester? tester,
  }) async {
    final testTester = tester ?? WidgetTester.instance;
    
    for (int i = 0; i < maxScrolls; i++) {
      if (finder.evaluate().isNotEmpty) {
        return;
      }
      
      await testTester.drag(scrollable, const Offset(0, -100));
      await testTester.pump();
    }
    
    throw Exception('Widget not found after scrolling');
  }

  /// Take screenshot (for golden tests)
  static Future<void> takeScreenshot(
    String fileName, {
    WidgetTester? tester,
  }) async {
    final testTester = tester ?? WidgetTester.instance;
    await expectLater(
      find.byType(MaterialApp),
      matchesGoldenFile('goldens/$fileName.png'),
    );
  }

  /// Verify widget properties
  static void verifyWidgetProperties<T extends Widget>(
    Finder finder,
    Map<String, dynamic> expectedProperties,
  ) {
    final widget = finder.evaluate().first.widget as T;
    
    for (final entry in expectedProperties.entries) {
      // This would need to be implemented based on specific widget types
      // For example, using reflection or specific widget getters
    }
  }
}

/// Mock HTTP client for testing
class MockHttpClient extends Mock implements HttpClient {}

/// Mock API utilities
class MockApiUtils {
  /// Setup mock HTTP client
  static MockHttpClient setupMockHttpClient() {
    final mockClient = MockHttpClient();
    return mockClient;
  }

  /// Mock successful GET response
  static void mockGetSuccess(
    MockHttpClient mockClient,
    String path,
    dynamic data,
  ) {
    when(mockClient.get(any))
        .thenAnswer((_) async => HttpResponse.success(
              statusCode: 200,
              data: data,
              headers: {},
            ));
  }

  /// Mock failed GET response
  static void mockGetError(
    MockHttpClient mockClient,
    String path,
    int statusCode,
    String message,
  ) {
    when(mockClient.get(any))
        .thenThrow(HttpClientException(
          message: message,
          statusCode: statusCode,
          responseTime: 0,
        ));
  }

  /// Mock successful POST response
  static void mockPostSuccess(
    MockHttpClient mockClient,
    String path,
    dynamic data,
    dynamic responseData,
  ) {
    when(mockClient.post(any, data: anyNamed('data')))
        .thenAnswer((_) async => HttpResponse.success(
              statusCode: 201,
              data: responseData,
              headers: {},
            ));
  }

  /// Verify HTTP call was made
  static void verifyHttpCall(
    MockHttpClient mockClient,
    String method,
    String path, {
    dynamic data,
  }) {
    switch (method.toLowerCase()) {
      case 'get':
        verify(mockClient.get(path)).called(1);
        break;
      case 'post':
        verify(mockClient.post(path, data: data)).called(1);
        break;
      case 'put':
        verify(mockClient.put(path, data: data)).called(1);
        break;
      case 'delete':
        verify(mockClient.delete(path)).called(1);
        break;
    }
  }
}

/// Test data manager
class TestDataManager {
  final Map<String, dynamic> _data = {};
  final List<File> _tempFiles = [];

  /// Set test data
  void setData(String key, dynamic value) {
    _data[key] = value;
  }

  /// Get test data
  T? getData<T>(String key) {
    return _data[key] as T?;
  }

  /// Create temporary file for testing
  Future<File> createTempFile(String content, {String? extension}) async {
    final tempDir = Directory.systemTemp;
    final fileName = 'test_${DateTime.now().millisecondsSinceEpoch}.${extension ?? 'txt'}';
    final file = File('${tempDir.path}/$fileName');
    
    await file.writeAsString(content);
    _tempFiles.add(file);
    
    return file;
  }

  /// Create temporary image file
  Future<File> createTempImage() async {
    // Create a simple 1x1 PNG image
    final pngBytes = Uint8List.fromList([
      0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, // PNG signature
      0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52, // IHDR chunk
      0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, // 1x1 dimensions
      0x08, 0x02, 0x00, 0x00, 0x00, 0x90, 0x77, 0x53, // bit depth, color type
      0xDE, 0x00, 0x00, 0x00, 0x0C, 0x49, 0x44, 0x41, // IDAT chunk
      0x54, 0x08, 0x99, 0x01, 0x01, 0x01, 0x00, 0x00, // image data
      0xFE, 0xFF, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01, // CRC
      0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4E, 0x44, // IEND chunk
      0xAE, 0x42, 0x60, 0x82, // CRC
    ]);

    return createTempFile('', extension: 'png').then((file) async {
      await file.writeAsBytes(pngBytes);
      return file;
    });
  }

  /// Cleanup test data
  Future<void> cleanup() async {
    _data.clear();
    
    for (final file in _tempFiles) {
      try {
        if (await file.exists()) {
          await file.delete();
        }
      } catch (e) {
        // Ignore cleanup errors
      }
    }
    
    _tempFiles.clear();
  }
}

/// Performance testing utilities
class PerformanceTestUtils {
  /// Measure widget build time
  static Future<Duration> measureBuildTime(
    Widget widget, {
    WidgetTester? tester,
  }) async {
    final testTester = tester ?? WidgetTester.instance;
    
    final stopwatch = Stopwatch()..start();
    await testTester.pumpWidget(widget);
    await testTester.pumpAndSettle();
    stopwatch.stop();
    
    return stopwatch.elapsed;
  }

  /// Measure function execution time
  static Future<Duration> measureExecutionTime<T>(
    Future<T> Function() function,
  ) async {
    final stopwatch = Stopwatch()..start();
    await function();
    stopwatch.stop();
    
    return stopwatch.elapsed;
  }

  /// Benchmark widget rendering
  static Future<BenchmarkResult> benchmarkWidget(
    Widget widget, {
    int iterations = 10,
    WidgetTester? tester,
  }) async {
    final durations = <Duration>[];
    
    for (int i = 0; i < iterations; i++) {
      final duration = await measureBuildTime(widget, tester: tester);
      durations.add(duration);
    }
    
    return BenchmarkResult(durations);
  }

  /// Measure memory usage
  static Future<MemoryUsage> measureMemoryUsage(
    Widget widget, {
    WidgetTester? tester,
  }) async {
    final testTester = tester ?? WidgetTester.instance;
    
    // Get initial memory
    final initialMemory = _getCurrentMemoryUsage();
    
    // Build widget
    await testTester.pumpWidget(widget);
    await testTester.pumpAndSettle();
    
    // Get final memory
    final finalMemory = _getCurrentMemoryUsage();
    
    return MemoryUsage(
      initial: initialMemory,
      final: finalMemory,
      delta: finalMemory - initialMemory,
    );
  }

  /// Get current memory usage (simplified)
  static int _getCurrentMemoryUsage() {
    // This is a simplified implementation
    // In a real app, you'd use platform-specific APIs
    return 0;
  }
}

/// Benchmark result
class BenchmarkResult {
  final List<Duration> durations;
  
  BenchmarkResult(this.durations);
  
  Duration get average {
    final totalMs = durations.fold<int>(
      0, (sum, duration) => sum + duration.inMilliseconds,
    );
    return Duration(milliseconds: totalMs ~/ durations.length);
  }
  
  Duration get min => durations.reduce((a, b) => a.inMilliseconds < b.inMilliseconds ? a : b);
  
  Duration get max => durations.reduce((a, b) => a.inMilliseconds > b.inMilliseconds ? a : b);
  
  double get standardDeviation {
    final avg = average.inMilliseconds.toDouble();
    final variance = durations.fold<double>(
      0.0,
      (sum, duration) => sum + math.pow(duration.inMilliseconds - avg, 2),
    ) / durations.length;
    
    return math.sqrt(variance);
  }
}

/// Memory usage result
class MemoryUsage {
  final int initial;
  final int final;
  final int delta;
  
  const MemoryUsage({
    required this.initial,
    required this.final,
    required this.delta,
  });
  
  @override
  String toString() {
    return 'MemoryUsage(initial: ${initial}KB, final: ${final}KB, delta: ${delta}KB)';
  }
}

/// Integration test utilities
class IntegrationTestUtils {
  /// Setup integration test
  static Future<void> setupIntegrationTest() async {
    IntegrationTestWidgetsFlutterBinding.ensureInitialized();
  }

  /// Wait for network request
  static Future<void> waitForNetworkRequest({
    Duration timeout = const Duration(seconds: 30),
  }) async {
    // Wait for any pending network requests
    await Future.delayed(const Duration(milliseconds: 100));
    await Future.delayed(timeout);
  }

  /// Take screenshot in integration test
  static Future<void> takeScreenshot(
    String fileName, {
    WidgetTester? tester,
  }) async {
    final testTester = tester ?? WidgetTester.instance;
    await binding.takeScreenshot(fileName);
  }

  /// Test app lifecycle
  static Future<void> testAppLifecycle(
    WidgetTester tester,
    List<AppLifecycleState> states,
  ) async {
    for (final state in states) {
      await binding.defaultBinaryMessenger.handlePlatformMessage(
        'flutter/lifecycle',
        StringCodec().encode(state.name),
        (data) {},
      );
      await tester.pumpAndSettle();
    }
  }
}

/// Accessibility testing utilities
class AccessibilityTestUtils {
  /// Check widget has semantic label
  static void hasSemanticLabel(
    Finder finder,
    String expectedLabel,
  ) {
    expect(finder, matchesSemantics(label: expectedLabel));
  }

  /// Check widget is accessible
  static void isAccessible(Finder finder) {
    expect(finder, matchesSemantics());
  }

  /// Check button has accessibility hint
  static void buttonHasAccessibilityHint(
    Finder finder,
    String hint,
  ) {
    expect(finder, matchesSemantics(
      label: hint,
      button: true,
    ));
  }

  /// Check text field has accessibility label
  static void textFieldHasAccessibilityLabel(
    Finder finder,
    String label,
  ) {
    expect(finder, matchesSemantics(
      label: label,
      textField: true,
    ));
  }

  /// Verify all interactive widgets have labels
  static void verifyAccessibilityLabels(WidgetTester tester) {
    final buttons = find.byType(ElevatedButton);
    final textFields = find.byType(TextField);
    
    // Check buttons have labels
    for (final button in buttons.evaluate()) {
      expect(button, matchesSemantics());
    }
    
    // Check text fields have labels
    for (final textField in textFields.evaluate()) {
      expect(textField, matchesSemantics());
    }
  }
}

/// Test widget wrapper
class TestWidgetWrapper extends StatelessWidget {
  final Widget child;
  final ThemeData? theme;
  final MediaQueryData? mediaQueryData;
  
  const TestWidgetWrapper({
    Key? key,
    required this.child,
    this.theme,
    this.mediaQueryData,
  }) : super(key: key);

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      theme: theme ?? ThemeData.light(),
      home: MediaQuery(
        data: mediaQueryData ?? const MediaQueryData(),
        child: Scaffold(body: child),
      ),
    );
  }
}

/// Golden test utilities
class GoldenTestUtils {
  /// Create golden test for widget
  static Widget createGoldenTestWidget(
    Widget widget, {
    ThemeData? theme,
    Size? surfaceSize,
  }) {
    return TestWidgetWrapper(
      theme: theme ?? ThemeData.light(),
      mediaQueryData: surfaceSize != null
          ? MediaQueryData(size: surfaceSize)
          : null,
      child: widget,
    );
  }

  /// Compare widget with golden file
  static Future<void> compareWithGolden(
    Widget widget,
    String goldenFileName, {
    WidgetTester? tester,
  }) async {
    final testTester = tester ?? WidgetTester.instance;
    
    await testTester.pumpWidget(createGoldenTestWidget(widget));
    await testTester.pumpAndSettle();
    
    await expectLater(
      find.byType(MaterialApp),
      matchesGoldenFile('goldens/$goldenFileName.png'),
    );
  }
}

/// Custom test matchers
class CustomMatchers {
  /// Matcher for widget visibility
  static Matcher isVisible() {
    return matchesGoldenFile('visible.png');
  }

  /// Matcher for widget enabled state
  static Matcher isEnabled() {
    return isA<Widget>().having(
      (widget) => _isWidgetEnabled(widget),
      'enabled',
      true,
    );
  }

  /// Matcher for widget disabled state
  static Matcher isDisabled() {
    return isA<Widget>().having(
      (widget) => _isWidgetEnabled(widget),
      'enabled',
      false,
    );
  }

  /// Check if widget is enabled (simplified)
  static bool _isWidgetEnabled(Widget widget) {
    // This would need to be implemented based on specific widget types
    return true;
  }
}

/// Test configuration
class TestConfig {
  static const Duration defaultTimeout = Duration(seconds: 30);
  static const Duration shortTimeout = Duration(seconds: 5);
  static const Duration longTimeout = Duration(minutes: 2);
  
  static const int defaultTestIterations = 10;
  static const int performanceTestIterations = 100;
  
  static const String goldenFilesPath = 'test/goldens';
  static const String tempFilesPath = 'test/temp';
}

/// Example test class
class ExampleWidgetTest {
  /// Test basic widget functionality
  static Widget createTestWidget() {
    return const TestWidgetWrapper(
      child: Column(
        children: [
          Text('Test Widget'),
          ElevatedButton(
            key: Key('test_button'),
            onPressed: null,
            child: Text('Click Me'),
          ),
          TextField(
            key: Key('test_field'),
            decoration: InputDecoration(labelText: 'Test Field'),
          ),
        ],
      ),
    );
  }

  /// Example test method
  static void exampleTest() {
    testWidgets('Example widget test', (WidgetTester tester) async {
      // Build widget
      await tester.pumpWidget(createTestWidget());
      
      // Verify text exists
      expect(find.text('Test Widget'), findsOneWidget);
      
      // Tap button
      await WidgetTestUtils.tapByKey(const Key('test_button'), tester: tester);
      
      // Enter text in field
      await WidgetTestUtils.enterText(
        const Key('test_field'),
        'Hello World',
        tester: tester,
      );
      
      // Verify text was entered
      expect(find.text('Hello World'), findsOneWidget);
    });
  }
}

void main() {
  // Example usage
  ExampleWidgetTest.exampleTest();
}

export {
  // Data utilities
  MockDataFactory,
  TestDataManager,

  // Widget testing
  WidgetTestUtils,
  TestWidgetWrapper,

  // Mock utilities
  MockHttpClient,
  MockApiUtils,

  // Performance testing
  PerformanceTestUtils,
  BenchmarkResult,
  MemoryUsage,

  // Integration testing
  IntegrationTestUtils,

  // Accessibility testing
  AccessibilityTestUtils,

  // Golden testing
  GoldenTestUtils,

  // Custom matchers
  CustomMatchers,

  // Configuration
  TestConfig,
};
