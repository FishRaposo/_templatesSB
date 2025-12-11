import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:mockito/mockito.dart';
import 'package:mockito/annotations.dart';
import 'package:bloc_test/bloc_test.dart';
import 'package:network_image_mock/network_image_mock.dart';
import 'package:fake_cloud_firestore/fake_cloud_firestore.dart';
import 'package:fake_firebase_auth/fake_firebase_auth.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'dart:io';
import 'dart:math';

// =============================================================================
// WIDGET TESTING HELPERS
// =============================================================================

class WidgetTestHelper {
  static Widget createMaterialApp({
    required Widget child,
    ThemeData? theme,
    Locale? locale,
    String? title,
    Map<String, WidgetBuilder>? routes,
    GlobalKey<NavigatorState>? navigatorKey,
  }) {
    return MaterialApp(
      title: title ?? 'Test App',
      theme: theme ?? ThemeData.light(),
      locale: locale ?? const Locale('en'),
      routes: routes ?? {},
      navigatorKey: navigatorKey,
      home: child,
    );
  }

  static Widget createMaterialAppWithScaffold({
    required Widget child,
    PreferredSizeWidget? appBar,
    Widget? floatingActionButton,
    Widget? drawer,
    Widget? bottomNavigationBar,
    Color? backgroundColor,
  }) {
    return MaterialApp(
      home: Scaffold(
        appBar: appBar,
        body: child,
        floatingActionButton: floatingActionButton,
        drawer: drawer,
        bottomNavigationBar: bottomNavigationBar,
        backgroundColor: backgroundColor,
      ),
    );
  }

  static Widget wrapWithMaterial({
    required Widget child,
    MaterialAppData? data,
  }) {
    return Material(
      child: child,
      data: data,
    );
  }

  static Widget wrapWithMediaQuery({
    required Widget child,
    Size? size,
    EdgeInsets? padding,
    bool? alwaysUse24HourFormat,
  }) {
    return MediaQuery(
      data: MediaQueryData(
        size: size ?? const Size(800, 600),
        padding: padding ?? EdgeInsets.zero,
        alwaysUse24HourFormat: alwaysUse24HourFormat ?? false,
      ),
      child: child,
    );
  }

  static Widget wrapWithDirectionality({
    required Widget child,
    TextDirection textDirection = TextDirection.ltr,
  }) {
    return Directionality(
      textDirection: textDirection,
      child: child,
    );
  }

  static Widget wrapWithScrollable({
    required Widget child,
    Axis scrollDirection = Axis.vertical,
    ScrollController? controller,
    bool? reverse,
    ScrollPhysics? physics,
  }) {
    return SingleChildScrollView(
      scrollDirection: scrollDirection,
      controller: controller,
      reverse: reverse ?? false,
      physics: physics,
      child: child,
    );
  }

  static Future<void> pumpAndSettle(
    WidgetTester tester, {
    Duration? duration,
    EnginePhase? phase,
  }) async {
    await tester.pumpAndSettle(duration: duration, phase: phase);
  }

  static Future<void> pumpFrames(
    WidgetTester tester, {
    required int count,
    Duration? duration,
  }) async {
    for (int i = 0; i < count; i++) {
      await tester.pump(duration);
    }
  }
}

// =============================================================================
// MOCK HELPERS
// =============================================================================

class MockHelper {
  static void mockNetworkImages() {
    mockNetworkImagesFor(() {});
  }

  static void mockPlatformChannel({
    String? channelName,
    MethodChannel? channel,
    dynamic Function(MethodCall call)? onMethodCall,
  }) {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(
      channel ?? MethodChannel(channelName ?? 'test_channel'),
      onMethodCall,
    );
  }

  static void mockSharedPreferences({
    Map<String, dynamic>? initialData,
  }) {
    SharedPreferences.setMockInitialValues(initialData ?? {});
  }

  static void mockFirebaseAuth({
    User? currentUser,
    bool isSignedIn = false,
  }) {
    final fakeAuth = FakeFirebaseAuth();
    if (isSignedIn && currentUser != null) {
      fakeAuth.signInWithEmailAndPassword(
        email: currentUser.email ?? '',
        password: 'password',
      );
    }
  }

  static void mockCloudFirestore({
    Map<String, dynamic>? initialData,
  }) {
    FakeFirebaseFirestore.instance;
    if (initialData != null) {
      // Initialize with test data
      initialData.forEach((path, data) {
        FakeFirebaseFirestore.instance.collection(path).add(data);
      });
    }
  }

  static void mockHttpOverrides({
    Map<String, dynamic>? responses,
  }) {
    HttpOverrides.global = MockHttpOverrides(responses ?? {});
  }
}

class MockHttpOverrides extends HttpOverrides {
  final Map<String, dynamic> responses;

  MockHttpOverrides(this.responses);

  @override
  HttpClient createHttpClient(SecurityContext? context) {
    return MockHttpClient(responses);
  }
}

class MockHttpClient implements HttpClient {
  final Map<String, dynamic> responses;

  MockHttpClient(this.responses);

  @override
  Future<HttpClientRequest> getUrl(String url, {Map<String, String>? headers}) {
    return _createMockRequest('GET', url, headers);
  }

  @override
  Future<HttpClientRequest> postUrl(String url, {Map<String, String>? headers}) {
    return _createMockRequest('POST', url, headers);
  }

  @override
  Future<HttpClientRequest> putUrl(String url, {Map<String, String>? headers}) {
    return _createMockRequest('PUT', url, headers);
  }

  @override
  Future<HttpClientRequest> deleteUrl(String url, {Map<String, String>? headers}) {
    return _createMockRequest('DELETE', url, headers);
  }

  Future<HttpClientRequest> _createMockRequest(
    String method,
    String url,
    Map<String, String>? headers,
  ) async {
    final response = responses[url];
    if (response != null) {
      return MockHttpClientRequest(response);
    }
    throw Exception('No mock response for $method $url');
  }

  @override
  void close({bool force = false}) {}
}

class MockHttpClientRequest implements HttpClientRequest {
  final dynamic response;

  MockHttpClientRequest(this.response);

  @override
  void add(List<int> data) {}

  @override
  void addError(Object error, [StackTrace? stackTrace]) {}

  @override
  void addStream(Stream<List<int>> stream) {}

  @override
  Future<HttpClientResponse> close() async {
    return MockHttpClientResponse(response);
  }

  @override
  HttpConnectionInfo? get connectionInfo => null;

  @override
  int get contentLength => 0;

  @override
  HttpHeaders get headers => MockHttpHeaders();

  @override
  bool get followRedirects => true;

  @override
  set followRedirects(bool followRedirects) {}

  @override
  int get maxRedirects => 5;

  @override
  set maxRedirects(int maxRedirects) {}

  @override
  String get method => 'GET';

  @override
  bool get persistentConnection => true;

  @override
  set persistentConnection(bool persistentConnection) {}

  @override
  void abort([Object? exception, StackTrace? stackTrace]) {}

  @override
  void setHeader(String key, String value) {}

  @override
  Future<HttpClientResponse> done() async {
    return MockHttpClientResponse(response);
  }

  @override
  void write(Object obj) {}

  @override
  void writeAll(Iterable<Object> objects, [String separator = '']) {}

  @override
  void writeCharCode(int charCode) {}

  @override
  void writeln([Object? obj = '']) {}
}

class MockHttpClientResponse implements HttpClientResponse {
  final dynamic response;

  MockHttpClientResponse(this.response);

  @override
  StreamSubscription<List<int>> listen(
    void Function(List<int> event)? onData, {
    Function? onError,
    void Function()? onDone,
    bool? cancelOnError,
  }) {
    return Stream.value(response.toString().codeUnits).listen(
      onData,
      onError: onError,
      onDone: onDone,
      cancelOnError: cancelOnError,
    );
  }

  @override
  HttpClientResponseCompression get compression =>
      HttpClientResponseCompression.none;

  @override
  HttpConnectionInfo? get connectionInfo => null;

  @override
  int get contentLength => response.toString().length;

  @override
  HttpHeaders get headers => MockHttpHeaders();

  @override
  bool get isRedirect => false;

  @override
  Stream<List<int>> get inputStream => Stream.value(response.toString().codeUnits);

  @override
  String get reasonPhrase => 'OK';

  @override
  int get statusCode => 200;

  @override
  Future<void> detach([Socket? socket]) async {}

  @override
  Future<bool> any(List<int> Function(List<int>) test, {int? count}) async {
    return false;
  }

  @override
  Future<List<int>> first([int? count]) async {
    return response.toString().codeUnits.take(count ?? 1).toList();
  }

  @override
  Future<bool> isEmpty() async {
    return false;
  }

  @override
  Future<List<int>> last([int? count]) async {
    return response.toString().codeUnits.takeLast(count ?? 1).toList();
  }

  @override
  Future<List<int>> single([int? count]) async {
    return response.toString().codeUnits.take(count ?? 1).toList();
  }

  @override
  Future<List<List<int>>> take(int count) async {
    return [response.toString().codeUnits.take(count).toList()];
  }

  @override
  Future<List<int>> takeWhile(bool Function(List<int>) test) async {
    return response.toString().codeUnits.toList();
  }

  @override
  Future<List<int>> toList() async {
    return response.toString().codeUnits.toList();
  }

  @override
  Future<String> toString() async {
    return response.toString();
  }
}

class MockHttpHeaders implements HttpHeaders {
  final Map<String, String> _headers = {};

  @override
  List<String>? operator [](String name) => _headers[name]?.split(',');

  @override
  void add(String name, String value) {
    _headers[name] = value;
  }

  @override
  void clear() {
    _headers.clear();
  }

  @override
  void forEach(void Function(String name, List<String> values) action) {
    _headers.forEach((key, value) {
      action(key, [value]);
    });
  }

  @override
  void set(String name, String value) {
    _headers[name] = value;
  }

  @override
  String? value(String name) => _headers[name];

  @override
  void remove(String name, String value) {
    _headers.remove(name);
  }

  @override
  void removeAll(String name) {
    _headers.remove(name);
  }
}

// =============================================================================
// TEST DATA GENERATORS
// =============================================================================

class TestDataGenerator {
  static final Random _random = Random();

  static Map<String, dynamic> generateUser({
    String? id,
    String? email,
    String? firstName,
    String? lastName,
    String? avatar,
    bool? isActive,
    bool? isVerified,
    List<String>? roles,
  }) {
    return {
      'id': id ?? _generateUuid(),
      'email': email ?? '${_random.nextInt(1000)}@example.com',
      'firstName': firstName ?? 'FirstName${_random.nextInt(1000)}',
      'lastName': lastName ?? 'LastName${_random.nextInt(1000)}',
      'avatar': avatar ?? 'https://example.com/avatar${_random.nextInt(1000)}.jpg',
      'isActive': isActive ?? _random.nextBool(),
      'isVerified': isVerified ?? _random.nextBool(),
      'roles': roles ?? ['user'],
      'createdAt': DateTime.now().toIso8601String(),
      'updatedAt': DateTime.now().toIso8601String(),
    };
  }

  static Map<String, dynamic> generateProduct({
    String? id,
    String? name,
    String? description,
    double? price,
    String? category,
    String? sku,
    int? stock,
    bool? isActive,
    List<String>? tags,
  }) {
    return {
      'id': id ?? _generateUuid(),
      'name': name ?? 'Product${_random.nextInt(1000)}',
      'description': description ?? 'Description for product ${_random.nextInt(1000)}',
      'price': price ?? (_random.nextDouble() * 1000).roundToDouble(),
      'category': category ?? _random.choice(['electronics', 'clothing', 'books', 'home']),
      'sku': sku ?? 'SKU-${_random.nextInt(100000)}',
      'stock': stock ?? _random.nextInt(1000),
      'isActive': isActive ?? _random.nextBool(),
      'tags': tags ?? _random.choice(['popular', 'new', 'sale', 'featured']),
      'createdAt': DateTime.now().toIso8601String(),
      'updatedAt': DateTime.now().toIso8601String(),
    };
  }

  static Map<String, dynamic> generateOrder({
    String? id,
    String? userId,
    String? status,
    double? totalAmount,
    String? currency,
    List<Map<String, dynamic>>? items,
  }) {
    return {
      'id': id ?? _generateUuid(),
      'userId': userId ?? _generateUuid(),
      'status': status ?? _random.choice(['pending', 'confirmed', 'shipped', 'delivered']),
      'totalAmount': totalAmount ?? (_random.nextDouble() * 500).roundToDouble(),
      'currency': currency ?? _random.choice(['USD', 'EUR', 'GBP']),
      'items': items ?? [
        {
          'productId': _generateUuid(),
          'quantity': _random.nextInt(5) + 1,
          'unitPrice': (_random.nextDouble() * 100).roundToDouble(),
          'totalPrice': (_random.nextDouble() * 100).roundToDouble(),
        }
      ],
      'createdAt': DateTime.now().toIso8601String(),
      'updatedAt': DateTime.now().toIso8601String(),
    };
  }

  static List<Map<String, dynamic>> generateUserList({int count = 10}) {
    return List.generate(count, (index) => generateUser());
  }

  static List<Map<String, dynamic>> generateProductList({int count = 10}) {
    return List.generate(count, (index) => generateProduct());
  }

  static List<Map<String, dynamic>> generateOrderList({int count = 10}) {
    return List.generate(count, (index) => generateOrder());
  }

  static String _generateUuid() {
    return '${_random.nextInt(1000000)}-${_random.nextInt(1000000)}-${_random.nextInt(1000000)}';
  }
}

// =============================================================================
// BLOC TESTING HELPERS
// =============================================================================

class BlocTestHelper {
  static blocTest<T extends BlocBase<E>, E, S>(
    String description,
    {
      required T build(),
      required Iterable<Expectation<S>> expect,
      Future<void> Function()? act,
      Iterable<void Function()>? setUp,
      void Function()? tearDown,
      Iterable<void Function()>? errors,
      Duration? wait,
      Duration? seed,
    },
  ) {
    return blocTest<T, E, S>(
      description,
      build: build,
      expect: expect,
      act: act,
      setUp: setUp,
      tearDown: tearDown,
      errors: errors,
      wait: wait,
      seed: seed,
    );
  }

  static blocBuilder<T extends BlocBase<E>, E, S>(
    String description,
    {
      required T build(),
      required Iterable<Expectation<S>> expect,
      Future<void> Function()? act,
      Iterable<void Function()>? setUp,
      void Function()? tearDown,
      Duration? wait,
      Duration? seed,
    },
  ) {
    return blocTest<T, E, S>(
      description,
      build: build,
      expect: expect,
      act: act,
      setUp: setUp,
      tearDown: tearDown,
      wait: wait,
      seed: seed,
    );
  }
}

// =============================================================================
// INTEGRATION TESTING HELPERS
// =============================================================================

class IntegrationTestHelper {
  static IntegrationTestWidgetsFlutterBinding ensureInitialized() {
    return IntegrationTestWidgetsFlutterBinding.ensureInitialized();
  }

  static Future<void> pumpAndSettleWithDelay(
    WidgetTester tester, {
    Duration delay = const Duration(milliseconds: 100),
  }) async {
    await tester.pumpAndSettle();
    await tester.pump(delay);
  }

  static Future<void> waitForElement(
    WidgetTester tester,
    Finder finder, {
    Duration timeout = const Duration(seconds: 10),
  }) async {
    final end = DateTime.now().add(timeout);
    
    while (DateTime.now().isBefore(end)) {
      try {
        expect(finder, findsOneWidget);
        return;
      } catch (e) {
        await tester.pump(const Duration(milliseconds: 100));
      }
    }
    
    throw Exception('Element not found within timeout: $finder');
  }

  static Future<void> scrollUntilVisible(
    WidgetTester tester,
    Finder finder, {
    Finder? scrollable,
    double delta = 100.0,
    Duration timeout = const Duration(seconds: 10),
  }) async {
    final scrollableFinder = scrollable ?? find.byType(Scrollable);
    final end = DateTime.now().add(timeout);
    
    while (DateTime.now().isBefore(end)) {
      try {
        expect(finder, findsOneWidget);
        return;
      } catch (e) {
        await tester.scrollUntilVisible(
          finder,
          scrollable: scrollableFinder,
          delta: delta,
        );
      }
    }
    
    throw Exception('Element not found after scrolling: $finder');
  }

  static Future<void> enterTextAndDismissKeyboard(
    WidgetTester tester,
    Finder finder,
    String text, {
    bool shouldDismiss = true,
  }) async {
    await tester.enterText(finder, text);
    if (shouldDismiss) {
      await tester.testTextInput.receiveAction(TextInputAction.done);
      await tester.pump();
    }
  }

  static Future<void> tapAndSettle(
    WidgetTester tester,
    Finder finder, {
    Duration settleDelay = const Duration(milliseconds: 100),
  }) async {
    await tester.tap(finder);
    await tester.pumpAndSettle();
    await tester.pump(settleDelay);
  }

  static Future<void> longPressAndSettle(
    WidgetTester tester,
    Finder finder, {
    Duration settleDelay = const Duration(milliseconds: 100),
  }) async {
    await tester.longPress(finder);
    await tester.pumpAndSettle();
    await tester.pump(settleDelay);
  }

  static Future<void> dragAndSettle(
    WidgetTester tester,
    Finder finder,
    Offset offset, {
    Duration settleDelay = const Duration(milliseconds: 100),
  }) async {
    await tester.drag(finder, offset.dx, offset.dy);
    await tester.pumpAndSettle();
    await tester.pump(settleDelay);
  }

  static Future<void> flingAndSettle(
    WidgetTester tester,
    Finder finder,
    Offset velocity, {
    Duration settleDelay = const Duration(milliseconds: 100),
  }) async {
    await tester.fling(finder, velocity.dx, velocity.dy);
    await tester.pumpAndSettle();
    await tester.pump(settleDelay);
  }
}

// =============================================================================
// ACCESSIBILITY TESTING HELPERS
// =============================================================================

class AccessibilityHelper {
  static void checkSemantics(
    WidgetTester tester,
    Finder finder, {
    bool isFocusable = true,
    bool isButton = false,
    bool isTextField = false,
    String? label,
    String? hint,
    String? value,
    bool? isChecked,
    bool? isEnabled,
  }) {
    final semantics = tester.semantics(find(finder));
    
    if (label != null) {
      expect(semantics.label, label);
    }
    
    if (hint != null) {
      expect(semantics.hint, hint);
    }
    
    if (value != null) {
      expect(semantics.value, value);
    }
    
    if (isChecked != null) {
      expect(semantics.hasFlag(SemanticsFlag.hasCheckedState), true);
      expect(semantics.isChecked, isChecked);
    }
    
    if (isEnabled != null) {
      expect(semantics.hasFlag(SemanticsFlag.hasEnabledState), true);
      expect(semantics.isEnabled, isEnabled);
    }
    
    expect(semantics.hasFlag(SemanticsFlag.isFocusable), isFocusable);
    
    if (isButton) {
      expect(semantics.hasFlag(SemanticsFlag.isButton), true);
    }
    
    if (isTextField) {
      expect(semantics.hasFlag(SemanticsFlag.isTextField), true);
    }
  }

  static void checkAccessibilityGuidelines(
    WidgetTester tester,
    Finder finder, {
    bool checkTextContrast = true,
    bool checkTapTargetSize = true,
    bool checkLabelledControls = true,
  }) {
    // Check text contrast
    if (checkTextContrast) {
      final renderObject = tester.renderObject(find(finder));
      if (renderObject is RenderParagraph) {
        // Add contrast checking logic here
      }
    }
    
    // Check tap target size (minimum 44x44 points)
    if (checkTapTargetSize) {
      final renderBox = tester.renderObject(find(finder)) as RenderBox?;
      if (renderBox != null) {
        final size = renderBox.size;
        expect(size.width, greaterThanOrEqualTo(44.0));
        expect(size.height, greaterThanOrEqualTo(44.0));
      }
    }
    
    // Check labelled controls
    if (checkLabelledControls) {
      final semantics = tester.semantics(find(finder));
      expect(semantics.label.isNotEmpty, true);
    }
  }
}

// =============================================================================
// PERFORMANCE TESTING HELPERS
// =============================================================================

class PerformanceHelper {
  static Future<PerformanceMetrics> measureRenderPerformance(
    WidgetTester tester,
    Widget widget, {
    int iterations = 10,
  }) async {
    final times = <Duration>[];
    
    for (int i = 0; i < iterations; i++) {
      final stopwatch = Stopwatch()..start();
      
      await tester.pumpWidget(widget);
      await tester.pumpAndSettle();
      
      stopwatch.stop();
      times.add(stopwatch.elapsed);
      
      await tester.pumpWidget(Container()); // Clear widget
    }
    
    return PerformanceMetrics(
      iterations: iterations,
      times: times,
      average: times.reduce((a, b) => a + b) / times.length,
      min: times.reduce(min),
      max: times.reduce(max),
    );
  }

  static Future<MemoryMetrics> measureMemoryUsage(
    WidgetTester tester,
    Widget widget, {
    Duration duration = const Duration(seconds: 5),
  }) async {
    final measurements = <int>[];
    final timer = Timer.periodic(const Duration(milliseconds: 100), (timer) {
      // This would need to be implemented with actual memory measurement
      // For now, we'll simulate it
      measurements.add(Random().nextInt(100000));
    });
    
    await tester.pumpWidget(widget);
    await tester.pumpAndSettle();
    
    await Future.delayed(duration);
    timer.cancel();
    
    return MemoryMetrics(
      measurements: measurements,
      average: measurements.reduce((a, b) => a + b) / measurements.length,
      min: measurements.reduce(min),
      max: measurements.reduce(max),
    );
  }

  static Future<void> profileWidget(
    WidgetTester tester,
    Widget widget, {
    Duration duration = const Duration(seconds: 5),
  }) async {
    // This would integrate with Flutter's profiling tools
    // For now, we'll simulate profiling
    await tester.pumpWidget(widget);
    await tester.pumpAndSettle();
    
    final stopwatch = Stopwatch()..start();
    await Future.delayed(duration);
    stopwatch.stop();
    
    print('Widget profiling completed in ${stopwatch.elapsed}');
  }
}

class PerformanceMetrics {
  final int iterations;
  final List<Duration> times;
  final Duration average;
  final Duration min;
  final Duration max;

  PerformanceMetrics({
    required this.iterations,
    required this.times,
    required this.average,
    required this.min,
    required this.max,
  });

  @override
  String toString() {
    return 'PerformanceMetrics('
        'iterations: $iterations, '
        'average: ${average.inMilliseconds}ms, '
        'min: ${min.inMilliseconds}ms, '
        'max: ${max.inMilliseconds}ms'
        ')';
  }
}

class MemoryMetrics {
  final List<int> measurements;
  final double average;
  final int min;
  final int max;

  MemoryMetrics({
    required this.measurements,
    required this.average,
    required this.min,
    required this.max,
  });

  @override
  String toString() {
    return 'MemoryMetrics('
        'measurements: ${measurements.length}, '
        'average: ${average.toStringAsFixed(2)}, '
        'min: $min, '
        'max: $max'
        ')';
  }
}

// =============================================================================
// COMMON FINDERS
// =============================================================================

class CommonFinders {
  static Finder byText(String text) {
    return find.text(text);
  }

  static Finder byKey(Key key) {
    return find.byKey(key);
  }

  static Finder byType<T>() {
    return find.byType<T>();
  }

  static Finder byIcon(IconData icon) {
    return find.byIcon(icon);
  }

  static Finder byImage(String image) {
    return find.byImage(image);
  }

  static Finder byTooltip(String message) {
    return find.byTooltip(message);
  }

  static Finder bySemanticsLabel(String label) {
    return find.bySemanticsLabel(label);
  }

  static Finder byWidgetPredicate(WidgetPredicate predicate) {
    return find.byWidgetPredicate(predicate);
  }

  static Finder byElementPredicate(ElementPredicate predicate) {
    return find.byElementPredicate(predicate);
  }

  static Finder byAncestor(Widget ancestor) {
    return find.ancestor(of: ancestor);
  }

  static Finder byDescendant(Widget descendant) {
    return find.descendant(of: descendant);
  }
}

// =============================================================================
// COMMON MATCHERS
// =============================================================================

class CommonMatchers {
  static Matcher hasText(String text) {
    return isA<Widget>().having(
      (widget) => widget is Text && (widget as Text).data == text,
      'has text',
      text,
    );
  }

  static Matcher hasIcon(IconData icon) {
    return isA<Widget>().having(
      (widget) => widget is Icon && (widget as Icon).icon == icon,
      'has icon',
      icon,
    );
  }

  static Matcher hasKey(Key key) {
    return isA<Widget>().having(
      (widget) => widget.key == key,
      'has key',
      key,
    );
  }

  static Matcher isDisabled() {
    return isA<Widget>().having(
      (widget) {
        if (widget is ElevatedButton) {
          return !(widget as ElevatedButton).onPressed != null;
        } else if (widget is TextButton) {
          return !(widget as TextButton).onPressed != null;
        } else if (widget is IconButton) {
          return !(widget as IconButton).onPressed != null;
        }
        return false;
      },
      'is disabled',
      true,
    );
  }

  static Matcher isEnabled() {
    return isA<Widget>().having(
      (widget) {
        if (widget is ElevatedButton) {
          return (widget as ElevatedButton).onPressed != null;
        } else if (widget is TextButton) {
          return (widget as TextButton).onPressed != null;
        } else if (widget is IconButton) {
          return (widget as IconButton).onPressed != null;
        }
        return false;
      },
      'is enabled',
      true,
    );
  }
}

// =============================================================================
// EXPORT ALL HELPERS
// =============================================================================

export 'package:flutter_test/flutter_test.dart';
export 'package:integration_test/integration_test.dart';
export 'package:mockito/mockito.dart';
export 'package:bloc_test/bloc_test.dart';

// Export custom helpers
export 'package:network_image_mock/network_image_mock.dart';
export 'package:fake_cloud_firestore/fake_cloud_firestore.dart';
export 'package:fake_firebase_auth/fake_firebase_auth.dart';

// Export helper classes
export 'widget_test_helper.dart' show WidgetTestHelper;
export 'mock_helper.dart' show MockHelper;
export 'test_data_generator.dart' show TestDataGenerator;
export 'bloc_test_helper.dart' show BlocTestHelper;
export 'integration_test_helper.dart' show IntegrationTestHelper;
export 'accessibility_helper.dart' show AccessibilityHelper;
export 'performance_helper.dart' show PerformanceHelper;
export 'common_finders.dart' show CommonFinders;
export 'common_matchers.dart' show CommonMatchers;