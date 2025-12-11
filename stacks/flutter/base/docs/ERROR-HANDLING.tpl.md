# Universal Template System - Flutter Stack
# Generated: 2025-12-10
# Purpose: Error handling utilities
# Tier: base
# Stack: flutter
# Category: template

# Error Handling Guide - Flutter

This guide covers comprehensive error handling strategies, exception management, and error recovery patterns for Flutter applications.

## 🚨 Flutter Error Handling Overview

Flutter provides robust error handling mechanisms through exceptions, error widgets, and async error handling. Proper error handling ensures app stability and good user experience.

## 📊 Error Categories

### Common Error Types
- **AssertionError**: Debug-time assertions and contract violations
- **FormatException**: Data parsing and validation errors
- **StateError**: Invalid state access (e.g., accessing disposed objects)
- **NetworkException**: HTTP and connectivity issues
- **PlatformException**: Platform-specific API failures
- **AsyncError**: Future and Stream operation failures

### Error Severity Levels
```dart
enum ErrorSeverity {
  critical,   // App crashes, data corruption
  high,       // Feature failures, major UX issues
  medium,     // Degraded functionality, minor UX issues
  low,        // Non-critical issues, logging only
}
```

## 🔍 Error Detection & Monitoring

### Error Detection Patterns

#### Before: Unhandled Errors
```dart
// BAD: Unhandled exceptions
class BadWidget extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    return ElevatedButton(
      onPressed: () {
        // Potential division by zero
        final result = 100 ~/ int.parse(userInput);
        print(result);
      },
      child: Text('Calculate'),
    );
  }
}
```

#### After: Comprehensive Error Handling
```dart
// GOOD: Proper error handling
class GoodWidget extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    return ElevatedButton(
      onPressed: () async {
        try {
          final input = int.parse(userInput);
          if (input == 0) {
            throw ArgumentError('Cannot divide by zero');
          }
          final result = 100 ~/ input;
          print(result);
        } on FormatException catch (e) {
          _showErrorDialog(context, 'Invalid number format: ${e.message}');
        } on ArgumentError catch (e) {
          _showErrorDialog(context, e.message);
        } catch (e) {
          _showErrorDialog(context, 'Unexpected error occurred');
          _logError(e);
        }
      },
      child: Text('Calculate'),
    );
  }
  
  void _showErrorDialog(BuildContext context, String message) {
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        title: Text('Error'),
        content: Text(message),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: Text('OK'),
          ),
        ],
      ),
    );
  }
  
  void _logError(dynamic error) {
    // Log to crash reporting service
    FirebaseCrashlytics.instance.recordError(error, null);
  }
}
```

### Custom Error Classes
```dart
// Custom error types for better error handling
abstract class AppException implements Exception {
  final String message;
  final String? code;
  final dynamic originalError;
  
  const AppException(this.message, {this.code, this.originalError});
  
  @override
  String toString() => message;
}

class NetworkException extends AppException {
  const NetworkException(String message, {String? code, dynamic originalError})
      : super(message, code: code, originalError: originalError);
}

class ValidationException extends AppException {
  final Map<String, String>? fieldErrors;
  
  const ValidationException(String message, {this.fieldErrors})
      : super(message);
}

class BusinessException extends AppException {
  const BusinessException(String message, {String? code})
      : super(message, code: code);
}

class SystemException extends AppException {
  const SystemException(String message, {dynamic originalError})
      : super(message, originalError: originalError);
}
```

## ⚡ Async Error Handling

### Future Error Handling

#### Before: Poor Async Error Handling
```dart
// BAD: Not handling async errors properly
Future<void> loadDataBad() async {
  final response = await http.get(Uri.parse('https://api.example.com/data'));
  final data = json.decode(response.body);
  // No error handling for network or parsing errors
}
```

#### After: Comprehensive Async Error Handling
```dart
// GOOD: Proper async error handling
class DataService {
  Future<DataModel> loadData() async {
    try {
      final response = await _makeRequest();
      return _parseResponse(response);
    } on SocketException catch (e) {
      throw NetworkException('No internet connection', originalError: e);
    } on TimeoutException catch (e) {
      throw NetworkException('Request timeout', originalError: e);
    } on HttpException catch (e) {
      throw NetworkException('HTTP error: ${e.message}', originalError: e);
    } on FormatException catch (e) {
      throw ValidationException('Invalid response format', originalError: e);
    } catch (e) {
      throw SystemException('Unexpected error loading data', originalError: e);
    }
  }
  
  Future<http.Response> _makeRequest() async {
    return await http
        .get(Uri.parse('https://api.example.com/data'))
        .timeout(const Duration(seconds: 30));
  }
  
  DataModel _parseResponse(http.Response response) {
    if (response.statusCode != 200) {
      throw HttpException('HTTP ${response.statusCode}');
    }
    
    try {
      final jsonData = json.decode(response.body) as Map<String, dynamic>;
      return DataModel.fromJson(jsonData);
    } catch (e) {
      throw FormatException('Failed to parse response: ${e.toString()}');
    }
  }
}
```

### Stream Error Handling
```dart
// GOOD: Stream error handling with proper error propagation
class StreamService {
  Stream<DataModel> getDataStream() {
    return _createDataStream()
        .handleError((error) {
          if (error is SocketException) {
            throw NetworkException('Connection lost', originalError: error);
          }
          throw SystemException('Stream error', originalError: error);
        })
        .where((event) => event != null)
        .cast<DataModel>();
  }
  
  Stream<DataModel?> _createDataStream() async* {
    // Simulate stream data with potential errors
    for (int i = 0; i < 10; i++) {
      await Future.delayed(const Duration(seconds: 1));
      
      if (i == 5) {
        throw SocketException('Simulated connection error');
      }
      
      yield DataModel(id: i, name: 'Item $i');
    }
  }
}

// Usage in widget
class StreamWidget extends StatefulWidget {
  @override
  _StreamWidgetState createState() => _StreamWidgetState();
}

class _StreamWidgetState extends State<StreamWidget> {
  final StreamService _service = StreamService();
  StreamSubscription<DataModel>? _subscription;
  
  @override
  void initState() {
    super.initState();
    _subscribeToStream();
  }
  
  void _subscribeToStream() {
    _subscription = _service.getDataStream().listen(
      (data) {
        setState(() {
          // Update UI with new data
        });
      },
      onError: (error) {
        _handleStreamError(error);
      },
    );
  }
  
  void _handleStreamError(dynamic error) {
    if (error is NetworkException) {
      _showSnackBar('Network error: ${error.message}');
    } else {
      _showSnackBar('Unexpected error occurred');
      _logError(error);
    }
  }
  
  @override
  void dispose() {
    _subscription?.cancel();
    super.dispose();
  }
}
```

## 🛡️ Error Boundaries & Recovery

### Custom Error Widget
```dart
// GOOD: Custom error widget for graceful error handling
class CustomErrorWidget extends StatelessWidget {
  final FlutterErrorDetails errorDetails;
  
  const CustomErrorWidget({required this.errorDetails});
  
  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      home: Scaffold(
        backgroundColor: Colors.red[50],
        appBar: AppBar(
          title: Text('Error Occurred'),
          backgroundColor: Colors.red[400],
        ),
        body: Padding(
          padding: const EdgeInsets.all(16.0),
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              Icon(
                Icons.error_outline,
                size: 100,
                color: Colors.red[400],
              ),
              const SizedBox(height: 16),
              Text(
                'Oops! Something went wrong',
                style: Theme.of(context).textTheme.headlineSmall,
                textAlign: TextAlign.center,
              ),
              const SizedBox(height: 8),
              Text(
                'We apologize for the inconvenience. '
                'The error has been reported to our team.',
                style: Theme.of(context).textTheme.bodyMedium,
                textAlign: TextAlign.center,
              ),
              const SizedBox(height: 24),
              Row(
                mainAxisAlignment: MainAxisAlignment.spaceEvenly,
                children: [
                  ElevatedButton(
                    onPressed: () => _restartApp(context),
                    child: Text('Restart App'),
                  ),
                  OutlinedButton(
                    onPressed: () => _reportError(context),
                    child: Text('Report Issue'),
                  ),
                ],
              ),
              if (kDebugMode)
                Expanded(
                  child: SingleChildScrollView(
                    child: Text(
                      errorDetails.toString(),
                      style: TextStyle(
                        fontFamily: 'monospace',
                        fontSize: 12,
                      ),
                    ),
                  ),
                ),
            ],
          ),
        ),
      ),
    );
  }
  
  void _restartApp(BuildContext context) {
    // Restart the app
    RestartWidget.restartApp(context);
  }
  
  void _reportError(BuildContext context) {
    // Send error report
    _sendErrorReport(errorDetails);
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(content: Text('Error report sent')),
    );
  }
  
  void _sendErrorReport(FlutterErrorDetails details) {
    FirebaseCrashlytics.instance.recordError(
      details.exception,
      details.stack,
      fatal: true,
    );
  }
}

// Error widget setup
void main() {
  ErrorWidget.builder = (FlutterErrorDetails errorDetails) {
    return CustomErrorWidget(errorDetails: errorDetails);
  };
  
  runApp(MyApp());
}
```

### Error Boundary Pattern
```dart
// GOOD: Error boundary widget for catching errors in subtrees
class ErrorBoundary extends StatefulWidget {
  final Widget child;
  final Widget Function(BuildContext, dynamic)? errorBuilder;
  
  const ErrorBoundary({
    required this.child,
    this.errorBuilder,
  });
  
  @override
  _ErrorBoundaryState createState() => _ErrorBoundaryState();
}

class _ErrorBoundaryState extends State<ErrorBoundary> {
  dynamic _error;
  
  @override
  void initState() {
    super.initState();
    FlutterError.onError = (FlutterErrorDetails details) {
      setState(() {
        _error = details.exception;
      });
      
      // Also report to crash service
      FirebaseCrashlytics.instance.recordError(
        details.exception,
        details.stack,
      );
    };
  }
  
  @override
  Widget build(BuildContext context) {
    if (_error != null) {
      return widget.errorBuilder?.call(context, _error) ??
          _defaultErrorBuilder(context, _error);
    }
    
    return widget.child;
  }
  
  Widget _defaultErrorBuilder(BuildContext context, dynamic error) {
    return Container(
      padding: const EdgeInsets.all(16),
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Icon(Icons.error, size: 50, color: Colors.red),
          const SizedBox(height: 16),
          Text(
            'An error occurred',
            style: Theme.of(context).textTheme.titleLarge,
          ),
          const SizedBox(height: 8),
          Text(
            error.toString(),
            style: Theme.of(context).textTheme.bodyMedium,
            textAlign: TextAlign.center,
          ),
          const SizedBox(height: 16),
          ElevatedButton(
            onPressed: () {
              setState(() {
                _error = null;
              });
            },
            child: Text('Retry'),
          ),
        ],
      ),
    );
  }
}

// Usage
class MyApp extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      home: ErrorBoundary(
        child: MyHomePage(),
        errorBuilder: (context, error) {
          return CustomErrorWidget(
            errorDetails: FlutterErrorDetails(
              exception: error,
              stack: StackTrace.current,
            ),
          );
        },
      ),
    );
  }
}
```

## 📝 Error Logging & Monitoring

### Comprehensive Error Logging
```dart
// GOOD: Centralized error logging service
class ErrorLogger {
  static final ErrorLogger _instance = ErrorLogger._internal();
  factory ErrorLogger() => _instance;
  ErrorLogger._internal();
  
  void logError(
    dynamic error, {
    StackTrace? stackTrace,
    Map<String, dynamic>? context,
    ErrorSeverity severity = ErrorSeverity.medium,
  }) {
    // Log to console in debug mode
    if (kDebugMode) {
      print('ERROR: $error');
      if (stackTrace != null) {
        print('STACK TRACE: $stackTrace');
      }
      if (context != null) {
        print('CONTEXT: $context');
      }
    }
    
    // Log to crash reporting service in production
    if (!kDebugMode) {
      _logToCrashService(error, stackTrace, context, severity);
    }
    
    // Log to analytics
    _logToAnalytics(error, context, severity);
  }
  
  void _logToCrashService(
    dynamic error,
    StackTrace? stackTrace,
    Map<String, dynamic>? context,
    ErrorSeverity severity,
  ) {
    FirebaseCrashlytics.instance.recordError(
      error,
      stackTrace,
      fatal: severity == ErrorSeverity.critical,
      information: context?.entries.map((e) => DiagnosticsProperty(e.key, e.value)).toList(),
    );
  }
  
  void _logToAnalytics(
    dynamic error,
    Map<String, dynamic>? context,
    ErrorSeverity severity,
  ) {
    FirebaseAnalytics.instance.logEvent(
      name: 'app_error',
      parameters: {
        'error_type': error.runtimeType.toString(),
        'error_message': error.toString(),
        'severity': severity.toString(),
        ...?context,
      },
    );
  }
  
  void logUserAction(String action, {Map<String, dynamic>? parameters}) {
    FirebaseAnalytics.instance.logEvent(
      name: 'user_action',
      parameters: {
        'action': action,
        ...?parameters,
      },
    );
  }
}

// Usage
class ExampleService {
  final ErrorLogger _logger = ErrorLogger();
  
  Future<void> performAction() async {
    try {
      // Perform action
      await _riskyOperation();
    } catch (error, stackTrace) {
      _logger.logError(
        error,
        stackTrace: stackTrace,
        context: {
          'action': 'performAction',
          'user_id': 'current_user_id',
          'timestamp': DateTime.now().toIso8601String(),
        },
        severity: ErrorSeverity.high,
      );
    }
  }
  
  Future<void> _riskyOperation() async {
    // Simulate error
    throw Exception('Something went wrong');
  }
}
```

## 🔄 Error Recovery Strategies

### Retry Mechanism
```dart
// GOOD: Retry mechanism with exponential backoff
class RetryService {
  static Future<T> retry<T>(
    Future<T> Function() operation, {
    int maxAttempts = 3,
    Duration delay = const Duration(seconds: 1),
    Duration maxDelay = const Duration(seconds: 30),
    bool Function(dynamic error)? retryIf,
  }) async {
    int attempt = 0;
    dynamic lastError;
    
    while (attempt < maxAttempts) {
      try {
        return await operation();
      } catch (error) {
        lastError = error;
        attempt++;
        
        if (attempt >= maxAttempts || (retryIf != null && !retryIf(error))) {
          rethrow;
        }
        
        // Exponential backoff
        final currentDelay = Duration(
          milliseconds: (delay.inMilliseconds * math.pow(2, attempt - 1)).round(),
        ).clamp(delay, maxDelay);
        
        await Future.delayed(currentDelay);
      }
    }
    
    throw lastError;
  }
}

// Usage
class NetworkService {
  Future<DataModel> fetchDataWithRetry() async {
    return await RetryService.retry(
      () => _fetchData(),
      maxAttempts: 3,
      delay: const Duration(seconds: 1),
      retryIf: (error) => error is NetworkException,
    );
  }
  
  Future<DataModel> _fetchData() async {
    // Network operation that might fail
    throw NetworkException('Connection failed');
  }
}
```

### Circuit Breaker Pattern
```dart
// GOOD: Circuit breaker for preventing cascading failures
class CircuitBreaker {
  final int failureThreshold;
  final Duration timeout;
  final Future<void> Function() resetTimeout;
  
  int _failureCount = 0;
  DateTime? _lastFailureTime;
  bool _isOpen = false;
  
  CircuitBreaker({
    this.failureThreshold = 5,
    this.timeout = const Duration(seconds: 60),
    Future<void> Function()? resetTimeout,
  }) : resetTimeout = resetTimeout ?? (() => Future.delayed(timeout));
  
  Future<T> execute<T>(Future<T> Function() operation) async {
    if (_isOpen) {
      if (_shouldAttemptReset()) {
        _isOpen = false;
        _failureCount = 0;
      } else {
        throw CircuitBreakerOpenException('Circuit breaker is open');
      }
    }
    
    try {
      final result = await operation();
      _onSuccess();
      return result;
    } catch (error) {
      _onFailure();
      rethrow;
    }
  }
  
  bool _shouldAttemptReset() {
    return _lastFailureTime != null &&
        DateTime.now().difference(_lastFailureTime!) > timeout;
  }
  
  void _onSuccess() {
    _failureCount = 0;
    _isOpen = false;
  }
  
  void _onFailure() {
    _failureCount++;
    _lastFailureTime = DateTime.now();
    
    if (_failureCount >= failureThreshold) {
      _isOpen = true;
    }
  }
}

class CircuitBreakerOpenException extends AppException {
  const CircuitBreakerOpenException(String message) : super(message);
}

// Usage
class ServiceWithCircuitBreaker {
  final CircuitBreaker _circuitBreaker = CircuitBreaker(
    failureThreshold: 3,
    timeout: const Duration(seconds: 30),
  );
  
  Future<DataModel> fetchData() async {
    return await _circuitBreaker.execute(() => _fetchDataFromApi());
  }
  
  Future<DataModel> _fetchDataFromApi() async {
    // Actual API call
    throw NetworkException('API unavailable');
  }
}
```

## 🧪 Error Testing

### Error Testing Patterns
```dart
// GOOD: Testing error scenarios
void main() {
  group('Error Handling Tests', () {
    testWidgets('should show error dialog on validation error', (tester) async {
      await tester.pumpWidget(MyApp());
      
      // Find and tap button that triggers error
      final button = find.byKey(Key('error_button'));
      await tester.tap(button);
      await tester.pumpAndSettle();
      
      // Verify error dialog is shown
      expect(find.byType(AlertDialog), findsOneWidget);
      expect(find.text('Invalid number format'), findsOneWidget);
    });
    
    test('should retry operation on network error', () async {
      final service = NetworkService();
      var attemptCount = 0;
      
      when(mockApi.fetchData()).thenAnswer((_) async {
        attemptCount++;
        if (attemptCount < 3) {
          throw NetworkException('Connection failed');
        }
        return DataModel(id: 1, name: 'Success');
      });
      
      final result = await service.fetchDataWithRetry();
      
      expect(result.name, equals('Success'));
      expect(attemptCount, equals(3));
    });
    
    test('should log error with context', () async {
      final logger = ErrorLogger();
      final loggedErrors = <Map<String, dynamic>>[];
      
      // Mock logger for testing
      // In real implementation, you'd use dependency injection
      
      try {
        throw Exception('Test error');
      } catch (error, stackTrace) {
        logger.logError(
          error,
          stackTrace: stackTrace,
          context: {'test': 'error_logging'},
        );
      }
      
      // Verify error was logged
      expect(loggedErrors.length, equals(1));
      expect(loggedErrors.first['error_type'], equals('Exception'));
    });
  });
}
```

## 📈 Error Monitoring Dashboard

### Error Metrics Collection
```dart
// GOOD: Error metrics collection
class ErrorMetrics {
  static final ErrorMetrics _instance = ErrorMetrics._internal();
  factory ErrorMetrics() => _instance;
  ErrorMetrics._internal();
  
  final Map<String, int> _errorCounts = {};
  final Map<String, List<DateTime>> _errorTimestamps = {};
  
  void recordError(String errorType) {
    _errorCounts[errorType] = (_errorCounts[errorType] ?? 0) + 1;
    _errorTimestamps[errorType] = [
      ...(_errorTimestamps[errorType] ?? []),
      DateTime.now(),
    ].take(100).toList(); // Keep last 100 occurrences
  }
  
  Map<String, dynamic> getMetrics() {
    return {
      'total_errors': _errorCounts.values.fold(0, (a, b) => a + b),
      'error_types': _errorCounts,
      'recent_errors': _getRecentErrors(),
    };
  }
  
  List<Map<String, dynamic>> _getRecentErrors() {
    final now = DateTime.now();
    final recent = <Map<String, dynamic>>[];
    
    _errorTimestamps.forEach((type, timestamps) {
      final recentTimestamps = timestamps
          .where((t) => now.difference(t).inMinutes < 60)
          .toList();
      
      if (recentTimestamps.isNotEmpty) {
        recent.add({
          'type': type,
          'count': recentTimestamps.length,
          'latest': recentTimestamps.last.toIso8601String(),
        });
      }
    });
    
    return recent;
  }
}
```

## 🚀 Best Practices Checklist

### Error Detection & Prevention
- [ ] Implement comprehensive try-catch blocks for all async operations
- [ ] Use custom exception classes for better error categorization
- [ ] Validate input data before processing
- [ ] Check for null values and edge cases
- [ ] Use assertions in debug mode for contract validation
- [ ] Implement proper state validation

### Error Handling Patterns
- [ ] Use error boundaries to catch widget errors
- [ ] Implement retry mechanisms with exponential backoff
- [ ] Use circuit breaker pattern for external dependencies
- [ ] Provide graceful degradation for non-critical features
- [ ] Implement proper async/await error handling
- [ ] Use Stream.error() for stream error propagation

### User Experience
- [ ] Show user-friendly error messages
- [ ] Provide recovery options when possible
- [ ] Implement loading states during error-prone operations
- [ ] Use snackbars or dialogs for error notifications
- [ ] Implement offline mode handling
- [ ] Provide error reporting functionality

### Logging & Monitoring
- [ ] Log all errors with context information
- [ ] Use crash reporting services in production
- [ ] Implement error metrics collection
- [ ] Log user actions leading to errors
- [ ] Monitor error rates and patterns
- [ ] Set up alerts for critical errors

### Testing & Validation
- [ ] Write tests for error scenarios
- [ ] Test error handling in edge cases
- [ ] Validate error recovery mechanisms
- [ ] Test error boundary functionality
- [ ] Verify error logging works correctly
- [ ] Test retry and circuit breaker logic

---

**Flutter Version**: [FLUTTER_VERSION]  
**Error Handling Framework**: Custom exceptions, Error boundaries, Firebase Crashlytics  
**Last Updated**: [DATE]  
**Template Version**: 1.0
