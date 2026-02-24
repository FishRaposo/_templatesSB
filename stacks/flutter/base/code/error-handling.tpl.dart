///
/// File: error-handling.tpl.dart
/// Purpose: Template for unknown implementation
/// Generated for: {{PROJECT_NAME}}
///

// -----------------------------------------------------------------------------
// FILE: error-handling.tpl.dart
// PURPOSE: Comprehensive error handling patterns and utilities for Flutter projects
// USAGE: Import and adapt for consistent error handling across the application
// DEPENDENCIES: dart:async, dart:io, flutter/foundation.dart, flutter/material.dart
// AUTHOR: [[.Author]]
// VERSION: [[.Version]]
// SINCE: [[.Version]]
// -----------------------------------------------------------------------------

/**
 * Flutter Error Handling Template
 * Purpose: Reusable error handling patterns and utilities for Flutter projects
 * Usage: Import and adapt for consistent error handling across the application
 */

import 'dart:async';
import 'dart:io';
import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';

/// Error severity levels
enum ErrorSeverity {
  low('low'),
  medium('medium'),
  high('high'),
  critical('critical');

  const ErrorSeverity(this.name);
  final String name;

  static ErrorSeverity fromString(String name) {
    switch (name.toLowerCase()) {
      case 'low':
        return ErrorSeverity.low;
      case 'medium':
        return ErrorSeverity.medium;
      case 'high':
        return ErrorSeverity.high;
      case 'critical':
        return ErrorSeverity.critical;
      default:
        return ErrorSeverity.medium;
    }
  }
}

/// Error categories
enum ErrorCategory {
  validation('validation'),
  businessLogic('business_logic'),
  externalApi('external_api'),
  network('network'),
  authentication('authentication'),
  authorization('authorization'),
  system('system'),
  userInput('user_input');

  const ErrorCategory(this.name);
  final String name;

  static ErrorCategory fromString(String name) {
    switch (name.toLowerCase()) {
      case 'validation':
        return ErrorCategory.validation;
      case 'business_logic':
      case 'business':
        return ErrorCategory.businessLogic;
      case 'external_api':
      case 'api':
        return ErrorCategory.externalApi;
      case 'network':
        return ErrorCategory.network;
      case 'authentication':
      case 'auth':
        return ErrorCategory.authentication;
      case 'authorization':
      case 'perm':
        return ErrorCategory.authorization;
      case 'system':
        return ErrorCategory.system;
      case 'user_input':
      case 'input':
        return ErrorCategory.userInput;
      default:
        return ErrorCategory.system;
    }
  }
}

/// Base application error class
abstract class AppException implements Exception {
  final String message;
  final ErrorSeverity severity;
  final ErrorCategory category;
  final String errorCode;
  final Map<String, dynamic> context;
  final DateTime timestamp;
  final String? userMessage;
  final Exception? cause;

  const AppException({
    required this.message,
    required this.severity,
    required this.category,
    required this.errorCode,
    this.context = const {},
    this.userMessage,
    this.cause,
  }) : timestamp = DateTime.now();

  /// Convert to JSON
  Map<String, dynamic> toJson() {
    return {
      'message': message,
      'severity': severity.name,
      'category': category.name,
      'errorCode': errorCode,
      'context': context,
      'timestamp': timestamp.toIso8601String(),
      'userMessage': userMessage ?? _getDefaultUserMessage(),
      'cause': cause?.toString(),
      'type': runtimeType.toString(),
    };
  }

  /// Get user-friendly message
  String get displayMessage => userMessage ?? _getDefaultUserMessage();

  /// Get default user message based on severity
  String _getDefaultUserMessage() {
    switch (severity) {
      case ErrorSeverity.low:
        return message;
      case ErrorSeverity.medium:
        return 'An error occurred. Please try again.';
      case ErrorSeverity.high:
      case ErrorSeverity.critical:
        return 'A serious error occurred. Please contact support.';
    }
  }

  @override
  String toString() {
    return '$runtimeType: $message';
  }
}

/// Validation error
class ValidationException extends AppException {
  final String? field;
  final dynamic value;

  const ValidationException({
    required String message,
    this.field,
    this.value,
    Map<String, dynamic> context = const {},
    String? userMessage,
  }) : super(
          message: message,
          severity: ErrorSeverity.low,
          category: ErrorCategory.validation,
          errorCode: 'VALIDATION_ERROR',
          context: {
            ...context,
            if (field != null) 'field': field,
            if (value != null) 'value': value,
          },
          userMessage: userMessage,
        );
}

/// Business logic error
class BusinessException extends AppException {
  const BusinessException({
    required String message,
    Map<String, dynamic> context = const {},
    String? userMessage,
    Exception? cause,
  }) : super(
          message: message,
          severity: ErrorSeverity.medium,
          category: ErrorCategory.businessLogic,
          errorCode: 'BUSINESS_ERROR',
          context: context,
          userMessage: userMessage,
          cause: cause,
        );
}

/// External API error
class ApiException extends AppException {
  final String? serviceName;
  final int? statusCode;
  final dynamic responseData;

  const ApiException({
    required String message,
    this.serviceName,
    this.statusCode,
    this.responseData,
    Map<String, dynamic> context = const {},
    String? userMessage,
    Exception? cause,
  }) : super(
          message: message,
          severity: ErrorSeverity.high,
          category: ErrorCategory.externalApi,
          errorCode: 'API_ERROR',
          context: {
            ...context,
            if (serviceName != null) 'serviceName': serviceName,
            if (statusCode != null) 'statusCode': statusCode,
            if (responseData != null) 'responseData': responseData,
          },
          userMessage: userMessage,
          cause: cause,
        );
}

/// Network error
class NetworkException extends AppException {
  final bool isOnline;

  const NetworkException({
    required String message,
    this.isOnline = true,
    Map<String, dynamic> context = const {},
    String? userMessage,
    Exception? cause,
  }) : super(
          message: message,
          severity: ErrorSeverity.high,
          category: ErrorCategory.network,
          errorCode: 'NETWORK_ERROR',
          context: {
            ...context,
            'isOnline': isOnline,
          },
          userMessage: userMessage ?? 'Network connection failed. Please check your internet connection.',
          cause: cause,
        );
}

/// Authentication error
class AuthenticationException extends AppException {
  const AuthenticationException({
    String message = 'Authentication failed',
    Map<String, dynamic> context = const {},
    String? userMessage,
    Exception? cause,
  }) : super(
          message: message,
          severity: ErrorSeverity.medium,
          category: ErrorCategory.authentication,
          errorCode: 'AUTH_ERROR',
          context: context,
          userMessage: userMessage ?? 'Please log in to continue.',
          cause: cause,
        );
}

/// Authorization error
class AuthorizationException extends AppException {
  final String? resource;
  final String? action;

  const AuthorizationException({
    String message = 'Access denied',
    this.resource,
    this.action,
    Map<String, dynamic> context = const {},
    String? userMessage,
    Exception? cause,
  }) : super(
          message: message,
          severity: ErrorSeverity.medium,
          category: ErrorCategory.authorization,
          errorCode: 'PERMISSION_ERROR',
          context: {
            ...context,
            if (resource != null) 'resource': resource,
            if (action != null) 'action': action,
          },
          userMessage: userMessage ?? 'You don\'t have permission to perform this action.',
          cause: cause,
        );
}

/// System error
class SystemException extends AppException {
  const SystemException({
    required String message,
    Map<String, dynamic> context = const {},
    String? userMessage,
    Exception? cause,
  }) : super(
          message: message,
          severity: ErrorSeverity.critical,
          category: ErrorCategory.system,
          errorCode: 'SYSTEM_ERROR',
          context: context,
          userMessage: userMessage ?? 'A system error occurred. Please try again later.',
          cause: cause,
        );
}

/// Error handler interface
abstract class ErrorHandler {
  void handleError(AppException error, {Map<String, dynamic>? context});
}

/// Error manager for centralized error handling
class ErrorManager {
  static ErrorManager? _instance;
  static ErrorManager get instance => _instance ??= ErrorManager._();

  ErrorManager._();

  final List<ErrorHandler> _handlers = [];
  final List<AppException> _errorHistory = [];
  final StreamController<AppException> _errorStreamController = StreamController<AppException>.broadcast();

  /// Get error stream
  Stream<AppException> get errorStream => _errorStreamController.stream;

  /// Add error handler
  void addHandler(ErrorHandler handler) {
    _handlers.add(handler);
  }

  /// Remove error handler
  void removeHandler(ErrorHandler handler) {
    _handlers.remove(handler);
  }

  /// Handle error
  void handleError(AppException error, {Map<String, dynamic>? context}) {
    // Add to history
    _errorHistory.add(error);
    
    // Keep only last 100 errors
    if (_errorHistory.length > 100) {
      _errorHistory.removeAt(0);
    }

    // Notify handlers
    for (final handler in _handlers) {
      handler.handleError(error, context: context);
    }

    // Add to stream
    _errorStreamController.add(error);

    // Log error
    if (kDebugMode) {
      print('Error handled: ${error.toString()}');
      print('Context: ${error.context}');
      if (context != null) {
        print('Additional context: $context');
      }
    }
  }

  /// Handle generic exception
  void handleException(Exception exception, {Map<String, dynamic>? context}) {
    AppException appException;

    if (exception is AppException) {
      appException = exception;
    } else if (exception is SocketException) {
      appException = NetworkException(
        message: 'Network connection failed',
        cause: exception,
        context: context ?? {},
      );
    } else if (exception is TimeoutException) {
      appException = NetworkException(
        message: 'Request timed out',
        cause: exception,
        context: context ?? {},
      );
    } else if (exception is FormatException) {
      appException = ValidationException(
        message: 'Invalid data format',
        context: context ?? {},
        cause: exception,
      );
    } else {
      appException = SystemException(
        message: exception.toString(),
        context: context ?? {},
        cause: exception,
      );
    }

    handleError(appException);
  }

  /// Get error history
  List<AppException> get errorHistory => List.unmodifiable(_errorHistory);

  /// Clear error history
  void clearHistory() {
    _errorHistory.clear();
  }

  /// Dispose
  void dispose() {
    _errorStreamController.close();
    _handlers.clear();
    _errorHistory.clear();
  }
}

/// Console error handler
class ConsoleErrorHandler implements ErrorHandler {
  @override
  void handleError(AppException error, {Map<String, dynamic>? context}) {
    if (kDebugMode) {
      print('=== ERROR ===');
      print('Type: ${error.runtimeType}');
      print('Message: ${error.message}');
      print('Severity: ${error.severity.name}');
      print('Category: ${error.category.name}');
      print('Code: ${error.errorCode}');
      print('User Message: ${error.displayMessage}');
      print('Timestamp: ${error.timestamp}');
      print('Context: ${error.context}');
      if (context != null) {
        print('Additional Context: $context');
      }
      if (error.cause != null) {
        print('Cause: ${error.cause}');
      }
      print('============');
    }
  }
}

/// Dialog error handler for UI
class DialogErrorHandler implements ErrorHandler {
  final BuildContext context;

  DialogErrorHandler(this.context);

  @override
  void handleError(AppException error, {Map<String, dynamic>? context}) {
    WidgetsBinding.instance.addPostFrameCallback((_) {
      _showErrorDialog(error);
    });
  }

  void _showErrorDialog(AppException error) {
    showDialog(
      context: context,
      builder: (BuildContext context) {
        return AlertDialog(
          title: Text(_getErrorTitle(error)),
          content: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(error.displayMessage),
              if (kDebugMode) ...[
                const SizedBox(height: 16),
                const Text('Debug Info:', style: TextStyle(fontWeight: FontWeight.bold)),
                Text('Type: ${error.runtimeType}'),
                Text('Code: ${error.errorCode}'),
                Text('Category: ${error.category.name}'),
                if (error.context.isNotEmpty) ...[
                  const Text('Context:'),
                  Text(error.context.toString()),
                ],
              ],
            ],
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.of(context).pop(),
              child: const Text('OK'),
            ),
            if (error.severity == ErrorSeverity.critical) ...[
              TextButton(
                onPressed: () {
                  Navigator.of(context).pop();
                  // Restart app or navigate to safe screen
                },
                child: const Text('Restart'),
              ),
            ],
          ],
        );
      },
    );
  }

  String _getErrorTitle(AppException error) {
    switch (error.severity) {
      case ErrorSeverity.low:
        return 'Notice';
      case ErrorSeverity.medium:
        return 'Warning';
      case ErrorSeverity.high:
        return 'Error';
      case ErrorSeverity.critical:
        return 'Critical Error';
    }
  }
}

/// Snackbar error handler
class SnackbarErrorHandler implements ErrorHandler {
  final BuildContext context;
  final ScaffoldMessengerState scaffoldMessenger;

  SnackbarErrorHandler(this.context) : scaffoldMessenger = ScaffoldMessenger.of(context);

  @override
  void handleError(AppException error, {Map<String, dynamic>? context}) {
    WidgetsBinding.instance.addPostFrameCallback((_) {
      scaffoldMessenger.showSnackBar(
        SnackBar(
          content: Text(error.displayMessage),
          backgroundColor: _getErrorColor(error.severity),
          duration: _getErrorDuration(error.severity),
          action: error.severity == ErrorSeverity.critical
              ? SnackBarAction(
                  label: 'Report',
                  onPressed: () {
                    // Handle error reporting
                  },
                )
              : null,
        ),
      );
    });
  }

  Color _getErrorColor(ErrorSeverity severity) {
    switch (severity) {
      case ErrorSeverity.low:
        return Colors.blue;
      case ErrorSeverity.medium:
        return Colors.orange;
      case ErrorSeverity.high:
        return Colors.red;
      case ErrorSeverity.critical:
        return Colors.purple;
    }
  }

  Duration _getErrorDuration(ErrorSeverity severity) {
    switch (severity) {
      case ErrorSeverity.low:
        return const Duration(seconds: 2);
      case ErrorSeverity.medium:
        return const Duration(seconds: 4);
      case ErrorSeverity.high:
        return const Duration(seconds: 6);
      case ErrorSeverity.critical:
        return const Duration(seconds: 10);
    }
  }
}

/// Remote error handler
class RemoteErrorHandler implements ErrorHandler {
  final String apiUrl;
  final String apiKey;

  RemoteErrorHandler({
    required this.apiUrl,
    required this.apiKey,
  });

  @override
  void handleError(AppException error, {Map<String, dynamic>? context}) {
    // Only send errors of medium severity or higher
    if (error.severity.index < ErrorSeverity.medium.index) return;

    _sendErrorReport(error, context);
  }

  Future<void> _sendErrorReport(AppException error, Map<String, dynamic>? context) async {
    try {
      final uri = Uri.parse(apiUrl);
      final request = await HttpClient().postUrl(uri);

      request.headers.contentType = ContentType.json;
      request.headers.set('Authorization', 'Bearer $apiKey');

      final payload = {
        'error': error.toJson(),
        'context': context,
        'platform': Platform.operatingSystem,
        'timestamp': DateTime.now().toIso8601String(),
      };

      request.add(utf8.encode(jsonEncode(payload)));
      final response = await request.close();

      if (response.statusCode != 200) {
        print('Failed to send error report: ${response.statusCode}');
      }
    } catch (e) {
      print('Failed to send error report: $e');
    }
  }
}

/// Error boundary widget
class ErrorBoundary extends StatefulWidget {
  final Widget child;
  final Widget Function(BuildContext, AppException)? errorBuilder;
  final void Function(AppException)? onError;

  const ErrorBoundary({
    Key? key,
    required this.child,
    this.errorBuilder,
    this.onError,
  }) : super(key: key);

  @override
  State<ErrorBoundary> createState() => _ErrorBoundaryState();
}

class _ErrorBoundaryState extends State<ErrorBoundary> {
  AppException? _error;

  @override
  void initState() {
    super.initState();
    FlutterError.onError = _handleFlutterError;
  }

  void _handleFlutterError(FlutterErrorDetails details) {
    final error = SystemException(
      message: details.exception.toString(),
      context: {
        'stack': details.stack?.toString(),
        'library': details.library,
        'context': details.context?.toString(),
      },
      cause: details.exception as Exception?,
    );

    setState(() {
      _error = error;
    });

    ErrorManager.instance.handleError(error);
    widget.onError?.call(error);
  }

  @override
  Widget build(BuildContext context) {
    if (_error != null) {
      return widget.errorBuilder?.call(context, _error!) ??
          _DefaultErrorWidget(error: _error!);
    }

    return widget.child;
  }
}

/// Default error widget
class _DefaultErrorWidget extends StatelessWidget {
  final AppException error;

  const _DefaultErrorWidget({required this.error});

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Error'),
        backgroundColor: _getErrorColor(error.severity),
      ),
      body: Padding(
        padding: const EdgeInsets.all(16.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              'An error occurred',
              style: Theme.of(context).textTheme.headlineSmall,
            ),
            const SizedBox(height: 16),
            Text(error.displayMessage),
            if (kDebugMode) ...[
              const SizedBox(height: 16),
              const Text('Debug Information:', style: TextStyle(fontWeight: FontWeight.bold)),
              Text('Type: ${error.runtimeType}'),
              Text('Code: ${error.errorCode}'),
              Text('Category: ${error.category.name}'),
              Text('Timestamp: ${error.timestamp}'),
              if (error.context.isNotEmpty) ...[
                const Text('Context:'),
                Text(error.context.toString()),
              ],
            ],
            const Spacer(),
            Row(
              children: [
                ElevatedButton(
                  onPressed: () {
                    setState(() {
                      // Clear error and retry
                    });
                  },
                  child: const Text('Retry'),
                ),
                const SizedBox(width: 8),
                ElevatedButton(
                  onPressed: () {
                    // Restart app
                  },
                  child: const Text('Restart App'),
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }

  Color _getErrorColor(ErrorSeverity severity) {
    switch (severity) {
      case ErrorSeverity.low:
        return Colors.blue;
      case ErrorSeverity.medium:
        return Colors.orange;
      case ErrorSeverity.high:
        return Colors.red;
      case ErrorSeverity.critical:
        return Colors.purple;
    }
  }
}

/// Retry utility
class RetryManager {
  /// Retry operation with exponential backoff
  static Future<T> retry<T>(
    Future<T> Function() operation, {
    int maxAttempts = 3,
    Duration initialDelay = const Duration(seconds: 1),
    double backoffMultiplier = 2.0,
    bool Function(Exception)? shouldRetry,
  }) async {
    Exception? lastException;

    for (int attempt = 0; attempt < maxAttempts; attempt++) {
      try {
        return await operation();
      } catch (e) {
        lastException = e as Exception;

        if (attempt == maxAttempts - 1) {
          break;
        }

        if (shouldRetry != null && !shouldRetry(lastException)) {
          break;
        }

        final delay = Duration(
          milliseconds: (initialDelay.inMilliseconds * 
              math.pow(backoffMultiplier, attempt)).round(),
        );

        await Future.delayed(delay);
      }
    }

    throw lastException!;
  }
}

/// Error reporting widget
class ErrorReportWidget extends StatefulWidget {
  const ErrorReportWidget({Key? key}) : super(key: key);

  @override
  State<ErrorReportWidget> createState() => _ErrorReportWidgetState();
}

class _ErrorReportWidgetState extends State<ErrorReportWidget> {
  @override
  Widget build(BuildContext context) {
    final errorHistory = ErrorManager.instance.errorHistory;

    if (errorHistory.isEmpty) {
      return const Center(child: Text('No errors reported'));
    }

    return ListView.builder(
      itemCount: errorHistory.length,
      itemBuilder: (context, index) {
        final error = errorHistory[index];
        return ExpansionTile(
          title: Text('${error.runtimeType} - ${error.timestamp}'),
          subtitle: Text(error.displayMessage),
          children: [
            Padding(
              padding: const EdgeInsets.all(16.0),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text('Severity: ${error.severity.name}'),
                  Text('Category: ${error.category.name}'),
                  Text('Code: ${error.errorCode}'),
                  if (error.context.isNotEmpty) ...[
                    const SizedBox(height: 8),
                    const Text('Context:', style: TextStyle(fontWeight: FontWeight.bold)),
                    Text(error.context.toString()),
                  ],
                ],
              ),
            ),
          ],
        );
      },
    );
  }
}

/// Example usage
void main() async {
  // Initialize error manager
  ErrorManager.instance.addHandler(ConsoleErrorHandler());

  // Handle different types of errors
  try {
    throw ValidationException(
      message: 'Invalid email format',
      field: 'email',
      value: 'invalid-email',
    );
  } catch (e) {
    ErrorManager.instance.handleException(e as Exception);
  }

  try {
    throw NetworkException(
      message: 'Connection failed',
      isOnline: false,
    );
  } catch (e) {
    ErrorManager.instance.handleException(e as Exception);
  }

  // Retry example
  try {
    await RetryManager.retry(
      () async {
        throw NetworkException(message: 'Temporary failure');
      },
      maxAttempts: 3,
      shouldRetry: (error) => error is NetworkException,
    );
  } catch (e) {
    ErrorManager.instance.handleException(e as Exception);
  }
}

export {
  // Enums
  ErrorSeverity,
  ErrorCategory,

  // Exception classes
  AppException,
  ValidationException,
  BusinessException,
  ApiException,
  NetworkException,
  AuthenticationException,
  AuthorizationException,
  SystemException,

  // Error management
  ErrorManager,
  ErrorHandler,
  ConsoleErrorHandler,
  DialogErrorHandler,
  SnackbarErrorHandler,
  RemoteErrorHandler,

  // UI components
  ErrorBoundary,
  ErrorReportWidget,

  // Utilities
  RetryManager,
};
