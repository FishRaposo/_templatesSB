///
/// File: http-client.tpl.dart
/// Purpose: Template for unknown implementation
/// Generated for: {{PROJECT_NAME}}
///

/// Template: http-client.tpl.dart
/// Purpose: http-client template
/// Stack: flutter
/// Tier: base

# Universal Template System - Flutter Stack
# Generated: 2025-12-10
# Purpose: HTTP client utilities
# Tier: base
# Stack: flutter
# Category: utilities

// -----------------------------------------------------------------------------
// FILE: http-client.tpl.dart
// PURPOSE: Comprehensive HTTP client utilities for Flutter projects
// USAGE: Import and adapt for consistent HTTP communication across the application
// DEPENDENCIES: dart:async, dart:convert, dart:io, dart:typed_data for HTTP operations
// AUTHOR: [[.Author]]
// VERSION: [[.Version]]
// SINCE: [[.Version]]
// -----------------------------------------------------------------------------

/**
 * Flutter HTTP Client Utilities Template
 * Purpose: Reusable HTTP client utilities for Flutter projects
 * Usage: Import and adapt for consistent HTTP communication across the application
 */

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';
import 'package:flutter/foundation.dart';
import 'package:http/http.dart' as http;
import 'package:http_parser/http_parser.dart';

/// HTTP methods
enum HttpMethod {
  get('GET'),
  post('POST'),
  put('PUT'),
  delete('DELETE'),
  patch('PATCH'),
  head('HEAD'),
  options('OPTIONS');

  const HttpMethod(this.name);
  final String name;
}

/// HTTP response wrapper
class HttpResponse<T> {
  final int statusCode;
  final T data;
  final Map<String, String> headers;
  final bool success;
  final String? error;
  final int responseTime;
  final String? requestId;

  const HttpResponse({
    required this.statusCode,
    required this.data,
    required this.headers,
    required this.success,
    this.error,
    required this.responseTime,
    this.requestId,
  });

  /// Create success response
  factory HttpResponse.success({
    required int statusCode,
    required T data,
    required Map<String, String> headers,
    int responseTime = 0,
    String? requestId,
  }) {
    return HttpResponse<T>(
      statusCode: statusCode,
      data: data,
      headers: headers,
      success: true,
      responseTime: responseTime,
      requestId: requestId,
    );
  }

  /// Create error response
  factory HttpResponse.error({
    required int statusCode,
    required String error,
    required Map<String, String> headers,
    T? data,
    int responseTime = 0,
    String? requestId,
  }) {
    return HttpResponse<T>(
      statusCode: statusCode,
      data: data ?? (null as T),
      headers: headers,
      success: false,
      error: error,
      responseTime: responseTime,
      requestId: requestId,
    );
  }

  /// Check if response is successful
  bool get isSuccessful => success && statusCode >= 200 && statusCode < 300;

  /// Check if response is client error
  bool get isClientError => statusCode >= 400 && statusCode < 500;

  /// Check if response is server error
  bool get isServerError => statusCode >= 500;

  @override
  String toString() {
    return 'HttpResponse(statusCode: $statusCode, success: $success, error: $error)';
  }
}

/// HTTP client exception
class HttpClientException implements Exception {
  final String message;
  final int? statusCode;
  final dynamic responseData;
  final String? requestId;
  final int responseTime;

  const HttpClientException({
    required this.message,
    this.statusCode,
    this.responseData,
    this.requestId,
    required this.responseTime,
  });

  @override
  String toString() {
    return 'HttpClientException: $message (Status: $statusCode, Time: ${responseTime}ms)';
  }
}

/// HTTP request configuration
class HttpRequestConfig {
  final Duration timeout;
  final int maxRetries;
  final Duration retryDelay;
  final Map<String, String> defaultHeaders;
  final bool enableLogging;
  final String? apiKey;
  final String? bearerToken;

  const HttpRequestConfig({
    this.timeout = const Duration(seconds: 30),
    this.maxRetries = 3,
    this.retryDelay = const Duration(seconds: 1),
    this.defaultHeaders = const {},
    this.enableLogging = false,
    this.apiKey,
    this.bearerToken,
  });

  /// Copy with changes
  HttpRequestConfig copyWith({
    Duration? timeout,
    int? maxRetries,
    Duration? retryDelay,
    Map<String, String>? defaultHeaders,
    bool? enableLogging,
    String? apiKey,
    String? bearerToken,
  }) {
    return HttpRequestConfig(
      timeout: timeout ?? this.timeout,
      maxRetries: maxRetries ?? this.maxRetries,
      retryDelay: retryDelay ?? this.retryDelay,
      defaultHeaders: defaultHeaders ?? this.defaultHeaders,
      enableLogging: enableLogging ?? this.enableLogging,
      apiKey: apiKey ?? this.apiKey,
      bearerToken: bearerToken ?? this.bearerToken,
    );
  }
}

/// HTTP client class
class HttpClient {
  final HttpRequestConfig config;
  final String? baseUrl;
  final Map<String, String> _defaultHeaders;
  final List<HttpInterceptor> _interceptors = [];

  HttpClient({
    this.config = const HttpRequestConfig(),
    this.baseUrl,
    Map<String, String>? headers,
  }) : _defaultHeaders = {
         'Content-Type': 'application/json',
         'Accept': 'application/json',
         'User-Agent': 'Flutter-HTTP-Client/1.0',
         ...config.defaultHeaders,
         ...?headers,
       };

  /// Add interceptor
  void addInterceptor(HttpInterceptor interceptor) {
    _interceptors.add(interceptor);
  }

  /// Remove interceptor
  void removeInterceptor(HttpInterceptor interceptor) {
    _interceptors.remove(interceptor);
  }

  /// Generate unique request ID
  String _generateRequestId() {
    return '${DateTime.now().millisecondsSinceEpoch}-${_randomString(8)}';
  }

  /// Generate random string
  String _randomString(int length) {
    const chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
    final random = Random();
    return String.fromCharCodes(
      Iterable.generate(length).map((_) => chars.codeUnitAt(random.nextInt(chars.length))),
    );
  }

  /// Prepare headers
  Map<String, String> _prepareHeaders(Map<String, String>? additionalHeaders) {
    final headers = Map<String, String>.from(_defaultHeaders);
    
    if (additionalHeaders != null) {
      headers.addAll(additionalHeaders);
    }

    // Add API key if provided
    if (config.apiKey != null) {
      headers['X-API-Key'] = config.apiKey!;
    }

    // Add bearer token if provided
    if (config.bearerToken != null) {
      headers['Authorization'] = 'Bearer ${config.bearerToken!}';
    }

    return headers;
  }

  /// Make HTTP request with retry logic
  Future<HttpResponse<T>> _makeRequest<T>(
    HttpMethod method,
    String path, {
    dynamic data,
    Map<String, String>? headers,
    Map<String, String>? queryParameters,
    T Function(dynamic)? dataParser,
  }) async {
    final stopwatch = Stopwatch()..start();
    final requestId = _generateRequestId();
    
    String url = path;
    if (baseUrl != null && !path.startsWith('http')) {
      url = '$baseUrl$path';
    }

    if (queryParameters != null && queryParameters.isNotEmpty) {
      final uri = Uri.parse(url);
      url = uri.replace(queryParameters: queryParameters).toString();
    }

    final requestHeaders = _prepareHeaders(headers);
    dynamic responseBody;
    int statusCode = 0;
    Map<String, String> responseHeaders = {};
    String? errorMessage;

    for (int attempt = 0; attempt <= config.maxRetries; attempt++) {
      try {
        // Execute request interceptors
        for (final interceptor in _interceptors) {
          await interceptor.onRequest(method, url, data, requestHeaders);
        }

        late http.Response response;
        final body = data != null ? jsonEncode(data) : null;

        switch (method) {
          case HttpMethod.get:
            response = await http.get(
              Uri.parse(url),
              headers: requestHeaders,
            ).timeout(config.timeout);
            break;
          case HttpMethod.post:
            response = await http.post(
              Uri.parse(url),
              headers: requestHeaders,
              body: body,
            ).timeout(config.timeout);
            break;
          case HttpMethod.put:
            response = await http.put(
              Uri.parse(url),
              headers: requestHeaders,
              body: body,
            ).timeout(config.timeout);
            break;
          case HttpMethod.delete:
            response = await http.delete(
              Uri.parse(url),
              headers: requestHeaders,
            ).timeout(config.timeout);
            break;
          case HttpMethod.patch:
            response = await http.patch(
              Uri.parse(url),
              headers: requestHeaders,
              body: body,
            ).timeout(config.timeout);
            break;
          case HttpMethod.head:
            response = await http.head(
              Uri.parse(url),
              headers: requestHeaders,
            ).timeout(config.timeout);
            break;
          case HttpMethod.options:
            response = await http.request(
              url,
              method.name,
              headers: requestHeaders,
            ).timeout(config.timeout);
            break;
        }

        statusCode = response.statusCode;
        responseHeaders = response.headers;
        
        // Parse response body
        if (response.body.isNotEmpty) {
          try {
            responseBody = jsonDecode(response.body);
          } catch (e) {
            responseBody = response.body;
          }
        }

        // Execute response interceptors
        for (final interceptor in _interceptors) {
          await interceptor.onResponse(method, url, statusCode, responseBody, responseHeaders);
        }

        // Check if request was successful
        if (statusCode >= 200 && statusCode < 300) {
          stopwatch.stop();
          final parsedData = dataParser != null ? dataParser(responseBody) : responseBody;
          
          return HttpResponse<T>.success(
            statusCode: statusCode,
            data: parsedData,
            headers: responseHeaders,
            responseTime: stopwatch.elapsedMilliseconds,
            requestId: requestId,
          );
        } else {
          // Request failed, check if we should retry
          if (attempt < config.maxRetries && _shouldRetry(statusCode)) {
            await Future.delayed(config.retryDelay * math.pow(2, attempt));
            continue;
          }
          
          errorMessage = _getErrorMessage(statusCode, responseBody);
          break;
        }

      } catch (e) {
        if (attempt < config.maxRetries && _shouldRetryException(e)) {
          await Future.delayed(config.retryDelay * math.pow(2, attempt));
          continue;
        }
        
        errorMessage = e.toString();
        statusCode = 0;
        break;
      }
    }

    stopwatch.stop();

    // Execute error interceptors
    for (final interceptor in _interceptors) {
      await interceptor.onError(method, url, statusCode, errorMessage, responseHeaders);
    }

    throw HttpClientException(
      message: errorMessage ?? 'Request failed',
      statusCode: statusCode,
      responseData: responseBody,
      requestId: requestId,
      responseTime: stopwatch.elapsedMilliseconds,
    );
  }

  /// Check if request should be retried based on status code
  bool _shouldRetry(int statusCode) {
    // Retry on 5xx errors and 429 (rate limiting)
    return statusCode >= 500 || statusCode == 429;
  }

  /// Check if request should be retried based on exception
  bool _shouldRetryException(dynamic exception) {
    // Retry on network errors and timeouts
    return exception is SocketException ||
           exception is TimeoutException ||
           exception is HttpException;
  }

  /// Get error message from status code and response body
  String _getErrorMessage(int statusCode, dynamic responseBody) {
    if (responseBody is Map && responseBody['message'] != null) {
      return responseBody['message'] as String;
    }
    
    switch (statusCode) {
      case 400:
        return 'Bad request';
      case 401:
        return 'Unauthorized';
      case 403:
        return 'Forbidden';
      case 404:
        return 'Not found';
      case 429:
        return 'Too many requests';
      case 500:
        return 'Internal server error';
      case 502:
        return 'Bad gateway';
      case 503:
        return 'Service unavailable';
      case 504:
        return 'Gateway timeout';
      default:
        return 'Request failed with status $statusCode';
    }
  }

  /// HTTP method helpers
  Future<HttpResponse<T>> get<T>(
    String path, {
    Map<String, String>? headers,
    Map<String, String>? queryParameters,
    T Function(dynamic)? dataParser,
  }) {
    return _makeRequest<T>(
      HttpMethod.get,
      path,
      headers: headers,
      queryParameters: queryParameters,
      dataParser: dataParser,
    );
  }

  Future<HttpResponse<T>> post<T>(
    String path,
    dynamic data, {
    Map<String, String>? headers,
    T Function(dynamic)? dataParser,
  }) {
    return _makeRequest<T>(
      HttpMethod.post,
      path,
      data: data,
      headers: headers,
      dataParser: dataParser,
    );
  }

  Future<HttpResponse<T>> put<T>(
    String path,
    dynamic data, {
    Map<String, String>? headers,
    T Function(dynamic)? dataParser,
  }) {
    return _makeRequest<T>(
      HttpMethod.put,
      path,
      data: data,
      headers: headers,
      dataParser: dataParser,
    );
  }

  Future<HttpResponse<T>> delete<T>(
    String path, {
    Map<String, String>? headers,
    T Function(dynamic)? dataParser,
  }) {
    return _makeRequest<T>(
      HttpMethod.delete,
      path,
      headers: headers,
      dataParser: dataParser,
    );
  }

  Future<HttpResponse<T>> patch<T>(
    String path,
    dynamic data, {
    Map<String, String>? headers,
    T Function(dynamic)? dataParser,
  }) {
    return _makeRequest<T>(
      HttpMethod.patch,
      path,
      data: data,
      headers: headers,
      dataParser: dataParser,
    );
  }
}

/// HTTP interceptor interface
abstract class HttpInterceptor {
  Future<void> onRequest(HttpMethod method, String url, dynamic data, Map<String, String> headers);
  Future<void> onResponse(HttpMethod method, String url, int statusCode, dynamic data, Map<String, String> headers);
  Future<void> onError(HttpMethod method, String url, int statusCode, String? error, Map<String, String> headers);
}

/// Logging interceptor
class LoggingInterceptor implements HttpInterceptor {
  @override
  Future<void> onRequest(HttpMethod method, String url, dynamic data, Map<String, String> headers) async {
    if (kDebugMode) {
      print('HTTP Request: ${method.name} $url');
      if (data != null) {
        print('Request Body: $data');
      }
    }
  }

  @override
  Future<void> onResponse(HttpMethod method, String url, int statusCode, dynamic data, Map<String, String> headers) async {
    if (kDebugMode) {
      print('HTTP Response: ${method.name} $url - $statusCode');
      if (data != null) {
        print('Response Body: $data');
      }
    }
  }

  @override
  Future<void> onError(HttpMethod method, String url, int statusCode, String? error, Map<String, String> headers) async {
    if (kDebugMode) {
      print('HTTP Error: ${method.name} $url - $statusCode - $error');
    }
  }
}

/// Authentication interceptor
class AuthenticationInterceptor implements HttpInterceptor {
  final String Function() tokenProvider;

  AuthenticationInterceptor({required this.tokenProvider});

  @override
  Future<void> onRequest(HttpMethod method, String url, dynamic data, Map<String, String> headers) async {
    final token = tokenProvider();
    if (token.isNotEmpty) {
      headers['Authorization'] = 'Bearer $token';
    }
  }

  @override
  Future<void> onResponse(HttpMethod method, String url, int statusCode, dynamic data, Map<String, String> headers) async {
    // Handle token refresh if needed
    if (statusCode == 401) {
      // Token expired, implement refresh logic
    }
  }

  @override
  Future<void> onError(HttpMethod method, String url, int statusCode, String? error, Map<String, String> headers) async {
    // Handle authentication errors
  }
}

/// File upload utilities
class FileUploadClient extends HttpClient {
  FileUploadClient({
    HttpRequestConfig config = const HttpRequestConfig(),
    String? baseUrl,
    Map<String, String>? headers,
  }) : super(config: config, baseUrl: baseUrl, headers: headers);

  /// Upload file
  Future<HttpResponse<Map<String, dynamic>>> uploadFile(
    String path,
    File file, {
    String fieldName = 'file',
    Map<String, String>? fields,
    Map<String, String>? headers,
    ProgressCallback? onProgress,
  }) async {
    final stopwatch = Stopwatch()..start();
    final requestId = _generateRequestId();

    try {
      final url = baseUrl != null ? '$baseUrl$path' : path;
      final request = http.MultipartRequest('POST', Uri.parse(url));
      
      // Add headers
      final requestHeaders = _prepareHeaders(headers);
      request.headers.addAll(requestHeaders);

      // Add file
      final fileSize = await file.length();
      final stream = file.openRead();
      final multipartFile = http.MultipartFile(
        fieldName,
        stream,
        fileSize,
        filename: file.path.split('/').last,
      );
      request.files.add(multipartFile);

      // Add additional fields
      if (fields != null) {
        request.fields.addAll(fields);
      }

      // Send request
      final streamedResponse = await request.send().timeout(config.timeout);
      final response = await http.Response.fromStream(streamedResponse);

      stopwatch.stop();

      // Parse response
      Map<String, dynamic> responseData = {};
      if (response.body.isNotEmpty) {
        try {
          responseData = jsonDecode(response.body) as Map<String, dynamic>;
        } catch (e) {
          responseData = {'rawResponse': response.body};
        }
      }

      if (response.statusCode >= 200 && response.statusCode < 300) {
        return HttpResponse<Map<String, dynamic>>.success(
          statusCode: response.statusCode,
          data: responseData,
          headers: response.headers,
          responseTime: stopwatch.elapsedMilliseconds,
          requestId: requestId,
        );
      } else {
        throw HttpClientException(
          message: _getErrorMessage(response.statusCode, responseData),
          statusCode: response.statusCode,
          responseData: responseData,
          requestId: requestId,
          responseTime: stopwatch.elapsedMilliseconds,
        );
      }

    } catch (e) {
      stopwatch.stop();
      throw HttpClientException(
        message: e.toString(),
        responseTime: stopwatch.elapsedMilliseconds,
        requestId: requestId,
      );
    }
  }
}

/// Progress callback for file uploads
typedef ProgressCallback = void Function(int bytesSent, int totalBytes);

/// API client base class
class ApiClient {
  final HttpClient _httpClient;
  final String _apiVersion;

  ApiClient({
    required HttpClient httpClient,
    String apiVersion = 'v1',
  }) : _httpClient = httpClient,
       _apiVersion = apiVersion;

  /// Get API endpoint URL
  String _getEndpoint(String endpoint) {
    return '/api/$_apiVersion/$endpoint';
  }

  /// Make GET request
  Future<HttpResponse<T>> get<T>(
    String endpoint, {
    Map<String, String>? headers,
    Map<String, String>? queryParameters,
    T Function(dynamic)? dataParser,
  }) {
    return _httpClient.get<T>(
      _getEndpoint(endpoint),
      headers: headers,
      queryParameters: queryParameters,
      dataParser: dataParser,
    );
  }

  /// Make POST request
  Future<HttpResponse<T>> post<T>(
    String endpoint,
    dynamic data, {
    Map<String, String>? headers,
    T Function(dynamic)? dataParser,
  }) {
    return _httpClient.post<T>(
      _getEndpoint(endpoint),
      data,
      headers: headers,
      dataParser: dataParser,
    );
  }

  /// Make PUT request
  Future<HttpResponse<T>> put<T>(
    String endpoint,
    dynamic data, {
    Map<String, String>? headers,
    T Function(dynamic)? dataParser,
  }) {
    return _httpClient.put<T>(
      _getEndpoint(endpoint),
      data,
      headers: headers,
      dataParser: dataParser,
    );
  }

  /// Make DELETE request
  Future<HttpResponse<T>> delete<T>(
    String endpoint, {
    Map<String, String>? headers,
    T Function(dynamic)? dataParser,
  }) {
    return _httpClient.delete<T>(
      _getEndpoint(endpoint),
      headers: headers,
      dataParser: dataParser,
    );
  }

  /// Make PATCH request
  Future<HttpResponse<T>> patch<T>(
    String endpoint,
    dynamic data, {
    Map<String, String>? headers,
    T Function(dynamic)? dataParser,
  }) {
    return _httpClient.patch<T>(
      _getEndpoint(endpoint),
      data,
      headers: headers,
      dataParser: dataParser,
    );
  }
}

/// HTTP metrics collector
class HttpMetrics {
  int totalRequests = 0;
  int successfulRequests = 0;
  int failedRequests = 0;
  int totalResponseTime = 0;
  final Map<int, int> errorsByStatus = {};

  void recordRequest(HttpResponse response) {
    totalRequests++;
    totalResponseTime += response.responseTime;

    if (response.success) {
      successfulRequests++;
    } else {
      failedRequests++;
      errorsByStatus[response.statusCode] = (errorsByStatus[response.statusCode] ?? 0) + 1;
    }
  }

  void reset() {
    totalRequests = 0;
    successfulRequests = 0;
    failedRequests = 0;
    totalResponseTime = 0;
    errorsByStatus.clear();
  }

  double get averageResponseTime {
    return totalRequests > 0 ? totalResponseTime / totalRequests : 0;
  }

  double get successRate {
    return totalRequests > 0 ? successfulRequests / totalRequests : 0;
  }
}

/// Example usage
void main() async {
  // Create HTTP client
  final httpClient = HttpClient(
    config: const HttpRequestConfig(
      timeout: Duration(seconds: 30),
      maxRetries: 3,
      enableLogging: true,
    ),
    baseUrl: 'https://jsonplaceholder.typicode.com',
  );

  // Add logging interceptor
  httpClient.addInterceptor(LoggingInterceptor());

  try {
    // Make GET request
    final response = await httpClient.get('/posts/1');
    print('GET Response: ${response.data}');

    // Make POST request
    final postResponse = await httpClient.post('/posts', {
      'title': 'Test Post',
      'body': 'This is a test post',
      'userId': 1,
    });
    print('POST Response: ${postResponse.data}');

    // Use API client
    final apiClient = ApiClient(httpClient: httpClient);
    final apiResponse = await apiClient.get<Map<String, dynamic>>('posts/1');
    print('API Response: ${apiResponse.data}');

  } catch (e) {
    print('HTTP Error: $e');
  }
}

export {
  // Enums
  HttpMethod,

  // Classes
  HttpResponse,
  HttpClientException,
  HttpRequestConfig,
  HttpClient,
  ApiClient,
  FileUploadClient,
  HttpMetrics,

  // Interfaces
  HttpInterceptor,

  // Implementations
  LoggingInterceptor,
  AuthenticationInterceptor,

  // Type definitions
  ProgressCallback,
};
