<!--
File: NETWORKING.tpl.md
Purpose: Template for unknown implementation
Template Version: 1.0
-->

# {{PROJECT_NAME}} - Flutter Networking

**Tier**: {{TIER}} | **Stack**: Flutter

## 🌐 Blessed HTTP Client: dio

### **Why dio**
- Powerful HTTP client with interceptors
- Request/response transformation
- Timeout and retry support
- File upload/download
- Excellent error handling

## 📱 MVP Tier - Basic Networking

### **Simple API Client**
```dart
// lib/core/network/api_client.dart
import 'package:dio/dio.dart';

class ApiClient {
  late Dio _dio;
  
  ApiClient() {
    _dio = Dio(BaseOptions(
      baseUrl: 'https://api.example.com',
      connectTimeout: const Duration(seconds: 10),
      receiveTimeout: const Duration(seconds: 10),
    ));
  }
  
  Future<Map<String, dynamic>> get(String path) async {
    try {
      final response = await _dio.get(path);
      return response.data;
    } on DioException catch (e) {
      throw _handleError(e);
    }
  }
  
  Future<Map<String, dynamic>> post(String path, dynamic data) async {
    try {
      final response = await _dio.post(path, data: data);
      return response.data;
    } on DioException catch (e) {
      throw _handleError(e);
    }
  }
  
  String _handleError(DioException error) {
    switch (error.type) {
      case DioExceptionType.connectionTimeout:
        return 'Connection timeout';
      case DioExceptionType.receiveTimeout:
        return 'Receive timeout';
      case DioExceptionType.badResponse:
        return 'Server error: ${error.response?.statusCode}';
      default:
        return 'Network error: ${error.message}';
    }
  }
}
```

## 🏗️ CORE Tier - Repository Pattern

### **Advanced API Client with Interceptors**
```dart
// lib/core/network/dio_client.dart
import 'package:dio/dio.dart';
import 'package:flutter/foundation.dart';
import '../services/storage_service.dart';

class DioClient {
  late Dio _dio;
  
  DioClient({
    required String baseUrl,
    required StorageService storage,
  }) {
    _dio = Dio(BaseOptions(
      baseUrl: baseUrl,
      connectTimeout: const Duration(seconds: 15),
      receiveTimeout: const Duration(seconds: 15),
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
      },
    ));
    
    _setupInterceptors(storage);
  }
  
  void _setupInterceptors(StorageService storage) {
    // Auth interceptor
    _dio.interceptors.add(InterceptorsWrapper(
      onRequest: (options, handler) async {
        final token = await storage.getAuthToken();
        if (token != null) {
          options.headers['Authorization'] = 'Bearer $token';
        }
        handler.next(options);
      },
      onError: (error, handler) async {
        if (error.response?.statusCode == 401) {
          // Handle token refresh
          await _refreshToken(storage);
          // Retry the request
          final response = await _dio.fetch(error.requestOptions);
          handler.resolve(response);
          return;
        }
        handler.next(error);
      },
    ));
    
    // Logging interceptor (debug only)
    if (kDebugMode) {
      _dio.interceptors.add(LogInterceptor(
        requestBody: true,
        responseBody: true,
        requestHeader: true,
        responseHeader: true,
      ));
    }
  }
  
  Future<Response<T>> get<T>(
    String path, {
    Map<String, dynamic>? queryParameters,
    Options? options,
  }) async {
    return _dio.get<T>(
      path,
      queryParameters: queryParameters,
      options: options,
    );
  }
  
  Future<Response<T>> post<T>(
    String path, {
    dynamic data,
    Map<String, dynamic>? queryParameters,
    Options? options,
  }) async {
    return _dio.post<T>(
      path,
      data: data,
      queryParameters: queryParameters,
      options: options,
    );
  }
  
  Future<Response<T>> put<T>(
    String path, {
    dynamic data,
    Map<String, dynamic>? queryParameters,
    Options? options,
  }) async {
    return _dio.put<T>(
      path,
      data: data,
      queryParameters: queryParameters,
      options: options,
    );
  }
  
  Future<Response<T>> delete<T>(
    String path, {
    dynamic data,
    Map<String, dynamic>? queryParameters,
    Options? options,
  }) async {
    return _dio.delete<T>(
      path,
      data: data,
      queryParameters: queryParameters,
      options: options,
    );
  }
  
  Future<void> _refreshToken(StorageService storage) async {
    try {
      final refreshToken = await storage.getRefreshToken();
      if (refreshToken != null) {
        // Implement token refresh logic
        final response = await _dio.post('/auth/refresh', data: {
          'refresh_token': refreshToken,
        });
        
        final newToken = response.data['access_token'];
        await storage.saveAuthToken(newToken);
      }
    } catch (e) {
      // Refresh failed, logout user
      await storage.clearAuthTokens();
      // Navigate to login
    }
  }
}
```

### **Repository Pattern Template**
```dart
// lib/features/authentication/data/repositories/auth_repository_impl.dart
import 'package:dio/dio.dart';
import '../domain/repositories/auth_repository.dart';
import '../domain/entities/auth_user.dart';
import '../datasources/auth_remote_datasource.dart';
import '../datasources/auth_local_datasource.dart';

class AuthRepositoryImpl implements AuthRepository {
  final AuthRemoteDataSource _remoteDataSource;
  final AuthLocalDataSource _localDataSource;
  
  AuthRepositoryImpl({
    required AuthRemoteDataSource remoteDataSource,
    required AuthLocalDataSource localDataSource,
  })  : _remoteDataSource = remoteDataSource,
        _localDataSource = localDataSource;
  
  @override
  Future<AuthUser> signIn(String email, String password) async {
    try {
      final userData = await _remoteDataSource.signIn(email, password);
      final user = AuthUser.fromJson(userData);
      await _localDataSource.saveUser(user);
      return user;
    } on DioException catch (e) {
      throw AuthException.fromDioError(e);
    }
  }
  
  @override
  Future<void> signOut() async {
    try {
      await _remoteDataSource.signOut();
      await _localDataSource.clearUser();
    } catch (e) {
      // Continue with local cleanup even if remote fails
      await _localDataSource.clearUser();
    }
  }
  
  @override
  Stream<AuthUser?> get userStream => _localDataSource.userStream;
  
  @override
  Future<AuthUser?> getCurrentUser() async {
    return await _localDataSource.getUser();
  }
}
```

### **Remote Data Source Template**
```dart
// lib/features/authentication/data/datasources/auth_remote_datasource.dart
import 'package:dio/dio.dart';
import '../../domain/entities/auth_user.dart';

abstract class AuthRemoteDataSource {
  Future<Map<String, dynamic>> signIn(String email, String password);
  Future<void> signOut();
  Future<Map<String, dynamic>> signUp(String email, String password);
}

class AuthRemoteDataSourceImpl implements AuthRemoteDataSource {
  final Dio _dio;
  
  AuthRemoteDataSourceImpl(this._dio);
  
  @override
  Future<Map<String, dynamic>> signIn(String email, String password) async {
    final response = await _dio.post('/auth/signin', data: {
      'email': email,
      'password': password,
    });
    
    if (response.statusCode == 200) {
      return response.data;
    } else {
      throw AuthException(response.data['message'] ?? 'Sign in failed');
    }
  }
  
  @override
  Future<void> signOut() async {
    await _dio.post('/auth/signout');
  }
  
  @override
  Future<Map<String, dynamic>> signUp(String email, String password) async {
    final response = await _dio.post('/auth/signup', data: {
      'email': email,
      'password': password,
    });
    
    if (response.statusCode == 201) {
      return response.data;
    } else {
      throw AuthException(response.data['message'] ?? 'Sign up failed');
    }
  }
}
```

## 🚀 FULL Tier - Advanced Networking

### **Network Layer with Caching and Retry**
```dart
// lib/core/network/advanced_dio_client.dart
import 'package:dio/dio.dart';
import 'package:flutter_cache_manager/flutter_cache_manager.dart';
import 'package:connectivity_plus/connectivity_plus.dart';

class AdvancedDioClient {
  late Dio _dio;
  late CacheManager _cacheManager;
  
  AdvancedDioClient({
    required String baseUrl,
    required StorageService storage,
  }) {
    _dio = Dio(BaseOptions(
      baseUrl: baseUrl,
      connectTimeout: const Duration(seconds: 20),
      receiveTimeout: const Duration(seconds: 20),
    ));
    
    _cacheManager = CacheManager('app_cache');
    _setupAdvancedInterceptors(storage);
  }
  
  void _setupAdvancedInterceptors(StorageService storage) {
    // Retry interceptor
    _dio.interceptors.add(RetryInterceptor(
      dio: _dio,
      retries: 3,
      retryDelays: const [
        Duration(seconds: 1),
        Duration(seconds: 2),
        Duration(seconds: 3),
      ],
    ));
    
    // Cache interceptor
    _dio.interceptors.add(CacheInterceptor(
      cacheManager: _cacheManager,
    ));
    
    // Connectivity interceptor
    _dio.interceptors.add(ConnectivityInterceptor());
    
    // Performance monitoring
    _dio.interceptors.add(PerformanceInterceptor());
  }
  
  Future<Response<T>> getWithCache<T>(
    String path, {
    Duration? maxAge,
    bool forceRefresh = false,
  }) async {
    if (forceRefresh) {
      return _dio.get<T>(path, options: Options(extra: {'forceRefresh': true}));
    }
    
    return _dio.get<T>(
      path,
      options: Options(extra: {'maxAge': maxAge ?? const Duration(hours: 1)}),
    );
  }
}

class RetryInterceptor extends Interceptor {
  final Dio dio;
  final int retries;
  final List<Duration> retryDelays;
  
  RetryInterceptor({
    required this.dio,
    this.retries = 3,
    this.retryDelays = const [
      Duration(seconds: 1),
      Duration(seconds: 2),
      Duration(seconds: 3),
    ],
  });
  
  @override
  void onError(DioException error, ErrorInterceptorHandler handler) async {
    final extra = error.requestOptions.extra;
    final currentRetry = extra['retryCount'] ?? 0;
    
    if (currentRetry < retries && _shouldRetry(error)) {
      extra['retryCount'] = currentRetry + 1;
      
      // Wait before retry
      final delay = retryDelays[currentRetry];
      await Future.delayed(delay);
      
      try {
        final response = await dio.fetch(error.requestOptions);
        handler.resolve(response);
        return;
      } catch (e) {
        // Continue with error if retry fails
      }
    }
    
    handler.next(error);
  }
  
  bool _shouldRetry(DioException error) {
    return error.type == DioExceptionType.connectionTimeout ||
           error.type == DioExceptionType.receiveTimeout ||
           error.type == DioExceptionType.connectionError ||
           (error.type == DioExceptionType.badResponse && 
            error.response?.statusCode != null &&
            [500, 502, 503, 504].contains(error.response!.statusCode!));
  }
}
```

## 🧪 Networking Testing Template

### **Repository Testing**
```dart
// test/unit/repositories/auth_repository_test.dart
import 'package:flutter_test/flutter_test.dart';
import 'package:mockito/mockito.dart';
import 'package:dio/dio.dart';

void main() {
  group('AuthRepositoryImpl', () {
    late AuthRepositoryImpl repository;
    late MockAuthRemoteDataSource mockRemoteDataSource;
    late MockAuthLocalDataSource mockLocalDataSource;
    
    setUp(() {
      mockRemoteDataSource = MockAuthRemoteDataSource();
      mockLocalDataSource = MockAuthLocalDataSource();
      repository = AuthRepositoryImpl(
        remoteDataSource: mockRemoteDataSource,
        localDataSource: mockLocalDataSource,
      );
    });
    
    test('should sign in successfully', () async {
      // Arrange
      const email = 'test@example.com';
      const password = 'password123';
      final userData = {
        'id': '1',
        'email': email,
        'name': 'Test User',
      };
      
      when(mockRemoteDataSource.signIn(email, password))
          .thenAnswer((_) async => userData);
      
      // Act
      final result = await repository.signIn(email, password);
      
      // Assert
      expect(result.email, equals(email));
      verify(mockRemoteDataSource.signIn(email, password));
      verify(mockLocalDataSource.saveUser(any));
    });
    
    test('should throw AuthException on sign in failure', () async {
      // Arrange
      when(mockRemoteDataSource.signIn(any, any))
          .thenThrow(DioException(
            requestOptions: RequestOptions(path: '/auth/signin'),
            response: Response(
              statusCode: 401,
              requestOptions: RequestOptions(path: '/auth/signin'),
              data: {'message': 'Invalid credentials'},
            ),
          ));
      
      // Act & Assert
      expect(
        () => repository.signIn('test@example.com', 'wrong'),
        throwsA(isA<AuthException>()),
      );
    });
  });
}
```

## 📊 Networking Best Practices

### **1. Use Repository Pattern**
- Separate data sources from business logic
- Handle offline scenarios
- Implement proper caching

### **2. Implement Error Handling**
- Custom exception types
- User-friendly error messages
- Proper logging and monitoring

### **3. Handle Authentication**
- Token management
- Refresh token flow
- Secure storage

### **4. Optimize Performance**
- Request caching
- Request deduplication
- Connection pooling

### **5. Test Thoroughly**
- Mock network responses
- Test error scenarios
- Performance testing

---

**Flutter Version**: [FLUTTER_VERSION]  
**Dart Version**: [DART_VERSION]  
**Last Updated**: [DATE]  
**Template Version**: 1.0
