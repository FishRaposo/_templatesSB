<!--
File: ARCHITECTURE-flutter.tpl.md
Purpose: Template for unknown implementation
Template Version: 1.0
-->

# Flutter Architecture Guide - {{PROJECT_NAME}}

**Tier**: {{TIER}} | **Stack**: Flutter

## 🏗️ Flutter Architecture Overview

Flutter applications follow **Clean Architecture** principles with **feature-based modularization**. This ensures maintainability, testability, and scalability across MVP, CORE, and FULL tiers.

## 📊 Tier-Based Architecture Patterns

### **MVP Tier - Simple Monolithic Architecture**

```
lib/
├── main.dart                    # App entry point
├── app.dart                     # App configuration
├── core/                        # Shared utilities
│   ├── constants/              # App constants
│   ├── themes/                 # App themes
│   └── utils/                  # Helper functions
├── features/                   # Single feature module
│   └── feature_name/
│       ├── data/               # Data layer
│       ├── domain/             # Business logic
│       └── presentation/       # UI layer
└── shared/                     # Shared widgets
    └── widgets/                # Reusable components
```

**Characteristics**:
- Single feature module
- Simple state management
- Direct API calls
- Minimal abstraction layers

**When to Use**:
- Proof of concepts
- Simple applications
- Learning projects
- Internal tools

### **CORE Tier - Modular Clean Architecture**

```
lib/
├── main.dart                    # App entry point
├── app.dart                     # App configuration
├── core/                        # Core infrastructure
│   ├── constants/              # App constants
│   ├── errors/                 # Custom errors
│   ├── network/                # HTTP client setup
│   ├── themes/                 # Theme system
│   ├── utils/                  # Helper functions
│   └── services/               # Global services
├── features/                   # Feature modules
│   ├── authentication/         # Auth feature
│   │   ├── data/               # Data implementation
│   │   │   ├── datasources/    # API/local storage
│   │   │   ├── models/         # Data models
│   │   │   └── repositories/   # Repository implementations
│   │   ├── domain/             # Business logic
│   │   │   ├── entities/       # Business entities
│   │   │   ├── repositories/   # Repository interfaces
│   │   │   └── usecases/       # Business use cases
│   │   └── presentation/       # UI layer
│   │       ├── pages/          # Screen widgets
│   │       ├── widgets/        # Feature widgets
│   │       └── providers/      # State management
│   ├── profile/                # Profile feature
│   └── [other_features]/       # Additional features
└── shared/                     # Shared components
    ├── widgets/                # Reusable UI components
    └── extensions/             # Dart extensions
```

**Characteristics**:
- Multiple feature modules
- Clean architecture layers
- Repository pattern
- Dependency injection
- Comprehensive state management

**When to Use**:
- Production applications
- Team development
- Complex business logic
- Long-term maintenance

### **FULL Tier - Enterprise Architecture**

```
lib/
├── main.dart                    # App entry point
├── app.dart                     # App configuration
├── core/                        # Core infrastructure
│   ├── [CORE tier structure]
│   ├── monitoring/             # Performance monitoring
│   ├── analytics/              # Analytics integration
│   └── enterprise/             # Enterprise features
├── features/                   # Feature modules
│   ├── [CORE tier features]
│   ├── admin/                  # Admin features
│   ├── analytics/              # Analytics features
│   ├── monitoring/             # Monitoring features
│   └── enterprise/             # Enterprise-specific features
├── infrastructure/             # Infrastructure layer
│   ├── monitoring/             # Monitoring setup
│   ├── analytics/              # Analytics setup
│   ├── crashlytics/            # Crash reporting
│   └── remote_config/          # Remote configuration
├── shared/                     # Shared components
│   ├── components/             # Component library
│   ├── extensions/             # Dart extensions
│   └── utilities/              # Advanced utilities
└── enterprise/                 # Enterprise modules
    ├── compliance/             # Compliance features
    ├── security/               # Security features
    └── audit/                  # Audit features
```

**Characteristics**:
- Enterprise-grade architecture
- Micro-frontend patterns
- Advanced monitoring
- Compliance and security layers
- Feature flag integration

## 🎯 Layer Responsibilities

### **1. Data Layer**

#### **Purpose**: Handle data persistence and external API communication

#### **Components**:
- **Data Sources**: API clients, local storage, caching
- **Models**: Data transfer objects with serialization
- **Repository Implementations**: Concrete data access implementations

#### **MVP Implementation**:
```dart
// features/counter/data/datasources/counter_local_datasource.dart
class CounterLocalDataSource {
  Future<int> getCount() async {
    // Simple local storage or API call
    return 0;
  }
  
  Future<void> saveCount(int count) async {
    // Save to local storage or API
  }
}
```

#### **CORE Implementation**:
```dart
// features/authentication/data/datasources/auth_remote_datasource.dart
abstract class AuthRemoteDataSource {
  Future<UserModel> signIn(String email, String password);
  Future<void> signOut();
  Future<UserModel> signUp(String email, String password);
}

class AuthRemoteDataSourceImpl implements AuthRemoteDataSource {
  final Dio _dio;
  
  AuthRemoteDataSourceImpl(this._dio);
  
  @override
  Future<UserModel> signIn(String email, String password) async {
    final response = await _dio.post('/auth/signin', data: {
      'email': email,
      'password': password,
    });
    return UserModel.fromJson(response.data);
  }
}
```

#### **FULL Implementation**:
```dart
// features/profile/data/datasources/profile_remote_datasource.dart
class ProfileRemoteDataSourceImpl implements ProfileRemoteDataSource {
  final Dio _dio;
  final CacheManager _cache;
  final AnalyticsService _analytics;
  
  ProfileRemoteDataSourceImpl(this._dio, this._cache, this._analytics);
  
  @override
  Future<ProfileModel> getProfile(String userId) async {
    _analytics.trackEvent('profile_fetch_started');
    
    // Try cache first
    final cached = await _cache.get('profile_$userId');
    if (cached != null) {
      return ProfileModel.fromJson(cached);
    }
    
    // Fetch from API
    final response = await _dio.get('/profiles/$userId');
    final profile = ProfileModel.fromJson(response.data);
    
    // Cache result
    await _cache.set('profile_$userId', response.data);
    
    _analytics.trackEvent('profile_fetch_completed');
    return profile;
  }
}
```

### **2. Domain Layer**

#### **Purpose**: Contains business logic and rules, independent of frameworks

#### **Components**:
- **Entities**: Core business objects
- **Repository Interfaces**: Contracts for data access
- **Use Cases**: Application business logic

#### **MVP Implementation**:
```dart
// features/counter/domain/entities/counter.dart
class Counter {
  final int value;
  
  Counter(this.value);
  
  Counter increment() => Counter(value + 1);
  Counter decrement() => value > 0 ? Counter(value - 1) : Counter(0);
}
```

#### **CORE Implementation**:
```dart
// features/authentication/domain/entities/user.dart
class User {
  final String id;
  final String email;
  final String name;
  final DateTime createdAt;
  
  User({
    required this.id,
    required this.email,
    required this.name,
    required this.createdAt,
  });
  
  User copyWith({
    String? id,
    String? email,
    String? name,
    DateTime? createdAt,
  }) {
    return User(
      id: id ?? this.id,
      email: email ?? this.email,
      name: name ?? this.name,
      createdAt: createdAt ?? this.createdAt,
    );
  }
}

// features/authentication/domain/usecases/sign_in_usecase.dart
class SignInUseCase {
  final AuthRepository _repository;
  
  SignInUseCase(this._repository);
  
  Future<User> call(String email, String password) async {
    if (!_isValidEmail(email)) {
      throw AuthException('Invalid email format');
    }
    
    return await _repository.signIn(email, password);
  }
  
  bool _isValidEmail(String email) {
    return email.contains('@') && email.contains('.');
  }
}
```

#### **FULL Implementation**:
```dart
// features/profile/domain/usecases/update_profile_usecase.dart
class UpdateProfileUseCase {
  final ProfileRepository _repository;
  final AnalyticsService _analytics;
  final ValidationService _validator;
  
  UpdateProfileUseCase(this._repository, this._analytics, this._validator);
  
  Future<Profile> call(String userId, ProfileUpdate update) async {
    // Business validation
    final validationResult = await _validator.validateProfileUpdate(update);
    if (!validationResult.isValid) {
      throw ValidationException(validationResult.errors);
    }
    
    // Audit logging
    await _analytics.trackEvent('profile_update_attempt', {
      'user_id': userId,
      'fields_updated': update.getChangedFields(),
    });
    
    // Business logic
    final currentProfile = await _repository.getProfile(userId);
    if (currentProfile == null) {
      throw ProfileNotFoundException();
    }
    
    // Apply business rules
    final updatedProfile = await _applyBusinessRules(currentProfile, update);
    
    // Persist changes
    final result = await _repository.updateProfile(userId, updatedProfile);
    
    // Analytics
    await _analytics.trackEvent('profile_update_completed', {
      'user_id': userId,
      'success': true,
    });
    
    return result;
  }
  
  Future<Profile> _applyBusinessRules(Profile current, ProfileUpdate update) async {
    // Apply enterprise business rules
    if (update.name != null && update.name!.length < 2) {
      throw ValidationException('Name must be at least 2 characters');
    }
    
    return current.copyWith(
      name: update.name,
      bio: update.bio,
      updatedAt: DateTime.now(),
    );
  }
}
```

### **3. Presentation Layer**

#### **Purpose**: UI components and state management

#### **Components**:
- **Pages**: Screen-level widgets
- **Widgets**: Reusable UI components
- **Providers**: State management (Riverpod)

#### **MVP Implementation**:
```dart
// features/counter/presentation/providers/counter_provider.dart
class CounterNotifier extends StateNotifier<CounterState> {
  CounterNotifier() : super(CounterState());
  
  void increment() {
    state = state.copyWith(value: state.value + 1);
  }
  
  void decrement() {
    state = state.copyWith(value: state.value > 0 ? state.value - 1 : 0);
  }
}
```

#### **CORE Implementation**:
```dart
// features/authentication/presentation/providers/auth_provider.dart
class AuthNotifier extends StateNotifier<AuthState> {
  final SignInUseCase _signInUseCase;
  final SignOutUseCase _signOutUseCase;
  final GetCurrentUserUseCase _getCurrentUserUseCase;
  
  AuthNotifier(
    this._signInUseCase,
    this._signOutUseCase,
    this._getCurrentUserUseCase,
  ) : super(AuthState()) {
    _loadUser();
  }
  
  Future<void> signIn(String email, String password) async {
    state = state.copyWith(isLoading: true, error: null);
    
    try {
      final user = await _signInUseCase(email, password);
      state = state.copyWith(user: user, isLoading: false);
    } catch (e) {
      state = state.copyWith(isLoading: false, error: e.toString());
    }
  }
  
  Future<void> _loadUser() async {
    try {
      final user = await _getCurrentUserUseCase();
      state = state.copyWith(user: user);
    } catch (e) {
      // User not logged in, that's okay
    }
  }
}
```

#### **FULL Implementation**:
```dart
// features/profile/presentation/providers/profile_notifier.dart
@riverpod
class ProfileNotifier extends _$ProfileNotifier {
  @override
  Future<Profile?> build() async {
    final userId = ref.watch(authProvider).user?.id;
    if (userId == null) return null;
    
    ref.watch(analyticsServiceProvider).trackScreenView('profile');
    return await _loadProfile(userId);
  }
  
  Future<void> updateProfile(ProfileUpdate update) async {
    final userId = ref.read(authProvider).user?.id;
    if (userId == null) throw AuthException('User not authenticated');
    
    state = const AsyncValue.loading();
    
    try {
      ref.watch(analyticsServiceProvider).trackEvent('profile_update_started');
      
      final updateUseCase = ref.read(updateProfileUseCaseProvider);
      final updatedProfile = await updateUseCase(userId, update);
      
      state = AsyncValue.data(updatedProfile);
      
      ref.watch(analyticsServiceProvider).trackEvent('profile_update_completed');
    } catch (e, stackTrace) {
      state = AsyncValue.error(e, stackTrace);
      ref.watch(analyticsServiceProvider).trackError('profile_update_failed', e);
    }
  }
}
```

## 🔄 Module Communication

### **Event-Driven Communication (FULL Tier)**

```dart
// core/events/event_bus.dart
class EventBus {
  final StreamController<AppEvent> _controller;
  
  EventBus() : _controller = StreamController<AppEvent>.broadcast();
  
  void emit(AppEvent event) {
    _controller.add(event);
  }
  
  Stream<T> on<T extends AppEvent>() {
    return _controller.stream.where((event) => event is T).cast<T>();
  }
}

// features/profile/events/profile_events.dart
class ProfileUpdatedEvent extends AppEvent {
  final Profile profile;
  
  ProfileUpdatedEvent(this.profile);
}

// features/authentication/providers/auth_provider.dart
class AuthNotifier extends StateNotifier<AuthState> {
  final EventBus _eventBus;
  
  AuthNotifier(this._eventBus, ...);
  
  Future<void> updateProfile(ProfileUpdate update) async {
    final updatedProfile = await _updateProfileUseCase(update);
    state = state.copyWith(user: updatedProfile);
    
    // Emit event for other modules to react
    _eventBus.emit(ProfileUpdatedEvent(updatedProfile));
  }
}
```

### **Shared Services**

```dart
// core/services/navigation_service.dart
class NavigationService {
  final GlobalKey<NavigatorState> navigatorKey;
  
  NavigationService(this.navigatorKey);
  
  Future<void> navigateToProfile(String userId) {
    return navigatorKey.currentState!.pushNamed('/profile/$userId');
  }
  
  void goBack() {
    return navigatorKey.currentState!.pop();
  }
}

// core/services/storage_service.dart
abstract class StorageService {
  Future<void> saveString(String key, String value);
  Future<String?> getString(String key);
  Future<void> remove(String key);
  Future<void> clear();
}
```

## 🎨 Component Architecture

### **Widget Hierarchy**

```
MaterialApp
├── AppShell (navigation, theme, etc.)
├── Feature Pages
│   ├── Screen Widgets
│   │   ├── Layout Components
│   │   │   ├── Feature Widgets
│   │   │   │   └── UI Components
│   │   │   └── Shared Widgets
│   │   └── Business Logic Widgets
│   └── State Management
└── Shared Components
    ├── UI Components
    ├── Layout Components
    └── Utility Widgets
```

### **Component Design Principles**

1. **Single Responsibility**: Each widget has one clear purpose
2. **Composition over Inheritance**: Build complex UIs from simple components
3. **Stateless by Default**: Use StatelessWidget unless state is needed
4. **Prop Drilling Avoidance**: Use Riverpod for shared state
5. **Testability**: Design widgets to be easily testable

## 📱 Platform-Specific Architecture

### **Platform Channels**

```dart
// core/platform/battery_service.dart
class BatteryService {
  static const MethodChannel _channel = MethodChannel('battery');
  
  Future<int> getBatteryLevel() async {
    try {
      final int batteryLevel = await _channel.invokeMethod('getBatteryLevel');
      return batteryLevel;
    } on PlatformException catch (e) {
      throw BatteryException("Failed to get battery level: '${e.message}'");
    }
  }
}
```

### **Platform-Specific Implementations**

```dart
// core/platform/file_service.dart
abstract class FileService {
  Future<String> getDocumentsDirectory();
  Future<void> saveFile(String path, Uint8List bytes);
  Future<Uint8List> readFile(String path);
}

// android/file_service_android.dart
class FileServiceAndroid implements FileService {
  @override
  Future<String> getDocumentsDirectory() async {
    final directory = await getApplicationDocumentsDirectory();
    return directory.path;
  }
}

// ios/file_service_ios.dart
class FileServiceIOS implements FileService {
  @override
  Future<String> getDocumentsDirectory() async {
    final directory = await getApplicationDocumentsDirectory();
    return directory.path;
  }
}
```

## 🚀 Performance Architecture

### **Image Loading Architecture**

```dart
// core/image/cached_image_widget.dart
class CachedImageWidget extends StatelessWidget {
  final String imageUrl;
  final double? width;
  final double? height;
  
  const CachedImageWidget({
    super.key,
    required this.imageUrl,
    this.width,
    this.height,
  });
  
  @override
  Widget build(BuildContext context) {
    return CachedNetworkImage(
      imageUrl: imageUrl,
      width: width,
      height: height,
      placeholder: (context, url) => const CircularProgressIndicator(),
      errorWidget: (context, url, error) => const Icon(Icons.error),
      memCacheWidth: width?.toInt(),
      memCacheHeight: height?.toInt(),
    );
  }
}
```

### **State Management Performance**

```dart
// core/performance/auto_dispose_provider.dart
@riverpod
class ExpensiveNotifier extends _$ExpensiveNotifier {
  @override
  Future<ExpensiveData> build() async {
    // Auto-dispose when not used
    ref.onDispose(() {
      // Cleanup resources
    });
    
    return await _loadExpensiveData();
  }
  
  // Keep alive for 5 minutes after last use
  @override
  bool get keepAlive => true;
}
```

## 🔒 Security Architecture

### **Secure Storage**

```dart
// core/security/secure_storage_service.dart
class SecureStorageService implements StorageService {
  final FlutterSecureStorage _storage;
  
  SecureStorageService(this._storage);
  
  @override
  Future<void> saveString(String key, String value) async {
    await _storage.write(key: key, value: value);
  }
  
  @override
  Future<String?> getString(String key) async {
    return await _storage.read(key: key);
  }
  
  @override
  Future<void> remove(String key) async {
    await _storage.delete(key: key);
  }
  
  @override
  Future<void> clear() async {
    await _storage.deleteAll();
  }
}
```

### **Network Security**

```dart
// core/network/secure_dio_client.dart
class SecureDioClient extends DioClient {
  SecureDioClient({
    required String baseUrl,
    required StorageService storage,
  }) : super(baseUrl: baseUrl, storage: storage) {
    _setupSecurity();
  }
  
  void _setupSecurity() {
    // SSL pinning
    (_dio.httpClientAdapter as DefaultHttpClientAdapter).onHttpClientCreate = (client) {
      client.badCertificateCallback = (cert, host, port) {
        return _validateCertificate(cert, host);
      };
      return client;
    };
    
    // Request encryption
    _dio.interceptors.add(EncryptionInterceptor());
    
    // Request signing
    _dio.interceptors.add(RequestSigningInterceptor());
  }
}
```

---

**Flutter Version**: [FLUTTER_VERSION]  
**Dart Version**: [DART_VERSION]  
**Last Updated**: [DATE]  
**Template Version**: 1.0
