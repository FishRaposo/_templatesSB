# Universal Template System - Flutter Stack
# Generated: 2025-12-10
# Purpose: flutter template utilities
# Tier: base
# Stack: flutter
# Category: template

# {{PROJECT_NAME}} - Flutter State Management

**Tier**: {{TIER}} | **Stack**: Flutter

## 🏆 Blessed State Management: Riverpod

### **Why Riverpod**
- Compile-safe state management
- Flexible and scalable
- Excellent testing support
- Works well with clean architecture
- Great performance

## 📱 Feature State Template

### **MVP Tier - Simple State**
```dart
// lib/features/counter/presentation/providers/counter_provider.dart
import 'package:flutter_riverpod/flutter_riverpod.dart';

class CounterState {
  final int count;
  final bool isLoading;
  
  CounterState({this.count = 0, this.isLoading = false});
  
  CounterState copyWith({int? count, bool? isLoading}) {
    return CounterState(
      count: count ?? this.count,
      isLoading: isLoading ?? this.isLoading,
    );
  }
}

class CounterNotifier extends StateNotifier<CounterState> {
  CounterNotifier() : super(CounterState());
  
  void increment() {
    state = state.copyWith(count: state.count + 1);
  }
  
  void decrement() {
    state = state.copyWith(count: state.count - 1);
  }
}

final counterProvider = StateNotifierProvider<CounterNotifier, CounterState>((ref) {
  return CounterNotifier();
});
```

### **CORE Tier - Feature State with Repository**
```dart
// lib/features/authentication/presentation/providers/auth_provider.dart
import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../domain/repositories/auth_repository.dart';
import '../domain/entities/auth_user.dart';

class AuthState {
  final AuthUser? user;
  final bool isLoading;
  final String? error;
  
  AuthState({this.user, this.isLoading = false, this.error});
  
  AuthState copyWith({AuthUser? user, bool? isLoading, String? error}) {
    return AuthState(
      user: user ?? this.user,
      isLoading: isLoading ?? this.isLoading,
      error: error ?? this.error,
    );
  }
}

class AuthNotifier extends StateNotifier<AuthState> {
  final AuthRepository _repository;
  
  AuthNotifier(this._repository) : super(AuthState());
  
  Future<void> signIn(String email, String password) async {
    state = state.copyWith(isLoading: true, error: null);
    
    try {
      final user = await _repository.signIn(email, password);
      state = state.copyWith(user: user, isLoading: false);
    } catch (e) {
      state = state.copyWith(isLoading: false, error: e.toString());
    }
  }
  
  Future<void> signOut() async {
    state = state.copyWith(isLoading: true);
    await _repository.signOut();
    state = AuthState();
  }
}

final authProvider = StateNotifierProvider<AuthNotifier, AuthState>((ref) {
  return AuthNotifier(ref.watch(authRepositoryProvider));
});
```

### **FULL Tier - Advanced State with Caching**
```dart
// lib/features/profile/presentation/providers/profile_provider.dart
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:riverpod_annotation/riverpod_annotation.dart';
import '../domain/repositories/profile_repository.dart';
import '../domain/entities/profile.dart';

part 'profile_provider.g.dart';

@riverpod
class ProfileNotifier extends _$ProfileNotifier {
  @override
  Future<Profile?> build() async {
    return _loadProfile();
  }
  
  Future<Profile?> _loadProfile() async {
    final repository = ref.read(profileRepositoryProvider);
    return await repository.getProfile();
  }
  
  Future<void> updateProfile(Profile profile) async {
    state = const AsyncValue.loading();
    
    try {
      final repository = ref.read(profileRepositoryProvider);
      final updatedProfile = await repository.updateProfile(profile);
      state = AsyncValue.data(updatedProfile);
    } catch (e, stackTrace) {
      state = AsyncValue.error(e, stackTrace);
    }
  }
  
  Future<void> refreshProfile() async {
    state = const AsyncValue.loading();
    state = await AsyncValue.guard(() => _loadProfile());
  }
}

// Stream provider for real-time updates
@riverpod
Stream<Profile> profileStream(ProfileStreamRef ref) {
  final repository = ref.read(profileRepositoryProvider);
  return repository.profileStream();
}
```

## 🌐 App State Template

### **Global App Configuration**
```dart
// lib/core/providers/app_provider.dart
import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../themes/app_theme.dart';
import '../services/storage_service.dart';

class AppState {
  final AppTheme theme;
  final bool isDarkMode;
  final String locale;
  
  AppState({
    this.theme = AppTheme.defaultTheme,
    this.isDarkMode = false,
    this.locale = 'en',
  });
  
  AppState copyWith({
    AppTheme? theme,
    bool? isDarkMode,
    String? locale,
  }) {
    return AppState(
      theme: theme ?? this.theme,
      isDarkMode: isDarkMode ?? this.isDarkMode,
      locale: locale ?? this.locale,
    );
  }
}

class AppNotifier extends StateNotifier<AppState> {
  final StorageService _storage;
  
  AppNotifier(this._storage) : super(AppState()) {
    _loadSettings();
  }
  
  Future<void> _loadSettings() async {
    final theme = await _storage.getTheme();
    final locale = await _storage.getLocale();
    state = state.copyWith(theme: theme, locale: locale);
  }
  
  Future<void> setTheme(AppTheme theme) async {
    state = state.copyWith(theme: theme);
    await _storage.saveTheme(theme);
  }
  
  Future<void> setLocale(String locale) async {
    state = state.copyWith(locale: locale);
    await _storage.saveLocale(locale);
  }
}

final appProvider = StateNotifierProvider<AppNotifier, AppState>((ref) {
  return AppNotifier(ref.watch(storageServiceProvider));
});
```

## 🔧 Dependency Injection Template

### **Service Providers**
```dart
// lib/core/providers/service_providers.dart
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:dio/dio.dart';
import '../network/dio_client.dart';
import '../services/storage_service.dart';
import '../services/navigation_service.dart';

// HTTP Client
final dioProvider = Provider<Dio>((ref) {
  return DioClient.create();
});

// Storage Service
final storageServiceProvider = Provider<StorageService>((ref) {
  return StorageService();
});

// Navigation Service
final navigationServiceProvider = Provider<NavigationService>((ref) {
  return NavigationService();
});

// Repository Providers
final authRepositoryProvider = Provider<AuthRepository>((ref) {
  return AuthRepositoryImpl(
    dio: ref.watch(dioProvider),
    storage: ref.watch(storageServiceProvider),
  );
});
```

## 📊 State Management Best Practices

### **1. Use StateNotifier for Complex State**
- Perfect for feature-specific state
- Handles async operations well
- Easy to test

### **2. Use FutureProvider for Read-Only Data**
- Ideal for API calls
- Automatic loading/error states
- Built-in caching

### **3. Use StreamProvider for Real-time Data**
- WebSocket connections
- Database listeners
- Live updates

### **4. Keep State Small and Focused**
- One provider per feature
- Avoid god-state providers
- Combine providers when needed

### **5. Testing Strategy**
```dart
// test/unit/providers/auth_provider_test.dart
import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:mockito/mockito.dart';

void main() {
  group('AuthNotifier', () {
    late AuthRepository mockRepository;
    late ProviderContainer container;
    
    setUp(() {
      mockRepository = MockAuthRepository();
      container = ProviderContainer(overrides: [
        authRepositoryProvider.overrideWithValue(mockRepository),
      ]);
    });
    
    test('should sign in successfully', () async {
      // Arrange
      final expectedUser = AuthUser(id: '1', email: 'test@example.com');
      when(mockRepository.signIn(any, any))
          .thenAnswer((_) async => expectedUser);
      
      // Act
      final notifier = container.read(authProvider.notifier);
      await notifier.signIn('test@example.com', 'password');
      
      // Assert
      final state = container.read(authProvider);
      expect(state.user, equals(expectedUser));
      expect(state.isLoading, isFalse);
      expect(state.error, isNull);
    });
  });
}
```

---

**Flutter Version**: [FLUTTER_VERSION]  
**Dart Version**: [DART_VERSION]  
**Last Updated**: [DATE]  
**Template Version**: 1.0
