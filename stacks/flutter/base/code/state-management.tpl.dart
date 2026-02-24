// File: state-management.tpl.dart
// Purpose: State management patterns using Riverpod
// Generated for: {{PROJECT_NAME}}

import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:riverpod_annotation/riverpod_annotation.dart';

part 'state_management.g.dart'; // Code generation support

// -----------------------------------------------------------------------------
// 1. Immutable State Model
// -----------------------------------------------------------------------------
class UserState {
  final String id;
  final String name;
  final bool isAuthenticated;

  const UserState({
    this.id = '',
    this.name = '',
    this.isAuthenticated = false,
  });

  UserState copyWith({String? id, String? name, bool? isAuthenticated}) {
    return UserState(
      id: id ?? this.id,
      name: name ?? this.name,
      isAuthenticated: isAuthenticated ?? this.isAuthenticated,
    );
  }
}

// -----------------------------------------------------------------------------
// 2. Notifier Provider (The Business Logic)
// -----------------------------------------------------------------------------
@riverpod
class UserNotifier extends _$UserNotifier {
  @override
  UserState build() {
    return const UserState();
  }

  void login(String username) {
    // Simulate API call
    state = state.copyWith(
      id: '123',
      name: username,
      isAuthenticated: true,
    );
  }

  void logout() {
    state = const UserState();
  }
}

// -----------------------------------------------------------------------------
// 3. Async Provider (For Data Fetching)
// -----------------------------------------------------------------------------
@riverpod
Future<List<String>> fetchItems(FetchItemsRef ref) async {
  // Simulate network delay
  await Future.delayed(const Duration(seconds: 1));
  return ['Item 1', 'Item 2', 'Item 3'];
}
