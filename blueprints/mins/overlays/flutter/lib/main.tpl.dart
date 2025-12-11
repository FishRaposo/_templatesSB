/// MINS Blueprint - Main entry point
/// 
/// Privacy-first Flutter micro-app framework with sustainable monetization.
/// 
/// CONFIDENTIAL - INTERNAL USE ONLY
library;

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import 'core/config/app_config.dart';
import 'core/theme/app_theme.dart';
import 'features/app_shell/presentation/app_shell.dart';
import 'services/storage/storage_service.dart';

/// Application entry point
void main() async {
  // Ensure Flutter bindings are initialized
  WidgetsFlutterBinding.ensureInitialized();
  
  // Initialize core services
  await _initializeApp();
  
  // Run the app with Riverpod state management
  runApp(
    const ProviderScope(
      child: MinsApp(),
    ),
  );
}

/// Initialize core services before app startup
Future<void> _initializeApp() async {
  // Load app configuration
  await ConfigService.instance.initialize();
  
  // Initialize Isar database
  await StorageService.initializeDatabase();
}

/// Main application widget
/// 
/// Provides:
/// - Theme configuration (Material 3)
/// - Navigation setup (GoRouter)
/// - State management (Riverpod)
class MinsApp extends ConsumerWidget {
  const MinsApp({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final router = ref.watch(appRouterProvider);
    
    return MaterialApp.router(
      title: ConfigService.instance.appName,
      debugShowCheckedModeBanner: false,
      
      // Theme configuration
      theme: AppTheme.lightTheme,
      darkTheme: AppTheme.darkTheme,
      
      // Navigation
      routerConfig: router,
    );
  }
}
