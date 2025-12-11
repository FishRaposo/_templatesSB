/// Template: config-management.tpl.dart
/// Purpose: config-management template
/// Stack: flutter
/// Tier: base

# Universal Template System - Flutter Stack
# Generated: 2025-12-10
# Purpose: Configuration management utilities
# Tier: base
# Stack: flutter
# Category: utilities

// -----------------------------------------------------------------------------
// FILE: config-management.tpl.dart
// PURPOSE: Comprehensive configuration management system for Flutter projects
// USAGE: Import and adapt for environment-specific settings, feature flags, and runtime configuration
// DEPENDENCIES: dart:convert, dart:io, flutter/foundation.dart, flutter/services.dart
// AUTHOR: [[.Author]]
// VERSION: [[.Version]]
// SINCE: [[.Version]]
// -----------------------------------------------------------------------------

/**
 * Flutter Configuration Management Template
 * Purpose: Reusable configuration management for Flutter projects
 * Usage: Import and adapt for environment-specific settings
 */

import 'dart:convert';
import 'dart:io';
import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'package:shared_preferences/shared_preferences.dart';

/// Configuration levels for different environments
enum Environment {
  development,
  staging,
  production,
  test,
}

/// Configuration data model
class AppConfig {
  final Environment environment;
  final String apiBaseUrl;
  final String apiVersion;
  final Duration apiTimeout;
  final bool enableLogging;
  final bool enableDebugMode;
  final bool enableAnalytics;
  final int maxRetries;
  final Duration retryDelay;
  final Map<String, dynamic> featureFlags;
  final Map<String, dynamic> customSettings;

  const AppConfig({
    required this.environment,
    required this.apiBaseUrl,
    required this.apiVersion,
    required this.apiTimeout,
    required this.enableLogging,
    required this.enableDebugMode,
    required this.enableAnalytics,
    required this.maxRetries,
    required this.retryDelay,
    required this.featureFlags,
    required this.customSettings,
  });

  /// Create config from JSON
  factory AppConfig.fromJson(Map<String, dynamic> json) {
    return AppConfig(
      environment: _parseEnvironment(json['environment'] as String? ?? 'development'),
      apiBaseUrl: json['apiBaseUrl'] as String? ?? '',
      apiVersion: json['apiVersion'] as String? ?? 'v1',
      apiTimeout: Duration(milliseconds: json['apiTimeoutMs'] as int? ?? 30000),
      enableLogging: json['enableLogging'] as bool? ?? false,
      enableDebugMode: json['enableDebugMode'] as bool? ?? false,
      enableAnalytics: json['enableAnalytics'] as bool? ?? false,
      maxRetries: json['maxRetries'] as int? ?? 3,
      retryDelay: Duration(milliseconds: json['retryDelayMs'] as int? ?? 1000),
      featureFlags: Map<String, dynamic>.from(json['featureFlags'] as Map? ?? {}),
      customSettings: Map<String, dynamic>.from(json['customSettings'] as Map? ?? {}),
    );
  }

  /// Convert config to JSON
  Map<String, dynamic> toJson() {
    return {
      'environment': environment.name,
      'apiBaseUrl': apiBaseUrl,
      'apiVersion': apiVersion,
      'apiTimeoutMs': apiTimeout.inMilliseconds,
      'enableLogging': enableLogging,
      'enableDebugMode': enableDebugMode,
      'enableAnalytics': enableAnalytics,
      'maxRetries': maxRetries,
      'retryDelayMs': retryDelay.inMilliseconds,
      'featureFlags': featureFlags,
      'customSettings': customSettings,
    };
  }

  /// Parse environment from string
  static Environment _parseEnvironment(String env) {
    switch (env.toLowerCase()) {
      case 'development':
        return Environment.development;
      case 'staging':
        return Environment.staging;
      case 'production':
        return Environment.production;
      case 'test':
        return Environment.test;
      default:
        return Environment.development;
    }
  }

  /// Check if feature is enabled
  bool isFeatureEnabled(String featureName) {
    return featureFlags[featureName] as bool? ?? false;
  }

  /// Get custom setting value
  T? getCustomSetting<T>(String key) {
    return customSettings[key] as T?;
  }

  /// Copy with changes
  AppConfig copyWith({
    Environment? environment,
    String? apiBaseUrl,
    String? apiVersion,
    Duration? apiTimeout,
    bool? enableLogging,
    bool? enableDebugMode,
    bool? enableAnalytics,
    int? maxRetries,
    Duration? retryDelay,
    Map<String, dynamic>? featureFlags,
    Map<String, dynamic>? customSettings,
  }) {
    return AppConfig(
      environment: environment ?? this.environment,
      apiBaseUrl: apiBaseUrl ?? this.apiBaseUrl,
      apiVersion: apiVersion ?? this.apiVersion,
      apiTimeout: apiTimeout ?? this.apiTimeout,
      enableLogging: enableLogging ?? this.enableLogging,
      enableDebugMode: enableDebugMode ?? this.enableDebugMode,
      enableAnalytics: enableAnalytics ?? this.enableAnalytics,
      maxRetries: maxRetries ?? this.maxRetries,
      retryDelay: retryDelay ?? this.retryDelay,
      featureFlags: featureFlags ?? this.featureFlags,
      customSettings: customSettings ?? this.customSettings,
    );
  }

  @override
  bool operator ==(Object other) {
    if (identical(this, other)) return true;
    return other is AppConfig &&
        other.environment == environment &&
        other.apiBaseUrl == apiBaseUrl &&
        other.apiVersion == apiVersion &&
        other.apiTimeout == apiTimeout &&
        other.enableLogging == enableLogging &&
        other.enableDebugMode == enableDebugMode &&
        other.enableAnalytics == enableAnalytics &&
        other.maxRetries == maxRetries &&
        other.retryDelay == retryDelay;
  }

  @override
  int get hashCode {
    return Object.hash(
      environment,
      apiBaseUrl,
      apiVersion,
      apiTimeout,
      enableLogging,
      enableDebugMode,
      enableAnalytics,
      maxRetries,
      retryDelay,
    );
  }

  @override
  String toString() {
    return 'AppConfig('
        'environment: $environment, '
        'apiBaseUrl: $apiBaseUrl, '
        'apiVersion: $apiVersion, '
        'enableLogging: $enableLogging, '
        'enableDebugMode: $enableDebugMode'
        ')';
  }
}

/// Configuration manager class
class ConfigManager {
  static ConfigManager? _instance;
  static ConfigManager get instance => _instance ??= ConfigManager._();

  ConfigManager._();

  AppConfig? _config;
  final Map<String, dynamic> _runtimeConfig = {};
  bool _isInitialized = false;

  /// Get current configuration
  AppConfig get config {
    if (_config == null) {
      throw StateError('ConfigManager not initialized. Call initialize() first.');
    }
    return _config!;
  }

  /// Check if manager is initialized
  bool get isInitialized => _isInitialized;

  /// Initialize configuration
  Future<void> initialize({Environment? environment}) async {
    if (_isInitialized) return;

    final env = environment ?? _detectEnvironment();
    _config = await _loadConfig(env);
    _isInitialized = true;

    if (kDebugMode) {
      print('ConfigManager initialized with environment: ${env.name}');
      print('Config: $_config');
    }
  }

  /// Detect current environment
  Environment _detectEnvironment() {
    if (kDebugMode) {
      return Environment.development;
    } else if (kProfileMode) {
      return Environment.staging;
    } else {
      return Environment.production;
    }
  }

  /// Load configuration for specific environment
  Future<AppConfig> _loadConfig(Environment environment) async {
    try {
      // Load base configuration
      final baseConfig = await _loadConfigFromFile('config/base.json');
      
      // Load environment-specific configuration
      final envConfig = await _loadConfigFromFile('config/${environment.name}.json');
      
      // Load user preferences
      final userConfig = await _loadUserPreferences();
      
      // Load runtime configuration (environment variables, etc.)
      final runtimeConfig = await _loadRuntimeConfig();

      // Merge all configurations
      final mergedConfig = {
        ...baseConfig,
        ...envConfig,
        ...userConfig,
        ...runtimeConfig,
        'environment': environment.name,
      };

      return AppConfig.fromJson(mergedConfig);
    } catch (e) {
      print('Error loading configuration: $e');
      // Return default configuration
      return _getDefaultConfig(environment);
    }
  }

  /// Load configuration from file
  Future<Map<String, dynamic>> _loadConfigFromFile(String filePath) async {
    try {
      final String configString = await rootBundle.loadString(filePath);
      return Map<String, dynamic>.from(json.decode(configString));
    } catch (e) {
      if (kDebugMode) {
        print('Could not load config file $filePath: $e');
      }
      return {};
    }
  }

  /// Load user preferences from SharedPreferences
  Future<Map<String, dynamic>> _loadUserPreferences() async {
    try {
      final prefs = await SharedPreferences.getInstance();
      final configString = prefs.getString('user_config');
      
      if (configString != null) {
        return Map<String, dynamic>.from(json.decode(configString));
      }
    } catch (e) {
      if (kDebugMode) {
        print('Could not load user preferences: $e');
      }
    }
    return {};
  }

  /// Load runtime configuration
  Future<Map<String, dynamic>> _loadRuntimeConfig() async {
    final Map<String, dynamic> runtimeConfig = {};
    
    // Add platform-specific configuration
    runtimeConfig['platform'] = Platform.operatingSystem;
    runtimeConfig['isDebugMode'] = kDebugMode;
    runtimeConfig['isProfileMode'] = kProfileMode;
    runtimeConfig['isReleaseMode'] = kReleaseMode;
    
    // Add runtime overrides
    runtimeConfig.addAll(_runtimeConfig);
    
    return runtimeConfig;
  }

  /// Get default configuration for environment
  AppConfig _getDefaultConfig(Environment environment) {
    switch (environment) {
      case Environment.development:
        return const AppConfig(
          environment: Environment.development,
          apiBaseUrl: 'http://localhost:8080/api',
          apiVersion: 'v1',
          apiTimeout: Duration(seconds: 30),
          enableLogging: true,
          enableDebugMode: true,
          enableAnalytics: false,
          maxRetries: 3,
          retryDelay: Duration(seconds: 1),
          featureFlags: {
            'darkMode': true,
            'betaFeatures': true,
            'debugMenu': true,
          },
          customSettings: {},
        );
      case Environment.staging:
        return const AppConfig(
          environment: Environment.staging,
          apiBaseUrl: 'https://staging-api.example.com/api',
          apiVersion: 'v1',
          apiTimeout: Duration(seconds: 30),
          enableLogging: true,
          enableDebugMode: false,
          enableAnalytics: true,
          maxRetries: 3,
          retryDelay: Duration(seconds: 1),
          featureFlags: {
            'darkMode': true,
            'betaFeatures': true,
            'debugMenu': false,
          },
          customSettings: {},
        );
      case Environment.production:
        return const AppConfig(
          environment: Environment.production,
          apiBaseUrl: 'https://api.example.com/api',
          apiVersion: 'v1',
          apiTimeout: Duration(seconds: 30),
          enableLogging: false,
          enableDebugMode: false,
          enableAnalytics: true,
          maxRetries: 3,
          retryDelay: Duration(seconds: 1),
          featureFlags: {
            'darkMode': true,
            'betaFeatures': false,
            'debugMenu': false,
          },
          customSettings: {},
        );
      case Environment.test:
        return const AppConfig(
          environment: Environment.test,
          apiBaseUrl: 'http://localhost:8081/api',
          apiVersion: 'v1',
          apiTimeout: Duration(seconds: 5),
          enableLogging: false,
          enableDebugMode: true,
          enableAnalytics: false,
          maxRetries: 1,
          retryDelay: Duration(milliseconds: 100),
          featureFlags: {},
          customSettings: {},
        );
    }
  }

  /// Update runtime configuration
  void updateRuntimeConfig(String key, dynamic value) {
    _runtimeConfig[key] = value;
  }

  /// Save user preferences
  Future<void> saveUserPreferences(Map<String, dynamic> preferences) async {
    try {
      final prefs = await SharedPreferences.getInstance();
      final configString = json.encode(preferences);
      await prefs.setString('user_config', configString);
      
      // Reload configuration
      await initialize();
    } catch (e) {
      print('Error saving user preferences: $e');
    }
  }

  /// Update configuration and save
  Future<void> updateConfig(AppConfig newConfig) async {
    _config = newConfig;
    await saveUserPreferences(newConfig.toJson());
  }

  /// Reset to default configuration
  Future<void> resetToDefaults() async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.remove('user_config');
    _runtimeConfig.clear();
    await initialize();
  }

  /// Clear all configuration
  void clear() {
    _config = null;
    _runtimeConfig.clear();
    _isInitialized = false;
  }
}

/// Configuration widget for managing settings
class ConfigSettingsWidget extends StatefulWidget {
  const ConfigSettingsWidget({Key? key}) : super(key: key);

  @override
  State<ConfigSettingsWidget> createState() => _ConfigSettingsWidgetState();
}

class _ConfigSettingsWidgetState extends State<ConfigSettingsWidget> {
  late AppConfig _config;
  bool _isLoading = true;

  @override
  void initState() {
    super.initState();
    _loadConfig();
  }

  Future<void> _loadConfig() async {
    try {
      final configManager = ConfigManager.instance;
      if (!configManager.isInitialized) {
        await configManager.initialize();
      }
      setState(() {
        _config = configManager.config;
        _isLoading = false;
      });
    } catch (e) {
      setState(() {
        _isLoading = false;
      });
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Error loading config: $e')),
        );
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    if (_isLoading) {
      return const Center(child: CircularProgressIndicator());
    }

    return Padding(
      padding: const EdgeInsets.all(16.0),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            'Configuration Settings',
            style: Theme.of(context).textTheme.headlineSmall,
          ),
          const SizedBox(height: 16),
          _buildConfigItem('Environment', _config.environment.name),
          _buildConfigItem('API Base URL', _config.apiBaseUrl),
          _buildConfigItem('API Version', _config.apiVersion),
          _buildConfigItem('Logging Enabled', _config.enableLogging.toString()),
          _buildConfigItem('Debug Mode', _config.enableDebugMode.toString()),
          _buildConfigItem('Analytics', _config.enableAnalytics.toString()),
          const SizedBox(height: 16),
          const Text(
            'Feature Flags',
            style: TextStyle(fontWeight: FontWeight.bold),
          ),
          ..._config.featureFlags.entries.map((entry) =>
            _buildConfigItem(entry.key, entry.value.toString()),
          ),
          const SizedBox(height: 16),
          Row(
            children: [
              ElevatedButton(
                onPressed: _resetConfig,
                child: const Text('Reset to Defaults'),
              ),
              const SizedBox(width: 8),
              ElevatedButton(
                onPressed: _reloadConfig,
                child: const Text('Reload Config'),
              ),
            ],
          ),
        ],
      ),
    );
  }

  Widget _buildConfigItem(String label, String value) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 4.0),
      child: Row(
        children: [
          SizedBox(
            width: 120,
            child: Text(
              '$label:',
              style: const TextStyle(fontWeight: FontWeight.w500),
            ),
          ),
          Expanded(child: Text(value)),
        ],
      ),
    );
  }

  Future<void> _resetConfig() async {
    try {
      await ConfigManager.instance.resetToDefaults();
      await _loadConfig();
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('Configuration reset to defaults')),
        );
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Error resetting config: $e')),
        );
      }
    }
  }

  Future<void> _reloadConfig() async {
    await _loadConfig();
    if (mounted) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Configuration reloaded')),
      );
    }
  }
}

/// Utility functions for configuration management
class ConfigUtils {
  /// Get environment-specific API URL
  static String getApiUrl(String endpoint) {
    final config = ConfigManager.instance.config;
    return '${config.apiBaseUrl}/${config.apiVersion}/$endpoint';
  }

  /// Check if current environment is development
  static bool isDevelopment() {
    return ConfigManager.instance.config.environment == Environment.development;
  }

  /// Check if current environment is production
  static bool isProduction() {
    return ConfigManager.instance.config.environment == Environment.production;
  }

  /// Get current environment name
  static String getEnvironmentName() {
    return ConfigManager.instance.config.environment.name;
  }

  /// Validate configuration
  static bool validateConfig(AppConfig config) {
    return config.apiBaseUrl.isNotEmpty &&
           config.apiVersion.isNotEmpty &&
           config.apiTimeout.inMilliseconds > 0 &&
           config.maxRetries >= 0 &&
           config.retryDelay.inMilliseconds >= 0;
  }
}

/// Example usage
void main() async {
  // Initialize configuration
  await ConfigManager.instance.initialize();

  // Get current config
  final config = ConfigManager.instance.config;
  print('Current environment: ${config.environment.name}');
  print('API URL: ${config.apiBaseUrl}');

  // Check feature flags
  if (config.isFeatureEnabled('darkMode')) {
    print('Dark mode is enabled');
  }

  // Get custom setting
  final customValue = config.getCustomSetting<String>('customKey');
  print('Custom value: $customValue');

  // Update runtime config
  ConfigManager.instance.updateRuntimeConfig('runtimeKey', 'runtimeValue');

  // Save user preferences
  await ConfigManager.instance.saveUserPreferences({
    'theme': 'dark',
    'language': 'en',
  });
}

export {
  Environment,
  AppConfig,
  ConfigManager,
  ConfigSettingsWidget,
  ConfigUtils,
};
