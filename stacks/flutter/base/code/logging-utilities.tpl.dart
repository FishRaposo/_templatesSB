///
/// File: logging-utilities.tpl.dart
/// Purpose: Template for unknown implementation
/// Generated for: {{PROJECT_NAME}}
///

// -----------------------------------------------------------------------------
// FILE: logging-utilities.tpl.dart
// PURPOSE: Comprehensive logging setup and utilities for Flutter projects
// USAGE: Import and adapt for structured logging across the application
// DEPENDENCIES: dart:convert, dart:developer, dart:io, flutter/foundation.dart
// AUTHOR: [[.Author]]
// VERSION: [[.Version]]
// SINCE: [[.Version]]
// -----------------------------------------------------------------------------

/**
 * Flutter Logging Utilities Template
 * Purpose: Reusable logging setup and utilities for Flutter projects
 * Usage: Import and adapt for structured logging across the application
 */

import 'dart:convert';
import 'dart:developer' as developer;
import 'dart:io';
import 'package:flutter/foundation.dart';
import 'package:intl/intl.dart';
import 'package:path_provider/path_provider.dart';
import 'package:shared_preferences/shared_preferences.dart';

/// Log levels
enum LogLevel {
  debug(0, 'DEBUG'),
  info(1, 'INFO'),
  warning(2, 'WARNING'),
  error(3, 'ERROR'),
  critical(4, 'CRITICAL');

  const LogLevel(this.value, this.name);
  final int value;
  final String name;

  static LogLevel fromString(String name) {
    switch (name.toUpperCase()) {
      case 'DEBUG':
        return LogLevel.debug;
      case 'INFO':
        return LogLevel.info;
      case 'WARNING':
      case 'WARN':
        return LogLevel.warning;
      case 'ERROR':
        return LogLevel.error;
      case 'CRITICAL':
      case 'FATAL':
        return LogLevel.critical;
      default:
        return LogLevel.info;
    }
  }
}

/// Log entry model
class LogEntry {
  final DateTime timestamp;
  final LogLevel level;
  final String loggerName;
  final String message;
  final Map<String, dynamic>? context;
  final StackTrace? stackTrace;
  final String? requestId;

  LogEntry({
    required this.timestamp,
    required this.level,
    required this.loggerName,
    required this.message,
    this.context,
    this.stackTrace,
    this.requestId,
  });

  /// Create log entry from JSON
  factory LogEntry.fromJson(Map<String, dynamic> json) {
    return LogEntry(
      timestamp: DateTime.parse(json['timestamp'] as String),
      level: LogLevel.fromString(json['level'] as String),
      loggerName: json['loggerName'] as String,
      message: json['message'] as String,
      context: json['context'] as Map<String, dynamic>?,
      stackTrace: json['stackTrace'] != null 
          ? StackTrace.fromString(json['stackTrace'] as String)
          : null,
      requestId: json['requestId'] as String?,
    );
  }

  /// Convert log entry to JSON
  Map<String, dynamic> toJson() {
    return {
      'timestamp': timestamp.toIso8601String(),
      'level': level.name,
      'loggerName': loggerName,
      'message': message,
      'context': context,
      'stackTrace': stackTrace?.toString(),
      'requestId': requestId,
    };
  }

  /// Convert to formatted string
  String toFormattedString({bool includeContext = true, bool includeStackTrace = false}) {
    final buffer = StringBuffer();
    buffer.write('${DateFormat('yyyy-MM-dd HH:mm:ss.SSS').format(timestamp)} ');
    buffer.write('[${level.name}] ');
    buffer.write('[$loggerName] ');
    buffer.write(message);

    if (includeContext && context != null && context!.isNotEmpty) {
      buffer.write(' | Context: ${jsonEncode(context)}');
    }

    if (includeStackTrace && stackTrace != null) {
      buffer.write('\nStackTrace: $stackTrace');
    }

    return buffer.toString();
  }

  @override
  String toString() {
    return toFormattedString();
  }
}

/// Log formatter interface
abstract class LogFormatter {
  String format(LogEntry entry);
}

/// JSON formatter for structured logging
class JsonFormatter implements LogFormatter {
  @override
  String format(LogEntry entry) {
    return jsonEncode(entry.toJson());
  }
}

/// Simple text formatter
class SimpleFormatter implements LogFormatter {
  final bool includeContext;
  final bool includeStackTrace;

  const SimpleFormatter({
    this.includeContext = false,
    this.includeStackTrace = false,
  });

  @override
  String format(LogEntry entry) {
    return entry.toFormattedString(
      includeContext: includeContext,
      includeStackTrace: includeStackTrace,
    );
  }
}

/// Colored console formatter for development
class ColoredFormatter implements LogFormatter {
  static const _colors = {
    LogLevel.debug: '\x1B[36m',    // Cyan
    LogLevel.info: '\x1B[32m',     // Green
    LogLevel.warning: '\x1B[33m',  // Yellow
    LogLevel.error: '\x1B[31m',    // Red
    LogLevel.critical: '\x1B[35m', // Magenta
  };
  static const _reset = '\x1B[0m';

  @override
  String format(LogEntry entry) {
    final color = _colors[entry.level] ?? '';
    final reset = _reset;
    final timestamp = DateFormat('HH:mm:ss.SSS').format(entry.timestamp);
    
    return '$color$timestamp [${entry.level.name}] [${entry.loggerName}] ${entry.message}$reset';
  }
}

/// Log output interface
abstract class LogOutput {
  void write(LogEntry entry);
  void close();
}

/// Console output
class ConsoleOutput implements LogOutput {
  final LogFormatter formatter;

  ConsoleOutput({this.formatter = const SimpleFormatter()});

  @override
  void write(LogEntry entry) {
    if (kDebugMode) {
      developer.log(
        formatter.format(entry),
        name: entry.loggerName,
        level: entry.level.value * 300, // Convert to developer.log levels
        time: entry.timestamp,
        zone: Zone.current,
        error: entry.level == LogLevel.error || entry.level == LogLevel.critical 
            ? entry.message 
            : null,
        stackTrace: entry.stackTrace,
      );
    }
  }

  @override
  void close() {
    // Nothing to close for console output
  }
}

/// File output
class FileOutput implements LogOutput {
  final LogFormatter formatter;
  final String fileName;
  final int maxFileSize;
  final int maxBackupFiles;
  late File _file;
  late IOSink _sink;
  bool _isInitialized = false;

  FileOutput({
    this.formatter = const JsonFormatter(),
    this.fileName = 'app.log',
    this.maxFileSize = 10 * 1024 * 1024, // 10MB
    this.maxBackupFiles = 5,
  });

  Future<void> _initialize() async {
    if (_isInitialized) return;

    try {
      final directory = await getApplicationDocumentsDirectory();
      _file = File('${directory.path}/$fileName');
      
      // Check file size and rotate if necessary
      if (await _file.exists()) {
        final stat = await _file.stat();
        if (stat.size > maxFileSize) {
          await _rotateLogFile();
        }
      }

      _sink = _file.openWrite(mode: FileMode.append);
      _isInitialized = true;
    } catch (e) {
      print('Failed to initialize file logging: $e');
    }
  }

  Future<void> _rotateLogFile() async {
    try {
      // Remove oldest backup if exists
      final oldestBackup = File('${_file.path}.$maxBackupFiles');
      if (await oldestBackup.exists()) {
        await oldestBackup.delete();
      }

      // Rotate existing backups
      for (int i = maxBackupFiles - 1; i >= 1; i--) {
        final currentBackup = File('${_file.path}.$i');
        final nextBackup = File('${_file.path}.${i + 1}');
        
        if (await currentBackup.exists()) {
          await currentBackup.rename(nextBackup.path);
        }
      }

      // Move current file to backup
      final firstBackup = File('${_file.path}.1');
      await _file.rename(firstBackup.path);
    } catch (e) {
      print('Failed to rotate log file: $e');
    }
  }

  @override
  void write(LogEntry entry) {
    if (!_isInitialized) {
      _initialize().then((_) => _writeEntry(entry));
    } else {
      _writeEntry(entry);
    }
  }

  void _writeEntry(LogEntry entry) {
    try {
      _sink.writeln(formatter.format(entry));
      _sink.flush();
    } catch (e) {
      print('Failed to write to log file: $e');
    }
  }

  @override
  void close() {
    if (_isInitialized) {
      _sink.close();
      _isInitialized = false;
    }
  }
}

/// Remote logging output
class RemoteOutput implements LogOutput {
  final String apiUrl;
  final String apiKey;
  final Duration timeout;
  final int batchSize;
  final Duration flushInterval;
  
  final List<LogEntry> _batch = [];
  Timer? _flushTimer;
  bool _isInitialized = false;

  RemoteOutput({
    required this.apiUrl,
    required this.apiKey,
    this.timeout = const Duration(seconds: 30),
    this.batchSize = 10,
    this.flushInterval = const Duration(seconds: 5),
  });

  Future<void> _initialize() async {
    if (_isInitialized) return;

    _flushTimer = Timer.periodic(flushInterval, (_) => _flushBatch());
    _isInitialized = true;
  }

  @override
  void write(LogEntry entry) {
    if (!_isInitialized) {
      _initialize().then((_) => _addToBatch(entry));
    } else {
      _addToBatch(entry);
    }
  }

  void _addToBatch(LogEntry entry) {
    _batch.add(entry);
    
    if (_batch.length >= batchSize) {
      _flushBatch();
    }
  }

  Future<void> _flushBatch() async {
    if (_batch.isEmpty) return;

    final entries = List<LogEntry>.from(_batch);
    _batch.clear();

    try {
      final uri = Uri.parse(apiUrl);
      final request = await HttpClient().postUrl(uri)
        .timeout(timeout);

      request.headers.contentType = ContentType.json;
      request.headers.set('Authorization', 'Bearer $apiKey');

      final payload = {
        'logs': entries.map((e) => e.toJson()).toList(),
        'timestamp': DateTime.now().toIso8601String(),
        'platform': Platform.operatingSystem,
        'version': '1.0.0', // Get from package info
      };

      request.add(utf8.encode(jsonEncode(payload)));
      
      final response = await request.close();
      
      if (response.statusCode != 200) {
        print('Failed to send logs to remote service: ${response.statusCode}');
      }
    } catch (e) {
      print('Failed to send logs to remote service: $e');
    }
  }

  @override
  void close() {
    _flushTimer?.cancel();
    _flushBatch(); // Flush remaining logs
    _isInitialized = false;
  }
}

/// Logger class
class Logger {
  final String name;
  final List<LogOutput> _outputs;
  LogLevel _level;

  Logger(
    this.name, {
    List<LogOutput>? outputs,
    LogLevel level = LogLevel.info,
  }) : _outputs = outputs ?? [ConsoleOutput()],
       _level = level;

  /// Set log level
  set level(LogLevel level) => _level = level;

  /// Get current log level
  LogLevel get level => _level;

  /// Add output
  void addOutput(LogOutput output) {
    _outputs.add(output);
  }

  /// Remove output
  void removeOutput(LogOutput output) {
    _outputs.remove(output);
  }

  /// Check if level should be logged
  bool _shouldLog(LogLevel level) {
    return level.value >= _level.value;
  }

  /// Log message
  void log(
    LogLevel level,
    String message, {
    Map<String, dynamic>? context,
    StackTrace? stackTrace,
    String? requestId,
  }) {
    if (!_shouldLog(level)) return;

    final entry = LogEntry(
      timestamp: DateTime.now(),
      level: level,
      loggerName: name,
      message: message,
      context: context,
      stackTrace: stackTrace,
      requestId: requestId,
    );

    for (final output in _outputs) {
      output.write(entry);
    }
  }

  /// Debug log
  void debug(String message, {Map<String, dynamic>? context, String? requestId}) {
    log(LogLevel.debug, message, context: context, requestId: requestId);
  }

  /// Info log
  void info(String message, {Map<String, dynamic>? context, String? requestId}) {
    log(LogLevel.info, message, context: context, requestId: requestId);
  }

  /// Warning log
  void warning(String message, {Map<String, dynamic>? context, String? requestId}) {
    log(LogLevel.warning, message, context: context, requestId: requestId);
  }

  /// Error log
  void error(String message, {Map<String, dynamic>? context, StackTrace? stackTrace, String? requestId}) {
    log(LogLevel.error, message, context: context, stackTrace: stackTrace, requestId: requestId);
  }

  /// Critical log
  void critical(String message, {Map<String, dynamic>? context, StackTrace? stackTrace, String? requestId}) {
    log(LogLevel.critical, message, context: context, stackTrace: stackTrace, requestId: requestId);
  }

  /// Close all outputs
  void close() {
    for (final output in _outputs) {
      output.close();
    }
  }
}

/// Logger manager
class LoggerManager {
  static LoggerManager? _instance;
  static LoggerManager get instance => _instance ??= LoggerManager._();

  LoggerManager._();

  final Map<String, Logger> _loggers = {};
  bool _isInitialized = false;

  /// Get or create logger
  Logger getLogger(String name) {
    if (!_loggers.containsKey(name)) {
      _loggers[name] = Logger(name);
    }
    return _loggers[name]!;
  }

  /// Initialize logging system
  Future<void> initialize({
    LogLevel globalLevel = LogLevel.info,
    bool enableConsoleLogging = true,
    bool enableFileLogging = false,
    bool enableRemoteLogging = false,
    String? remoteApiUrl,
    String? remoteApiKey,
  }) async {
    if (_isInitialized) return;

    // Setup default logger configuration
    if (enableConsoleLogging) {
      final formatter = kDebugMode 
          ? const ColoredFormatter()
          : const SimpleFormatter(includeContext: true);
      
      for (final logger in _loggers.values) {
        logger.addOutput(ConsoleOutput(formatter: formatter));
      }
    }

    if (enableFileLogging) {
      final fileOutput = FileOutput(
        formatter: const JsonFormatter(),
        fileName: 'app.log',
      );
      
      for (final logger in _loggers.values) {
        logger.addOutput(fileOutput);
      }
    }

    if (enableRemoteLogging && remoteApiUrl != null && remoteApiKey != null) {
      final remoteOutput = RemoteOutput(
        apiUrl: remoteApiUrl,
        apiKey: remoteApiKey,
      );
      
      for (final logger in _loggers.values) {
        logger.addOutput(remoteOutput);
      }
    }

    // Set global level
    for (final logger in _loggers.values) {
      logger.level = globalLevel;
    }

    _isInitialized = true;
    
    if (kDebugMode) {
      print('LoggerManager initialized');
    }
  }

  /// Set global log level
  void setGlobalLevel(LogLevel level) {
    for (final logger in _loggers.values) {
      logger.level = level;
    }
  }

  /// Close all loggers
  void close() {
    for (final logger in _loggers.values) {
      logger.close();
    }
    _loggers.clear();
    _isInitialized = false;
  }
}

/// Logger mixin for easy logging in classes
mixin LoggerMixin {
  late final Logger _logger;

  /// Initialize logger with class name
  void initLogger({String? name}) {
    _logger = LoggerManager.instance.getLogger(name ?? runtimeType.toString());
  }

  /// Get logger instance
  Logger get logger => _logger;

  /// Debug log
  void debugLog(String message, {Map<String, dynamic>? context}) {
    _logger.debug(message, context: context);
  }

  /// Info log
  void infoLog(String message, {Map<String, dynamic>? context}) {
    _logger.info(message, context: context);
  }

  /// Warning log
  void warningLog(String message, {Map<String, dynamic>? context}) {
    _logger.warning(message, context: context);
  }

  /// Error log
  void errorLog(String message, {Map<String, dynamic>? context, StackTrace? stackTrace}) {
    _logger.error(message, context: context, stackTrace: stackTrace);
  }

  /// Critical log
  void criticalLog(String message, {Map<String, dynamic>? context, StackTrace? stackTrace}) {
    _logger.critical(message, context: context, stackTrace: stackTrace);
  }
}

/// Performance logging decorator
class PerformanceLogger {
  final Logger _logger;
  final String _operationName;

  PerformanceLogger(this._logger, this._operationName);

  /// Measure execution time of a function
  Future<T> measure<T>(Future<T> Function() operation) async {
    final stopwatch = Stopwatch()..start();
    
    try {
      _logger.debug('Starting $_operationName');
      final result = await operation();
      stopwatch.stop();
      
      _logger.info(
        'Completed $_operationName',
        context: {
          'duration': '${stopwatch.elapsedMilliseconds}ms',
          'operation': _operationName,
        },
      );
      
      return result;
    } catch (error, stackTrace) {
      stopwatch.stop();
      
      _logger.error(
        'Failed $_operationName',
        context: {
          'duration': '${stopwatch.elapsedMilliseconds}ms',
          'operation': _operationName,
          'error': error.toString(),
        },
        stackTrace: stackTrace,
      );
      
      rethrow;
    }
  }
}

/// Utility functions
class LogUtils {
  /// Generate unique request ID
  static String generateRequestId() {
    return '${DateTime.now().millisecondsSinceEpoch}-${_randomString(8)}';
  }

  /// Generate random string
  static String _randomString(int length) {
    const chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
    final random = Random();
    return String.fromCharCodes(
      Iterable.generate(length).map((_) => chars.codeUnitAt(random.nextInt(chars.length))),
    );
  }

  /// Get current log level from preferences
  static Future<LogLevel> getLogLevelFromPreferences() async {
    try {
      final prefs = await SharedPreferences.getInstance();
      final levelString = prefs.getString('log_level') ?? 'info';
      return LogLevel.fromString(levelString);
    } catch (e) {
      return LogLevel.info;
    }
  }

  /// Save log level to preferences
  static Future<void> saveLogLevelToPreferences(LogLevel level) async {
    try {
      final prefs = await SharedPreferences.getInstance();
      await prefs.setString('log_level', level.name);
    } catch (e) {
      print('Failed to save log level: $e');
    }
  }
}

/// Example usage
class ExampleService with LoggerMixin {
  ExampleService() {
    initLogger();
  }

  Future<void> doSomething() async {
    final perfLogger = PerformanceLogger(logger, 'doSomething');
    
    await perfLogger.measure(() async {
      logger.info('Performing some operation');
      
      // Simulate work
      await Future.delayed(const Duration(milliseconds: 100));
      
      logger.debug('Operation completed successfully');
    });
  }

  Future<void> doSomethingWithError() async {
    final perfLogger = PerformanceLogger(logger, 'doSomethingWithError');
    
    try {
      await perfLogger.measure(() async {
        logger.info('Performing operation that will fail');
        
        // Simulate error
        throw Exception('Something went wrong');
      });
    } catch (e) {
      logger.error('Caught error in doSomethingWithError', context: {'error': e.toString()});
    }
  }
}

void main() async {
  // Initialize logging
  await LoggerManager.instance.initialize(
    globalLevel: LogLevel.debug,
    enableConsoleLogging: true,
    enableFileLogging: true,
  );

  // Get logger
  final logger = LoggerManager.instance.getLogger('Main');

  // Log messages
  logger.debug('Debug message');
  logger.info('Info message');
  logger.warning('Warning message');
  logger.error('Error message');

  // Use service with logging
  final service = ExampleService();
  await service.doSomething();
  await service.doSomethingWithError();

  // Close logging
  LoggerManager.instance.close();
}

export {
  LogLevel,
  LogEntry,
  Logger,
  LoggerManager,
  LoggerMixin,
  PerformanceLogger,
  LogUtils,
  
  // Formatters
  LogFormatter,
  JsonFormatter,
  SimpleFormatter,
  ColoredFormatter,
  
  // Outputs
  LogOutput,
  ConsoleOutput,
  FileOutput,
  RemoteOutput,
};
