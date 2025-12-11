// Template: logging-utilities.tpl.go
// Purpose: logging-utilities template
// Stack: go
// Tier: base

# Universal Template System - Go Stack
# Generated: 2025-12-10
# Purpose: Logging utilities
# Tier: base
# Stack: go
# Category: utilities

// -----------------------------------------------------------------------------
// FILE: logging-utilities.tpl.go
// PURPOSE: Comprehensive logging setup and utilities for Go projects
// USAGE: Import and configure for structured logging across the application
// DEPENDENCIES: encoding/json, fmt, io, log, os, path/filepath, runtime
// AUTHOR: [[.Author]]
// VERSION: [[.Version]]
// SINCE: [[.Version]]
// -----------------------------------------------------------------------------

package logging

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"gopkg.in/natefinch/lumberjack.v2"
)

// LogLevel represents the logging level
type LogLevel string

const (
	DEBUG LogLevel = "debug"
	INFO  LogLevel = "info"
	WARN  LogLevel = "warn"
	ERROR LogLevel = "error"
	FATAL LogLevel = "fatal"
	PANIC LogLevel = "panic"
)

// LogEntry represents a structured log entry
type LogEntry struct {
	Timestamp time.Time              `json:"timestamp"`
	Level     LogLevel               `json:"level"`
	Message   string                 `json:"message"`
	Logger    string                 `json:"logger"`
	Context   map[string]interface{} `json:"context,omitempty"`
	Stack     string                 `json:"stack,omitempty"`
	RequestID string                 `json:"request_id,omitempty"`
	UserID    string                 `json:"user_id,omitempty"`
}

// Logger interface defines logging methods
type Logger interface {
	Debug(message string, context ...map[string]interface{})
	Info(message string, context ...map[string]interface{})
	Warn(message string, context ...map[string]interface{})
	Error(message string, context ...map[string]interface{})
	Fatal(message string, context ...map[string]interface{})
	Panic(message string, context ...map[string]interface{})

	WithField(key string, value interface{}) Logger
	WithFields(fields map[string]interface{}) Logger
	WithRequestID(requestID string) Logger
	WithUserID(userID string) Logger

	SetLevel(level LogLevel)
	GetLevel() LogLevel
}

// Config represents logging configuration
type Config struct {
	Level      LogLevel `json:"level" yaml:"level"`
	Format     string   `json:"format" yaml:"format"`     // json or text
	Output     string   `json:"output" yaml:"output"`     // stdout, stderr, or file path
	MaxSize    int      `json:"max_size" yaml:"max_size"`
	MaxBackups int      `json:"max_backups" yaml:"max_backups"`
	MaxAge     int      `json:"max_age" yaml:"max_age"`
	Compress   bool     `json:"compress" yaml:"compress"`
}

// DefaultConfig returns default logging configuration
func DefaultConfig() Config {
	return Config{
		Level:      INFO,
		Format:     "json",
		Output:     "stdout",
		MaxSize:    100,
		MaxBackups: 3,
		MaxAge:     28,
		Compress:   true,
	}
}

// logger implements the Logger interface
type logger struct {
	name      string
	entry     *logrus.Entry
	requestID string
	userID    string
}

// NewLogger creates a new logger with the given configuration
func NewLogger(name string, config Config) (Logger, error) {
	// Create logrus instance
	log := logrus.New()

	// Set level
	level, err := logrus.ParseLevel(string(config.Level))
	if err != nil {
		return nil, fmt.Errorf("invalid log level: %w", err)
	}
	log.SetLevel(level)

	// Set formatter
	switch config.Format {
	case "json":
		log.SetFormatter(&logrus.JSONFormatter{
			TimestampFormat: time.RFC3339,
		})
	case "text":
		log.SetFormatter(&logrus.TextFormatter{
			FullTimestamp:   true,
			TimestampFormat: time.RFC3339,
		})
	default:
		return nil, fmt.Errorf("unsupported log format: %s", config.Format)
	}

	// Set output
	switch config.Output {
	case "stdout":
		log.SetOutput(os.Stdout)
	case "stderr":
		log.SetOutput(os.Stderr)
	default:
		// File output with rotation
		dir := filepath.Dir(config.Output)
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, fmt.Errorf("failed to create log directory: %w", err)
		}

		log.SetOutput(&lumberjack.Logger{
			Filename:   config.Output,
			MaxSize:    config.MaxSize,
			MaxBackups: config.MaxBackups,
			MaxAge:     config.MaxAge,
			Compress:   config.Compress,
		})
	}

	// Create entry with logger name
	entry := log.WithField("logger", name)

	return &logger{
		name:  name,
		entry: entry,
	}, nil
}

// NewDevelopmentLogger creates a logger for development environment
func NewDevelopmentLogger(name string) Logger {
	config := Config{
		Level:  DEBUG,
		Format: "text",
		Output: "stdout",
	}

	logger, _ := NewLogger(name, config)
	return logger
}

// NewProductionLogger creates a logger for production environment
func NewProductionLogger(name string, outputPath string) Logger {
	config := Config{
		Level:  INFO,
		Format: "json",
		Output: outputPath,
	}

	logger, _ := NewLogger(name, config)
	return logger
}

// Debug logs a debug message
func (l *logger) Debug(message string, context ...map[string]interface{}) {
	l.log(DEBUG, message, context...)
}

// Info logs an info message
func (l *logger) Info(message string, context ...map[string]interface{}) {
	l.log(INFO, message, context...)
}

// Warn logs a warning message
func (l *logger) Warn(message string, context ...map[string]interface{}) {
	l.log(WARN, message, context...)
}

// Error logs an error message
func (l *logger) Error(message string, context ...map[string]interface{}) {
	l.log(ERROR, message, context...)
}

// Fatal logs a fatal message and exits
func (l *logger) Fatal(message string, context ...map[string]interface{}) {
	l.log(FATAL, message, context...)
	os.Exit(1)
}

// Panic logs a panic message and panics
func (l *logger) Panic(message string, context ...map[string]interface{}) {
	l.log(PANIC, message, context...)
	panic(message)
}

// log is the internal logging method
func (l *logger) log(level LogLevel, message string, context ...map[string]interface{}) {
	entry := l.entry

	// Add request ID if present
	if l.requestID != "" {
		entry = entry.WithField("request_id", l.requestID)
	}

	// Add user ID if present
	if l.userID != "" {
		entry = entry.WithField("user_id", l.userID)
	}

	// Add context fields
	for _, ctx := range context {
		entry = entry.WithFields(ctx)
	}

	// Add stack trace for error levels
	if level == ERROR || level == FATAL || level == PANIC {
		if stack := l.getStackTrace(); stack != "" {
			entry = entry.WithField("stack", stack)
		}
	}

	// Log at appropriate level
	switch level {
	case DEBUG:
		entry.Debug(message)
	case INFO:
		entry.Info(message)
	case WARN:
		entry.Warn(message)
	case ERROR:
		entry.Error(message)
	case FATAL:
		entry.Fatal(message)
	case PANIC:
		entry.Panic(message)
	}
}

// WithField returns a new logger with the added field
func (l *logger) WithField(key string, value interface{}) Logger {
	return &logger{
		name:      l.name,
		entry:     l.entry.WithField(key, value),
		requestID: l.requestID,
		userID:    l.userID,
	}
}

// WithFields returns a new logger with the added fields
func (l *logger) WithFields(fields map[string]interface{}) Logger {
	return &logger{
		name:      l.name,
		entry:     l.entry.WithFields(fields),
		requestID: l.requestID,
		userID:    l.userID,
	}
}

// WithRequestID returns a new logger with the request ID
func (l *logger) WithRequestID(requestID string) Logger {
	return &logger{
		name:      l.name,
		entry:     l.entry,
		requestID: requestID,
		userID:    l.userID,
	}
}

// WithUserID returns a new logger with the user ID
func (l *logger) WithUserID(userID string) Logger {
	return &logger{
		name:      l.name,
		entry:     l.entry,
		requestID: l.requestID,
		userID:    userID,
	}
}

// SetLevel sets the logging level
func (l *logger) SetLevel(level LogLevel) {
	logrusLevel, _ := logrus.ParseLevel(string(level))
	l.entry.Logger.SetLevel(logrusLevel)
}

// GetLevel returns the current logging level
func (l *logger) GetLevel() LogLevel {
	return LogLevel(l.entry.Logger.GetLevel().String())
}

// getStackTrace returns the current stack trace
func (l *logger) getStackTrace() string {
	buf := make([]byte, 1024)
	for {
		n := runtime.Stack(buf, false)
		if n < len(buf) {
			return string(buf[:n])
		}
		buf = make([]byte, 2*len(buf))
	}
}

// LoggerManager manages multiple loggers
type LoggerManager struct {
	loggers map[string]Logger
	config  Config
}

// NewLoggerManager creates a new logger manager
func NewLoggerManager(config Config) *LoggerManager {
	return &LoggerManager{
		loggers: make(map[string]Logger),
		config:  config,
	}
}

// GetLogger returns a logger with the given name
func (lm *LoggerManager) GetLogger(name string) Logger {
	if logger, exists := lm.loggers[name]; exists {
		return logger
	}

	logger, err := NewLogger(name, lm.config)
	if err != nil {
		// Fallback to standard logger
		return &fallbackLogger{
			name: name,
		}
	}

	lm.loggers[name] = logger
	return logger
}

// SetConfig updates the configuration for all loggers
func (lm *LoggerManager) SetConfig(config Config) error {
	lm.config = config

	// Recreate all loggers with new config
	for name := range lm.loggers {
		logger, err := NewLogger(name, config)
		if err != nil {
			return err
		}
		lm.loggers[name] = logger
	}

	return nil
}

// Close closes all loggers
func (lm *LoggerManager) Close() {
	// Logrus doesn't have a close method, but we can clear the loggers
	lm.loggers = make(map[string]Logger)
}

// fallbackLogger is a simple fallback logger
type fallbackLogger struct {
	name string
}

func (l *fallbackLogger) Debug(message string, context ...map[string]interface{}) {
	l.log("DEBUG", message, context...)
}

func (l *fallbackLogger) Info(message string, context ...map[string]interface{}) {
	l.log("INFO", message, context...)
}

func (l *fallbackLogger) Warn(message string, context ...map[string]interface{}) {
	l.log("WARN", message, context...)
}

func (l *fallbackLogger) Error(message string, context ...map[string]interface{}) {
	l.log("ERROR", message, context...)
}

func (l *fallbackLogger) Fatal(message string, context ...map[string]interface{}) {
	l.log("FATAL", message, context...)
	os.Exit(1)
}

func (l *fallbackLogger) Panic(message string, context ...map[string]interface{}) {
	l.log("PANIC", message, context...)
	panic(message)
}

func (l *fallbackLogger) log(level, message string, context ...map[string]interface{}) {
	entry := LogEntry{
		Timestamp: time.Now(),
		Level:     LogLevel(level),
		Message:   message,
		Logger:    l.name,
	}

	if len(context) > 0 {
		entry.Context = context[0]
	}

	data, _ := json.Marshal(entry)
	fmt.Println(string(data))
}

func (l *fallbackLogger) WithField(key string, value interface{}) Logger {
	return l
}

func (l *fallbackLogger) WithFields(fields map[string]interface{}) Logger {
	return l
}

func (l *fallbackLogger) WithRequestID(requestID string) Logger {
	return l
}

func (l *fallbackLogger) WithUserID(userID string) Logger {
	return l
}

func (l *fallbackLogger) SetLevel(level LogLevel) {
	// No-op for fallback logger
}

func (l *fallbackLogger) GetLevel() LogLevel {
	return INFO
}

// PerformanceLogger logs performance metrics
type PerformanceLogger struct {
	logger Logger
	name   string
}

// NewPerformanceLogger creates a new performance logger
func NewPerformanceLogger(logger Logger, operationName string) *PerformanceLogger {
	return &PerformanceLogger{
		logger: logger,
		name:   operationName,
	}
}

// Measure measures the execution time of a function
func (pl *PerformanceLogger) Measure(fn func() error) error {
	start := time.Now()
	pl.logger.Debug("Starting operation", map[string]interface{}{
		"operation": pl.name,
	})

	err := fn()
	duration := time.Since(start)

	fields := map[string]interface{}{
		"operation": pl.name,
		"duration":  duration.String(),
		"ms":        duration.Milliseconds(),
	}

	if err != nil {
		pl.logger.Error("Operation failed", fields)
	} else {
		pl.logger.Info("Operation completed", fields)
	}

	return err
}

// MeasureAsync measures the execution time of an async function
func (pl *PerformanceLogger) MeasureAsync(fn func() error) error {
	return pl.Measure(fn)
}

// LoggingMiddleware provides HTTP request logging middleware
type LoggingMiddleware struct {
	logger Logger
}

// NewLoggingMiddleware creates new logging middleware
func NewLoggingMiddleware(logger Logger) *LoggingMiddleware {
	return &LoggingMiddleware{
		logger: logger,
	}
}

// LogRequest logs an HTTP request
func (lm *LoggingMiddleware) LogRequest(method, path, remoteAddr, userAgent string, statusCode int, duration time.Duration) {
	fields := map[string]interface{}{
		"method":      method,
		"path":        path,
		"remote_addr": remoteAddr,
		"user_agent":  userAgent,
		"status_code": statusCode,
		"duration":    duration.String(),
		"ms":          duration.Milliseconds(),
	}

	if statusCode >= 500 {
		lm.logger.Error("HTTP request failed", fields)
	} else if statusCode >= 400 {
		lm.logger.Warn("HTTP request warning", fields)
	} else {
		lm.logger.Info("HTTP request", fields)
	}
}

// Global logger manager instance
var globalLoggerManager = NewLoggerManager(DefaultConfig())

// GetLogger returns a logger from the global manager
func GetLogger(name string) Logger {
	return globalLoggerManager.GetLogger(name)
}

// SetGlobalConfig sets the global logging configuration
func SetGlobalConfig(config Config) error {
	return globalLoggerManager.SetConfig(config)
}

// CloseGlobalLogger closes the global logger manager
func CloseGlobalLogger() {
	globalLoggerManager.Close()
}

// Utility functions
func ParseLogLevel(level string) LogLevel {
	switch strings.ToLower(level) {
	case "debug":
		return DEBUG
	case "info":
		return INFO
	case "warn", "warning":
		return WARN
	case "error":
		return ERROR
	case "fatal":
		return FATAL
	case "panic":
		return PANIC
	default:
		return INFO
	}
}

// Example usage demonstrates how to use the logging utilities
func ExampleUsage() {
	// Create a logger
	logger, err := NewLogger("example", Config{
		Level:  DEBUG,
		Format: "json",
		Output: "stdout",
	})
	if err != nil {
		log.Fatal(err)
	}

	// Basic logging
	logger.Info("Application started")
	logger.Debug("Debug information", map[string]interface{}{
		"key": "value",
		"num": 42,
	})

	// With fields
	logger.WithFields(map[string]interface{}{
		"user_id": 123,
		"action":  "login",
	}).Info("User logged in")

	// With request ID
	logger.WithRequestID("req-123").Info("Processing request")

	// Performance logging
	perfLogger := NewPerformanceLogger(logger, "database_query")
	err = perfLogger.Measure(func() error {
		// Simulate some work
		time.Sleep(100 * time.Millisecond)
		return nil
	})
	if err != nil {
		logger.Error("Performance measurement failed", map[string]interface{}{
			"error": err.Error(),
		})
	}

	// Use global logger
	globalLogger := GetLogger("global")
	globalLogger.Info("Using global logger")
}
