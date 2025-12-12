// File: logging-utilities.tpl.go
// Purpose: Structured logging using standard library 'log/slog'
// Generated for: {{PROJECT_NAME}}

package logging

import (
	"context"
	"log/slog"
	"os"
	"strings"
)

// Logger is an alias for slog.Logger to allow easy swapping if needed
type Logger = slog.Logger

// Config holds logging configuration
type Config struct {
	Level  string // DEBUG, INFO, WARN, ERROR
	Format string // JSON, TEXT
}

// Global default logger
var Default *Logger

func init() {
	// Initialize with a safe default
	Default = slog.New(slog.NewJSONHandler(os.Stdout, nil))
}

// Setup initializes the global logger based on config
func Setup(cfg Config) {
	opts := &slog.HandlerOptions{
		Level: parseLevel(cfg.Level),
	}

	var handler slog.Handler
	if strings.ToUpper(cfg.Format) == "TEXT" {
		handler = slog.NewTextHandler(os.Stdout, opts)
	} else {
		handler = slog.NewJSONHandler(os.Stdout, opts)
	}

	logger := slog.New(handler)
	slog.SetDefault(logger)
	Default = logger
}

// parseLevel converts string to slog.Level
func parseLevel(level string) slog.Level {
	switch strings.ToUpper(level) {
	case "DEBUG":
		return slog.LevelDebug
	case "INFO":
		return slog.LevelInfo
	case "WARN":
		return slog.LevelWarn
	case "ERROR":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// Get finds a logger from context or returns default
func Get(ctx context.Context) *Logger {
	// In a real app, you might extract a logger decorated with Request-ID from context
	// For now, return the global default
	return Default
}

// ExampleUsage demonstrates logging
func ExampleUsage() {
	Setup(Config{Level: "DEBUG", Format: "JSON"})

	slog.Info("Application started", "version", "1.0.0")
	slog.Debug("Debugging database connection", 
		slog.String("host", "localhost"),
		slog.Int("port", 5432),
	)

	// Contextual logging
	logger := Default.With("service", "payment")
	logger.Info("Processing payment", "amount", 99.99)
}
