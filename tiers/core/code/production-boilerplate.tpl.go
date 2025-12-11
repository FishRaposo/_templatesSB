// Template: production-boilerplate.tpl.go
// Purpose: production-boilerplate template
// Stack: go
// Tier: base

# Universal Template System - Unknown Stack
# Generated: 2025-12-10
# Purpose: unknown template utilities
# Tier: core
# Stack: unknown
# Category: utilities

# Production Boilerplate Template (Core Tier)

## Purpose
Provides production-ready code structure for core projects that require reliability, maintainability, and proper operational practices.

## Usage
This template should be used for:
- Production applications
- SaaS products
- Enterprise applications
- Systems requiring 99%+ uptime

## Structure
```go
// [[.ProjectName]] - Production Application
// Author: [[.Author]]
// Version: [[.Version]]

package main

import (
    "context"
    "fmt"
    "log"
    "os"
    "os/signal"
    "syscall"
    "time"
    
    "github.com/go-chi/chi/v5"
    "github.com/go-chi/chi/v5/middleware"
    "go.uber.org/zap"
)

type Application struct {
    logger    *zap.Logger
    server    *http.Server
    config    *Config
    shutdown  chan os.Signal
}

type Config struct {
    Port         string
    LogLevel     string
    DatabaseURL  string
    RedisURL     string
    Environment  string
}

func main() {
    app, err := NewApplication()
    if err != nil {
        log.Fatal("Failed to initialize application:", err)
    }
    
    if err := app.Run(); err != nil {
        log.Fatal("Application failed:", err)
    }
}

func NewApplication() (*Application, error) {
    // Initialize structured logging
    logger, err := zap.NewProduction()
    if err != nil {
        return nil, fmt.Errorf("failed to initialize logger: %w", err)
    }
    
    // Load configuration
    config, err := loadConfig()
    if err != nil {
        logger.Error("Failed to load configuration", zap.Error(err))
        return nil, err
    }
    
    // Initialize application
    app := &Application{
        logger:   logger,
        config:   config,
        shutdown: make(chan os.Signal, 1),
    }
    
    // Setup graceful shutdown
    signal.Notify(app.shutdown, os.Interrupt, syscall.SIGTERM)
    
    return app, nil
}

func (app *Application) Run() error {
    // Initialize database connection
    db, err := app.initializeDatabase()
    if err != nil {
        return fmt.Errorf("failed to initialize database: %w", err)
    }
    defer db.Close()
    
    // Setup HTTP server with middleware
    router := app.setupRouter()
    
    app.server = &http.Server{
        Addr:         ":" + app.config.Port,
        Handler:      router,
        ReadTimeout:  15 * time.Second,
        WriteTimeout: 15 * time.Second,
        IdleTimeout:  60 * time.Second,
    }
    
    // Start server in goroutine
    go func() {
        app.logger.Info("Starting server", zap.String("port", app.config.Port))
        if err := app.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
            app.logger.Error("Server failed", zap.Error(err))
        }
    }()
    
    // Wait for shutdown signal
    <-app.shutdown
    
    // Graceful shutdown
    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()
    
    app.logger.Info("Shutting down server")
    return app.server.Shutdown(ctx)
}

func (app *Application) setupRouter() *chi.Mux {
    r := chi.NewRouter()
    
    // Production middleware
    r.Use(middleware.Logger)
    r.Use(middleware.Recoverer)
    r.Use(middleware.Timeout(60 * time.Second))
    r.Use(middleware.Heartbeat("/health"))
    r.Use(middleware.Compress(5))
    
    // API routes
    r.Route("/api/v1", func(r chi.Router) {
        r.Get("/", app.handleHealth)
        r.Get("/health", app.handleHealth)
        // Add your API endpoints here
    })
    
    return r
}

func (app *Application) handleHealth(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(http.StatusOK)
    fmt.Fprintf(w, `{"status":"healthy","timestamp":"%s"}`, time.Now().UTC().Format(time.RFC3339))
}

func (app *Application) initializeDatabase() (*sql.DB, error) {
    // Database initialization logic
    return nil, nil
}

func loadConfig() (*Config, error) {
    return &Config{
        Port:        os.Getenv("PORT"),
        LogLevel:    os.Getenv("LOG_LEVEL"),
        DatabaseURL: os.Getenv("DATABASE_URL"),
        RedisURL:    os.Getenv("REDIS_URL"),
        Environment: os.Getenv("ENVIRONMENT"),
    }, nil
}
```

## Core Production Guidelines
- **Reliability**: Graceful shutdown, error handling, circuit breakers
- **Observability**: Structured logging, health checks, metrics
- **Security**: HTTPS, input validation, rate limiting
- **Performance**: Connection pooling, caching, timeouts
- **Testing**: Unit tests, integration tests, manual testing
- **Documentation**: API docs, deployment guides, runbooks

## Required Dependencies
```go
// go.mod
require (
    github.com/go-chi/chi/v5 v5.0.8
    go.uber.org/zap v1.24.0
)
```

## What's Included (vs MVP)
- Structured logging with zap
- HTTP server with proper middleware
- Graceful shutdown handling
- Configuration management
- Health check endpoints
- Database connection management
- Production-ready error handling

## What's NOT Included (vs Full)
- No advanced monitoring/metrics
- No distributed tracing
- No advanced security features
- No multi-region deployment
- No advanced caching strategies
