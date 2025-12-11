// Template: production-boilerplate-go.tpl.go
// Purpose: production-boilerplate-go template
// Stack: go
// Tier: base

# Universal Template System - Unknown Stack
# Generated: 2025-12-10
# Purpose: unknown template utilities
# Tier: core
# Stack: unknown
# Category: utilities

# Production Boilerplate Template (Core Tier - Go)

## Purpose
Provides production-ready Go code structure for core projects that require reliability, maintainability, and proper operational practices.

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
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"
	
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// ProductionConfig holds production configuration
type ProductionConfig struct {
	Port         string
	LogLevel     string
	DatabaseURL  string
	RedisURL     string
	Environment  string
	MetricsPort  string
}

// SystemMetrics holds system metrics
type SystemMetrics struct {
	MemoryUsage  float64 `json:"memory_usage"`
	CPUUsage     float64 `json:"cpu_usage"`
	GoroutineCount int   `json:"goroutine_count"`
	ActiveUsers  int     `json:"active_users"`
	Timestamp    int64   `json:"timestamp"`
}

// ProductionService handles production operations
type ProductionService struct {
	logger    *zap.Logger
	config    *ProductionConfig
	metrics   *prometheus.Registry
	shutdown  chan os.Signal
	running   bool
}

// Prometheus metrics
var (
	httpRequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "http_requests_total",
			Help: "Total number of HTTP requests",
		},
		[]string{"method", "path", "status"},
	)
	
	httpRequestDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name: "http_request_duration_seconds",
			Help: "HTTP request duration in seconds",
		},
		[]string{"method", "path"},
	)
	
	activeConnections = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "active_connections",
			Help: "Number of active connections",
		},
	)
)

func init() {
	// Register Prometheus metrics
	prometheus.MustRegister(httpRequestsTotal)
	prometheus.MustRegister(httpRequestDuration)
	prometheus.MustRegister(activeConnections)
}

// NewProductionService creates a new production service
func NewProductionService() (*ProductionService, error) {
	// Initialize structured logging
	logger, err := initLogger()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize logger: %w", err)
	}
	
	// Load configuration
	config, err := loadConfig()
	if err != nil {
		logger.Error("Failed to load configuration", zap.Error(err))
		return nil, err
	}
	
	// Initialize metrics registry
	metrics := prometheus.NewRegistry()
	metrics.MustRegister(httpRequestsTotal)
	metrics.MustRegister(httpRequestDuration)
	metrics.MustRegister(activeConnections)
	
	service := &ProductionService{
		logger:   logger,
		config:   config,
		metrics:  metrics,
		shutdown: make(chan os.Signal, 1),
	}
	
	// Setup graceful shutdown
	signal.Notify(service.shutdown, os.Interrupt, syscall.SIGTERM)
	
	return service, nil
}

// initLogger initializes structured logging
func initLogger() (*zap.Logger, error) {
	config := zap.NewProductionConfig()
	config.Level = zap.NewAtomicLevelAt(zapcore.InfoLevel)
	config.OutputPaths = []string{"stdout"}
	config.ErrorOutputPaths = []string{"stderr"}
	config.EncoderConfig.TimeKey = "timestamp"
	config.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	
	return config.Build()
}

// loadConfig loads production configuration
func loadConfig() (*ProductionConfig, error) {
	return &ProductionConfig{
		Port:        getEnv("PORT", "8080"),
		LogLevel:    getEnv("LOG_LEVEL", "info"),
		DatabaseURL: getEnv("DATABASE_URL", ""),
		RedisURL:    getEnv("REDIS_URL", ""),
		Environment: getEnv("ENVIRONMENT", "production"),
		MetricsPort: getEnv("METRICS_PORT", "9090"),
	}, nil
}

// getEnv gets environment variable with default
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// Initialize initializes the production service
func (s *ProductionService) Initialize() error {
	s.logger.Info("Initializing production service")
	
	// Initialize database connection
	if err := s.initializeDatabase(); err != nil {
		return fmt.Errorf("failed to initialize database: %w", err)
	}
	
	// Initialize Redis connection
	if err := s.initializeRedis(); err != nil {
		return fmt.Errorf("failed to initialize Redis: %w", err)
	}
	
	s.running = true
	s.logger.Info("Production service initialized successfully")
	
	return nil
}

// initializeDatabase initializes database connection
func (s *ProductionService) initializeDatabase() error {
	// Database initialization logic
	s.logger.Info("Database connection initialized")
	return nil
}

// initializeRedis initializes Redis connection
func (s *ProductionService) initializeRedis() error {
	// Redis initialization logic
	s.logger.Info("Redis connection initialized")
	return nil
}

// Run starts the production service
func (s *ProductionService) Run() error {
	// Start HTTP server
	serverErr := make(chan error, 1)
	
	go func() {
		if err := s.startHTTPServer(); err != nil {
			serverErr <- err
		}
	}()
	
	// Start metrics server
	metricsErr := make(chan error, 1)
	
	go func() {
		if err := s.startMetricsServer(); err != nil {
			metricsErr <- err
		}
	}()
	
	// Start background tasks
	go s.startBackgroundTasks()
	
	// Wait for shutdown or errors
	select {
	case err := <-serverErr:
		return fmt.Errorf("HTTP server failed: %w", err)
	case err := <-metricsErr:
		return fmt.Errorf("Metrics server failed: %w", err)
	case <-s.shutdown:
		return s.shutdownGracefully()
	}
}

// startHTTPServer starts the main HTTP server
func (s *ProductionService) startHTTPServer() error {
	router := s.setupRouter()
	
	s.server = &http.Server{
		Addr:         ":" + s.config.Port,
		Handler:      router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
	
	s.logger.Info("Starting HTTP server", zap.String("port", s.config.Port))
	return s.server.ListenAndServe()
}

// startMetricsServer starts the Prometheus metrics server
func (s *ProductionService) startMetricsServer() error {
	router := chi.NewRouter()
	router.Handle("/metrics", promhttp.HandlerFor(s.metrics, promhttp.HandlerOpts{}))
	
	metricsServer := &http.Server{
		Addr:    ":" + s.config.MetricsPort,
		Handler: router,
	}
	
	s.logger.Info("Starting metrics server", zap.String("port", s.config.MetricsPort))
	return metricsServer.ListenAndServe()
}

// setupRouter sets up the HTTP router with middleware
func (s *ProductionService) setupRouter() *chi.Mux {
	r := chi.NewRouter()
	
	// Production middleware
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(60 * time.Second))
	r.Use(middleware.Compress(5))
	r.Use(s.metricsMiddleware)
	
	// Health check endpoints
	r.Route("/api/v1", func(r chi.Router) {
		r.Get("/", s.handleHealth)
		r.Get("/health", s.handleHealth)
		r.Get("/metrics", s.handleMetrics)
		r.Post("/action", s.handleAction)
	})
	
	return r
}

// metricsMiddleware tracks HTTP metrics
func (s *ProductionService) metricsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		
		// Wrap response writer to capture status code
		wrapped := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}
		
		next.ServeHTTP(wrapped, r)
		
		duration := time.Since(start).Seconds()
		
		// Update Prometheus metrics
		httpRequestsTotal.WithLabelValues(r.Method, r.URL.Path, fmt.Sprintf("%d", wrapped.statusCode)).Inc()
		httpRequestDuration.WithLabelValues(r.Method, r.URL.Path).Observe(duration)
	})
}

// responseWriter wraps http.ResponseWriter to capture status code
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// handleHealth handles health check requests
func (s *ProductionService) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	
	response := map[string]interface{}{
		"status":    "healthy",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"version":   "1.0.0",
		"service":   "production",
	}
	
	json.NewEncoder(w).Encode(response)
}

// handleMetrics handles metrics requests
func (s *ProductionService) handleMetrics(w http.ResponseWriter, r *http.Request) {
	metrics := s.collectMetrics()
	
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(metrics)
}

// handleAction handles production action requests
func (s *ProductionService) handleAction(w http.ResponseWriter, r *http.Request) {
	result, err := s.performAction()
	if err != nil {
		s.logger.Error("Production action failed", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(result)
}

// performAction performs a production action
func (s *ProductionService) performAction() (map[string]interface{}, error) {
	s.logger.Info("Performing production action")
	
	// Simulate work
	time.Sleep(500 * time.Millisecond)
	
	result := map[string]interface{}{
		"status":    "success",
		"message":   "Production action completed",
		"timestamp": time.Now().Unix(),
	}
	
	s.logger.Info("Production action completed successfully")
	return result, nil
}

// collectMetrics collects system metrics
func (s *ProductionService) collectMetrics() SystemMetrics {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	
	memoryUsage := float64(m.Alloc) / float64(m.Sys) * 100
	
	return SystemMetrics{
		MemoryUsage:    memoryUsage,
		CPUUsage:       0.0, // Would need external library for CPU usage
		GoroutineCount: runtime.NumGoroutine(),
		ActiveUsers:    1250, // Would come from actual user tracking
		Timestamp:      time.Now().Unix(),
	}
}

// startBackgroundTasks starts background monitoring tasks
func (s *ProductionService) startBackgroundTasks() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	
	for s.running {
		select {
		case <-ticker.C:
			metrics := s.collectMetrics()
			s.logger.Debug("Collected metrics", zap.Any("metrics", metrics))
			
		case <-s.shutdown:
			return
		}
	}
}

// shutdownGracefully performs graceful shutdown
func (s *ProductionService) shutdownGracefully() error {
	s.logger.Info("Shutting down gracefully")
	s.running = false
	
	if s.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		
		if err := s.server.Shutdown(ctx); err != nil {
			s.logger.Error("Server shutdown failed", zap.Error(err))
			return err
		}
	}
	
	s.logger.Info("Service shutdown complete")
	return nil
}

func main() {
	// Create production service
	service, err := NewProductionService()
	if err != nil {
		log.Fatal("Failed to create production service:", err)
	}
	
	// Initialize service
	if err := service.Initialize(); err != nil {
		log.Fatal("Failed to initialize service:", err)
	}
	
	// Run service
	if err := service.Run(); err != nil {
		log.Fatal("Service failed:", err)
	}
}
```

## Core Production Guidelines
- **Reliability**: Graceful shutdown, error handling, circuit breakers
- **Observability**: Structured logging with zap, Prometheus metrics, health checks
- **Security**: HTTPS, input validation, rate limiting, secure headers
- **Performance**: Connection pooling, caching, timeouts, middleware
- **Testing**: Unit tests, integration tests, load testing
- **Documentation**: API docs, deployment guides, runbooks

## Required Dependencies
```go
// go.mod
module production-app

go 1.21

require (
    github.com/go-chi/chi/v5 v5.0.8
    github.com/prometheus/client_golang v1.16.0
    go.uber.org/zap v1.24.0
)
```

## What's Included (vs MVP)
- Structured logging with zap
- HTTP server with proper middleware and metrics
- Graceful shutdown handling
- Configuration management
- Health check endpoints
- Prometheus metrics integration
- Production-ready error handling
- Background task management
- System metrics collection

## What's NOT Included (vs Full)
- No advanced monitoring/metrics dashboards
- No distributed tracing
- No advanced security features
- No multi-region deployment
- No advanced caching strategies
- No enterprise authentication systems
