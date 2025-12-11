// Template: config-management.tpl.go
// Purpose: config-management template
// Stack: go
// Tier: base

# Universal Template System - Go Stack
# Generated: 2025-12-10
# Purpose: Configuration management utilities
# Tier: base
# Stack: go
# Category: utilities

// -----------------------------------------------------------------------------
// FILE: config-management.tpl.go
// PURPOSE: Comprehensive configuration management system for Go projects
// USAGE: Import and adapt for environment-specific settings, feature flags, and runtime configuration
// DEPENDENCIES: encoding/json, fmt, io/ioutil, os, path/filepath, strconv, strings
// AUTHOR: [[.Author]]
// VERSION: [[.Version]]
// SINCE: [[.Version]]
// -----------------------------------------------------------------------------

package config

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v2"
)

// Environment represents the application environment
type Environment string

const (
	Development Environment = "development"
	Staging     Environment = "staging"
	Production  Environment = "production"
	Test        Environment = "test"
)

// Config represents the application configuration
type Config struct {
	Environment    Environment            `json:"environment" yaml:"environment"`
	Server         ServerConfig           `json:"server" yaml:"server"`
	Database       DatabaseConfig         `json:"database" yaml:"database"`
	Redis          RedisConfig            `json:"redis" yaml:"redis"`
	Logging        LoggingConfig          `json:"logging" yaml:"logging"`
	Auth           AuthConfig             `json:"auth" yaml:"auth"`
	ExternalAPIs   map[string]APIConfig   `json:"external_apis" yaml:"external_apis"`
	FeatureFlags   map[string]bool        `json:"feature_flags" yaml:"feature_flags"`
	CustomSettings map[string]interface{} `json:"custom_settings" yaml:"custom_settings"`
}

// ServerConfig represents server configuration
type ServerConfig struct {
	Host         string        `json:"host" yaml:"host"`
	Port         int           `json:"port" yaml:"port"`
	ReadTimeout  time.Duration `json:"read_timeout" yaml:"read_timeout"`
	WriteTimeout time.Duration `json:"write_timeout" yaml:"write_timeout"`
	IdleTimeout  time.Duration `json:"idle_timeout" yaml:"idle_timeout"`
	TLS          TLSConfig     `json:"tls" yaml:"tls"`
}

// TLSConfig represents TLS configuration
type TLSConfig struct {
	Enabled  bool   `json:"enabled" yaml:"enabled"`
	CertFile string `json:"cert_file" yaml:"cert_file"`
	KeyFile  string `json:"key_file" yaml:"key_file"`
}

// DatabaseConfig represents database configuration
type DatabaseConfig struct {
	Driver          string        `json:"driver" yaml:"driver"`
	Host            string        `json:"host" yaml:"host"`
	Port            int           `json:"port" yaml:"port"`
	Database        string        `json:"database" yaml:"database"`
	Username        string        `json:"username" yaml:"username"`
	Password        string        `json:"password" yaml:"password"`
	SSLMode         string        `json:"ssl_mode" yaml:"ssl_mode"`
	MaxOpenConns    int           `json:"max_open_conns" yaml:"max_open_conns"`
	MaxIdleConns    int           `json:"max_idle_conns" yaml:"max_idle_conns"`
	ConnMaxLifetime time.Duration `json:"conn_max_lifetime" yaml:"conn_max_lifetime"`
}

// RedisConfig represents Redis configuration
type RedisConfig struct {
	Host     string        `json:"host" yaml:"host"`
	Port     int           `json:"port" yaml:"port"`
	Password string        `json:"password" yaml:"password"`
	DB       int           `json:"db" yaml:"db"`
	PoolSize int           `json:"pool_size" yaml:"pool_size"`
	Timeout  time.Duration `json:"timeout" yaml:"timeout"`
}

// LoggingConfig represents logging configuration
type LoggingConfig struct {
	Level      string `json:"level" yaml:"level"`
	Format     string `json:"format" yaml:"format"`
	Output     string `json:"output" yaml:"output"`
	MaxSize    int    `json:"max_size" yaml:"max_size"`
	MaxBackups int    `json:"max_backups" yaml:"max_backups"`
	MaxAge     int    `json:"max_age" yaml:"max_age"`
}

// AuthConfig represents authentication configuration
type AuthConfig struct {
	JWTSecret     string        `json:"jwt_secret" yaml:"jwt_secret"`
	JWTExpiration time.Duration `json:"jwt_expiration" yaml:"jwt_expiration"`
	BcryptCost    int           `json:"bcrypt_cost" yaml:"bcrypt_cost"`
}

// APIConfig represents external API configuration
type APIConfig struct {
	BaseURL string            `json:"base_url" yaml:"base_url"`
	Timeout time.Duration     `json:"timeout" yaml:"timeout"`
	Headers map[string]string `json:"headers" yaml:"headers"`
	APIKey  string            `json:"api_key" yaml:"api_key"`
}

// ConfigManager manages application configuration
type ConfigManager struct {
	config *Config
	path   string
}

// NewConfigManager creates a new configuration manager
func NewConfigManager() *ConfigManager {
	return &ConfigManager{
		config: &Config{},
	}
}

// Load loads configuration from file and environment variables
func (cm *ConfigManager) Load(configPath string) error {
	// Load from file
	if err := cm.loadFromFile(configPath); err != nil {
		return fmt.Errorf("failed to load config from file: %w", err)
	}

	// Override with environment variables
	if err := cm.loadFromEnv(); err != nil {
		return fmt.Errorf("failed to load config from environment: %w", err)
	}

	// Set defaults
	cm.setDefaults()

	// Validate configuration
	if err := cm.validate(); err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}

	cm.path = configPath
	return nil
}

// loadFromFile loads configuration from a file
func (cm *ConfigManager) loadFromFile(path string) error {
	if path == "" {
		return nil // Skip if no path provided
	}

	// Check if file exists
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil // Skip if file doesn't exist
	}

	// Read file
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}

	// Determine file format by extension
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".json":
		return json.Unmarshal(data, cm.config)
	case ".yaml", ".yml":
		return yaml.Unmarshal(data, cm.config)
	default:
		return fmt.Errorf("unsupported config file format: %s", ext)
	}
}

// loadFromEnv loads configuration from environment variables
func (cm *ConfigManager) loadFromEnv() error {
	// Environment
	if env := os.Getenv("APP_ENV"); env != "" {
		cm.config.Environment = Environment(env)
	}

	// Server configuration
	if host := os.Getenv("SERVER_HOST"); host != "" {
		cm.config.Server.Host = host
	}
	if port := os.Getenv("SERVER_PORT"); port != "" {
		if p, err := strconv.Atoi(port); err == nil {
			cm.config.Server.Port = p
		}
	}

	// Database configuration
	if driver := os.Getenv("DB_DRIVER"); driver != "" {
		cm.config.Database.Driver = driver
	}
	if host := os.Getenv("DB_HOST"); host != "" {
		cm.config.Database.Host = host
	}
	if port := os.Getenv("DB_PORT"); port != "" {
		if p, err := strconv.Atoi(port); err == nil {
			cm.config.Database.Port = p
		}
	}
	if database := os.Getenv("DB_NAME"); database != "" {
		cm.config.Database.Database = database
	}
	if username := os.Getenv("DB_USER"); username != "" {
		cm.config.Database.Username = username
	}
	if password := os.Getenv("DB_PASSWORD"); password != "" {
		cm.config.Database.Password = password
	}

	// Redis configuration
	if host := os.Getenv("REDIS_HOST"); host != "" {
		cm.config.Redis.Host = host
	}
	if port := os.Getenv("REDIS_PORT"); port != "" {
		if p, err := strconv.Atoi(port); err == nil {
			cm.config.Redis.Port = p
		}
	}
	if password := os.Getenv("REDIS_PASSWORD"); password != "" {
		cm.config.Redis.Password = password
	}

	// JWT configuration
	if secret := os.Getenv("JWT_SECRET"); secret != "" {
		cm.config.Auth.JWTSecret = secret
	}

	return nil
}

// setDefaults sets default values for configuration
func (cm *ConfigManager) setDefaults() {
	// Environment
	if cm.config.Environment == "" {
		cm.config.Environment = Development
	}

	// Server defaults
	if cm.config.Server.Host == "" {
		cm.config.Server.Host = "localhost"
	}
	if cm.config.Server.Port == 0 {
		cm.config.Server.Port = 8080
	}
	if cm.config.Server.ReadTimeout == 0 {
		cm.config.Server.ReadTimeout = 30 * time.Second
	}
	if cm.config.Server.WriteTimeout == 0 {
		cm.config.Server.WriteTimeout = 30 * time.Second
	}
	if cm.config.Server.IdleTimeout == 0 {
		cm.config.Server.IdleTimeout = 60 * time.Second
	}

	// Database defaults
	if cm.config.Database.Driver == "" {
		cm.config.Database.Driver = "postgres"
	}
	if cm.config.Database.Host == "" {
		cm.config.Database.Host = "localhost"
	}
	if cm.config.Database.Port == 0 {
		cm.config.Database.Port = 5432
	}
	if cm.config.Database.SSLMode == "" {
		cm.config.Database.SSLMode = "disable"
	}
	if cm.config.Database.MaxOpenConns == 0 {
		cm.config.Database.MaxOpenConns = 25
	}
	if cm.config.Database.MaxIdleConns == 0 {
		cm.config.Database.MaxIdleConns = 5
	}
	if cm.config.Database.ConnMaxLifetime == 0 {
		cm.config.Database.ConnMaxLifetime = 5 * time.Minute
	}

	// Redis defaults
	if cm.config.Redis.Host == "" {
		cm.config.Redis.Host = "localhost"
	}
	if cm.config.Redis.Port == 0 {
		cm.config.Redis.Port = 6379
	}
	if cm.config.Redis.PoolSize == 0 {
		cm.config.Redis.PoolSize = 10
	}
	if cm.config.Redis.Timeout == 0 {
		cm.config.Redis.Timeout = 5 * time.Second
	}

	// Logging defaults
	if cm.config.Logging.Level == "" {
		cm.config.Logging.Level = "info"
	}
	if cm.config.Logging.Format == "" {
		cm.config.Logging.Format = "json"
	}
	if cm.config.Logging.Output == "" {
		cm.config.Logging.Output = "stdout"
	}
	if cm.config.Logging.MaxSize == 0 {
		cm.config.Logging.MaxSize = 100
	}
	if cm.config.Logging.MaxBackups == 0 {
		cm.config.Logging.MaxBackups = 3
	}
	if cm.config.Logging.MaxAge == 0 {
		cm.config.Logging.MaxAge = 28
	}

	// Auth defaults
	if cm.config.Auth.JWTExpiration == 0 {
		cm.config.Auth.JWTExpiration = 24 * time.Hour
	}
	if cm.config.Auth.BcryptCost == 0 {
		cm.config.Auth.BcryptCost = 12
	}

	// Initialize maps if nil
	if cm.config.ExternalAPIs == nil {
		cm.config.ExternalAPIs = make(map[string]APIConfig)
	}
	if cm.config.FeatureFlags == nil {
		cm.config.FeatureFlags = make(map[string]bool)
	}
	if cm.config.CustomSettings == nil {
		cm.config.CustomSettings = make(map[string]interface{})
	}
}

// validate validates the configuration
func (cm *ConfigManager) validate() error {
	// Validate environment
	switch cm.config.Environment {
	case Development, Staging, Production, Test:
		// Valid environments
	default:
		return fmt.Errorf("invalid environment: %s", cm.config.Environment)
	}

	// Validate server configuration
	if cm.config.Server.Port <= 0 || cm.config.Server.Port > 65535 {
		return fmt.Errorf("invalid server port: %d", cm.config.Server.Port)
	}

	// Validate database configuration
	if cm.config.Database.Driver == "" {
		return fmt.Errorf("database driver is required")
	}
	if cm.config.Database.Host == "" {
		return fmt.Errorf("database host is required")
	}
	if cm.config.Database.Database == "" {
		return fmt.Errorf("database name is required")
	}

	// Validate Redis configuration if host is specified
	if cm.config.Redis.Host != "" {
		if cm.config.Redis.Port <= 0 || cm.config.Redis.Port > 65535 {
			return fmt.Errorf("invalid redis port: %d", cm.config.Redis.Port)
		}
	}

	// Validate auth configuration
	if cm.config.Auth.JWTSecret == "" {
		return fmt.Errorf("JWT secret is required")
	}
	if cm.config.Auth.BcryptCost < 4 || cm.config.Auth.BcryptCost > 31 {
		return fmt.Errorf("bcrypt cost must be between 4 and 31")
	}

	return nil
}

// GetConfig returns the current configuration
func (cm *ConfigManager) GetConfig() *Config {
	return cm.config
}

// GetEnvironment returns the current environment
func (cm *ConfigManager) GetEnvironment() Environment {
	return cm.config.Environment
}

// IsDevelopment returns true if running in development environment
func (cm *ConfigManager) IsDevelopment() bool {
	return cm.config.Environment == Development
}

// IsProduction returns true if running in production environment
func (cm *ConfigManager) IsProduction() bool {
	return cm.config.Environment == Production
}

// IsFeatureEnabled checks if a feature flag is enabled
func (cm *ConfigManager) IsFeatureEnabled(feature string) bool {
	if cm.config.FeatureFlags == nil {
		return false
	}
	return cm.config.FeatureFlags[feature]
}

// GetCustomSetting returns a custom setting value
func (cm *ConfigManager) GetCustomSetting(key string) (interface{}, bool) {
	if cm.config.CustomSettings == nil {
		return nil, false
	}
	value, exists := cm.config.CustomSettings[key]
	return value, exists
}

// GetCustomString returns a custom setting as string
func (cm *ConfigManager) GetCustomString(key string) string {
	if value, exists := cm.GetCustomSetting(key); exists {
		if str, ok := value.(string); ok {
			return str
		}
	}
	return ""
}

// GetCustomInt returns a custom setting as integer
func (cm *ConfigManager) GetCustomInt(key string) int {
	if value, exists := cm.GetCustomSetting(key); exists {
		switch v := value.(type) {
		case int:
			return v
		case float64:
			return int(v)
		case string:
			if i, err := strconv.Atoi(v); err == nil {
				return i
			}
		}
	}
	return 0
}

// GetCustomBool returns a custom setting as boolean
func (cm *ConfigManager) GetCustomBool(key string) bool {
	if value, exists := cm.GetCustomSetting(key); exists {
		switch v := value.(type) {
		case bool:
			return v
		case string:
			return strings.ToLower(v) == "true" || v == "1"
		}
	}
	return false
}

// GetDatabaseDSN returns the database connection string
func (cm *ConfigManager) GetDatabaseDSN() string {
	switch cm.config.Database.Driver {
	case "postgres":
		return fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
			cm.config.Database.Host,
			cm.config.Database.Port,
			cm.config.Database.Username,
			cm.config.Database.Password,
			cm.config.Database.Database,
			cm.config.Database.SSLMode,
		)
	case "mysql":
		return fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?charset=utf8mb4&parseTime=True&loc=Local",
			cm.config.Database.Username,
			cm.config.Database.Password,
			cm.config.Database.Host,
			cm.config.Database.Port,
			cm.config.Database.Database,
		)
	case "sqlite":
		return cm.config.Database.Database
	default:
		return ""
	}
}

// GetRedisAddr returns the Redis connection address
func (cm *ConfigManager) GetRedisAddr() string {
	return fmt.Sprintf("%s:%d", cm.config.Redis.Host, cm.config.Redis.Port)
}

// GetServerAddr returns the server address
func (cm *ConfigManager) GetServerAddr() string {
	return fmt.Sprintf("%s:%d", cm.config.Server.Host, cm.config.Server.Port)
}

// Save saves the current configuration to file
func (cm *ConfigManager) Save(path string) error {
	var data []byte
	var err error

	// Determine file format by extension
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".json":
		data, err = json.MarshalIndent(cm.config, "", "  ")
	case ".yaml", ".yml":
		data, err = yaml.Marshal(cm.config)
	default:
		return fmt.Errorf("unsupported config file format: %s", ext)
	}

	if err != nil {
		return err
	}

	// Create directory if it doesn't exist
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	// Write file
	return ioutil.WriteFile(path, data, 0644)
}

// Update updates configuration values
func (cm *ConfigManager) Update(updates map[string]interface{}) error {
	// This is a simplified implementation
	// In a real application, you might want to use reflection or a more sophisticated approach
	for key, value := range updates {
		switch key {
		case "environment":
			if env, ok := value.(string); ok {
				cm.config.Environment = Environment(env)
			}
		case "server.host":
			if host, ok := value.(string); ok {
				cm.config.Server.Host = host
			}
		case "server.port":
			if port, ok := value.(float64); ok {
				cm.config.Server.Port = int(port)
			}
		// Add more cases as needed
		}
	}

	// Re-validate after update
	return cm.validate()
}

// String returns a string representation of the configuration
func (cm *ConfigManager) String() string {
	data, err := json.MarshalIndent(cm.config, "", "  ")
	if err != nil {
		return fmt.Sprintf("Error marshaling config: %v", err)
	}
	return string(data)
}

// CreateDefaultConfig creates a default configuration
func CreateDefaultConfig() *Config {
	return &Config{
		Environment: Development,
		Server: ServerConfig{
			Host:         "localhost",
			Port:         8080,
			ReadTimeout:  30 * time.Second,
			WriteTimeout: 30 * time.Second,
			IdleTimeout:  60 * time.Second,
		},
		Database: DatabaseConfig{
			Driver:          "postgres",
			Host:            "localhost",
			Port:            5432,
			Database:        "app_development",
			Username:        "postgres",
			Password:        "password",
			SSLMode:         "disable",
			MaxOpenConns:    25,
			MaxIdleConns:    5,
			ConnMaxLifetime: 5 * time.Minute,
		},
		Redis: RedisConfig{
			Host:     "localhost",
			Port:     6379,
			Password: "",
			DB:       0,
			PoolSize: 10,
			Timeout:  5 * time.Second,
		},
		Logging: LoggingConfig{
			Level:      "info",
			Format:     "json",
			Output:     "stdout",
			MaxSize:    100,
			MaxBackups: 3,
			MaxAge:     28,
		},
		Auth: AuthConfig{
			JWTSecret:     "your-secret-key",
			JWTExpiration: 24 * time.Hour,
			BcryptCost:    12,
		},
		ExternalAPIs:   make(map[string]APIConfig),
		FeatureFlags:   make(map[string]bool),
		CustomSettings: make(map[string]interface{}),
	}
}

// Example usage demonstrates how to use the configuration manager
func ExampleUsage() {
	// Create config manager
	configManager := NewConfigManager()

	// Load configuration
	if err := configManager.Load("config.yaml"); err != nil {
		panic(err)
	}

	// Get configuration
	config := configManager.GetConfig()

	// Use configuration
	fmt.Printf("Environment: %s\n", config.Environment)
	fmt.Printf("Server address: %s\n", configManager.GetServerAddr())
	fmt.Printf("Database DSN: %s\n", configManager.GetDatabaseDSN())

	// Check feature flags
	if configManager.IsFeatureEnabled("new_ui") {
		fmt.Println("New UI is enabled")
	}

	// Get custom settings
	if customValue, exists := configManager.GetCustomSetting("max_connections"); exists {
		fmt.Printf("Max connections: %v\n", customValue)
	}

	// Update configuration
	updates := map[string]interface{}{
		"server.port": float64(9000),
	}
	if err := configManager.Update(updates); err != nil {
		panic(err)
	}

	// Save configuration
	if err := configManager.Save("config-updated.yaml"); err != nil {
		panic(err)
	}
}
