// File: config.tpl.go
// Purpose: Application configuration management with Viper
// Generated for: {{PROJECT_NAME}}

package config

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/viper"
)

// ============================================================================
// Configuration Structures
// ============================================================================

type Config struct {
	App      AppConfig      `mapstructure:"app"`
	Server   ServerConfig   `mapstructure:"server"`
	Database DatabaseConfig `mapstructure:"database"`
	Redis    RedisConfig    `mapstructure:"redis"`
	Security SecurityConfig `mapstructure:"security"`
	Storage  StorageConfig  `mapstructure:"storage"`
	Email    EmailConfig    `mapstructure:"email"`
	Features FeatureFlags   `mapstructure:"features"`
	Logging  LoggingConfig  `mapstructure:"logging"`
}

type AppConfig struct {
	Name        string `mapstructure:"name"`
	Version     string `mapstructure:"version"`
	Environment string `mapstructure:"environment"`
	Debug       bool   `mapstructure:"debug"`
}

type ServerConfig struct {
	Host            string        `mapstructure:"host"`
	Port            int           `mapstructure:"port"`
	ReadTimeout     time.Duration `mapstructure:"read_timeout"`
	WriteTimeout    time.Duration `mapstructure:"write_timeout"`
	ShutdownTimeout time.Duration `mapstructure:"shutdown_timeout"`
}

type DatabaseConfig struct {
	Host            string        `mapstructure:"host"`
	Port            int           `mapstructure:"port"`
	Name            string        `mapstructure:"name"`
	User            string        `mapstructure:"user"`
	Password        string        `mapstructure:"password"`
	SSLMode         string        `mapstructure:"ssl_mode"`
	MaxOpenConns    int           `mapstructure:"max_open_conns"`
	MaxIdleConns    int           `mapstructure:"max_idle_conns"`
	ConnMaxLifetime time.Duration `mapstructure:"conn_max_lifetime"`
}

type RedisConfig struct {
	Host         string        `mapstructure:"host"`
	Port         int           `mapstructure:"port"`
	Password     string        `mapstructure:"password"`
	DB           int           `mapstructure:"db"`
	PoolSize     int           `mapstructure:"pool_size"`
	ReadTimeout  time.Duration `mapstructure:"read_timeout"`
	WriteTimeout time.Duration `mapstructure:"write_timeout"`
}

type SecurityConfig struct {
	SecretKey            string        `mapstructure:"secret_key"`
	Algorithm            string        `mapstructure:"algorithm"`
	AccessTokenExpiry    time.Duration `mapstructure:"access_token_expiry"`
	RefreshTokenExpiry   time.Duration `mapstructure:"refresh_token_expiry"`
	BcryptCost           int           `mapstructure:"bcrypt_cost"`
	CORSOrigins          []string      `mapstructure:"cors_origins"`
	CORSAllowCredentials bool          `mapstructure:"cors_allow_credentials"`
	RateLimitPerMinute   int           `mapstructure:"rate_limit_per_minute"`
}

type StorageConfig struct {
	Provider    string   `mapstructure:"provider"` // local, s3
	LocalPath   string   `mapstructure:"local_path"`
	S3Bucket    string   `mapstructure:"s3_bucket"`
	S3Region    string   `mapstructure:"s3_region"`
	S3AccessKey string   `mapstructure:"s3_access_key"`
	S3SecretKey string   `mapstructure:"s3_secret_key"`
	S3Endpoint  string   `mapstructure:"s3_endpoint"`
	MaxFileSize int64    `mapstructure:"max_file_size"`
	AllowedExts []string `mapstructure:"allowed_extensions"`
}

type EmailConfig struct {
	Provider     string `mapstructure:"provider"` // smtp, sendgrid
	SMTPHost     string `mapstructure:"smtp_host"`
	SMTPPort     int    `mapstructure:"smtp_port"`
	SMTPUser     string `mapstructure:"smtp_user"`
	SMTPPassword string `mapstructure:"smtp_password"`
	SMTPTLS      bool   `mapstructure:"smtp_tls"`
	FromEmail    string `mapstructure:"from_email"`
	FromName     string `mapstructure:"from_name"`
}

type FeatureFlags struct {
	EnableRegistration bool `mapstructure:"enable_registration"`
	EnableSocialLogin  bool `mapstructure:"enable_social_login"`
	EnableAPIKeys      bool `mapstructure:"enable_api_keys"`
	MaintenanceMode    bool `mapstructure:"maintenance_mode"`
}

type LoggingConfig struct {
	Level    string `mapstructure:"level"`
	Format   string `mapstructure:"format"` // json, text
	Output   string `mapstructure:"output"` // stdout, file
	FilePath string `mapstructure:"file_path"`
}

// ============================================================================
// Configuration Methods
// ============================================================================

func (c *AppConfig) IsProduction() bool {
	return c.Environment == "production"
}

func (c *AppConfig) IsDevelopment() bool {
	return c.Environment == "development"
}

func (c *AppConfig) IsTesting() bool {
	return c.Environment == "testing"
}

func (c *DatabaseConfig) DSN() string {
	return fmt.Sprintf(
		"host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		c.Host, c.Port, c.User, c.Password, c.Name, c.SSLMode,
	)
}

func (c *DatabaseConfig) URL() string {
	return fmt.Sprintf(
		"postgres://%s:%s@%s:%d/%s?sslmode=%s",
		c.User, c.Password, c.Host, c.Port, c.Name, c.SSLMode,
	)
}

func (c *RedisConfig) URL() string {
	if c.Password != "" {
		return fmt.Sprintf("redis://:%s@%s:%d/%d", c.Password, c.Host, c.Port, c.DB)
	}
	return fmt.Sprintf("redis://%s:%d/%d", c.Host, c.Port, c.DB)
}

func (c *ServerConfig) Address() string {
	return fmt.Sprintf("%s:%d", c.Host, c.Port)
}

// ============================================================================
// Configuration Loading
// ============================================================================

var cfg *Config

func Load(configPath string) (*Config, error) {
	v := viper.New()

	// Set config file
	if configPath != "" {
		v.SetConfigFile(configPath)
	} else {
		// Default config locations
		v.SetConfigName("config")
		v.SetConfigType("yaml")
		v.AddConfigPath(".")
		v.AddConfigPath("./config")
		v.AddConfigPath("/etc/app")
	}

	// Read from environment variables
	v.AutomaticEnv()
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	// Set defaults
	setDefaults(v)

	// Read config file
	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("error reading config: %w", err)
		}
		// Config file not found, use defaults and env vars
	}

	// Unmarshal config
	cfg = &Config{}
	if err := v.Unmarshal(cfg); err != nil {
		return nil, fmt.Errorf("error unmarshaling config: %w", err)
	}

	// Validate config
	if err := validate(cfg); err != nil {
		return nil, fmt.Errorf("config validation error: %w", err)
	}

	return cfg, nil
}

func Get() *Config {
	if cfg == nil {
		panic("config not loaded - call Load() first")
	}
	return cfg
}

func MustLoad(configPath string) *Config {
	c, err := Load(configPath)
	if err != nil {
		panic(err)
	}
	return c
}

// ============================================================================
// Defaults
// ============================================================================

func setDefaults(v *viper.Viper) {
	// App
	v.SetDefault("app.name", "{{PROJECT_NAME}}")
	v.SetDefault("app.version", "1.0.0")
	v.SetDefault("app.environment", "development")
	v.SetDefault("app.debug", false)

	// Server
	v.SetDefault("server.host", "0.0.0.0")
	v.SetDefault("server.port", 8080)
	v.SetDefault("server.read_timeout", "15s")
	v.SetDefault("server.write_timeout", "15s")
	v.SetDefault("server.shutdown_timeout", "30s")

	// Database
	v.SetDefault("database.host", "localhost")
	v.SetDefault("database.port", 5432)
	v.SetDefault("database.name", "app_db")
	v.SetDefault("database.user", "postgres")
	v.SetDefault("database.password", "")
	v.SetDefault("database.ssl_mode", "disable")
	v.SetDefault("database.max_open_conns", 25)
	v.SetDefault("database.max_idle_conns", 5)
	v.SetDefault("database.conn_max_lifetime", "5m")

	// Redis
	v.SetDefault("redis.host", "localhost")
	v.SetDefault("redis.port", 6379)
	v.SetDefault("redis.password", "")
	v.SetDefault("redis.db", 0)
	v.SetDefault("redis.pool_size", 10)
	v.SetDefault("redis.read_timeout", "3s")
	v.SetDefault("redis.write_timeout", "3s")

	// Security
	v.SetDefault("security.secret_key", "change-me-in-production")
	v.SetDefault("security.algorithm", "HS256")
	v.SetDefault("security.access_token_expiry", "30m")
	v.SetDefault("security.refresh_token_expiry", "168h") // 7 days
	v.SetDefault("security.bcrypt_cost", 12)
	v.SetDefault("security.cors_origins", []string{"*"})
	v.SetDefault("security.cors_allow_credentials", true)
	v.SetDefault("security.rate_limit_per_minute", 60)

	// Storage
	v.SetDefault("storage.provider", "local")
	v.SetDefault("storage.local_path", "./uploads")
	v.SetDefault("storage.max_file_size", 10*1024*1024) // 10 MB
	v.SetDefault("storage.allowed_extensions", []string{"jpg", "jpeg", "png", "gif", "pdf"})

	// Email
	v.SetDefault("email.provider", "smtp")
	v.SetDefault("email.smtp_host", "smtp.gmail.com")
	v.SetDefault("email.smtp_port", 587)
	v.SetDefault("email.smtp_tls", true)
	v.SetDefault("email.from_email", "noreply@example.com")
	v.SetDefault("email.from_name", "{{PROJECT_NAME}}")

	// Features
	v.SetDefault("features.enable_registration", true)
	v.SetDefault("features.enable_social_login", false)
	v.SetDefault("features.enable_api_keys", true)
	v.SetDefault("features.maintenance_mode", false)

	// Logging
	v.SetDefault("logging.level", "info")
	v.SetDefault("logging.format", "json")
	v.SetDefault("logging.output", "stdout")
}

// ============================================================================
// Validation
// ============================================================================

func validate(c *Config) error {
	// Validate required fields
	if c.Security.SecretKey == "change-me-in-production" && c.App.IsProduction() {
		return fmt.Errorf("secret_key must be changed in production")
	}

	// Validate storage path exists for local storage
	if c.Storage.Provider == "local" {
		if err := os.MkdirAll(c.Storage.LocalPath, 0755); err != nil {
			return fmt.Errorf("failed to create storage directory: %w", err)
		}
	}

	return nil
}

// ============================================================================
// Environment-specific Loading
// ============================================================================

func LoadForEnvironment(env string) (*Config, error) {
	configPath := fmt.Sprintf("config.%s.yaml", env)

	if _, err := os.Stat(configPath); err == nil {
		return Load(configPath)
	}

	// Fall back to default config
	return Load("")
}

func GetEnvironment() string {
	env := os.Getenv("APP_ENVIRONMENT")
	if env == "" {
		env = os.Getenv("GO_ENV")
	}
	if env == "" {
		env = "development"
	}
	return env
}
