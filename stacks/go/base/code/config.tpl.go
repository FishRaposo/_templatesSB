// File: config.tpl.go
// Purpose: Environment-based configuration for Go
// Generated for: {{PROJECT_NAME}}

package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/joho/godotenv"
)

type Config struct {
	App      AppConfig
	Database DatabaseConfig
	Redis    RedisConfig
	Auth     AuthConfig
}

type AppConfig struct {
	Name      string
	Version   string
	Env       string
	Debug     bool
	Port      int
	Host      string
	APIPrefix string
}

type DatabaseConfig struct {
	Host     string
	Port     int
	Name     string
	User     string
	Password string
}

func (d *DatabaseConfig) URL() string {
	return fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=disable",
		d.User, d.Password, d.Host, d.Port, d.Name)
}

type RedisConfig struct {
	Host     string
	Port     int
	DB       int
	Password string
}

func (r *RedisConfig) Addr() string {
	return fmt.Sprintf("%s:%d", r.Host, r.Port)
}

type AuthConfig struct {
	JWTSecret                string
	JWTAlgorithm             string
	AccessTokenExpireMinutes int
	RefreshTokenExpireDays   int
}

var (
	cfg  *Config
	once sync.Once
)

func Load() *Config {
	once.Do(func() {
		_ = godotenv.Load()

		cfg = &Config{
			App: AppConfig{
				Name:      getEnv("APP_NAME", "{{PROJECT_NAME}}"),
				Version:   getEnv("APP_VERSION", "1.0.0"),
				Env:       getEnv("APP_ENV", "development"),
				Debug:     getEnvBool("DEBUG", false),
				Port:      getEnvInt("PORT", 8080),
				Host:      getEnv("HOST", "0.0.0.0"),
				APIPrefix: getEnv("API_PREFIX", "/api/v1"),
			},
			Database: DatabaseConfig{
				Host:     getEnv("DB_HOST", "localhost"),
				Port:     getEnvInt("DB_PORT", 5432),
				Name:     getEnv("DB_NAME", "app"),
				User:     getEnv("DB_USER", "postgres"),
				Password: getEnv("DB_PASSWORD", ""),
			},
			Redis: RedisConfig{
				Host:     getEnv("REDIS_HOST", "localhost"),
				Port:     getEnvInt("REDIS_PORT", 6379),
				DB:       getEnvInt("REDIS_DB", 0),
				Password: getEnv("REDIS_PASSWORD", ""),
			},
			Auth: AuthConfig{
				JWTSecret:                getEnv("JWT_SECRET", "change-me-in-production"),
				JWTAlgorithm:             getEnv("JWT_ALGORITHM", "HS256"),
				AccessTokenExpireMinutes: getEnvInt("ACCESS_TOKEN_EXPIRE_MINUTES", 30),
				RefreshTokenExpireDays:   getEnvInt("REFRESH_TOKEN_EXPIRE_DAYS", 7),
			},
		}
	})

	return cfg
}

func (c *Config) IsProduction() bool {
	return c.App.Env == "production"
}

func (c *Config) IsDevelopment() bool {
	return c.App.Env == "development"
}

// Helper functions
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if i, err := strconv.Atoi(value); err == nil {
			return i
		}
	}
	return defaultValue
}

func getEnvBool(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		return strings.ToLower(value) == "true"
	}
	return defaultValue
}

// Usage:
// cfg := config.Load()
// fmt.Println(cfg.Database.URL())
// fmt.Println(cfg.Auth.JWTSecret)
