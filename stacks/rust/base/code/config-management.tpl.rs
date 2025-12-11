// Universal Template System - Rust Config Management Template
// File: config-management.tpl.rs
// Purpose: Template for unknown implementation
// Generated for: {{PROJECT_NAME}}

// -----------------------------------------------------------------------------
// FILE: config-management.tpl.rs
// PURPOSE: Comprehensive configuration management system for Rust projects
// USAGE: Import and adapt for environment-specific settings, feature flags, and runtime configuration
// DEPENDENCIES: config, serde, thiserror for configuration handling
// AUTHOR: [[.Author]]
// VERSION: [[.Version]]
// SINCE: [[.Version]]
// -----------------------------------------------------------------------------

//! Rust Configuration Management Template
//! Purpose: Reusable configuration management for Rust projects
//! Usage: Import and adapt for environment-specific settings

use config::{Config, File, Environment};
use serde::Deserialize;
use std::sync::OnceLock;
use thiserror::Error;

/// Configuration error type
#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("Configuration error: {0}")]
    Config(#[from] config::ConfigError),
    #[error("Environment variable error: {0}")]
    Env(#[from] std::env::VarError),
    #[error("Validation error: {0}")]
    Validation(String),
}

/// Database configuration
#[derive(Debug, Clone, Deserialize)]
pub struct DatabaseConfig {
    pub host: String,
    pub port: u16,
    pub name: String,
    pub user: String,
    pub password: String,
    pub ssl_mode: String,
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            host: "localhost".to_string(),
            port: 5432,
            name: "myapp".to_string(),
            user: "postgres".to_string(),
            password: "".to_string(),
            ssl_mode: "prefer".to_string(),
        }
    }
}

/// Server configuration
#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub debug: bool,
    pub workers: usize,
    pub log_level: String,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: "0.0.0.0".to_string(),
            port: 8000,
            debug: false,
            workers: 1,
            log_level: "info".to_string(),
        }
    }
}

/// API configuration
#[derive(Debug, Clone, Deserialize)]
pub struct ApiConfig {
    pub base_url: String,
    pub timeout: u64,
    pub max_retries: u32,
    pub retry_delay: u64,
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            base_url: "http://localhost:8080/api".to_string(),
            timeout: 30,
            max_retries: 3,
            retry_delay: 1,
        }
    }
}

/// Feature flags configuration
#[derive(Debug, Clone, Deserialize)]
pub struct FeatureFlags {
    pub dark_mode: bool,
    pub beta_features: bool,
    pub debug_menu: bool,
}

impl Default for FeatureFlags {
    fn default() -> Self {
        Self {
            dark_mode: false,
            beta_features: false,
            debug_menu: false,
        }
    }
}

/// Main application configuration
#[derive(Debug, Clone, Deserialize)]
pub struct AppConfig {
    pub environment: String,
    pub database: DatabaseConfig,
    pub server: ServerConfig,
    pub api: ApiConfig,
    pub feature_flags: FeatureFlags,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            environment: "development".to_string(),
            database: DatabaseConfig::default(),
            server: ServerConfig::default(),
            api: ApiConfig::default(),
            feature_flags: FeatureFlags::default(),
        }
    }
}

impl AppConfig {
    /// Validate configuration
    pub fn validate(&self) -> Result<(), ConfigError> {
        // Validate database configuration
        if self.database.host.is_empty() {
            return Err(ConfigError::Validation("Database host cannot be empty".to_string()));
        }
        
        if self.database.port == 0 {
            return Err(ConfigError::Validation("Database port cannot be 0".to_string()));
        }
        
        // Validate server configuration
        if self.server.host.is_empty() {
            return Err(ConfigError::Validation("Server host cannot be empty".to_string()));
        }
        
        if self.server.port == 0 {
            return Err(ConfigError::Validation("Server port cannot be 0".to_string()));
        }
        
        // Validate API configuration
        if self.api.base_url.is_empty() {
            return Err(ConfigError::Validation("API base URL cannot be empty".to_string()));
        }
        
        if self.api.timeout == 0 {
            return Err(ConfigError::Validation("API timeout cannot be 0".to_string()));
        }
        
        Ok(())
    }
    
    /// Get database connection string
    pub fn get_database_url(&self) -> String {
        format!(
            "postgres://{}:{}@{}:{}/{}?sslmode={}",
            self.database.user,
            self.database.password,
            self.database.host,
            self.database.port,
            self.database.name,
            self.database.ssl_mode
        )
    }
    
    /// Check if feature is enabled
    pub fn is_feature_enabled(&self, feature_name: &str) -> bool {
        match feature_name {
            "dark_mode" => self.feature_flags.dark_mode,
            "beta_features" => self.feature_flags.beta_features,
            "debug_menu" => self.feature_flags.debug_menu,
            _ => false,
        }
    }
    
    /// Get API base URL
    pub fn get_api_base_url(&self) -> &str {
        &self.api.base_url
    }
}

/// Configuration manager
#[derive(Debug, Clone)]
pub struct ConfigManager {
    config: AppConfig,
}

impl ConfigManager {
    /// Create a new configuration manager
    pub fn new() -> Result<Self, ConfigError> {
        let mut config = Config::default();
        
        // Load from default configuration file
        config.merge(File::with_name("config/default"))?;
        
        // Load environment-specific configuration
        let environment = std::env::var("ENVIRONMENT").unwrap_or_else(|_| "development".to_string());
        config.merge(File::with_name(&format!("config/{}", environment)).required(false))?;
        
        // Load from environment variables with prefix
        config.merge(Environment::with_prefix("APP").separator("__"))?;
        
        // Build configuration
        let app_config: AppConfig = config.try_into()?;
        
        // Validate configuration
        app_config.validate()?;
        
        Ok(Self { config: app_config })
    }
    
    /// Get the loaded configuration
    pub fn get_config(&self) -> &AppConfig {
        &self.config
    }
    
    /// Get database configuration
    pub fn get_database_config(&self) -> &DatabaseConfig {
        &self.config.database
    }
    
    /// Get server configuration
    pub fn get_server_config(&self) -> &ServerConfig {
        &self.config.server
    }
    
    /// Get API configuration
    pub fn get_api_config(&self) -> &ApiConfig {
        &self.config.api
    }
    
    /// Get feature flags
    pub fn get_feature_flags(&self) -> &FeatureFlags {
        &self.config.feature_flags
    }
}

/// Global configuration instance
pub fn get_global_config() -> &'static ConfigManager {
    static INSTANCE: OnceLock<ConfigManager> = OnceLock::new();
    
    INSTANCE.get_or_init(|| {
        ConfigManager::new().expect("Failed to load configuration")
    })
}

/// Configuration utility functions
pub mod config_utils {
    use super::*;
    
    /// Create sample configuration files
    pub fn create_sample_configs() -> Result<(), ConfigError> {
        // Create config directory
        std::fs::create_dir_all("config")?;
        
        // Development configuration
        let dev_config = AppConfig {
            environment: "development".to_string(),
            database: DatabaseConfig {
                host: "localhost".to_string(),
                port: 5432,
                name: "myapp_dev".to_string(),
                user: "dev_user".to_string(),
                password: "dev_password".to_string(),
                ssl_mode: "disable".to_string(),
            },
            server: ServerConfig {
                host: "127.0.0.1".to_string(),
                port: 8000,
                debug: true,
                workers: 1,
                log_level: "debug".to_string(),
            },
            api: ApiConfig {
                base_url: "http://localhost:8080/api".to_string(),
                timeout: 60,
                max_retries: 5,
                retry_delay: 1,
            },
            feature_flags: FeatureFlags {
                dark_mode: true,
                beta_features: true,
                debug_menu: true,
            },
        };
        
        // Production configuration
        let prod_config = AppConfig {
            environment: "production".to_string(),
            database: DatabaseConfig {
                host: "prod-db.example.com".to_string(),
                port: 5432,
                name: "myapp_prod".to_string(),
                user: "prod_user".to_string(),
                password: "prod_password".to_string(),
                ssl_mode: "require".to_string(),
            },
            server: ServerConfig {
                host: "0.0.0.0".to_string(),
                port: 8080,
                debug: false,
                workers: 4,
                log_level: "info".to_string(),
            },
            api: ApiConfig {
                base_url: "https://api.example.com/api".to_string(),
                timeout: 30,
                max_retries: 3,
                retry_delay: 2,
            },
            feature_flags: FeatureFlags {
                dark_mode: true,
                beta_features: false,
                debug_menu: false,
            },
        };
        
        // Save development configuration
        let dev_config_str = toml::to_string(&dev_config)?;
        std::fs::write("config/development.toml", dev_config_str)?;
        
        // Save production configuration
        let prod_config_str = toml::to_string(&prod_config)?;
        std::fs::write("config/production.toml", prod_config_str)?;
        
        Ok(())
    }
    
    /// Load configuration from environment variables
    pub fn load_env_config() -> Result<AppConfig, ConfigError> {
        let mut config = AppConfig::default();
        
        // Load from environment variables
        if let Ok(host) = std::env::var("DB_HOST") {
            config.database.host = host;
        }
        
        if let Ok(port) = std::env::var("DB_PORT") {
            config.database.port = port.parse()?;
        }
        
        if let Ok(name) = std::env::var("DB_NAME") {
            config.database.name = name;
        }
        
        if let Ok(user) = std::env::var("DB_USER") {
            config.database.user = user;
        }
        
        if let Ok(password) = std::env::var("DB_PASSWORD") {
            config.database.password = password;
        }
        
        if let Ok(env) = std::env::var("ENVIRONMENT") {
            config.environment = env;
        }
        
        Ok(config)
    }
}

/// Example usage and demonstration
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_config_loading() {
        // Create sample configuration files
        config_utils::create_sample_configs().unwrap();
        
        // Load configuration
        let config_manager = ConfigManager::new().unwrap();
        let config = config_manager.get_config();
        
        // Verify configuration
        assert_eq!(config.environment, "development");
        assert_eq!(config.database.host, "localhost");
        assert_eq!(config.server.port, 8000);
        assert!(config.feature_flags.dark_mode);
    }
    
    #[test]
    fn test_config_validation() {
        // Test with invalid configuration
        let invalid_config = AppConfig {
            database: DatabaseConfig {
                host: "".to_string(),
                ..Default::default()
            },
            ..Default::default()
        };
        
        let result = invalid_config.validate();
        assert!(result.is_err());
    }
    
    #[test]
    fn test_database_url() {
        let config = AppConfig::default();
        let db_url = config.get_database_url();
        
        assert!(db_url.contains("postgres://"));
        assert!(db_url.contains("localhost"));
        assert!(db_url.contains("myapp"));
    }
    
    #[test]
    fn test_feature_flags() {
        let config = AppConfig::default();
        
        assert!(!config.is_feature_enabled("dark_mode"));
        assert!(!config.is_feature_enabled("nonexistent_feature"));
    }
}

/// Main function demonstrating usage
#[cfg(feature = "example")]
fn main() -> Result<(), ConfigError> {
    println!("=== Rust Configuration Management Demo ===");
    
    // Create sample configuration files
    println!("\n1. Creating sample configuration files...");
    config_utils::create_sample_configs()?;
    println!("   ✓ Created config/development.toml");
    println!("   ✓ Created config/production.toml");
    
    // Load configuration
    println!("
2. Loading configuration...");
    let config_manager = ConfigManager::new()?;
    let config = config_manager.get_config();
    println!("   ✓ Loaded configuration for environment: {}", config.environment);
    
    // Display configuration
    println!("
3. Configuration Details:");
    println!("   Database: {}:{}@{}", 
             config.database.user, 
             config.database.password, 
             config.database.host);
    println!("   Server: {}:{}", config.server.host, config.server.port);
    println!("   API: {}", config.api.base_url);
    println!("   Features: Dark Mode={}, Beta Features={}", 
             config.feature_flags.dark_mode, 
             config.feature_flags.beta_features);
    
    // Test database URL
    println!("
4. Database Connection URL:");
    println!("   {}", config.get_database_url());
    
    // Test feature flags
    println!("
5. Feature Flag Checks:");
    println!("   Dark Mode: {}", config.is_feature_enabled("dark_mode"));
    println!("   Debug Menu: {}", config.is_feature_enabled("debug_menu"));
    println!("   Nonexistent: {}", config.is_feature_enabled("nonexistent"));
    
    // Test configuration validation
    println!("
6. Configuration Validation:");
    match config.validate() {
        Ok(_) => println!("   ✓ Configuration is valid"),
        Err(e) => println!("   ✗ Configuration error: {}", e),
    }
    
    println!("
=== Demo Complete ===");
    
    Ok(())
}
