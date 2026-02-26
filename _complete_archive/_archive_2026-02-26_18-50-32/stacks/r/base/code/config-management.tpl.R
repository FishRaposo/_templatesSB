#'
#' File: config-management.tpl.R
#' Purpose: Template for unknown implementation
#' Generated for: {{PROJECT_NAME}}
#'

# -----------------------------------------------------------------------------
# FILE: config-management.tpl.R
# PURPOSE: Comprehensive configuration management system for R projects
# USAGE: Import and adapt for environment-specific settings, feature flags, and runtime configuration
# DEPENDENCIES: config, yaml, jsonlite, R6 for configuration handling
# AUTHOR: [[.Author]]
# VERSION: [[.Version]]
# SINCE: [[.Version]]
# -----------------------------------------------------------------------------

#' R Configuration Management Template
#' Purpose: Reusable configuration management for R projects
#' Usage: Import and adapt for environment-specific settings

# Load required packages
if (!requireNamespace("config", quietly = TRUE)) install.packages("config")
if (!requireNamespace("yaml", quietly = TRUE)) install.packages("yaml")
if (!requireNamespace("jsonlite", quietly = TRUE)) install.packages("jsonlite")
if (!requireNamespace("R6", quietly = TRUE)) install.packages("R6")

library(config)
library(yaml)
library(jsonlite)
library(R6)

#' Configuration Manager Class
#' @description Manages application configuration across different environments
#' @param env Environment name (development, staging, production, test)
#' @param config_path Path to configuration files
ConfigManager <- R6::R6Class(
  "ConfigManager",
  public = list(
    env = NULL,
    config_path = NULL,
    config = NULL,
    
    #' Initialize configuration manager
    #' @param env Environment name
    #' @param config_path Path to configuration files
    initialize = function(env = "development", config_path = "config") {
      self$env <- env
      self$config_path <- config_path
      self$load_config()
    },
    
    #' Load configuration from files
    load_config = function() {
      # Load YAML configuration
      yaml_file <- file.path(self$config_path, paste0("config-", self$env, ".yaml"))
      if (file.exists(yaml_file)) {
        self$config <- yaml::read_yaml(yaml_file)
      } else {
        # Fallback to default configuration
        self$config <- self$get_default_config()
        warning(paste("Configuration file not found:", yaml_file, "Using default configuration."))
      }
      
      # Override with environment variables
      self$override_with_env_vars()
      
      # Validate configuration
      self$validate_config()
      
      message(paste("Configuration loaded for environment:", self$env))
    },
    
    #' Get default configuration
    get_default_config = function() {
      list(
        environment = self$env,
        database = list(
          host = "localhost",
          port = 5432,
          name = "myapp",
          user = "postgres",
          password = "",
          ssl_mode = "prefer"
        ),
        server = list(
          host = "127.0.0.1",
          port = 8080,
          debug = TRUE,
          workers = 1,
          log_level = "INFO"
        ),
        api = list(
          base_url = "http://localhost:8080/api",
          timeout = 30,
          max_retries = 3,
          retry_delay = 1
        ),
        feature_flags = list(
          dark_mode = TRUE,
          beta_features = FALSE,
          debug_menu = FALSE
        ),
        logging = list(
          level = "INFO",
          file = "app.log",
          max_size = "10MB",
          max_files = 5
        )
      )
    },
    
    #' Override configuration with environment variables
    override_with_env_vars = function() {
      # Database settings from environment variables
      if (!is.null(Sys.getenv("DB_HOST"))) {
        self$config$database$host <- Sys.getenv("DB_HOST")
      }
      if (!is.null(Sys.getenv("DB_PORT"))) {
        self$config$database$port <- as.integer(Sys.getenv("DB_PORT"))
      }
      if (!is.null(Sys.getenv("DB_NAME"))) {
        self$config$database$name <- Sys.getenv("DB_NAME")
      }
      if (!is.null(Sys.getenv("DB_USER"))) {
        self$config$database$user <- Sys.getenv("DB_USER")
      }
      if (!is.null(Sys.getenv("DB_PASSWORD"))) {
        self$config$database$password <- Sys.getenv("DB_PASSWORD")
      }
      
      # Server settings from environment variables
      if (!is.null(Sys.getenv("HOST"))) {
        self$config$server$host <- Sys.getenv("HOST")
      }
      if (!is.null(Sys.getenv("PORT"))) {
        self$config$server$port <- as.integer(Sys.getenv("PORT"))
      }
      if (!is.null(Sys.getenv("DEBUG"))) {
        self$config$server$debug <- Sys.getenv("DEBUG") == "TRUE"
      }
      
      # API settings from environment variables
      if (!is.null(Sys.getenv("API_BASE_URL"))) {
        self$config$api$base_url <- Sys.getenv("API_BASE_URL")
      }
      if (!is.null(Sys.getenv("API_TIMEOUT"))) {
        self$config$api$timeout <- as.integer(Sys.getenv("API_TIMEOUT"))
      }
    },
    
    #' Validate configuration
    validate_config = function() {
      # Check required database settings
      required_db_fields <- c("host", "port", "name", "user")
      for (field in required_db_fields) {
        if (is.null(self$config$database[[field]]) || self$config$database[[field]] == "") {
          stop(paste("Missing required database configuration:", field))
        }
      }
      
      # Check required server settings
      required_server_fields <- c("host", "port")
      for (field in required_server_fields) {
        if (is.null(self$config$server[[field]]) || self$config$server[[field]] == "") {
          stop(paste("Missing required server configuration:", field))
        }
      }
      
      # Check required API settings
      required_api_fields <- c("base_url", "timeout")
      for (field in required_api_fields) {
        if (is.null(self$config$api[[field]]) || self$config$api[[field]] == "") {
          stop(paste("Missing required API configuration:", field))
        }
      }
    },
    
    #' Get configuration value
    #' @param key Configuration key (dot notation supported)
    #' @return Configuration value
    get = function(key) {
      keys <- strsplit(key, "\\.")[[1]]
      value <- self$config
      
      for (k in keys) {
        if (is.null(value[[k]])) {
          return(NULL)
        }
        value <- value[[k]]
      }
      
      return(value)
    },
    
    #' Set configuration value
    #' @param key Configuration key (dot notation supported)
    #' @param value Configuration value
    set = function(key, value) {
      keys <- strsplit(key, "\\.")[[1]]
      current <- self$config
      
      # Navigate to the parent object
      for (i in 1:(length(keys) - 1)) {
        if (is.null(current[[keys[i]]])) {
          current[[keys[i]]] <- list()
        }
        current <- current[[keys[i]]]
      }
      
      # Set the final value
      current[[keys[length(keys)]]] <- value
    },
    
    #' Check if feature is enabled
    #' @param feature_name Feature name
    #' @return TRUE if feature is enabled, FALSE otherwise
    is_feature_enabled = function(feature_name) {
      if (is.null(self$config$feature_flags[[feature_name]])) {
        return(FALSE)
      }
      return(self$config$feature_flags[[feature_name]])
    },
    
    #' Get database connection string
    get_db_connection_string = function() {
      db <- self$config$database
      return(paste0(
        "host=", db$host, " ",
        "port=", db$port, " ",
        "dbname=", db$name, " ",
        "user=", db$user, " ",
        "password=", db$password, " ",
        "sslmode=", db$ssl_mode
      ))
    },
    
    #' Get API base URL
    get_api_base_url = function() {
      return(self$config$api$base_url)
    },
    
    #' Save configuration to file
    #' @param filename Output filename
    save_config = function(filename) {
      if (grepl("\\.yaml$", filename)) {
        yaml::write_yaml(self$config, filename)
      } else if (grepl("\\.json$", filename)) {
        jsonlite::write_json(self$config, filename, pretty = TRUE)
      } else {
        yaml::write_yaml(self$config, filename)
      }
      message(paste("Configuration saved to:", filename))
    },
    
    #' Print configuration summary
    print_summary = function() {
      cat("\n=== Configuration Summary ===\n")
      cat(paste("Environment:", self$env, "\n"))
      cat("Database:\n")
      cat(paste("  Host:", self$config$database$host, "\n"))
      cat(paste("  Port:", self$config$database$port, "\n"))
      cat(paste("  Name:", self$config$database$name, "\n"))
      cat("Server:\n")
      cat(paste("  Host:", self$config$server$host, "\n"))
      cat(paste("  Port:", self$config$server$port, "\n"))
      cat(paste("  Debug:", self$config$server$debug, "\n"))
      cat("API:\n")
      cat(paste("  Base URL:", self$config$api$base_url, "\n"))
      cat(paste("  Timeout:", self$config$api$timeout, " seconds\n"))
      cat("Feature Flags:\n")
      for (flag in names(self$config$feature_flags)) {
        cat(paste("  ", flag, ":", self$config$feature_flags[[flag]], "\n"))
      }
    }
  )
)

#' Configuration Utility Functions
#' @description Helper functions for configuration management

#' Create sample configuration files
create_sample_configs <- function() {
  # Development configuration
  dev_config <- list(
    environment = "development",
    database = list(
      host = "localhost",
      port = 5432,
      name = "myapp_dev",
      user = "dev_user",
      password = "dev_password",
      ssl_mode = "disable"
    ),
    server = list(
      host = "127.0.0.1",
      port = 8000,
      debug = TRUE,
      workers = 1,
      log_level = "DEBUG"
    ),
    api = list(
      base_url = "http://localhost:8080/api",
      timeout = 60,
      max_retries = 5,
      retry_delay = 1
    ),
    feature_flags = list(
      dark_mode = TRUE,
      beta_features = TRUE,
      debug_menu = TRUE
    )
  )

  # Production configuration
  prod_config <- list(
    environment = "production",
    database = list(
      host = "prod-db.example.com",
      port = 5432,
      name = "myapp_prod",
      user = "prod_user",
      password = "prod_password",
      ssl_mode = "require"
    ),
    server = list(
      host = "0.0.0.0",
      port = 8080,
      debug = FALSE,
      workers = 4,
      log_level = "INFO"
    ),
    api = list(
      base_url = "https://api.example.com/api",
      timeout = 30,
      max_retries = 3,
      retry_delay = 2
    ),
    feature_flags = list(
      dark_mode = TRUE,
      beta_features = FALSE,
      debug_menu = FALSE
    )
  )

  # Save sample configs
  yaml::write_yaml(dev_config, "config/config-development.yaml")
  yaml::write_yaml(prod_config, "config/config-production.yaml")
  
  message("Sample configuration files created:")
  message("  - config/config-development.yaml")
  message("  - config/config-production.yaml")
}

#' Load configuration from environment variables
load_env_config <- function() {
  config <- list()
  
  # Load all environment variables starting with APP_
  env_vars <- Sys.getenv()
  app_vars <- env_vars[names(env_vars) %like% "^APP_"]
  
  for (var_name in names(app_vars)) {
    # Remove APP_ prefix and convert to lowercase
    config_name <- tolower(gsub("^APP_", "", var_name))
    # Convert to appropriate type
    value <- app_vars[[var_name]]
    
    # Try to convert to numeric if possible
    if (grepl("^[0-9]+$", value)) {
      value <- as.integer(value)
    } else if (grepl("^[0-9]+\\.[0-9]+$", value)) {
      value <- as.numeric(value)
    } else if (value %in% c("TRUE", "FALSE")) {
      value <- value == "TRUE"
    }
    
    config[[config_name]] <- value
  }
  
  return(config)
}

#' Validate configuration structure
validate_config_structure <- function(config, required_fields) {
  missing_fields <- character(0)
  
  for (field in required_fields) {
    if (is.null(config[[field]])) {
      missing_fields <- c(missing_fields, field)
    }
  }
  
  if (length(missing_fields) > 0) {
    stop(paste("Missing required configuration fields:", paste(missing_fields, collapse = ", ")))
  }
  
  return(TRUE)
}

#' Example usage and demonstration
#' @description Demonstrate how to use the configuration manager
main <- function() {
  cat("\n=== R Configuration Management Demo ===\n")
  
  # Create sample configuration files
  create_sample_configs()
  
  # Initialize configuration manager
  config_manager <- ConfigManager$new(env = "development")
  
  # Print configuration summary
  config_manager$print_summary()
  
  # Access configuration values
  cat("\n=== Configuration Access Examples ===\n")
  cat(paste("Database host:", config_manager$get("database.host"), "\n"))
  cat(paste("API base URL:", config_manager$get("api.base_url"), "\n"))
  cat(paste("Debug mode:", config_manager$get("server.debug"), "\n"))
  
  # Check feature flags
  cat("\n=== Feature Flag Examples ===\n")
  cat(paste("Dark mode enabled:", config_manager$is_feature_enabled("dark_mode"), "\n"))
  cat(paste("Beta features enabled:", config_manager$is_feature_enabled("beta_features"), "\n"))
  
  # Get database connection string
  cat("\n=== Database Connection ===\n")
  cat(paste("Connection string:", config_manager$get_db_connection_string(), "\n"))
  
  # Modify configuration
  cat("\n=== Configuration Modification ===\n")
  config_manager$set("api.timeout", 120)
  cat(paste("Updated API timeout:", config_manager$get("api.timeout"), "\n"))
  
  # Save modified configuration
  config_manager$save_config("config/config-modified.yaml")
  
  # Test with production environment
  cat("\n=== Production Environment ===\n")
  prod_config_manager <- ConfigManager$new(env = "production")
  prod_config_manager$print_summary()
  
  # Demonstrate environment variable override
  cat("\n=== Environment Variable Override ===\n")
  Sys.setenv(APP_DB_HOST = "env-override-db.example.com")
  env_config <- load_env_config()
  print(env_config)
  
  cat("\n=== Demo Complete ===\n")
}

# Run the demo if this script is executed directly
if (interactive() || !is.null(Sys.getenv("RSCRIPT"))) {
  main()
}

# Export public functions
#' @export
create_sample_configs

#' @export
load_env_config

#' @export
validate_config_structure

#' @export
ConfigManager