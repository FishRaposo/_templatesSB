--
-- File: config-management.tpl.sql
-- Purpose: Template for unknown implementation
-- Generated for: {{PROJECT_NAME}}
--

-- -----------------------------------------------------------------------------
-- FILE: config-management.tpl.sql
-- PURPOSE: Comprehensive configuration management for SQL projects
-- USAGE: Use to manage database configuration, connection settings, and environment-specific parameters
-- DEPENDENCIES: Standard SQL syntax, database-specific extensions
-- AUTHOR: [[.Author]]
-- VERSION: [[.Version]]
-- SINCE: [[.Version]]
-- -----------------------------------------------------------------------------

--
-- SQL Configuration Management Template
-- Purpose: Manage database configuration and connection settings
-- Usage: Execute these scripts to set up and manage database configuration
--

-- ============================================
-- 1. DATABASE CONFIGURATION TABLE
-- ============================================

CREATE TABLE IF NOT EXISTS app_config (
    config_key VARCHAR(100) PRIMARY KEY,
    config_value TEXT NOT NULL,
    data_type VARCHAR(20) NOT NULL,
    description TEXT,
    environment VARCHAR(20) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    is_active BOOLEAN DEFAULT TRUE
);

-- Create index for faster lookups
CREATE INDEX idx_config_environment ON app_config(environment);
CREATE INDEX idx_config_key ON app_config(config_key);

-- ============================================
-- 2. ENVIRONMENT MANAGEMENT
-- ============================================

-- Define supported environments
CREATE TABLE IF NOT EXISTS environments (
    environment_name VARCHAR(20) PRIMARY KEY,
    description TEXT NOT NULL,
    is_production BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Insert default environments
INSERT INTO environments (environment_name, description, is_production) VALUES
('development', 'Development environment', FALSE),
('staging', 'Staging environment for testing', FALSE),
('production', 'Production environment', TRUE),
('test', 'Test environment for automated tests', FALSE)
ON DUPLICATE KEY UPDATE description = VALUES(description);

-- ============================================
-- 3. FEATURE FLAGS MANAGEMENT
-- ============================================

CREATE TABLE IF NOT EXISTS feature_flags (
    flag_name VARCHAR(100) PRIMARY KEY,
    description TEXT NOT NULL,
    is_enabled BOOLEAN DEFAULT FALSE,
    environment VARCHAR(20) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (environment) REFERENCES environments(environment_name)
);

-- Create index for feature flag lookups
CREATE INDEX idx_feature_flags_env ON feature_flags(environment);

-- ============================================
-- 4. CONFIGURATION STORED PROCEDURES
-- ============================================

DELIMITER //

-- Procedure to get configuration value
CREATE OR REPLACE PROCEDURE get_config_value(
    IN p_config_key VARCHAR(100),
    IN p_environment VARCHAR(20),
    OUT p_config_value TEXT,
    OUT p_data_type VARCHAR(20)
)
BEGIN
    SELECT config_value, data_type 
    INTO p_config_value, p_data_type
    FROM app_config
    WHERE config_key = p_config_key 
    AND environment = p_environment
    AND is_active = TRUE;
END //

-- Procedure to set configuration value
CREATE OR REPLACE PROCEDURE set_config_value(
    IN p_config_key VARCHAR(100),
    IN p_config_value TEXT,
    IN p_data_type VARCHAR(20),
    IN p_environment VARCHAR(20),
    IN p_description TEXT
)
BEGIN
    INSERT INTO app_config (config_key, config_value, data_type, description, environment)
    VALUES (p_config_key, p_config_value, p_data_type, p_description, p_environment)
    ON DUPLICATE KEY UPDATE 
        config_value = VALUES(config_value),
        data_type = VALUES(data_type),
        description = VALUES(description),
        updated_at = CURRENT_TIMESTAMP;
END //

-- Procedure to get feature flag status
CREATE OR REPLACE PROCEDURE get_feature_flag(
    IN p_flag_name VARCHAR(100),
    IN p_environment VARCHAR(20),
    OUT p_is_enabled BOOLEAN
)
BEGIN
    SELECT is_enabled INTO p_is_enabled
    FROM feature_flags
    WHERE flag_name = p_flag_name
    AND environment = p_environment;
END //

-- Procedure to set feature flag status
CREATE OR REPLACE PROCEDURE set_feature_flag(
    IN p_flag_name VARCHAR(100),
    IN p_environment VARCHAR(20),
    IN p_is_enabled BOOLEAN,
    IN p_description TEXT
)
BEGIN
    INSERT INTO feature_flags (flag_name, description, is_enabled, environment)
    VALUES (p_flag_name, p_description, p_is_enabled, p_environment)
    ON DUPLICATE KEY UPDATE 
        is_enabled = VALUES(is_enabled),
        description = VALUES(description),
        updated_at = CURRENT_TIMESTAMP;
END //

DELIMITER ;

-- ============================================
-- 5. CONFIGURATION FUNCTIONS
-- ============================================

-- Function to get configuration value as string
CREATE OR REPLACE FUNCTION get_config_string(
    p_config_key VARCHAR(100),
    p_environment VARCHAR(20)
) RETURNS TEXT
DETERMINISTIC
READS SQL DATA
BEGIN
    DECLARE result_value TEXT;
    
    SELECT config_value INTO result_value
    FROM app_config
    WHERE config_key = p_config_key
    AND environment = p_environment
    AND is_active = TRUE;
    
    RETURN result_value;
END //

-- Function to get configuration value as integer
CREATE OR REPLACE FUNCTION get_config_int(
    p_config_key VARCHAR(100),
    p_environment VARCHAR(20)
) RETURNS INT
DETERMINISTIC
READS SQL DATA
BEGIN
    DECLARE result_value TEXT;
    DECLARE int_value INT;
    
    SELECT config_value INTO result_value
    FROM app_config
    WHERE config_key = p_config_key
    AND environment = p_environment
    AND is_active = TRUE;
    
    IF result_value IS NOT NULL THEN
        SET int_value = CAST(result_value AS INT);
        RETURN int_value;
    END IF;
    
    RETURN NULL;
END //

-- Function to check if feature is enabled
CREATE OR REPLACE FUNCTION is_feature_enabled(
    p_flag_name VARCHAR(100),
    p_environment VARCHAR(20)
) RETURNS BOOLEAN
DETERMINISTIC
READS SQL DATA
BEGIN
    DECLARE is_enabled BOOLEAN;
    
    SELECT ff.is_enabled INTO is_enabled
    FROM feature_flags ff
    WHERE ff.flag_name = p_flag_name
    AND ff.environment = p_environment;
    
    RETURN COALESCE(is_enabled, FALSE);
END //

-- ============================================
-- 6. SAMPLE CONFIGURATION DATA
-- ============================================

-- Insert sample configuration for development environment
INSERT INTO app_config (config_key, config_value, data_type, description, environment) VALUES
('api.base_url', 'http://localhost:8080/api', 'string', 'Base URL for API endpoints', 'development'),
('api.timeout_seconds', '30', 'integer', 'API request timeout in seconds', 'development'),
('database.max_connections', '10', 'integer', 'Maximum database connections', 'development'),
('logging.level', 'DEBUG', 'string', 'Logging level for application', 'development'),
('cache.ttl_seconds', '3600', 'integer', 'Cache time-to-live in seconds', 'development')
ON DUPLICATE KEY UPDATE 
    config_value = VALUES(config_value),
    data_type = VALUES(data_type),
    description = VALUES(description),
    updated_at = CURRENT_TIMESTAMP;

-- Insert sample configuration for production environment
INSERT INTO app_config (config_key, config_value, data_type, description, environment) VALUES
('api.base_url', 'https://api.example.com/api', 'string', 'Base URL for API endpoints', 'production'),
('api.timeout_seconds', '15', 'integer', 'API request timeout in seconds', 'production'),
('database.max_connections', '50', 'integer', 'Maximum database connections', 'production'),
('logging.level', 'INFO', 'string', 'Logging level for application', 'production'),
('cache.ttl_seconds', '7200', 'integer', 'Cache time-to-live in seconds', 'production')
ON DUPLICATE KEY UPDATE 
    config_value = VALUES(config_value),
    data_type = VALUES(data_type),
    description = VALUES(description),
    updated_at = CURRENT_TIMESTAMP;

-- Insert sample feature flags
INSERT INTO feature_flags (flag_name, description, is_enabled, environment) VALUES
('dark_mode', 'Enable dark mode UI theme', TRUE, 'development'),
('beta_features', 'Enable beta features for testing', TRUE, 'development'),
('debug_menu', 'Enable debug menu for developers', TRUE, 'development'),
('dark_mode', 'Enable dark mode UI theme', TRUE, 'production'),
('beta_features', 'Enable beta features for testing', FALSE, 'production'),
('debug_menu', 'Enable debug menu for developers', FALSE, 'production')
ON DUPLICATE KEY UPDATE 
    is_enabled = VALUES(is_enabled),
    description = VALUES(description),
    updated_at = CURRENT_TIMESTAMP;

-- ============================================
-- 7. CONFIGURATION VIEWS
-- ============================================

-- View for current environment configuration
CREATE OR REPLACE VIEW current_config AS
SELECT 
    ac.config_key,
    ac.config_value,
    ac.data_type,
    ac.description,
    ac.environment,
    ac.created_at,
    ac.updated_at
FROM app_config ac
JOIN environments e ON ac.environment = e.environment_name
WHERE ac.is_active = TRUE
ORDER BY ac.config_key;

-- View for feature flags by environment
CREATE OR REPLACE VIEW feature_flags_by_environment AS
SELECT 
    ff.flag_name,
    ff.description,
    ff.is_enabled,
    ff.environment,
    ff.created_at,
    ff.updated_at,
    e.description as environment_description
FROM feature_flags ff
JOIN environments e ON ff.environment = e.environment_name
ORDER BY ff.environment, ff.flag_name;

-- ============================================
-- 8. CONFIGURATION MANAGEMENT SCRIPTS
-- ============================================

-- Script to initialize configuration for a new environment
-- Usage: CALL initialize_environment_config('new_environment', 'Based on development');
DELIMITER //
CREATE OR REPLACE PROCEDURE initialize_environment_config(
    IN p_new_environment VARCHAR(20),
    IN p_base_environment VARCHAR(20)
)
BEGIN
    DECLARE done INT DEFAULT FALSE;
    DECLARE config_key VARCHAR(100);
    DECLARE config_value TEXT;
    DECLARE data_type VARCHAR(20);
    DECLARE description TEXT;
    
    -- Check if new environment exists
    IF NOT EXISTS (SELECT 1 FROM environments WHERE environment_name = p_new_environment) THEN
        INSERT INTO environments (environment_name, description) 
        VALUES (p_new_environment, CONCAT('Environment: ', p_new_environment));
    END IF;
    
    -- Copy configuration from base environment
    DECLARE config_cursor CURSOR FOR
        SELECT config_key, config_value, data_type, description
        FROM app_config
        WHERE environment = p_base_environment;
    
    DECLARE CONTINUE HANDLER FOR NOT FOUND SET done = TRUE;
    
    OPEN config_cursor;
    
    read_loop: LOOP
        FETCH config_cursor INTO config_key, config_value, data_type, description;
        IF done THEN
            LEAVE read_loop;
        END IF;
        
        -- Insert configuration for new environment
        INSERT INTO app_config (config_key, config_value, data_type, description, environment)
        VALUES (config_key, config_value, data_type, description, p_new_environment)
        ON DUPLICATE KEY UPDATE
            config_value = VALUES(config_value),
            data_type = VALUES(data_type),
            description = VALUES(description),
            updated_at = CURRENT_TIMESTAMP;
    END LOOP;
    
    CLOSE config_cursor;
END //
DELIMITER ;

-- ============================================
-- 9. USAGE EXAMPLES
-- ============================================

-- Example 1: Get configuration value
-- CALL get_config_value('api.base_url', 'development', @base_url, @data_type);
-- SELECT @base_url, @data_type;

-- Example 2: Set configuration value
-- CALL set_config_value('api.timeout_seconds', '60', 'integer', 'development', 'Increased timeout for development');

-- Example 3: Check feature flag
-- SELECT is_feature_enabled('dark_mode', 'production') as dark_mode_enabled;

-- Example 4: Get all configuration for environment
-- SELECT * FROM current_config WHERE environment = 'development';

-- Example 5: Initialize new environment
-- CALL initialize_environment_config('testing', 'development');

-- ============================================
-- 10. MAINTENANCE AND CLEANUP
-- ============================================

-- Procedure to cleanup inactive configurations
CREATE OR REPLACE PROCEDURE cleanup_inactive_configs()
BEGIN
    DELETE FROM app_config WHERE is_active = FALSE AND updated_at < DATE_SUB(NOW(), INTERVAL 30 DAY);
END //

-- Procedure to archive old configurations
CREATE OR REPLACE PROCEDURE archive_old_configs()
BEGIN
    -- Create archive table if not exists
    CREATE TABLE IF NOT EXISTS app_config_archive LIKE app_config;
    
    -- Archive configurations older than 6 months
    INSERT INTO app_config_archive
    SELECT * FROM app_config
    WHERE updated_at < DATE_SUB(NOW(), INTERVAL 6 MONTH);
    
    -- Delete archived configurations
    DELETE FROM app_config WHERE updated_at < DATE_SUB(NOW(), INTERVAL 6 MONTH);
END //

-- ============================================
-- END OF CONFIGURATION MANAGEMENT TEMPLATE
-- ============================================

-- Summary of what this template provides:
-- 1. Configuration table with environment support
-- 2. Environment management system
-- 3. Feature flags management
-- 4. Stored procedures for configuration operations
-- 5. Functions for easy configuration access
-- 6. Sample configuration data
-- 7. Configuration views for easy access
-- 8. Environment initialization scripts
-- 9. Usage examples
-- 10. Maintenance procedures

-- This template supports:
-- - Multi-environment configurations
-- - Feature flag management
-- - Type-safe configuration values
-- - Easy configuration access via functions
-- - Configuration versioning and archiving
-- - Environment initialization and cloning