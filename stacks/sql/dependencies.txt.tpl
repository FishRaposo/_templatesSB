-- SQL Stack Dependencies Template
-- Complete SQL scripts and configurations for database projects

-- ====================
-- DATABASE INITIALIZATION
-- ====================

-- PostgreSQL
CREATE DATABASE {{PROJECT_NAME}};
CREATE USER {{DB_USER}} WITH PASSWORD '{{DB_PASSWORD}}';
GRANT ALL PRIVILEGES ON DATABASE {{PROJECT_NAME}} TO {{DB_USER}};

-- MySQL
CREATE DATABASE IF NOT EXISTS {{PROJECT_NAME}};
CREATE USER IF NOT EXISTS '{{DB_USER}}'@'%' IDENTIFIED BY '{{DB_PASSWORD}}';
GRANT ALL PRIVILEGES ON {{PROJECT_NAME}}.* TO '{{DB_USER}}'@'%';
FLUSH PRIVILEGES;

-- SQLite
-- File-based, no initialization needed

-- ====================
-- SCHEMA VERSIONING
-- ====================

-- Create migrations table
CREATE TABLE IF NOT EXISTS schema_migrations (
    version VARCHAR(255) PRIMARY KEY,
    applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ====================
-- CORE TABLES
-- ====================

-- Users Table
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    first_name VARCHAR(100),
    last_name VARCHAR(100),
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Sessions Table
CREATE TABLE sessions (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    token VARCHAR(255) UNIQUE NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- API Keys Table
CREATE TABLE api_keys (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    key_hash VARCHAR(255) UNIQUE NOT NULL,
    name VARCHAR(100),
    permissions JSONB,
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP
);

-- ====================
-- AUDIT LOGGING
-- ====================

-- Audit Log Table
CREATE TABLE audit_logs (
    id SERIAL PRIMARY KEY,
    table_name VARCHAR(100) NOT NULL,
    record_id INTEGER NOT NULL,
    action VARCHAR(20) NOT NULL, -- INSERT, UPDATE, DELETE
    old_values JSONB,
    new_values JSONB,
    user_id INTEGER REFERENCES users(id),
    ip_address INET,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create audit log trigger function
CREATE OR REPLACE FUNCTION audit_trigger_function()
RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        INSERT INTO audit_logs (table_name, record_id, action, new_values, user_id)
        VALUES (TG_TABLE_NAME, NEW.id, 'INSERT', row_to_json(NEW), current_user_id());
        RETURN NEW;
    ELSIF TG_OP = 'UPDATE' THEN
        INSERT INTO audit_logs (table_name, record_id, action, old_values, new_values, user_id)
        VALUES (TG_TABLE_NAME, NEW.id, 'UPDATE', row_to_json(OLD), row_to_json(NEW), current_user_id());
        RETURN NEW;
    ELSIF TG_OP = 'DELETE' THEN
        INSERT INTO audit_logs (table_name, record_id, action, old_values, user_id)
        VALUES (TG_TABLE_NAME, OLD.id, 'DELETE', row_to_json(OLD), current_user_id());
        RETURN OLD;
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

-- ====================
-- INDEXING STRATEGY
-- ====================

-- User indexes
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_created_at ON users(created_at);

-- Session indexes
CREATE INDEX idx_sessions_user_id ON sessions(user_id);
CREATE INDEX idx_sessions_token ON sessions(token);
CREATE INDEX idx_sessions_expires_at ON sessions(expires_at);

-- API Key indexes
CREATE INDEX idx_api_keys_user_id ON api_keys(user_id);
CREATE INDEX idx_api_keys_key_hash ON api_keys(key_hash);
CREATE INDEX idx_api_keys_is_active ON api_keys(is_active) WHERE is_active = true;

-- Audit log indexes
CREATE INDEX idx_audit_logs_table_name ON audit_logs(table_name);
CREATE INDEX idx_audit_logs_record_id ON audit_logs(record_id);
CREATE INDEX idx_audit_logs_user_id ON audit_logs(user_id);
CREATE INDEX idx_audit_logs_created_at ON audit_logs(created_at);

-- ====================
-- STORED PROCEDURES
-- ====================

-- User Registration
CREATE OR REPLACE PROCEDURE register_user(
    p_email VARCHAR(255),
    p_password_hash VARCHAR(255),
    p_first_name VARCHAR(100),
    p_last_name VARCHAR(100)
)
LANGUAGE plpgsql
AS $$
BEGIN
    INSERT INTO users (email, password_hash, first_name, last_name)
    VALUES (p_email, p_password_hash, p_first_name, p_last_name);
    COMMIT;
END;
$$;

-- User Authentication
CREATE OR REPLACE FUNCTION authenticate_user(
    p_email VARCHAR(255),
    p_password_hash VARCHAR(255)
)
RETURNS TABLE(user_id INTEGER, success BOOLEAN)
LANGUAGE plpgsql
AS $$
BEGIN
    RETURN QUERY
    SELECT 
        u.id,
        u.password_hash = p_password_hash AS success
    FROM users u
    WHERE u.email = p_email AND u.is_active = true;
END;
$$;

-- ====================
-- MATERIALIZED VIEWS
-- ====================

-- User Statistics
CREATE MATERIALIZED VIEW user_stats AS
SELECT 
    DATE_TRUNC('day', created_at) AS date,
    COUNT(*) AS new_users,
    COUNT(CASE WHEN is_active THEN 1 END) AS active_users
FROM users
GROUP BY DATE_TRUNC('day', created_at);

CREATE INDEX idx_user_stats_date ON user_stats(date);

-- Refresh strategy
CREATE OR REPLACE FUNCTION refresh_user_stats()
RETURNS void AS $$
BEGIN
    REFRESH MATERIALIZED VIEW CONCURRENTLY user_stats;
END;
$$ LANGUAGE plpgsql;

-- ====================
-- PARTITIONING (for large tables)
-- ====================

-- Partition audit_logs by month
CREATE TABLE audit_logs_partitioned (
    LIKE audit_logs INCLUDING ALL
) PARTITION BY RANGE (created_at);

-- Create partitions for each month
CREATE TABLE audit_logs_y2024m01 PARTITION OF audit_logs_partitioned
    FOR VALUES FROM ('2024-01-01') TO ('2024-02-01');
CREATE TABLE audit_logs_y2024m02 PARTITION OF audit_logs_partitioned
    FOR VALUES FROM ('2024-02-01') TO ('2024-03-01');
-- Continue for all months...

-- ====================
-- BACKUP STRATEGY
-- ====================

-- PostgreSQL pg_dump example:
-- pg_dump {{PROJECT_NAME}} > backup_$(date +%Y%m%d_%H%M%S).sql

-- MySQL mysqldump example:
-- mysqldump -u {{DB_USER}} -p {{PROJECT_NAME}} > backup_$(date +%Y%m%d_%H%M%S).sql

-- SQLite backup:
-- sqlite3 {{DB_NAME}}.db ".backup backup_$(date +%Y%m%d_%H%M%S).db"

-- ====================
-- PERFORMANCE MONITORING
-- ====================

-- Enable pg_stat_statements (PostgreSQL)
CREATE EXTENSION IF NOT EXISTS pg_stat_statements;

-- Query performance view
CREATE VIEW slow_queries AS
SELECT 
    query,
    calls,
    total_exec_time,
    mean_exec_time,
    stddev_exec_time,
    rows
FROM pg_stat_statements
WHERE mean_exec_time > 1000  -- Queries slower than 1 second
ORDER BY mean_exec_time DESC
LIMIT 100;

-- ====================
# DATABASE MIGRATIONS TOOLING
# ====================

# Flyway: Database migrations
# https://flywaydb.org/documentation/

# Liquibase: Database version control
# https://www.liquibase.org/

# DBMate: Lightweight migration tool
# https://github.com/amacneil/dbmate

# ====================
# TEST DATA GENERATION
# ====================

-- Generate test users
INSERT INTO users (email, password_hash, first_name, last_name)
SELECT 
    'user' || i || '@example.com',
    'hashed_password_' || i,
    'First' || i,
    'Last' || i
FROM generate_series(1, 1000) AS i;

-- ====================
# MONITORING AND ALERTING
# ====================

# pgAdmin: PostgreSQL management
# MySQL Workbench: MySQL management
# DBeaver: Universal database tool

# Prometheus metrics for databases:
# postgres_exporter
# mysql_exporter

-- ====================
# SECURITY BEST PRACTICES
# ====================

-- Use .pgpass for PostgreSQL credentials (Linux/Mac)
-- Use database secrets management (AWS Secrets Manager, HashiCorp Vault)
-- Enable SSL connections
-- Implement row-level security (RLS)
-- Regular security audits

CREATE ROLE readonly;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO readonly;

CREATE ROLE app_user;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO app_user;

-- ====================
# OPTIMIZATION TIPS
# ====================

# 1. Use connection pooling (PgBouncer for PostgreSQL)
# 2. Implement query result caching (Redis)
# 3. Monitor with EXPLAIN ANALYZE
# 4. Use appropriate indexes
# 5. Partition large tables
# 6. Archive old data

-- Example EXPLAIN ANALYZE
EXPLAIN ANALYZE SELECT * FROM users WHERE email = 'test@example.com';

-- ====================
# DEVELOPMENT WORKFLOW
# ====================

# 1. Create migration:
#    dbmate new create_users_table

# 2. Apply migrations:
#    dbmate migrate

# 3. Rollback migrations:
#    dbmate rollback

# 4. Seed database:
#    psql {{PROJECT_NAME}} < seed.sql

# 5. Backup database:
#    pg_dump {{PROJECT_NAME}} > backup.sql

# 6. Restore database:
#    psql {{PROJECT_NAME}} < backup.sql

-- ====================
# TROUBLESHOOTING
# ====================

# Connection issues:
# - Check PostgreSQL: pg_isready -h localhost -p 5432
# - Check MySQL: mysqladmin ping -u root -p

# Performance issues:
# - Check active connections: SELECT * FROM pg_stat_activity;
# - Check locks: SELECT * FROM pg_locks;
# - Check table sizes: \dt+ (psql)

-- ====================
# TEMPLATE VARIABLES
# ====================

-- Replace these variables:
-- {{PROJECT_NAME}} - Your project name
-- {{DB_USER}} - Database username
-- {{DB_PASSWORD}} - Database password
-- {{DB_NAME}} - Database name

-- ====================
# VERSION CONTROL
# ====================

-- Store SQL files in:
-- migrations/
--   001_create_users_table.sql
--   002_create_sessions_table.sql
--   003_create_audit_logs_table.sql
-- seeds/
--   001_seed_users.sql
--   002_seed_test_data.sql

-- Use version control system (Git) for SQL scripts
-- Tag releases with database schema versions

-- ====================
# DOCUMENTATION
# ====================

-- Generate database documentation:
-- 1. Use SchemaSpy for PostgreSQL
-- 2. Use MySQL Workbench for MySQL
-- 3. Create ERD diagrams
-- 4. Document stored procedures

-- ====================
# SAMPLE QUERIES
# ====================

-- Get user with sessions
SELECT u.*, json_agg(s.*) as sessions
FROM users u
LEFT JOIN sessions s ON u.id = s.user_id
WHERE u.id = 1
GROUP BY u.id;

-- Get user statistics
SELECT 
    DATE(created_at) as date,
    COUNT(*) as registrations,
    COUNT(CASE WHEN is_active THEN 1 END) as active
FROM users
GROUP BY DATE(created_at)
ORDER BY date DESC
LIMIT 30;

-- Find slow queries (PostgreSQL)
SELECT query, mean_exec_time, calls
FROM pg_stat_statements
ORDER BY mean_exec_time DESC
LIMIT 10;

-- ====================
# END OF TEMPLATE
# ====================
