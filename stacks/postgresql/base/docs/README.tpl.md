# Universal Template System - PostgreSQL Stack
# Generated: {{DATE}}
# Purpose: PostgreSQL stack setup guide
# Tier: base
# Stack: postgresql
# Category: documentation

---

# PostgreSQL Stack Setup Guide

This guide helps you set up and configure a PostgreSQL database using the Universal Template System.

## 📋 Prerequisites

- PostgreSQL 14+ (or Docker)
- psql command-line tool
- Database migration tool (Alembic, Flyway, or Liquibase)
- Backup solution

## 🚀 Quick Start

### 1. Installation

#### Using Docker (Recommended)

```bash
# Start PostgreSQL with Docker Compose
docker-compose up -d

# Check status
docker-compose ps

# View logs
docker-compose logs -f postgres
```

#### Native Installation

```bash
# Ubuntu/Debian
sudo apt-get install postgresql postgresql-contrib

# macOS (Homebrew)
brew install postgresql@16

# Start service
sudo systemctl start postgresql  # Linux
brew services start postgresql@16  # macOS
```

### 2. Initial Configuration

```bash
# Connect to PostgreSQL
psql -U postgres

# Create database
CREATE DATABASE {{PROJECT_NAME}};

# Create user
CREATE USER {{DB_USER}} WITH ENCRYPTED PASSWORD 'your-secure-password';

# Grant privileges
GRANT ALL PRIVILEGES ON DATABASE {{PROJECT_NAME}} TO {{DB_USER}};

# Connect to database
\c {{PROJECT_NAME}}
```

### 3. Initialize Schema

```bash
# Run schema initialization
psql -U {{DB_USER}} -d {{PROJECT_NAME}} -f schema.sql

# Run functions
psql -U {{DB_USER}} -d {{PROJECT_NAME}} -f functions.sql

# Run triggers
psql -U {{DB_USER}} -d {{PROJECT_NAME}} -f triggers.sql
```

### 4. Configure Connection Pooling (Optional)

```bash
# Start PgBouncer
docker-compose up -d pgbouncer

# Or configure manually
vi /etc/pgbouncer/pgbouncer.ini
```

## 📁 Database Structure

```
{{PROJECT_NAME}}/
├── schema.sql              # Table definitions
├── functions.sql           # Stored procedures
├── triggers.sql            # Database triggers
├── views.sql              # Views and materialized views
├── indexes.sql            # Index strategies
├── migrations/            # Database migrations
│   ├── V001__initial_schema.sql
│   ├── V002__add_users.sql
│   └── V003__add_indexes.sql
├── seeds/                 # Seed data
│   └── initial_data.sql
└── tests/                 # Database tests
    └── test_queries.sql
```

## 🔧 Configuration

### PostgreSQL Configuration (postgresql.conf)

```conf
# Connection Settings
max_connections = 100
shared_buffers = 256MB
effective_cache_size = 1GB
maintenance_work_mem = 64MB
checkpoint_completion_target = 0.9
wal_buffers = 16MB
default_statistics_target = 100
random_page_cost = 1.1
effective_io_concurrency = 200
work_mem = 4MB
min_wal_size = 1GB
max_wal_size = 4GB

# Logging
log_destination = 'stderr'
logging_collector = on
log_directory = 'log'
log_filename = 'postgresql-%Y-%m-%d_%H%M%S.log'
log_line_prefix = '%t [%p]: [%l-1] user=%u,db=%d,app=%a,client=%h '
log_checkpoints = on
log_connections = on
log_disconnections = on
log_duration = off
log_lock_waits = on
log_statement = 'ddl'
log_min_duration_statement = 1000

# Performance
shared_preload_libraries = 'pg_stat_statements'
```

### Environment Variables

```bash
# Database Connection
export DB_HOST=localhost
export DB_PORT=5432
export DB_USER={{DB_USER}}
export DB_PASSWORD=your-secure-password
export DB_NAME={{PROJECT_NAME}}

# Connection Pool
export DB_POOL_SIZE=20
export DB_MAX_OVERFLOW=10

# Application
export DATABASE_URL="postgresql://${DB_USER}:${DB_PASSWORD}@${DB_HOST}:${DB_PORT}/${DB_NAME}"
```

## 📊 Performance Optimization

### Indexing Strategies

```sql
-- B-tree index (default)
CREATE INDEX idx_users_email ON users(email);

-- Partial index
CREATE INDEX idx_active_users ON users(email) WHERE is_active = true;

-- Composite index
CREATE INDEX idx_items_owner_created ON items(owner_id, created_at DESC);

-- GIN index for JSONB
CREATE INDEX idx_metadata_gin ON items USING GIN (metadata);

-- Full-text search index
CREATE INDEX idx_search_name ON items USING GIN (to_tsvector('english', name));

-- Covering index
CREATE INDEX idx_users_covering ON users(id) INCLUDE (email, username);
```

### Query Optimization

```sql
-- Use EXPLAIN ANALYZE
EXPLAIN ANALYZE
SELECT * FROM items
WHERE owner_id = 123
ORDER BY created_at DESC
LIMIT 10;

-- Check index usage
SELECT 
    schemaname,
    tablename,
    indexname,
    idx_scan,
    idx_tup_read,
    idx_tup_fetch
FROM pg_stat_user_indexes
ORDER BY idx_scan DESC;

-- Find missing indexes
SELECT 
    schemaname,
    tablename,
    attname,
    n_distinct,
    correlation
FROM pg_stats
WHERE schemaname = 'public'
ORDER BY abs(correlation) DESC;
```

### Vacuum and Analyze

```sql
-- Manual vacuum
VACUUM ANALYZE users;

-- Auto-vacuum configuration
ALTER TABLE items SET (autovacuum_vacuum_scale_factor = 0.1);
ALTER TABLE items SET (autovacuum_analyze_scale_factor = 0.05);
```

## 🔄 Database Migrations

### Using Alembic (Python)

```bash
# Initialize Alembic
alembic init alembic

# Create migration
alembic revision --autogenerate -m "Add users table"

# Apply migrations
alembic upgrade head

# Rollback
alembic downgrade -1
```

### Using Flyway (Java)

```bash
# Run migrations
flyway migrate

# Show status
flyway info

# Rollback
flyway undo
```

### Manual Migrations

```sql
-- V001__initial_schema.sql
CREATE TABLE schema_version (
    version VARCHAR(50) PRIMARY KEY,
    applied_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO schema_version (version) VALUES ('V001');
```

## 💾 Backup & Recovery

### Backup Strategies

```bash
# Full backup
pg_dump -U {{DB_USER}} -d {{PROJECT_NAME}} > backup.sql

# Compressed backup
pg_dump -U {{DB_USER}} -d {{PROJECT_NAME}} | gzip > backup.sql.gz

# Schema only
pg_dump -U {{DB_USER}} -d {{PROJECT_NAME}} --schema-only > schema.sql

# Data only
pg_dump -U {{DB_USER}} -d {{PROJECT_NAME}} --data-only > data.sql

# Specific tables
pg_dump -U {{DB_USER}} -d {{PROJECT_NAME}} -t users -t items > tables.sql
```

### Restore

```bash
# Restore from backup
psql -U {{DB_USER}} -d {{PROJECT_NAME}} < backup.sql

# Restore compressed
gunzip -c backup.sql.gz | psql -U {{DB_USER}} -d {{PROJECT_NAME}}
```

### Automated Backups

```bash
# Daily backup script
#!/bin/bash
BACKUP_DIR="/backups"
DATE=$(date +%Y%m%d_%H%M%S)
pg_dump -U {{DB_USER}} {{PROJECT_NAME}} | gzip > "${BACKUP_DIR}/{{PROJECT_NAME}}_${DATE}.sql.gz"

# Delete old backups (keep 30 days)
find ${BACKUP_DIR} -name "{{PROJECT_NAME}}_*.sql.gz" -mtime +30 -delete
```

## 🔐 Security

### User Management

```sql
-- Create read-only user
CREATE USER readonly WITH PASSWORD 'password';
GRANT CONNECT ON DATABASE {{PROJECT_NAME}} TO readonly;
GRANT USAGE ON SCHEMA public TO readonly;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO readonly;

-- Create application user
CREATE USER app_user WITH PASSWORD 'password';
GRANT CONNECT ON DATABASE {{PROJECT_NAME}} TO app_user;
GRANT USAGE, CREATE ON SCHEMA public TO app_user;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO app_user;
```

### Row-Level Security

```sql
-- Enable RLS
ALTER TABLE items ENABLE ROW LEVEL SECURITY;

-- Create policy
CREATE POLICY items_owner_policy ON items
    FOR ALL
    TO app_user
    USING (owner_id = current_setting('app.user_id')::bigint);
```

### SSL Configuration

```conf
# postgresql.conf
ssl = on
ssl_cert_file = '/path/to/server.crt'
ssl_key_file = '/path/to/server.key'
ssl_ca_file = '/path/to/ca.crt'
```

## 📈 Monitoring

### Essential Queries

```sql
-- Active queries
SELECT pid, usename, state, query, now() - query_start as duration
FROM pg_stat_activity
WHERE state != 'idle'
ORDER BY duration DESC;

-- Long-running queries
SELECT pid, usename, query, now() - query_start as duration
FROM pg_stat_activity
WHERE state = 'active' AND now() - query_start > interval '1 minute';

-- Database size
SELECT pg_database.datname, pg_size_pretty(pg_database_size(pg_database.datname))
FROM pg_database
ORDER BY pg_database_size(pg_database.datname) DESC;

-- Table sizes
SELECT schemaname, tablename, pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename))
FROM pg_tables
WHERE schemaname = 'public'
ORDER BY pg_total_relation_size(schemaname||'.'||tablename) DESC;
```

## 🚀 High Availability

### Replication Setup

```bash
# On primary server
# postgresql.conf
wal_level = replica
max_wal_senders = 3
wal_keep_size = 64

# Create replication user
CREATE USER replicator WITH REPLICATION PASSWORD 'password';

# On replica server
# Start as replica
pg_basebackup -h primary_host -D /var/lib/postgresql/data -U replicator -P

# Create recovery configuration
# standby.signal (empty file)
```

## 📚 Additional Resources

- [PostgreSQL Documentation](https://www.postgresql.org/docs/)
- [PostgreSQL Tutorial](https://www.postgresqltutorial.com/)
- [PgTune](https://pgtune.leopard.in.ua/) - Configuration generator
- [pgAdmin](https://www.pgadmin.org/) - GUI tool
- [PostgreSQL Extensions](https://pgxn.org/)

---

**Last Updated**: {{DATE}}  
**Stack Version**: 1.0  
**Minimum PostgreSQL**: 14+
