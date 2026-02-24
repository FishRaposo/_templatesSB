# SQL Workflow Testing Template
# Workflow testing patterns for SQL/database projects with migration pipelines, CI/CD, monitoring, and security

"""
SQL Workflow Test Patterns
Database workflow testing including migration pipelines, CI/CD integration, automated deployments, and security scanning
"""

-- Database: Workflow Testing Framework
-- Database: Migration Pipeline Testing
-- Database: CI/CD Integration Testing
-- Database: Automated Deployment Testing
-- Database: Security and Compliance Testing
-- Database: Monitoring and Alerting Integration

# ====================
# DATABASE WORKFLOW TEST PATTERNS
# ====================

## Migration Pipeline Workflow Testing

### Flyway Migration Pipeline

```sql
-- Migration Pipeline Testing Template
-- File: tests/workflow/test_migration_pipeline.sql

-- Test setup
CREATE SCHEMA IF NOT EXISTS workflow_test;
SET search_path TO workflow_test;

-- Create migration tracking tables
CREATE TABLE flyway_history (
    installed_rank INTEGER PRIMARY KEY,
    version VARCHAR(50),
    description VARCHAR(200),
    type VARCHAR(20),
    script VARCHAR(1000),
    checksum INTEGER,
    installed_by VARCHAR(100),
    installed_on TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    execution_time INTEGER,
    success BOOLEAN
);

CREATE TABLE migration_validation_log (
    id SERIAL PRIMARY KEY,
    version VARCHAR(50),
    validation_type VARCHAR(100),
    validation_result BOOLEAN,
    error_message TEXT,
    execution_time_ms INTEGER,
    executed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create test schema evolution
-- Migration V1.0.0 - Initial schema
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    username VARCHAR(100) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO flyway_history (installed_rank, version, description, type, script, checksum, installed_by, execution_time, success) VALUES
(1, '1.0.0', 'Initial schema', 'SQL', 'V1.0.0__Initial_schema.sql', 123456789, 'migration_user', 1500, true);

-- Migration V1.1.0 - Add user profile
ALTER TABLE users ADD COLUMN first_name VARCHAR(100);
ALTER TABLE users ADD COLUMN last_name VARCHAR(100);
ALTER TABLE users ADD COLUMN is_active BOOLEAN DEFAULT TRUE;

INSERT INTO flyway_history (installed_rank, version, description, type, script, checksum, installed_by, execution_time, success) VALUES
(2, '1.1.0', 'Add user profile', 'SQL', 'V1.1.0__Add_user_profile.sql', 987654321, 'migration_user', 800, true);

-- Migration V1.2.0 - Create products and orders
CREATE TABLE products (
    id SERIAL PRIMARY KEY,
    sku VARCHAR(50) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    price_cents INTEGER NOT NULL CHECK (price_cents >= 0),
    stock_quantity INTEGER NOT NULL DEFAULT 0 CHECK (stock_quantity >= 0),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE orders (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    order_number VARCHAR(20) UNIQUE NOT NULL,
    total_cents INTEGER NOT NULL,
    status VARCHAR(50) DEFAULT 'pending',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO flyway_history (installed_rank, version, description, type, script, checksum, installed_by, execution_time, success) VALUES
(3, '1.2.0', 'Create products and orders', 'SQL', 'V1.2.0__Create_products_and_orders.sql', 456789123, 'migration_user', 1200, true);

-- Workflow test for migration pipeline
BEGIN;
SELECT plan(20);

-- Test 1: Verify migration history integrity
SELECT results_eq(
    $$SELECT COUNT(*) FROM flyway_history WHERE success = true$$,
    $$VALUES (3)$$,
    'Should have 3 successful migrations'
);

SELECT results_eq(
    $$SELECT COUNT(DISTINCT version) FROM flyway_history WHERE success = true$$,
    $$VALUES (3)$$,
    'Should have 3 unique migration versions'
);

-- Test 2: Validate schema after migrations
SELECT has_table('workflow_test', 'users', 'Users table should exist after migration');
SELECT has_table('workflow_test', 'products', 'Products table should exist after migration');
SELECT has_table('workflow_test', 'orders', 'Orders table should exist after migration');

-- Test 3: Validate migration checksums
SELECT results_eq(
    $$SELECT checksum FROM flyway_history WHERE version = '1.0.0'$$,
    $$VALUES (123456789)$$,
    'V1.0.0 checksum should match'
);

SELECT results_eq(
    $$SELECT checksum FROM flyway_history WHERE version = '1.1.0'$$,
    $$VALUES (987654321)$$,
    'V1.1.0 checksum should match'
);

-- Test 4: Test migration rollback simulation
SELECT lives_ok(
    $$CREATE TABLE migration_rollback_log (
        id SERIAL PRIMARY KEY,
        version VARCHAR(50),
        rollback_sql TEXT,
        executed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        success BOOLEAN
    )$$,
    'Should create rollback log table'
);

SELECT lives_ok(
    $$INSERT INTO migration_rollback_log (version, rollback_sql, success) VALUES 
    ('1.2.0', 'DROP TABLE orders; DROP TABLE products;', true)$$,
    'Should log rollback operations'
);

-- Test 5: Validate data integrity after migrations
SELECT lives_ok(
    $$INSERT INTO users (email, username, password_hash, first_name, last_name) VALUES 
    ('test@example.com', 'testuser', 'password_hash', 'Test', 'User')$$,
    'Should insert user with new profile fields'
);

SELECT lives_ok(
    $$INSERT INTO products (sku, name, price_cents, stock_quantity) VALUES 
    ('SKU001', 'Test Product', 9999, 100)$$,
    'Should insert product data'
);

SELECT lives_ok(
    $$INSERT INTO orders (user_id, order_number, total_cents) VALUES 
    (1, 'ORD001', 9999)$$,
    'Should insert order data'
);

-- Test 6: Test migration validation procedures
SELECT lives_ok(
    $$INSERT INTO migration_validation_log (version, validation_type, validation_result, execution_time_ms) VALUES 
    ('1.2.0', 'schema_validation', true, 150),
    ('1.2.0', 'data_integrity_check', true, 75),
    ('1.2.0', 'constraint_validation', true, 200)$$,
    'Should log migration validation results'
);

SELECT results_eq(
    $$SELECT COUNT(*) FROM migration_validation_log WHERE validation_result = true$$,
    $$VALUES (3)$$,
    'All validations should pass'
);

-- Test 7: Test migration performance tracking
SELECT results_eq(
    $$SELECT SUM(execution_time) FROM flyway_history$$,
    $$VALUES (3500)$$,
    'Total migration time should be tracked'
);

SELECT results_eq(
    $$SELECT AVG(execution_time) FROM flyway_history$$,
    $$VALUES (1167)$$$,
    'Average migration time should be calculated'
);

-- Test 8: Test concurrent migration prevention
SELECT lives_ok(
    $$CREATE UNIQUE INDEX idx_flyway_active_migration ON flyway_history (CASE WHEN success = false THEN 1 END)$$,
    'Should prevent concurrent migrations'
);

-- Test 9: Test migration dependency validation
SELECT lives_ok(
    $$CREATE TABLE migration_dependencies (
        id SERIAL PRIMARY KEY,
        version VARCHAR(50) UNIQUE NOT NULL,
        depends_on VARCHAR(50)[] DEFAULT '{}',
        validated BOOLEAN DEFAULT false
    )$$,
    'Should create migration dependencies table'
);

SELECT lives_ok(
    $$INSERT INTO migration_dependencies (version, depends_on, validated) VALUES 
    ('1.2.0', ARRAY['1.0.0', '1.1.0'], true)$$,
    'Should validate migration dependencies'
);

-- Test 10: Test migration conflict detection
SELECT lives_ok(
    $$CREATE TABLE migration_conflicts (
        id SERIAL PRIMARY KEY,
        version1 VARCHAR(50),
        version2 VARCHAR(50),
        conflict_type VARCHAR(100),
        description TEXT,
        detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )$$,
    'Should create migration conflicts table'
);

-- Test 11: Test migration environment promotion
SELECT lives_ok(
    $$CREATE TABLE environment_promotion (
        id SERIAL PRIMARY KEY,
        version VARCHAR(50),
        from_environment VARCHAR(50),
        to_environment VARCHAR(50),
        promoted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        promoted_by VARCHAR(100),
        success BOOLEAN
    )$$,
    'Should create environment promotion table'
);

SELECT lives_ok(
    $$INSERT INTO environment_promotion (version, from_environment, to_environment, promoted_by, success) VALUES 
    ('1.2.0', 'development', 'staging', 'deploy_user', true)$$,
    'Should record environment promotion'
);

-- Test 12: Test migration rollback procedures
SELECT lives_ok(
    $$CREATE OR REPLACE FUNCTION rollback_migration(p_version VARCHAR(50))
    RETURNS BOOLEAN AS $$
    BEGIN
        -- Simulate rollback logic
        INSERT INTO migration_rollback_log (version, rollback_sql, success) 
        VALUES (p_version, 'ROLLBACK SQL for ' || p_version, true);
        RETURN true;
    END;
    $$ LANGUAGE plpgsql;$$,
    'Should create rollback function'
);

SELECT results_eq(
    $$SELECT rollback_migration('1.2.0')$$,
    $$VALUES (true)$$,
    'Rollback function should work'
);

-- Test 13: Test migration testing framework
SELECT lives_ok(
    $$CREATE TABLE migration_test_results (
        id SERIAL PRIMARY KEY,
        version VARCHAR(50),
        test_name VARCHAR(200),
        test_result BOOLEAN,
        error_details TEXT,
        execution_time_ms INTEGER,
        tested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )$$,
    'Should create migration test results table'
);

-- Test 14: Test migration approval workflow
SELECT lives_ok(
    $$CREATE TABLE migration_approvals (
        id SERIAL PRIMARY KEY,
        version VARCHAR(50),
        approver VARCHAR(100),
        approval_status VARCHAR(50) CHECK (approval_status IN ('pending', 'approved', 'rejected')),
        comments TEXT,
        approved_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )$$,
    'Should create migration approvals table'
);

SELECT lives_ok(
    $$INSERT INTO migration_approvals (version, approver, approval_status, approved_at) VALUES 
    ('1.2.0', 'dba_user', 'approved', CURRENT_TIMESTAMP)$$,
    'Should record migration approval'
);

SELECT results_eq(
    $$SELECT COUNT(*) FROM migration_approvals WHERE approval_status = 'approved'$$,
    $$VALUES (1)$$,
    'Migration should be approved'
);

-- Test 15: Test migration deployment pipeline
SELECT results_eq(
    $$SELECT 
        fh.version,
        fh.success,
        mv.validation_result,
        ma.approval_status
    FROM flyway_history fh
    LEFT JOIN migration_validation_log mv ON fh.version = mv.version
    LEFT JOIN migration_approvals ma ON fh.version = ma.version
    WHERE fh.version = '1.2.0'
    ORDER BY mv.executed_at DESC, ma.approved_at DESC
    LIMIT 1$$,
    $$VALUES ('1.2.0', true, true, 'approved')$$,
    'Complete migration pipeline should be successful'
);

SELECT * FROM finish();
ROLLBACK;
```

### Liquibase Migration Pipeline

```sql
-- Liquibase Migration Pipeline Testing Template
-- File: tests/workflow/test_liquibase_pipeline.sql

-- Test setup
CREATE SCHEMA IF NOT EXISTS liquibase_workflow;
SET search_path TO liquibase_workflow;

-- Create Liquibase tracking tables
CREATE TABLE databasechangelog (
    id VARCHAR(255) NOT NULL,
    author VARCHAR(255) NOT NULL,
    filename VARCHAR(255) NOT NULL,
    dateexecuted TIMESTAMP NOT NULL,
    orderexecuted INTEGER NOT NULL,
    exectype VARCHAR(10) NOT NULL,
    md5sum VARCHAR(35),
    description VARCHAR(255),
    comments VARCHAR(255),
    tag VARCHAR(255),
    liquibase VARCHAR(20),
    contexts VARCHAR(255),
    labels VARCHAR(255),
    deployment_id VARCHAR(10)
);

CREATE TABLE liquibase_validation_log (
    id SERIAL PRIMARY KEY,
    changeset_id VARCHAR(255),
    validation_type VARCHAR(100),
    validation_result BOOLEAN,
    error_message TEXT,
    execution_time_ms INTEGER,
    validated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Simulate Liquibase changeset execution
-- Changeset 001: Initial schema
CREATE TABLE lb_users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    username VARCHAR(100) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO databasechangelog (id, author, filename, dateexecuted, orderexecuted, exectype, description) VALUES
('001-create-users', 'developer', 'changelog-001.xml', CURRENT_TIMESTAMP, 1, 'EXECUTED', 'createTable');

-- Changeset 002: Add user profile
ALTER TABLE lb_users ADD COLUMN first_name VARCHAR(100);
ALTER TABLE lb_users ADD COLUMN last_name VARCHAR(100);
ALTER TABLE lb_users ADD COLUMN is_active BOOLEAN DEFAULT TRUE;

INSERT INTO databasechangelog (id, author, filename, dateexecuted, orderexecuted, exectype, description) VALUES
('002-add-user-profile', 'developer', 'changelog-002.xml', CURRENT_TIMESTAMP, 2, 'EXECUTED', 'addColumn');

-- Changeset 003: Create audit log
CREATE TABLE audit_log (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES lb_users(id),
    action VARCHAR(100) NOT NULL,
    details JSONB,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO databasechangelog (id, author, filename, dateexecuted, orderexecuted, exectype, description) VALUES
('003-create-audit-log', 'developer', 'changelog-003.xml', CURRENT_TIMESTAMP, 3, 'EXECUTED', 'createTable');

-- Workflow test for Liquibase pipeline
BEGIN;
SELECT plan(15);

-- Test 1: Verify Liquibase changelog tracking
SELECT has_table('liquibase_workflow', 'databasechangelog', 'Liquibase changelog table should exist');

SELECT results_eq(
    $$SELECT COUNT(*) FROM databasechangelog WHERE exectype = 'EXECUTED'$$,
    $$VALUES (3)$$,
    'Should have 3 executed changesets'
);

-- Test 2: Verify changeset integrity
SELECT results_eq(
    $$SELECT COUNT(DISTINCT id) FROM databasechangelog$$,
    $$VALUES (3)$$,
    'Should have 3 unique changeset IDs'
);

-- Test 3: Validate changeset ordering
SELECT results_eq(
    $$SELECT orderexecuted FROM databasechangelog ORDER BY orderexecuted$$,
    $$VALUES (1), (2), (3)$$,
    'Changesets should be in correct order'
);

-- Test 4: Test changeset validation
SELECT lives_ok(
    $$INSERT INTO liquibase_validation_log (changeset_id, validation_type, validation_result, execution_time_ms) VALUES 
    ('001-create-users', 'schema_validation', true, 100),
    ('002-add-user-profile', 'column_validation', true, 150),
    ('003-create-audit-log', 'foreign_key_validation', true, 200)$$,
    'Should validate changesets'
);

SELECT results_eq(
    $$SELECT COUNT(*) FROM liquibase_validation_log WHERE validation_result = true$$,
    $$VALUES (3)$$,
    'All changeset validations should pass'
);

-- Test 5: Test Liquibase contexts and labels
SELECT lives_ok(
    $$UPDATE databasechangelog SET contexts = 'development,testing', labels = 'user-management' WHERE id = '001-create-users'$$,
    'Should set contexts and labels'
);

SELECT results_eq(
    $$SELECT contexts, labels FROM databasechangelog WHERE id = '001-create-users'$$,
    $$VALUES ('development,testing', 'user-management')$$,
    'Contexts and labels should be set correctly'
);

-- Test 6: Test changeset rollback simulation
SELECT lives_ok(
    $$CREATE TABLE liquibase_rollback_log (
        id SERIAL PRIMARY KEY,
        changeset_id VARCHAR(255),
        rollback_sql TEXT,
        executed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        success BOOLEAN
    )$$,
    'Should create rollback log table'
);

-- Test 7: Test Liquibase tags
SELECT lives_ok(
    $$UPDATE databasechangelog SET tag = 'release-1.0.0' WHERE orderexecuted = 3$$,
    'Should tag changeset'
);

SELECT results_eq(
    $$SELECT tag FROM databasechangelog WHERE orderexecuted = 3$$,
    $$VALUES ('release-1.0.0')$$,
    'Tag should be set correctly'
);

-- Test 8: Test changeset preconditions
SELECT lives_ok(
    $$CREATE TABLE liquibase_preconditions (
        id SERIAL PRIMARY KEY,
        changeset_id VARCHAR(255),
        precondition_type VARCHAR(100),
        precondition_sql TEXT,
        expected_result BOOLEAN,
        actual_result BOOLEAN,
        validated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )$$,
    'Should create preconditions table'
);

SELECT lives_ok(
    $$INSERT INTO liquibase_preconditions (changeset_id, precondition_type, precondition_sql, expected_result, actual_result) VALUES 
    ('003-create-audit-log', 'table_exists', 'SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = ''lb_users'')', true, true)$$,
    'Should validate preconditions'
);

-- Test 9: Test Liquibase deployment tracking
SELECT lives_ok(
    $$CREATE TABLE liquibase_deployment_tracking (
        id SERIAL PRIMARY KEY,
        deployment_id VARCHAR(50),
        environment VARCHAR(50),
        start_time TIMESTAMP,
        end_time TIMESTAMP,
        status VARCHAR(50),
        deployed_by VARCHAR(100),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )$$,
    'Should create deployment tracking table'
);

-- Test 10: Test changeset conflict resolution
SELECT lives_ok(
    $$CREATE TABLE liquibase_conflicts (
        id SERIAL PRIMARY KEY,
        changeset_id1 VARCHAR(255),
        changeset_id2 VARCHAR(255),
        conflict_type VARCHAR(100),
        resolution_strategy VARCHAR(200),
        resolved_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )$$,
    'Should create conflicts table'
);

-- Test 11: Test Liquibase environment promotion
SELECT lives_eq(
    $$INSERT INTO liquibase_deployment_tracking (deployment_id, environment, start_time, end_time, status, deployed_by) VALUES 
    ('deploy_001', 'development', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP + INTERVAL '5 minutes', 'completed', 'deploy_user')$$,
    $$INSERT INTO liquibase_deployment_tracking (deployment_id, environment, start_time, end_time, status, deployed_by) VALUES 
    ('deploy_002', 'staging', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP + INTERVAL '3 minutes', 'completed', 'deploy_user')$$,
    'Should track environment promotions'
);

SELECT results_eq(
    $$SELECT COUNT(*) FROM liquibase_deployment_tracking WHERE status = 'completed'$$,
    $$VALUES (2)$$,
    'Deployments should be completed'
);

-- Test 12: Test complete Liquibase workflow
SELECT results_eq(
    $$SELECT 
        dc.id,
        dc.exectype,
        lv.validation_result,
        ld.status
    FROM databasechangelog dc
    LEFT JOIN liquibase_validation_log lv ON dc.id = lv.changeset_id
    LEFT JOIN liquibase_deployment_tracking ld ON dc.deployment_id = ld.deployment_id
    WHERE dc.id = '003-create-audit-log'
    ORDER BY lv.validated_at DESC, ld.created_at DESC
    LIMIT 1$$,
    $$VALUES ('003-create-audit-log', 'EXECUTED', true, 'completed')$$,
    'Complete Liquibase workflow should be successful'
);

SELECT * FROM finish();
ROLLBACK;
```

# ====================
# CI/CD INTEGRATION TESTING
# ====================

## Database CI/CD Pipeline Testing

```sql
-- CI/CD Integration Testing Template
-- File: tests/workflow/test_cicd_integration.sql

-- Test setup
CREATE SCHEMA IF NOT EXISTS cicd_test;
SET search_path TO cicd_test;

-- Create CI/CD tracking tables
CREATE TABLE ci_pipeline_runs (
    id SERIAL PRIMARY KEY,
    pipeline_name VARCHAR(100) NOT NULL,
    branch_name VARCHAR(100),
    commit_sha VARCHAR(40),
    run_number INTEGER,
    status VARCHAR(50) CHECK (status IN ('running', 'success', 'failed', 'cancelled')),
    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    finished_at TIMESTAMP,
    duration_seconds INTEGER,
    triggered_by VARCHAR(100)
);

CREATE TABLE ci_test_results (
    id SERIAL PRIMARY KEY,
    pipeline_run_id INTEGER REFERENCES ci_pipeline_runs(id),
    test_suite VARCHAR(100),
    test_name VARCHAR(200),
    test_result VARCHAR(20) CHECK (test_result IN ('passed', 'failed', 'skipped')),
    error_message TEXT,
    execution_time_ms INTEGER,
    executed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE cd_deployment_stages (
    id SERIAL PRIMARY KEY,
    pipeline_run_id INTEGER REFERENCES ci_pipeline_runs(id),
    stage_name VARCHAR(100) NOT NULL,
    environment VARCHAR(50),
    status VARCHAR(50) CHECK (status IN ('pending', 'running', 'success', 'failed', 'skipped')),
    started_at TIMESTAMP,
    finished_at TIMESTAMP,
    deployment_id VARCHAR(100),
    deployed_by VARCHAR(100)
);

CREATE TABLE database_deployment_log (
    id SERIAL PRIMARY KEY,
    deployment_stage_id INTEGER REFERENCES cd_deployment_stages(id),
    database_name VARCHAR(100),
    migration_version VARCHAR(50),
    deployment_type VARCHAR(50) CHECK (deployment_type IN ('schema', 'data', 'seed', 'rollback')),
    status VARCHAR(50) CHECK (status IN ('pending', 'running', 'success', 'failed')),
    start_time TIMESTAMP,
    end_time TIMESTAMP,
    error_message TEXT,
    executed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Workflow test for CI/CD integration
BEGIN;
SELECT plan(20);

-- Test 1: Simulate CI pipeline run
SELECT lives_ok(
    $$INSERT INTO ci_pipeline_runs (pipeline_name, branch_name, commit_sha, run_number, status, triggered_by) VALUES 
    ('database-ci', 'feature/user-profiles', 'abc123def456', 42, 'running', 'jenkins')$$,
    'Should start CI pipeline'
);

SELECT results_eq(
    $$SELECT status FROM ci_pipeline_runs WHERE pipeline_name = 'database-ci'$$,
    $$VALUES ('running')$$,
    'CI pipeline should be running'
);

-- Test 2: Simulate test execution
SELECT lives_ok(
    $$INSERT INTO ci_test_results (pipeline_run_id, test_suite, test_name, test_result, execution_time_ms) VALUES 
    (1, 'unit_tests', 'test_user_creation', 'passed', 45),
    (1, 'unit_tests', 'test_user_validation', 'passed', 23),
    (1, 'unit_tests', 'test_product_creation', 'passed', 67),
    (1, 'integration_tests', 'test_order_workflow', 'passed', 234),
    (1, 'integration_tests', 'test_payment_processing', 'passed', 189)$$,
    'Should record test results'
);

SELECT results_eq(
    $$SELECT COUNT(*) FROM ci_test_results WHERE test_result = 'passed'$$,
    $$VALUES (5)$$,
    'All tests should pass'
);

-- Test 3: Complete CI pipeline successfully
SELECT lives_ok(
    $$UPDATE ci_pipeline_runs SET status = 'success', finished_at = CURRENT_TIMESTAMP, duration_seconds = 300 WHERE id = 1$$,
    'Should complete CI pipeline'
);

SELECT results_eq(
    $$SELECT status FROM ci_pipeline_runs WHERE id = 1$$,
    $$VALUES ('success')$$,
    'CI pipeline should be successful'
);

-- Test 4: Simulate CD deployment stages
SELECT lives_ok(
    $$INSERT INTO cd_deployment_stages (pipeline_run_id, stage_name, environment, status, started_at, deployed_by) VALUES 
    (1, 'deploy_to_staging', 'staging', 'running', CURRENT_TIMESTAMP, 'deploy_bot')$$,
    'Should start staging deployment'
);

SELECT lives_ok(
    $$INSERT INTO database_deployment_log (deployment_stage_id, database_name, migration_version, deployment_type, status, start_time) VALUES 
    (1, 'staging_db', '1.2.0', 'schema', 'running', CURRENT_TIMESTAMP)$$,
    'Should start database deployment'
);

-- Test 5: Complete staging deployment
SELECT lives_ok(
    $$UPDATE database_deployment_log SET status = 'success', end_time = CURRENT_TIMESTAMP WHERE deployment_stage_id = 1$$,
    'Should complete database deployment'
);

SELECT lives_ok(
    $$UPDATE cd_deployment_stages SET status = 'success', finished_at = CURRENT_TIMESTAMP WHERE id = 1$$,
    'Should complete staging deployment'
);

-- Test 6: Test production deployment approval
SELECT lives_ok(
    $$INSERT INTO cd_deployment_stages (pipeline_run_id, stage_name, environment, status, deployed_by) VALUES 
    (1, 'deploy_to_production', 'production', 'pending', 'manager')$$,
    'Should create production deployment stage'
);

SELECT results_eq(
    $$SELECT status FROM cd_deployment_stages WHERE stage_name = 'deploy_to_production'$$,
    $$VALUES ('pending')$$,
    'Production deployment should be pending approval'
);

-- Test 7: Approve and execute production deployment
SELECT lives_ok(
    $$UPDATE cd_deployment_stages SET status = 'running', started_at = CURRENT_TIMESTAMP WHERE stage_name = 'deploy_to_production'$$,
    'Should start production deployment'
);

SELECT lives_ok(
    $$INSERT INTO database_deployment_log (deployment_stage_id, database_name, migration_version, deployment_type, status, start_time) VALUES 
    (2, 'production_db', '1.2.0', 'schema', 'running', CURRENT_TIMESTAMP)$$,
    'Should start production database deployment'
);

SELECT lives_ok(
    $$UPDATE database_deployment_log SET status = 'success', end_time = CURRENT_TIMESTAMP WHERE deployment_stage_id = 2$$,
    'Should complete production database deployment'
);

SELECT lives_ok(
    $$UPDATE cd_deployment_stages SET status = 'success', finished_at = CURRENT_TIMESTAMP WHERE stage_name = 'deploy_to_production'$$,
    'Should complete production deployment'
);

-- Test 8: Test deployment rollback simulation
SELECT lives_ok(
    $$INSERT INTO cd_deployment_stages (pipeline_run_id, stage_name, environment, status, deployed_by) VALUES 
    (1, 'rollback_staging', 'staging', 'running', 'deploy_bot')$$,
    'Should start staging rollback'
);

SELECT lives_ok(
    $$INSERT INTO database_deployment_log (deployment_stage_id, database_name, migration_version, deployment_type, status, start_time) VALUES 
    (3, 'staging_db', '1.1.0', 'rollback', 'running', CURRENT_TIMESTAMP)$$,
    'Should start database rollback'
);

SELECT lives_ok(
    $$UPDATE database_deployment_log SET status = 'success', end_time = CURRENT_TIMESTAMP WHERE deployment_stage_id = 3$$,
    'Should complete database rollback'
);

-- Test 9: Test deployment metrics
SELECT results_eq(
    $$SELECT COUNT(*) FROM cd_deployment_stages WHERE status = 'success'$$,
    $$VALUES (2)$$,
    'Should have successful deployments'
);

SELECT results_eq(
    $$SELECT COUNT(*) FROM database_deployment_log WHERE status = 'success'$$,
    $$VALUES (2)$$,
    'Should have successful database deployments'
);

-- Test 10: Test deployment performance
SELECT results_eq(
    $$SELECT AVG(EXTRACT(EPOCH FROM (end_time - start_time))) FROM database_deployment_log WHERE status = 'success'$$,
    $$VALUES (0)$$$,
    'Average deployment time should be calculated'
);

-- Test 11: Test deployment failure simulation
SELECT lives_ok(
    $$INSERT INTO ci_pipeline_runs (pipeline_name, branch_name, commit_sha, run_number, status, triggered_by) VALUES 
    ('database-ci', 'bugfix/critical-fix', 'def456ghi789', 43, 'failed', 'jenkins')$$,
    'Should record failed pipeline'
);

SELECT lives_ok(
    $$INSERT INTO ci_test_results (pipeline_run_id, test_suite, test_name, test_result, error_message) VALUES 
    (2, 'unit_tests', 'test_database_connection', 'failed', 'Connection timeout')$$,
    'Should record failed test'
);

SELECT results_eq(
    $$SELECT COUNT(*) FROM ci_pipeline_runs WHERE status = 'failed'$$,
    $$VALUES (1)$$,
    'Failed pipeline should be recorded'
);

-- Test 12: Test complete CI/CD workflow
SELECT results_eq(
    $$SELECT 
        cipr.pipeline_name,
        cipr.status,
        COUNT(DISTINCT cts.id) as test_count,
        COUNT(DISTINCT cds.id) as deployment_count
    FROM ci_pipeline_runs cipr
    LEFT JOIN ci_test_results cts ON cipr.id = cts.pipeline_run_id
    LEFT JOIN cd_deployment_stages cds ON cipr.id = cds.pipeline_run_id
    WHERE cipr.id = 1
    GROUP BY cipr.pipeline_name, cipr.status$$,
    $$VALUES ('database-ci', 'success', 5, 2)$$,
    'Complete CI/CD workflow should be successful'
);

-- Test 13: Test deployment approval workflow
SELECT lives_ok(
    $$CREATE TABLE deployment_approvals (
        id SERIAL PRIMARY KEY,
        deployment_stage_id INTEGER REFERENCES cd_deployment_stages(id),
        approver VARCHAR(100),
        approval_status VARCHAR(50) CHECK (approval_status IN ('pending', 'approved', 'rejected')),
        comments TEXT,
        approved_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )$$,
    'Should create deployment approvals table'
);

-- Test 14: Test deployment notification system
SELECT lives_ok(
    $$CREATE TABLE deployment_notifications (
        id SERIAL PRIMARY KEY,
        deployment_stage_id INTEGER REFERENCES cd_deployment_stages(id),
        notification_type VARCHAR(50) CHECK (notification_type IN ('email', 'slack', 'webhook')),
        recipient VARCHAR(255),
        message TEXT,
        status VARCHAR(50) CHECK (status IN ('sent', 'failed', 'pending')),
        sent_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )$$,
    'Should create deployment notifications table'
);

-- Test 15: Test complete deployment pipeline
SELECT results_eq(
    $$SELECT 
        cipr.status as pipeline_status,
        SUM(CASE WHEN cds.status = 'success' THEN 1 ELSE 0 END) as successful_deployments,
        SUM(CASE WHEN dbl.status = 'success' THEN 1 ELSE 0 END) as successful_db_deployments
    FROM ci_pipeline_runs cipr
    LEFT JOIN cd_deployment_stages cds ON cipr.id = cds.pipeline_run_id
    LEFT JOIN database_deployment_log dbl ON cds.id = dbl.deployment_stage_id
    WHERE cipr.id = 1
    GROUP BY cipr.status$$,
    $$VALUES ('success', 2, 2)$$,
    'Complete deployment pipeline should be successful'
);

SELECT * FROM finish();
ROLLBACK;
```

# ====================
# AUTOMATED DEPLOYMENT TESTING
# ====================

## Database Automated Deployment Testing

```sql
-- Automated Deployment Testing Template
-- File: tests/workflow/test_automated_deployment.sql

-- Test setup
CREATE SCHEMA IF NOT EXISTS deployment_test;
SET search_path TO deployment_test;

-- Create deployment tracking tables
CREATE TABLE deployment_configurations (
    id SERIAL PRIMARY KEY,
    application_name VARCHAR(100) NOT NULL,
    environment VARCHAR(50) NOT NULL,
    database_name VARCHAR(100) NOT NULL,
    deployment_strategy VARCHAR(50) CHECK (deployment_strategy IN ('blue_green', 'rolling', 'canary', 'recreate')),
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE deployment_executions (
    id SERIAL PRIMARY KEY,
    configuration_id INTEGER REFERENCES deployment_configurations(id),
    deployment_id VARCHAR(100) UNIQUE NOT NULL,
    version VARCHAR(50) NOT NULL,
    status VARCHAR(50) CHECK (status IN ('pending', 'preparing', 'running', 'success', 'failed', 'rolled_back')),
    started_at TIMESTAMP,
    finished_at TIMESTAMP,
    deployed_by VARCHAR(100),
    error_message TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE deployment_steps (
    id SERIAL PRIMARY KEY,
    execution_id INTEGER REFERENCES deployment_executions(id),
    step_name VARCHAR(100) NOT NULL,
    step_type VARCHAR(50) CHECK (step_type IN ('pre_check', 'backup', 'migration', 'validation', 'post_check', 'rollback')),
    status VARCHAR(50) CHECK (status IN ('pending', 'running', 'success', 'failed', 'skipped')),
    started_at TIMESTAMP,
    finished_at TIMESTAMP,
    execution_time_ms INTEGER,
    error_message TEXT,
    executed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE deployment_health_checks (
    id SERIAL PRIMARY KEY,
    execution_id INTEGER REFERENCES deployment_executions(id),
    check_name VARCHAR(100) NOT NULL,
    check_type VARCHAR(50) CHECK (check_type IN ('connection', 'query', 'migration', 'performance', 'security')),
    status VARCHAR(50) CHECK (status IN 'pending', 'running', 'success', 'failed', 'warning')),
    result_data JSONB,
    error_message TEXT,
    executed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Workflow test for automated deployment
BEGIN;
SELECT plan(20);

-- Test 1: Create deployment configuration
SELECT lives_ok(
    $$INSERT INTO deployment_configurations (application_name, environment, database_name, deployment_strategy) VALUES 
    ('ecommerce_app', 'staging', 'staging_ecommerce', 'blue_green')$$,
    'Should create deployment configuration'
);

SELECT results_eq(
    $$SELECT deployment_strategy FROM deployment_configurations WHERE application_name = 'ecommerce_app'$$,
    $$VALUES ('blue_green')$$,
    'Deployment strategy should be blue_green'
);

-- Test 2: Start automated deployment
SELECT lives_ok(
    $$INSERT INTO deployment_executions (configuration_id, deployment_id, version, status, started_at, deployed_by) VALUES 
    (1, 'deploy_20240101_120000', '2.0.0', 'preparing', CURRENT_TIMESTAMP, 'deployment_bot')$$,
    'Should start deployment execution'
);

SELECT results_eq(
    $$SELECT status FROM deployment_executions WHERE deployment_id = 'deploy_20240101_120000'$$,
    $$VALUES ('preparing')$$,
    'Deployment should be in preparing status'
);

-- Test 3: Execute pre-deployment checks
SELECT lives_ok(
    $$INSERT INTO deployment_steps (execution_id, step_name, step_type, status, started_at) VALUES 
    (1, 'pre_deployment_checks', 'pre_check', 'running', CURRENT_TIMESTAMP)$$,
    'Should start pre-deployment checks'
);

SELECT lives_ok(
    $$UPDATE deployment_steps SET status = 'success', finished_at = CURRENT_TIMESTAMP, execution_time_ms = 5000 WHERE step_name = 'pre_deployment_checks'$$,
    'Should complete pre-deployment checks'
);

-- Test 4: Execute database backup
SELECT lives_ok(
    $$INSERT INTO deployment_steps (execution_id, step_name, step_type, status, started_at) VALUES 
    (1, 'database_backup', 'backup', 'running', CURRENT_TIMESTAMP)$$,
    'Should start database backup'
);

SELECT lives_ok(
    $$UPDATE deployment_steps SET status = 'success', finished_at = CURRENT_TIMESTAMP, execution_time_ms = 30000 WHERE step_name = 'database_backup'$$,
    'Should complete database backup'
);

-- Test 5: Execute database migration
SELECT lives_ok(
    $$INSERT INTO deployment_steps (execution_id, step_name, step_type, status, started_at) VALUES 
    (1, 'database_migration', 'migration', 'running', CURRENT_TIMESTAMP)$$,
    'Should start database migration'
);

SELECT lives_ok(
    $$UPDATE deployment_steps SET status = 'success', finished_at = CURRENT_TIMESTAMP, execution_time_ms = 45000 WHERE step_name = 'database_migration'$$,
    'Should complete database migration'
);

-- Test 6: Execute post-migration validation
SELECT lives_ok(
    $$INSERT INTO deployment_steps (execution_id, step_name, step_type, status, started_at) VALUES 
    (1, 'post_migration_validation', 'validation', 'running', CURRENT_TIMESTAMP)$$,
    'Should start post-migration validation'
);

SELECT lives_ok(
    $$UPDATE deployment_steps SET status = 'success', finished_at = CURRENT_TIMESTAMP, execution_time_ms = 15000 WHERE step_name = 'post_migration_validation'$$,
    'Should complete post-migration validation'
);

-- Test 7: Execute health checks
SELECT lives_ok(
    $$INSERT INTO deployment_health_checks (execution_id, check_name, check_type, status) VALUES 
    (1, 'database_connection', 'connection', 'running'),
    (1, 'critical_queries', 'query', 'running'),
    (1, 'migration_verification', 'migration', 'running')$$,
    'Should start health checks'
);

SELECT lives_ok(
    $$UPDATE deployment_health_checks SET status = 'success', result_data = '{\"response_time_ms\": 50}' WHERE check_name = 'database_connection'$$,
    'Database connection check should pass'
);

SELECT lives_ok(
    $$UPDATE deployment_health_checks SET status = 'success', result_data = '{\"query_performance\": \"acceptable\"}' WHERE check_name = 'critical_queries'$$,
    'Critical queries check should pass'
);

SELECT lives_ok(
    $$UPDATE deployment_health_checks SET status = 'success', result_data = '{\"migration_count\": 5}' WHERE check_name = 'migration_verification'$$,
    'Migration verification should pass'
);

-- Test 8: Complete deployment
SELECT lives_ok(
    $$UPDATE deployment_executions SET status = 'success', finished_at = CURRENT_TIMESTAMP WHERE deployment_id = 'deploy_20240101_120000'$$,
    'Should complete deployment'
);

SELECT results_eq(
    $$SELECT status FROM deployment_executions WHERE deployment_id = 'deploy_20240101_120000'$$,
    $$VALUES ('success')$$,
    'Deployment should be successful'
);

-- Test 9: Test deployment with failures
SELECT lives_ok(
    $$INSERT INTO deployment_executions (configuration_id, deployment_id, version, status, started_at, deployed_by) VALUES 
    (1, 'deploy_20240101_130000', '2.1.0', 'preparing', CURRENT_TIMESTAMP, 'deployment_bot')$$,
    'Should start second deployment'
);

SELECT lives_ok(
    $$INSERT INTO deployment_steps (execution_id, step_name, step_type, status, started_at) VALUES 
    (2, 'pre_deployment_checks', 'pre_check', 'running', CURRENT_TIMESTAMP)$$,
    'Should start pre-deployment checks for second deployment'
);

SELECT lives_ok(
    $$UPDATE deployment_steps SET status = 'failed', finished_at = CURRENT_TIMESTAMP, error_message = 'Database connection timeout', execution_time_ms = 10000 WHERE execution_id = 2 AND step_name = 'pre_deployment_checks'$$,
    'Should fail pre-deployment checks'
);

SELECT lives_ok(
    $$UPDATE deployment_executions SET status = 'failed', finished_at = CURRENT_TIMESTAMP, error_message = 'Pre-deployment checks failed' WHERE deployment_id = 'deploy_20240101_130000'$$,
    'Should fail deployment'
);

SELECT results_eq(
    $$SELECT status FROM deployment_executions WHERE deployment_id = 'deploy_20240101_130000'$$,
    $$VALUES ('failed')$$,
    'Deployment should be failed'
);

-- Test 10: Test deployment metrics
SELECT results_eq(
    $$SELECT COUNT(*) FROM deployment_executions WHERE status = 'success'$$,
    $$VALUES (1)$$,
    'Should have successful deployments'
);

SELECT results_eq(
    $$SELECT COUNT(*) FROM deployment_steps WHERE status = 'success'$$,
    $$VALUES (4)$$,
    'Should have successful deployment steps'
);

SELECT results_eq(
    $$SELECT COUNT(*) FROM deployment_health_checks WHERE status = 'success'$$,
    $$VALUES (3)$$,
    'Should have successful health checks'
);

-- Test 11: Test deployment performance metrics
SELECT results_eq(
    $$SELECT AVG(execution_time_ms) FROM deployment_steps WHERE status = 'success'$$,
    $$VALUES (23750)$$$,
    'Average step execution time should be calculated'
);

-- Test 12: Test blue-green deployment simulation
SELECT lives_ok(
    $$INSERT INTO deployment_configurations (application_name, environment, database_name, deployment_strategy) VALUES 
    ('analytics_app', 'production', 'prod_analytics', 'blue_green')$$,
    'Should create blue-green deployment configuration'
);

-- Test 13: Test canary deployment simulation
SELECT lives_ok(
    $$INSERT INTO deployment_configurations (application_name, environment, database_name, deployment_strategy) VALUES 
    ('api_gateway', 'production', 'prod_gateway', 'canary')$$,
    'Should create canary deployment configuration'
);

SELECT results_eq(
    $$SELECT COUNT(*) FROM deployment_configurations WHERE deployment_strategy IN ('blue_green', 'canary')$$,
    $$VALUES (2)$$,
    'Advanced deployment strategies should be configured'
);

-- Test 14: Test deployment automation level
SELECT results_eq(
    $$SELECT 
        COUNT(CASE WHEN status = 'success' THEN 1 END) as successful,
        COUNT(CASE WHEN status = 'failed' THEN 1 END) as failed
    FROM deployment_executions$$,
    $$VALUES (1, 1)$$,
    'Deployment success/failure rate should be tracked'
);

-- Test 15: Test complete deployment workflow
SELECT results_eq(
    $$SELECT 
        de.status,
        COUNT(DISTINCT ds.id) as total_steps,
        COUNT(DISTINCT dhc.id) as total_health_checks,
        AVG(ds.execution_time_ms) as avg_step_time
    FROM deployment_executions de
    LEFT JOIN deployment_steps ds ON de.id = ds.execution_id
    LEFT JOIN deployment_health_checks dhc ON de.id = dhc.execution_id
    WHERE de.deployment_id = 'deploy_20240101_120000'
    GROUP BY de.status$$,
    $$VALUES ('success', 4, 3, 23750)$$,
    'Complete deployment workflow should be successful'
);

SELECT * FROM finish();
ROLLBACK;
```

# ====================
# SECURITY AND COMPLIANCE TESTING
# ====================

## Database Security and Compliance Testing

```sql
-- Security and Compliance Testing Template
-- File: tests/workflow/test_security_compliance.sql

-- Test setup
CREATE SCHEMA IF NOT EXISTS security_compliance_test;
SET search_path TO security_compliance_test;

-- Create security and compliance tracking tables
CREATE TABLE security_scans (
    id SERIAL PRIMARY KEY,
    scan_type VARCHAR(100) NOT NULL,
    target_type VARCHAR(50) CHECK (target_type IN ('database', 'schema', 'table', 'column', 'user', 'role')),
    target_name VARCHAR(100),
    scan_status VARCHAR(50) CHECK (scan_status IN ('pending', 'running', 'completed', 'failed')),
    scan_results JSONB,
    vulnerabilities_found INTEGER DEFAULT 0,
    critical_issues INTEGER DEFAULT 0,
    scan_started_at TIMESTAMP,
    scan_completed_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE compliance_checks (
    id SERIAL PRIMARY KEY,
    compliance_framework VARCHAR(100) NOT NULL,
    control_id VARCHAR(50),
    control_description TEXT,
    check_type VARCHAR(50) CHECK (check_type IN ('automated', 'manual')),
    check_status VARCHAR(50) CHECK (check_status IN ('pending', 'running', 'passed', 'failed', 'exception')),
    check_results JSONB,
    remediation_required BOOLEAN DEFAULT FALSE,
    exception_approved BOOLEAN DEFAULT FALSE,
    checked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE access_control_audit (
    id SERIAL PRIMARY KEY,
    audit_type VARCHAR(50) CHECK (audit_type IN ('user_access', 'role_assignment', 'permission_change', 'privilege_escalation')),
    user_name VARCHAR(100),
    role_name VARCHAR(100),
    permission_type VARCHAR(100),
    resource_type VARCHAR(50),
    resource_name VARCHAR(100),
    action VARCHAR(50) CHECK (action IN ('granted', 'revoked', 'modified', 'detected')),
    detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    severity VARCHAR(20) CHECK (severity IN ('low', 'medium', 'high', 'critical'))
);

CREATE TABLE data_classification (
    id SERIAL PRIMARY KEY,
    table_name VARCHAR(100) NOT NULL,
    column_name VARCHAR(100) NOT NULL,
    data_type VARCHAR(50) CHECK (data_type IN ('public', 'internal', 'confidential', 'restricted')),
    classification_reason TEXT,
    encryption_required BOOLEAN DEFAULT FALSE,
    masking_required BOOLEAN DEFAULT FALSE,
    audited_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Workflow test for security and compliance
BEGIN;
SELECT plan(20);

-- Test 1: Simulate security scan execution
SELECT lives_ok(
    $$INSERT INTO security_scans (scan_type, target_type, target_name, scan_status, scan_started_at) VALUES 
    ('vulnerability_scan', 'database', 'production_db', 'running', CURRENT_TIMESTAMP)$$,
    'Should start security scan'
);

SELECT lives_ok(
    $$UPDATE security_scans SET scan_status = 'completed', scan_completed_at = CURRENT_TIMESTAMP, vulnerabilities_found = 2, critical_issues = 0, scan_results = '{\"scan_duration_seconds\": 300, \"issues_found\": 2}' WHERE scan_type = 'vulnerability_scan'$$,
    'Should complete security scan'
);

SELECT results_eq(
    $$SELECT scan_status FROM security_scans WHERE scan_type = 'vulnerability_scan'$$,
    $$VALUES ('completed')$$,
    'Security scan should be completed'
);

-- Test 2: Simulate compliance check execution
SELECT lives_ok(
    $$INSERT INTO compliance_checks (compliance_framework, control_id, control_description, check_type, check_status) VALUES 
    ('SOX', 'SOX-1.1', 'Database access controls', 'automated', 'running')$$,
    'Should start compliance check'
);

SELECT lives_ok(
    $$UPDATE compliance_checks SET check_status = 'passed', check_results = '{\"control_met\": true, \"evidence\": \"Access controls configured\"}' WHERE control_id = 'SOX-1.1'$$,
    'Should pass compliance check'
);

SELECT results_eq(
    $$SELECT check_status FROM compliance_checks WHERE control_id = 'SOX-1.1'$$,
    $$VALUES ('passed')$$,
    'Compliance check should pass'
);

-- Test 3: Test data classification workflow
SELECT lives_ok(
    $$INSERT INTO data_classification (table_name, column_name, data_type, classification_reason, encryption_required) VALUES 
    ('users', 'email', 'confidential', 'Contains personal email addresses', true),
    ('users', 'password_hash', 'restricted', 'Contains authentication credentials', true),
    ('orders', 'total_amount', 'internal', 'Contains financial data', false)$$,
    'Should classify data'
);

SELECT results_eq(
    $$SELECT COUNT(*) FROM data_classification WHERE encryption_required = true$$,
    $$VALUES (2)$$,
    'Sensitive data should require encryption'
);

-- Test 4: Test access control audit
SELECT lives_ok(
    $$INSERT INTO access_control_audit (audit_type, user_name, role_name, permission_type, resource_type, resource_name, action, severity) VALUES 
    ('user_access', 'admin_user', 'super_admin', 'ALL', 'database', 'production_db', 'granted', 'high'),
    ('privilege_escalation', 'regular_user', NULL, 'SELECT', 'table', 'sensitive_data', 'detected', 'critical')$$,
    'Should audit access control events'
);

SELECT results_eq(
    $$SELECT COUNT(*) FROM access_control_audit WHERE severity = 'critical'$$,
    $$VALUES (1)$$,
    'Critical access events should be detected'
);

-- Test 5: Test GDPR compliance check
SELECT lives_ok(
    $$INSERT INTO compliance_checks (compliance_framework, control_id, control_description, check_type, check_status) VALUES 
    ('GDPR', 'GDPR-17.1', 'Right to erasure implementation', 'automated', 'running')$$,
    'Should start GDPR compliance check'
);

SELECT lives_ok(
    $$UPDATE compliance_checks SET check_status = 'passed', check_results = '{\"right_to_erasure\": \"implemented\", \"data_retention\": \"configured\"}' WHERE control_id = 'GDPR-17.1'$$,
    'Should pass GDPR compliance check'
);

-- Test 6: Test HIPAA compliance check
SELECT lives_ok(
    $$INSERT INTO compliance_checks (compliance_framework, control_id, control_description, check_type, check_status) VALUES 
    ('HIPAA', 'HIPAA-164.312', 'Encryption of data at rest', 'automated', 'running')$$,
    'Should start HIPAA compliance check'
);

SELECT lives_ok(
    $$UPDATE compliance_checks SET check_status = 'passed', check_results = '{\"encryption_at_rest\": \"enabled\", \"key_management\": \"configured\"}' WHERE control_id = 'HIPAA-164.312'$$,
    'Should pass HIPAA compliance check'
);

-- Test 7: Test PCI DSS compliance check
SELECT lives_ok(
    $$INSERT INTO compliance_checks (compliance_framework, control_id, control_description, check_type, check_status) VALUES 
    ('PCI_DSS', 'PCI-3.4', 'Primary account number protection', 'automated', 'running')$$,
    'Should start PCI DSS compliance check'
);

SELECT lives_ok(
    $$UPDATE compliance_checks SET check_status = 'passed', check_results = '{\"pan_protection\": \"encrypted\", \"key_rotation\": \"enabled\"}' WHERE control_id = 'PCI-3.4'$$,
    'Should pass PCI DSS compliance check'
);

-- Test 8: Test compliance reporting
SELECT results_eq(
    $$SELECT COUNT(*) FROM compliance_checks WHERE check_status = 'passed'$$,
    $$VALUES (4)$$,
    'All compliance checks should pass'
);

SELECT results_eq(
    $$SELECT COUNT(DISTINCT compliance_framework) FROM compliance_checks$$,
    $$VALUES (4)$$,
    'Should cover multiple compliance frameworks'
);

-- Test 9: Test security incident response
SELECT lives_ok(
    $$UPDATE security_scans SET scan_results = '{\"incident_detected\": true, \"severity\": \"high\", \"action_taken\": \"access_revoked\"}' WHERE scan_type = 'vulnerability_scan'$$,
    'Should simulate security incident response'
);

SELECT results_eq(
    $$SELECT COUNT(*) FROM security_scans WHERE scan_results->>'incident_detected' = 'true'$$,
    $$VALUES (1)$$,
    'Security incident should be detected'
);

-- Test 10: Test data masking requirements
SELECT lives_ok(
    $$UPDATE data_classification SET masking_required = true WHERE data_type = 'confidential' AND column_name = 'email'$$,
    'Should require masking for confidential data'
);

SELECT results_eq(
    $$SELECT COUNT(*) FROM data_classification WHERE masking_required = true$$,
    $$VALUES (1)$$,
    'Data masking requirements should be identified'
);

-- Test 11: Test audit trail completeness
SELECT results_eq(
    $$SELECT COUNT(*) FROM access_control_audit WHERE audit_type = 'privilege_escalation'$$,
    $$VALUES (1)$$,
    'Privilege escalation should be audited'
);

SELECT results_eq(
    $$SELECT COUNT(*) FROM access_control_audit WHERE severity IN ('high', 'critical')$$,
    $$VALUES (2)$$,
    'High and critical events should be audited'
);

-- Test 12: Test remediation tracking
SELECT lives_ok(
    $$UPDATE compliance_checks SET remediation_required = true, check_results = '{\"issue\": \"missing_encryption\", \"remediation\": \"enable_encryption\"}' WHERE control_id = 'HIPAA-164.312'$$,
    'Should track remediation requirements'
);

SELECT results_eq(
    $$SELECT COUNT(*) FROM compliance_checks WHERE remediation_required = true$$,
    $$VALUES (1)$$,
    'Remediation requirements should be tracked'
);

-- Test 13: Test exception handling
SELECT lives_ok(
    $$UPDATE compliance_checks SET exception_approved = true, check_status = 'exception' WHERE control_id = 'PCI-3.4'$$,
    'Should handle compliance exceptions'
);

SELECT results_eq(
    $$SELECT COUNT(*) FROM compliance_checks WHERE exception_approved = true$$,
    $$VALUES (1)$$,
    'Approved exceptions should be tracked'
);

-- Test 14: Test complete security workflow
SELECT results_eq(
    $$SELECT 
        COUNT(DISTINCT cs.compliance_framework) as frameworks,
        SUM(CASE WHEN cs.check_status = 'passed' THEN 1 ELSE 0 END) as passed_checks,
        SUM(CASE WHEN ss.critical_issues > 0 THEN 1 ELSE 0 END) as critical_issues,
        SUM(CASE WHEN dc.encryption_required = true THEN 1 ELSE 0 END) as encryption_required
    FROM compliance_checks cs
    LEFT JOIN security_scans ss ON cs.compliance_framework = 'SECURITY'
    LEFT JOIN data_classification dc ON 1=1
    WHERE cs.check_status IN ('passed', 'exception')$$,
    $$VALUES (4, 4, 0, 2)$$,
    'Complete security workflow should be successful'
);

-- Test 15: Test compliance dashboard data
SELECT results_eq(
    $$SELECT 
        compliance_framework,
        COUNT(*) as total_checks,
        SUM(CASE WHEN check_status = 'passed' THEN 1 ELSE 0 END) as passed,
        SUM(CASE WHEN check_status = 'failed' THEN 1 ELSE 0 END) as failed,
        SUM(CASE WHEN check_status = 'exception' THEN 1 ELSE 0 END) as exceptions
    FROM compliance_checks
    GROUP BY compliance_framework
    ORDER BY compliance_framework$$,
    $$VALUES ('GDPR', 1, 1, 0, 0), ('HIPAA', 1, 1, 0, 0), ('PCI_DSS', 1, 0, 0, 1), ('SOX', 1, 1, 0, 0)$$,
    'Compliance dashboard should show correct status'
);

SELECT * FROM finish();
ROLLBACK;
```

# ====================
# MONITORING AND ALERTING INTEGRATION
# ====================

## Database Monitoring Integration Testing

```sql
-- Monitoring Integration Testing Template
-- File: tests/workflow/test_monitoring_integration.sql

-- Test setup
CREATE SCHEMA IF NOT EXISTS monitoring_integration_test;
SET search_path TO monitoring_integration_test;

-- Create monitoring integration tables
CREATE TABLE monitoring_metrics (
    id SERIAL PRIMARY KEY,
    metric_name VARCHAR(100) NOT NULL,
    metric_value NUMERIC NOT NULL,
    metric_unit VARCHAR(20),
    labels JSONB DEFAULT '{}',
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE alerting_rules (
    id SERIAL PRIMARY KEY,
    rule_name VARCHAR(100) UNIQUE NOT NULL,
    metric_name VARCHAR(100) NOT NULL,
    condition VARCHAR(200) NOT NULL,
    threshold_value NUMERIC,
    duration_seconds INTEGER DEFAULT 300,
    severity VARCHAR(20) CHECK (severity IN ('info', 'warning', 'critical')),
    notification_channels JSONB DEFAULT '[]',
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE alert_notifications (
    id SERIAL PRIMARY KEY,
    alert_name VARCHAR(100) NOT NULL,
    metric_name VARCHAR(100) NOT NULL,
    metric_value NUMERIC NOT NULL,
    severity VARCHAR(20) NOT NULL,
    status VARCHAR(50) CHECK (status IN ('firing', 'resolved', 'silenced')),
    notification_channel VARCHAR(100),
    sent_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE monitoring_dashboards (
    id SERIAL PRIMARY KEY,
    dashboard_name VARCHAR(100) UNIQUE NOT NULL,
    dashboard_config JSONB NOT NULL,
    refresh_interval_seconds INTEGER DEFAULT 60,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE sla_metrics (
    id SERIAL PRIMARY KEY,
    service_name VARCHAR(100) NOT NULL,
    metric_type VARCHAR(50) CHECK (metric_type IN ('availability', 'response_time', 'error_rate', 'throughput')),
    target_value NUMERIC NOT NULL,
    actual_value NUMERIC,
    measurement_period VARCHAR(50) DEFAULT '1h',
    sla_met BOOLEAN,
    measured_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Workflow test for monitoring integration
BEGIN;
SELECT plan(20);

-- Test 1: Simulate metric collection
SELECT lives_ok(
    $$INSERT INTO monitoring_metrics (metric_name, metric_value, metric_unit, labels) VALUES 
    ('database_cpu_usage', 75.5, 'percent', '{\"host\": \"db-prod-1\", \"region\": \"us-east\"}'),
    ('database_memory_usage', 82.3, 'percent', '{\"host\": \"db-prod-1\", \"region\": \"us-east\"}'),
    ('database_disk_usage', 68.7, 'percent', '{\"host\": \"db-prod-1\", \"disk\": \"/var/lib/postgresql\"}'),
    ('database_connection_count', 145, 'count', '{\"host\": \"db-prod-1\"}'),
    ('database_query_duration_p95', 250, 'milliseconds', '{\"host\": \"db-prod-1\"}')$$,
    'Should collect monitoring metrics'
);

SELECT results_eq(
    $$SELECT COUNT(*) FROM monitoring_metrics WHERE metric_name LIKE 'database_%'$$,
    $$VALUES (5)$$,
    'Should have database metrics'
);

-- Test 2: Create alerting rules
SELECT lives_ok(
    $$INSERT INTO alerting_rules (rule_name, metric_name, condition, threshold_value, duration_seconds, severity, notification_channels) VALUES 
    ('high_cpu_usage', 'database_cpu_usage', 'greater_than', 80, 300, 'warning', '[\"email\", \"slack\"]'),
    ('critical_cpu_usage', 'database_cpu_usage', 'greater_than', 90, 120, 'critical', '[\"email\", \"slack\", \"pagerduty\"]'),
    ('high_memory_usage', 'database_memory_usage', 'greater_than', 85, 600, 'warning', '[\"email\", \"slack\"]'),
    ('disk_space_low', 'database_disk_usage', 'greater_than', 85, 3600, 'warning', '[\"email\", \"slack\"]')$$,
    'Should create alerting rules'
);

SELECT results_eq(
    $$SELECT COUNT(*) FROM alerting_rules WHERE is_active = true$$,
    $$VALUES (4)$$,
    'Should have active alerting rules'
);

-- Test 3: Simulate alert firing
SELECT lives_ok(
    $$INSERT INTO alert_notifications (alert_name, metric_name, metric_value, severity, status, notification_channel) VALUES 
    ('high_cpu_usage', 'database_cpu_usage', 85.2, 'warning', 'firing', 'email')$$,
    'Should fire alert'
);

SELECT results_eq(
    $$SELECT status FROM alert_notifications WHERE alert_name = 'high_cpu_usage'$$,
    $$VALUES ('firing')$$,
    'Alert should be firing'
);

-- Test 4: Simulate alert resolution
SELECT lives_ok(
    $$INSERT INTO alert_notifications (alert_name, metric_name, metric_value, severity, status, notification_channel) VALUES 
    ('high_cpu_usage', 'database_cpu_usage', 65.1, 'warning', 'resolved', 'email')$$,
    'Should resolve alert'
);

SELECT results_eq(
    $$SELECT COUNT(*) FROM alert_notifications WHERE alert_name = 'high_cpu_usage' AND status = 'resolved'$$,
    $$VALUES (1)$$,
    'Alert should be resolved'
);

-- Test 5: Create monitoring dashboards
SELECT lives_ok(
    $$INSERT INTO monitoring_dashboards (dashboard_name, dashboard_config, refresh_interval_seconds) VALUES 
    ('database_overview', '{\"panels\": [\"cpu\", \"memory\", \"disk\"], \"time_range\": \"1h\"}', 30),
    ('database_performance', '{\"panels\": [\"queries\", \"connections\", \"locks\"], \"time_range\": \"30m\"}', 60)$$,
    'Should create monitoring dashboards'
);

SELECT results_eq(
    $$SELECT COUNT(*) FROM monitoring_dashboards WHERE is_active = true$$,
    $$VALUES (2)$$,
    'Should have active dashboards'
);

-- Test 6: Simulate SLA monitoring
SELECT lives_ok(
    $$INSERT INTO sla_metrics (service_name, metric_type, target_value, actual_value, sla_met) VALUES 
    ('database_service', 'availability', 99.9, 99.95, true),
    ('database_service', 'response_time', 100, 85, true),
    ('database_service', 'error_rate', 0.1, 0.02, true)$$,
    'Should record SLA metrics'
);

SELECT results_eq(
    $$SELECT COUNT(*) FROM sla_metrics WHERE sla_met = true$$,
    $$VALUES (3)$$,
    'All SLA metrics should be met'
);

-- Test 7: Test metric aggregation
SELECT results_eq(
    $$SELECT COUNT(*) FROM (
        SELECT metric_name, AVG(metric_value) as avg_value, MAX(metric_value) as max_value
        FROM monitoring_metrics
        WHERE timestamp >= CURRENT_TIMESTAMP - INTERVAL '1 hour'
        GROUP BY metric_name
    ) hourly_aggregates$$,
    $$VALUES (5)$$,
    'Should aggregate metrics correctly'
);

-- Test 8: Test alerting performance
SELECT results_eq(
    $$SELECT AVG(metric_value) FROM monitoring_metrics WHERE metric_name = 'database_cpu_usage'$$,
    $$VALUES (75.5)$$,
    'Average CPU usage should be calculated'
);

-- Test 9: Test notification channel effectiveness
SELECT results_eq(
    $$SELECT COUNT(DISTINCT notification_channel) FROM alert_notifications$$,
    $$VALUES (1)$$,
    'Should use notification channels'
);

-- Test 10: Test monitoring coverage
SELECT results_eq(
    $$SELECT COUNT(DISTINCT metric_name) FROM monitoring_metrics$$,
    $$VALUES (5)$$,
    'Should monitor multiple metrics'
);

SELECT results_eq(
    $$SELECT COUNT(DISTINCT metric_name) FROM alerting_rules$$,
    $$VALUES (3)$$,
    'Should have alerting rules for monitored metrics'
);

-- Test 11: Test dashboard configuration
SELECT results_eq(
    $$SELECT dashboard_config->>'time_range' FROM monitoring_dashboards WHERE dashboard_name = 'database_overview'$$,
    $$VALUES ('1h')$$,
    'Dashboard configuration should be stored correctly'
);

-- Test 12: Test SLA compliance
SELECT results_eq(
    $$SELECT 
        COUNT(CASE WHEN sla_met = true THEN 1 END) as sla_met,
        COUNT(CASE WHEN sla_met = false THEN 1 END) as sla_missed
    FROM sla_metrics$$,
    $$VALUES (3, 0)$$,
    'SLA compliance should be tracked'
);

-- Test 13: Test monitoring alert correlation
SELECT lives_ok(
    $$SELECT COUNT(*) FROM alert_notifications an1
    JOIN alert_notifications an2 ON an1.alert_name = an2.alert_name
    WHERE an1.status = 'firing' AND an2.status = 'resolved'
    AND an1.sent_at < an2.sent_at$$,
    'Should correlate alert firing and resolution'
);

-- Test 14: Test monitoring integration with external systems
SELECT lives_ok(
    $$UPDATE alerting_rules SET notification_channels = '[\"email\", \"slack\", \"webhook\", \"pagerduty\"]' WHERE rule_name = 'critical_cpu_usage'$$,
    'Should integrate with multiple notification systems'
);

SELECT results_eq(
    $$SELECT jsonb_array_length(notification_channels) FROM alerting_rules WHERE rule_name = 'critical_cpu_usage'$$,
    $$VALUES (4)$$,
    'Should integrate with 4 notification systems'
);

-- Test 15: Test complete monitoring workflow
SELECT results_eq(
    $$SELECT 
        COUNT(DISTINCT mm.metric_name) as metrics_monitored,
        COUNT(DISTINCT ar.rule_name) as alerting_rules,
        COUNT(DISTINCT an.alert_name) as alerts_generated,
        COUNT(DISTINCT md.dashboard_name) as dashboards
    FROM monitoring_metrics mm
    LEFT JOIN alerting_rules ar ON mm.metric_name = ar.metric_name
    LEFT JOIN alert_notifications an ON ar.rule_name = an.alert_name
    LEFT JOIN monitoring_dashboards md ON md.is_active = true
    WHERE mm.timestamp >= CURRENT_TIMESTAMP - INTERVAL '1 hour'$$,
    $$VALUES (5, 3, 2, 2)$$,
    'Complete monitoring workflow should be active'
);

SELECT * FROM finish();
ROLLBACK;
```

# ====================
# PYTHON WORKFLOW TESTING FRAMEWORK
# ====================

```python
# Python Workflow Testing Framework
# File: tests/workflow/test_database_workflows.py

import pytest
import asyncio
import asyncpg
import aiomysql
import subprocess
import os
import json
import time
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from unittest.mock import Mock, patch, MagicMock

class TestDatabaseWorkflows:
    """Workflow-level tests for database operations"""
    
    @pytest.fixture
    async def postgres_pool(self):
        """PostgreSQL connection pool for workflow tests"""
        pool = await asyncpg.create_pool(
            host="localhost",
            port=5432,
            database="workflow_test",
            user="workflow_user",
            password="workflow_pass",
            min_size=1,
            max_size=10
        )
        yield pool
        await pool.close()
    
    async def test_migration_pipeline_workflow(self, postgres_pool):
        """Test complete migration pipeline workflow"""
        async with postgres_pool.acquire() as conn:
            # Setup migration tracking
            await conn.execute("""
                CREATE SCHEMA IF NOT EXISTS migration_workflow;
                SET search_path TO migration_workflow;
                
                CREATE TABLE flyway_history (
                    installed_rank INTEGER PRIMARY KEY,
                    version VARCHAR(50),
                    description VARCHAR(200),
                    type VARCHAR(20),
                    script VARCHAR(1000),
                    checksum INTEGER,
                    installed_by VARCHAR(100),
                    installed_on TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    execution_time INTEGER,
                    success BOOLEAN
                );
            """)
            
            # Simulate migration execution
            migrations = [
                {
                    "version": "1.0.0",
                    "description": "Initial schema",
                    "sql": """
                        CREATE TABLE users (
                            id SERIAL PRIMARY KEY,
                            email VARCHAR(255) UNIQUE NOT NULL,
                            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                        );
                    """,
                    "checksum": 123456789
                },
                {
                    "version": "1.1.0", 
                    "description": "Add user profile",
                    "sql": """
                        ALTER TABLE users ADD COLUMN first_name VARCHAR(100);
                        ALTER TABLE users ADD COLUMN last_name VARCHAR(100);
                    """,
                    "checksum": 987654321
                }
            ]
            
            for i, migration in enumerate(migrations, 1):
                start_time = time.time()
                
                try:
                    # Execute migration
                    await conn.execute(migration["sql"])
                    
                    # Record successful migration
                    execution_time = int((time.time() - start_time) * 1000)
                    await conn.execute("""
                        INSERT INTO flyway_history 
                        (installed_rank, version, description, type, script, checksum, installed_by, execution_time, success)
                        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                    """, i, migration["version"], migration["description"], "SQL", 
                       migration["sql"][:100], migration["checksum"], "workflow_user", execution_time, True)
                    
                except Exception as e:
                    # Record failed migration
                    await conn.execute("""
                        INSERT INTO flyway_history 
                        (installed_rank, version, description, type, script, checksum, installed_by, execution_time, success)
                        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                    """, i, migration["version"], migration["description"], "SQL", 
                       migration["sql"][:100], migration["checksum"], "workflow_user", 0, False)
                    raise
            
            # Verify migration history
            migration_count = await conn.fetchval("SELECT COUNT(*) FROM flyway_history WHERE success = true")
            assert migration_count == 2, "Migrations should be recorded as successful"
            
            # Verify schema changes
            has_profile = await conn.fetchval("""
                SELECT EXISTS (
                    SELECT 1 FROM information_schema.columns 
                    WHERE table_name = 'users' AND column_name = 'first_name'
                )
            """)
            assert has_profile, "Profile columns should be added"
    
    async def test_cicd_integration_workflow(self, postgres_pool):
        """Test CI/CD integration workflow"""
        async with postgres_pool.acquire() as conn:
            # Setup CI/CD tracking
            await conn.execute("""
                CREATE SCHEMA IF NOT EXISTS cicd_workflow;
                SET search_path TO cicd_workflow;
                
                CREATE TABLE ci_pipeline_runs (
                    id SERIAL PRIMARY KEY,
                    pipeline_name VARCHAR(100) NOT NULL,
                    branch_name VARCHAR(100),
                    commit_sha VARCHAR(40),
                    run_number INTEGER,
                    status VARCHAR(50),
                    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    finished_at TIMESTAMP,
                    duration_seconds INTEGER,
                    triggered_by VARCHAR(100)
                );
                
                CREATE TABLE ci_test_results (
                    id SERIAL PRIMARY KEY,
                    pipeline_run_id INTEGER REFERENCES ci_pipeline_runs(id),
                    test_suite VARCHAR(100),
                    test_name VARCHAR(200),
                    test_result VARCHAR(20),
                    error_message TEXT,
                    execution_time_ms INTEGER,
                    executed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """)
            
            # Simulate CI pipeline
            pipeline_id = await conn.fetchval("""
                INSERT INTO ci_pipeline_runs 
                (pipeline_name, branch_name, commit_sha, run_number, status, triggered_by)
                VALUES ($1, $2, $3, $4, $5, $6)
                RETURNING id
            """, "database-ci", "feature/new-schema", "abc123def456", 42, "running", "jenkins")
            
            # Simulate test execution
            test_results = [
                ("unit_tests", "test_user_creation", "passed", 45),
                ("unit_tests", "test_user_validation", "passed", 23),
                ("integration_tests", "test_order_workflow", "passed", 234),
                ("integration_tests", "test_payment_processing", "failed", 189, "Connection timeout")
            ]
            
            for test_result in test_results:
                if len(test_result) == 4:
                    suite, name, result, duration = test_result
                    error = None
                else:
                    suite, name, result, duration, error = test_result
                
                await conn.execute("""
                    INSERT INTO ci_test_results 
                    (pipeline_run_id, test_suite, test_name, test_result, error_message, execution_time_ms)
                    VALUES ($1, $2, $3, $4, $5, $6)
                """, pipeline_id, suite, name, result, error, duration)
            
            # Update pipeline status based on test results
            failed_tests = await conn.fetchval("""
                SELECT COUNT(*) FROM ci_test_results 
                WHERE pipeline_run_id = $1 AND test_result = 'failed'
            """, pipeline_id)
            
            final_status = "failed" if failed_tests > 0 else "success"
            await conn.execute("""
                UPDATE ci_pipeline_runs 
                SET status = $1, finished_at = CURRENT_TIMESTAMP, duration_seconds = 300
                WHERE id = $2
            """, final_status, pipeline_id)
            
            # Verify pipeline results
            assert final_status == "failed", "Pipeline should fail due to test failure"
            
            failed_count = await conn.fetchval("""
                SELECT COUNT(*) FROM ci_test_results 
                WHERE pipeline_run_id = $1 AND test_result = 'failed'
            """, pipeline_id)
            assert failed_count == 1, "One test should have failed"
    
    async def test_automated_deployment_workflow(self, postgres_pool):
        """Test automated deployment workflow"""
        async with postgres_pool.acquire() as conn:
            # Setup deployment tracking
            await conn.execute("""
                CREATE SCHEMA IF NOT EXISTS deployment_workflow;
                SET search_path TO deployment_workflow;
                
                CREATE TABLE deployment_executions (
                    id SERIAL PRIMARY KEY,
                    deployment_id VARCHAR(100) UNIQUE NOT NULL,
                    version VARCHAR(50) NOT NULL,
                    status VARCHAR(50),
                    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    finished_at TIMESTAMP,
                    deployed_by VARCHAR(100)
                );
                
                CREATE TABLE deployment_steps (
                    id SERIAL PRIMARY KEY,
                    execution_id INTEGER REFERENCES deployment_executions(id),
                    step_name VARCHAR(100) NOT NULL,
                    step_type VARCHAR(50),
                    status VARCHAR(50),
                    started_at TIMESTAMP,
                    finished_at TIMESTAMP,
                    execution_time_ms INTEGER,
                    error_message TEXT
                );
            """)
            
            # Start deployment
            deployment_id = await conn.fetchval("""
                INSERT INTO deployment_executions 
                (deployment_id, version, status, deployed_by)
                VALUES ($1, $2, $3, $4)
                RETURNING id
            """, "deploy_20240101_120000", "2.0.0", "preparing", "deployment_bot")
            
            # Define deployment steps
            steps = [
                ("pre_deployment_checks", "pre_check"),
                ("database_backup", "backup"),
                ("schema_migration", "migration"),
                ("post_migration_validation", "validation")
            ]
            
            for step_name, step_type in steps:
                # Start step
                step_id = await conn.fetchval("""
                    INSERT INTO deployment_steps 
                    (execution_id, step_name, step_type, status, started_at)
                    VALUES ($1, $2, $3, $4, $5)
                    RETURNING id
                """, deployment_id, step_name, step_type, "running", datetime.now())
                
                # Simulate step execution
                await asyncio.sleep(0.1)  # Simulate work
                
                # Complete step
                execution_time = 5000 + (hash(step_name) % 10000)  # Varying execution times
                await conn.execute("""
                    UPDATE deployment_steps 
                    SET status = $1, finished_at = $2, execution_time_ms = $3
                    WHERE id = $4
                """, "success", datetime.now(), execution_time, step_id)
            
            # Complete deployment
            await conn.execute("""
                UPDATE deployment_executions 
                SET status = $1, finished_at = $2
                WHERE id = $3
            """, "success", datetime.now(), deployment_id)
            
            # Verify deployment results
            final_status = await conn.fetchval("""
                SELECT status FROM deployment_executions WHERE id = $1
            """, deployment_id)
            assert final_status == "success", "Deployment should be successful"
            
            # Verify all steps completed
            completed_steps = await conn.fetchval("""
                SELECT COUNT(*) FROM deployment_steps 
                WHERE execution_id = $1 AND status = 'success'
            """, deployment_id)
            assert completed_steps == 4, "All deployment steps should be successful"
    
    async def test_security_compliance_workflow(self, postgres_pool):
        """Test security and compliance workflow"""
        async with postgres_pool.acquire() as conn:
            # Setup compliance tracking
            await conn.execute("""
                CREATE SCHEMA IF NOT EXISTS compliance_workflow;
                SET search_path TO compliance_workflow;
                
                CREATE TABLE compliance_checks (
                    id SERIAL PRIMARY KEY,
                    compliance_framework VARCHAR(100) NOT NULL,
                    control_id VARCHAR(50),
                    control_description TEXT,
                    check_type VARCHAR(50),
                    check_status VARCHAR(50),
                    check_results JSONB,
                    checked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
                
                CREATE TABLE security_scans (
                    id SERIAL PRIMARY KEY,
                    scan_type VARCHAR(100) NOT NULL,
                    target_type VARCHAR(50),
                    scan_status VARCHAR(50),
                    scan_results JSONB,
                    vulnerabilities_found INTEGER DEFAULT 0,
                    scan_completed_at TIMESTAMP,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """)
            
            # Run security scans
            scans = [
                ("vulnerability_scan", "database", "running"),
                ("configuration_scan", "schema", "running"),
                ("access_control_scan", "user", "running")
            ]
            
            for scan_type, target_type, status in scans:
                scan_id = await conn.fetchval("""
                    INSERT INTO security_scans 
                    (scan_type, target_type, scan_status)
                    VALUES ($1, $2, $3)
                    RETURNING id
                """, scan_type, target_type, status)
                
                # Simulate scan execution
                await asyncio.sleep(0.05)
                
                # Complete scan with results
                vulnerabilities = hash(scan_type) % 5  # 0-4 vulnerabilities
                await conn.execute("""
                    UPDATE security_scans 
                    SET scan_status = $1, scan_completed_at = $2, 
                        vulnerabilities_found = $3,
                        scan_results = $4
                    WHERE id = $5
                """, "completed", datetime.now(), vulnerabilities, 
                     json.dumps({"scan_duration": 30, "issues_found": vulnerabilities}), scan_id)
            
            # Run compliance checks
            compliance_checks = [
                ("SOX", "SOX-1.1", "Database access controls", "automated"),
                ("GDPR", "GDPR-17.1", "Right to erasure", "automated"),
                ("HIPAA", "HIPAA-164.312", "Encryption at rest", "automated")
            ]
            
            for framework, control_id, description, check_type in compliance_checks:
                check_id = await conn.fetchval("""
                    INSERT INTO compliance_checks 
                    (compliance_framework, control_id, control_description, check_type, check_status)
                    VALUES ($1, $2, $3, $4, $5)
                    RETURNING id
                """, framework, control_id, description, check_type, "running")
                
                # Simulate compliance check
                await asyncio.sleep(0.05)
                
                # Complete check (assume all pass for this test)
                await conn.execute("""
                    UPDATE compliance_checks 
                    SET check_status = $1, check_results = $2
                    WHERE id = $3
                """, "passed", json.dumps({"control_met": True, "evidence": "Control implemented"}), check_id)
            
            # Verify security scan results
            total_vulnerabilities = await conn.fetchval("SELECT SUM(vulnerabilities_found) FROM security_scans")
            assert total_vulnerabilities is not None, "Security scan results should be available"
            
            # Verify compliance results
            passed_checks = await conn.fetchval("SELECT COUNT(*) FROM compliance_checks WHERE check_status = 'passed'")
            assert passed_checks == 3, "All compliance checks should pass"
            
            # Verify no critical security issues
            critical_scans = await conn.fetchval("""
                SELECT COUNT(*) FROM security_scans 
                WHERE vulnerabilities_found > 3
            """)
            assert critical_scans == 0, "No critical security issues should be found"
    
    async def test_monitoring_integration_workflow(self, postgres_pool):
        """Test monitoring and alerting integration workflow"""
        async with postgres_pool.acquire() as conn:
            # Setup monitoring
            await conn.execute("""
                CREATE SCHEMA IF NOT EXISTS monitoring_workflow;
                SET search_path TO monitoring_workflow;
                
                CREATE TABLE monitoring_metrics (
                    id SERIAL PRIMARY KEY,
                    metric_name VARCHAR(100) NOT NULL,
                    metric_value NUMERIC NOT NULL,
                    metric_unit VARCHAR(20),
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
                
                CREATE TABLE alerting_rules (
                    id SERIAL PRIMARY KEY,
                    rule_name VARCHAR(100) UNIQUE NOT NULL,
                    metric_name VARCHAR(100) NOT NULL,
                    threshold_value NUMERIC NOT NULL,
                    comparison_operator VARCHAR(10),
                    severity VARCHAR(20),
                    is_active BOOLEAN DEFAULT TRUE
                );
            """)
            
            # Create alerting rules
            rules = [
                ("high_cpu_usage", "database_cpu_usage", 80, ">", "warning"),
                ("critical_cpu_usage", "database_cpu_usage", 90, ">", "critical"),
                ("high_memory_usage", "database_memory_usage", 85, ">", "warning")
            ]
            
            for rule_name, metric_name, threshold, operator, severity in rules:
                await conn.execute("""
                    INSERT INTO alerting_rules 
                    (rule_name, metric_name, threshold_value, comparison_operator, severity)
                    VALUES ($1, $2, $3, $4, $5)
                """, rule_name, metric_name, threshold, operator, severity)
            
            # Simulate metric collection
            metrics = [
                ("database_cpu_usage", 75.5, "percent"),
                ("database_cpu_usage", 85.2, "percent"),  # Should trigger warning
                ("database_cpu_usage", 65.1, "percent"),  # Should resolve
                ("database_memory_usage", 82.3, "percent"),
                ("database_memory_usage", 87.1, "percent")  # Should trigger warning
            ]
            
            alerts_generated = []
            
            for metric_name, value, unit in metrics:
                # Record metric
                await conn.execute("""
                    INSERT INTO monitoring_metrics 
                    (metric_name, metric_value, metric_unit)
                    VALUES ($1, $2, $3)
                """, metric_name, value, unit)
                
                # Check for alert conditions
                alerts = await conn.fetch("""
                    SELECT rule_name, threshold_value, severity
                    FROM alerting_rules
                    WHERE metric_name = $1 AND is_active = true
                    AND (
                        (comparison_operator = '>' AND $2 > threshold_value) OR
                        (comparison_operator = '<' AND $2 < threshold_value)
                    )
                """, metric_name, value)
                
                for alert in alerts:
                    alerts_generated.append({
                        "rule_name": alert["rule_name"],
                        "metric_value": value,
                        "threshold": alert["threshold_value"],
                        "severity": alert["severity"]
                    })
            
            # Verify alerting behavior
            warning_alerts = [a for a in alerts_generated if a["severity"] == "warning"]
            critical_alerts = [a for a in alerts_generated if a["severity"] == "critical"]
            
            assert len(warning_alerts) == 3, "Should generate warning alerts"
            assert len(critical_alerts) == 0, "Should not generate critical alerts"
            
            # Verify metrics were recorded
            metric_count = await conn.fetchval("SELECT COUNT(*) FROM monitoring_metrics")
            assert metric_count == 5, "All metrics should be recorded"

# Workflow test utilities
class WorkflowTestUtils:
    """Utility functions for workflow testing"""
    
    @staticmethod
    async def simulate_migration_execution(conn, migration_sql: str, version: str) -> bool:
        """Simulate migration execution with error handling"""
        try:
            await conn.execute(migration_sql)
            return True
        except Exception as e:
            print(f"Migration {version} failed: {e}")
            return False
    
    @staticmethod
    async def validate_migration_checksum(conn, version: str, expected_checksum: int) -> bool:
        """Validate migration checksum"""
        actual_checksum = await conn.fetchval("""
            SELECT checksum FROM flyway_history WHERE version = $1
        """, version)
        return actual_checksum == expected_checksum
    
    @staticmethod
    def generate_test_data(table_name: str, row_count: int) -> List[Dict[str, Any]]:
        """Generate test data for workflow testing"""
        data = []
        for i in range(row_count):
            data.append({
                "id": i + 1,
                "name": f"test_item_{i}",
                "value": hash(f"item_{i}") % 1000,
                "created_at": datetime.now().isoformat()
            })
        return data
    
    @staticmethod
    async def measure_workflow_performance(workflow_func, *args, **kwargs) -> Dict[str, float]:
        """Measure workflow performance metrics"""
        start_time = time.time()
        
        try:
            result = await workflow_func(*args, **kwargs)
            success = True
            error = None
        except Exception as e:
            result = None
            success = False
            error = str(e)
        
        end_time = time.time()
        
        return {
            "execution_time": end_time - start_time,
            "success": success,
            "error": error,
            "result": result
        }
    
    @staticmethod
    def create_test_migration(version: str, description: str, sql_commands: List[str]) -> Dict[str, Any]:
        """Create a test migration"""
        return {
            "version": version,
            "description": description,
            "sql": "\\n".join(sql_commands),
            "checksum": hash(f"{version}{description}{''.join(sql_commands)}") % 1000000000
        }
    
    @staticmethod
    async def simulate_database_backup(conn, backup_path: str) -> bool:
        """Simulate database backup"""
        try:
            # This would typically use pg_dump or similar
            # For testing, we'll just create a marker file
            with open(backup_path, 'w') as f:
                f.write(f"Backup created at {datetime.now()}\\n")
            return True
        except Exception as e:
            print(f"Backup failed: {e}")
            return False
    
    @staticmethod
    async def simulate_deployment_rollback(conn, deployment_id: str) -> bool:
        """Simulate deployment rollback"""
        try:
            # This would typically revert migrations and restore data
            # For testing, we'll just update status
            await conn.execute("""
                UPDATE deployment_executions 
                SET status = 'rolled_back', finished_at = CURRENT_TIMESTAMP
                WHERE deployment_id = $1
            """, deployment_id)
            return True
        except Exception as e:
            print(f"Rollback failed: {e}")
            return False

# Usage example
if __name__ == "__main__":
    print("SQL Workflow Testing Template loaded!")
    print("Components included:")
    print("- Migration pipeline testing (Flyway, Liquibase)")
    print("- CI/CD integration testing")
    print("- Automated deployment testing")
    print("- Security and compliance testing")
    print("- Monitoring and alerting integration")
    print("- Python workflow testing framework")
    print("- Workflow test utilities and helpers")
    print("- Performance measurement tools")
    print("- Migration and deployment utilities")
    
    print("\nTo use this template:")
    print("1. Set up workflow test databases")
    print("2. Configure CI/CD pipeline integration")
    print("3. Implement migration tracking")
    print("4. Set up monitoring and alerting")
    print("5. Configure security scanning")
    print("6. Run workflow tests with pytest")
    print("7. Monitor workflow performance and success rates")
    
    print("\nWorkflow testing template completed!")
```