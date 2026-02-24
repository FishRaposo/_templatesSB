# SQL Integration Testing Template
# Integration testing patterns for SQL/database projects with migration testing

"""
SQL Integration Test Patterns
Database integration testing with migration validation, data integrity, and transaction testing
"""

-- Database: Integration Testing Framework
-- Database: Migration Testing (Flyway, Liquibase, DBMate)
-- Database: Data Integrity and Constraint Testing
-- Database: Transaction and Isolation Testing
-- Database: Cross-database Compatibility Testing

# ====================
# DATABASE INTEGRATION TEST PATTERNS
# ====================

## Migration Testing Framework

### Flyway Migration Testing

```sql
-- Flyway Migration Testing Template
-- File: tests/integration/test_flyway_migrations.sql

-- Test setup
CREATE SCHEMA IF NOT EXISTS flyway_test;
SET search_path TO flyway_test;

-- Migration V1__Create_users_table.sql
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    username VARCHAR(100) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Migration V2__Add_user_profile.sql
ALTER TABLE users ADD COLUMN profile_data JSONB;
ALTER TABLE users ADD COLUMN last_login TIMESTAMP;

-- Migration V3__Create_products_and_orders.sql
CREATE TABLE products (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    price DECIMAL(10,2) NOT NULL CHECK (price >= 0),
    stock INTEGER NOT NULL DEFAULT 0 CHECK (stock >= 0),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE orders (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    total_amount DECIMAL(10,2) NOT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'pending',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE order_items (
    id SERIAL PRIMARY KEY,
    order_id INTEGER REFERENCES orders(id),
    product_id INTEGER REFERENCES products(id),
    quantity INTEGER NOT NULL CHECK (quantity > 0),
    unit_price DECIMAL(10,2) NOT NULL,
    UNIQUE(order_id, product_id)
);

-- Integration test for migration sequence
BEGIN;
SELECT plan(15);

-- Test 1: Verify migration V1 was applied correctly
SELECT has_table('flyway_test', 'users', 'V1: users table should exist');
SELECT has_column('flyway_test', 'users', 'email', 'V1: users should have email column');
SELECT col_not_null('flyway_test', 'users', 'email', 'V1: email should be not null');
SELECT col_is_unique('flyway_test', 'users', 'email', 'V1: email should be unique');

-- Test 2: Verify migration V2 was applied correctly
SELECT has_column('flyway_test', 'users', 'profile_data', 'V2: users should have profile_data column');
SELECT has_column('flyway_test', 'users', 'last_login', 'V2: users should have last_login column');
SELECT col_type_is('flyway_test', 'users', 'profile_data', 'jsonb', 'V2: profile_data should be jsonb');

-- Test 3: Verify migration V3 was applied correctly
SELECT has_table('flyway_test', 'products', 'V3: products table should exist');
SELECT has_table('flyway_test', 'orders', 'V3: orders table should exist');
SELECT has_table('flyway_test', 'order_items', 'V3: order_items table should exist');

-- Test 4: Verify foreign key constraints
SELECT fk_ok('flyway_test', 'orders', 'user_id', 'flyway_test', 'users', 'id', 'V3: orders.user_id should reference users.id');
SELECT fk_ok('flyway_test', 'order_items', 'order_id', 'flyway_test', 'orders', 'id', 'V3: order_items.order_id should reference orders.id');
SELECT fk_ok('flyway_test', 'order_items', 'product_id', 'flyway_test', 'products', 'id', 'V3: order_items.product_id should reference products.id');

-- Test 5: Verify check constraints
SELECT has_pk('flyway_test', 'order_items', 'V3: order_items should have primary key');
SELECT col_has_check('flyway_test', 'products', 'price', 'V3: products.price should have check constraint');
SELECT col_has_check('flyway_test', 'products', 'stock', 'V3: products.stock should have check constraint');

SELECT * FROM finish();
ROLLBACK;
```

### Liquibase Migration Testing

```sql
-- Liquibase Migration Testing Template
-- File: tests/integration/test_liquibase_migrations.sql

-- Test setup for Liquibase migrations
CREATE SCHEMA IF NOT EXISTS liquibase_test;
SET search_path TO liquibase_test;

-- Simulate Liquibase changelog execution
-- Changeset 001-create-users-table
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

-- Changeset 001: Create base tables
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    username VARCHAR(100) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Record in changelog
INSERT INTO databasechangelog (id, author, filename, dateexecuted, orderexecuted, exectype, description) VALUES
('001-create-users-table', 'developer', 'changelog-001.xml', CURRENT_TIMESTAMP, 1, 'EXECUTED', 'createTable');

-- Changeset 002: Add user profile and preferences
ALTER TABLE users ADD COLUMN profile_data JSONB;
ALTER TABLE users ADD COLUMN preferences JSONB DEFAULT '{"theme": "light", "notifications": true}';
ALTER TABLE users ADD COLUMN last_login_at TIMESTAMP;
ALTER TABLE users ADD COLUMN login_count INTEGER DEFAULT 0;

INSERT INTO databasechangelog (id, author, filename, dateexecuted, orderexecuted, exectype, description) VALUES
('002-add-user-profile', 'developer', 'changelog-002.xml', CURRENT_TIMESTAMP, 2, 'EXECUTED', 'addColumn');

-- Changeset 003: Create product catalog
CREATE TABLE categories (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) UNIQUE NOT NULL,
    description TEXT,
    parent_id INTEGER REFERENCES categories(id),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE products (
    id SERIAL PRIMARY KEY,
    category_id INTEGER REFERENCES categories(id),
    sku VARCHAR(50) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    price DECIMAL(10,2) NOT NULL CHECK (price >= 0),
    cost DECIMAL(10,2) DEFAULT 0.00 CHECK (cost >= 0),
    weight DECIMAL(8,2) DEFAULT 0.00,
    dimensions JSONB DEFAULT '{"length": 0, "width": 0, "height": 0}',
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE product_inventory (
    product_id INTEGER PRIMARY KEY REFERENCES products(id),
    quantity INTEGER NOT NULL DEFAULT 0 CHECK (quantity >= 0),
    reserved_quantity INTEGER NOT NULL DEFAULT 0 CHECK (reserved_quantity >= 0),
    reorder_level INTEGER DEFAULT 10,
    reorder_quantity INTEGER DEFAULT 50,
    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO databasechangelog (id, author, filename, dateexecuted, orderexecuted, exectype, description) VALUES
('003-create-product-catalog', 'developer', 'changelog-003.xml', CURRENT_TIMESTAMP, 3, 'EXECUTED', 'createTable');

-- Integration test for Liquibase migration sequence
BEGIN;
SELECT plan(20);

-- Test 1: Verify changelog tracking
SELECT has_table('liquibase_test', 'databasechangelog', 'Liquibase changelog table should exist');
SELECT results_eq(
    $$SELECT COUNT(*) FROM databasechangelog$$,
    $$VALUES (3)$$,
    'Should have exactly 3 changelog entries'
);

-- Test 2: Verify changeset 001 application
SELECT has_table('liquibase_test', 'users', 'Changeset 001: users table should exist');
SELECT col_type_is('liquibase_test', 'users', 'is_active', 'boolean', 'Changeset 001: is_active should be boolean');
SELECT col_default_is('liquibase_test', 'users', 'is_active', true, 'Changeset 001: is_active should default to true');

-- Test 3: Verify changeset 002 application
SELECT has_column('liquibase_test', 'users', 'profile_data', 'Changeset 002: profile_data column should exist');
SELECT has_column('liquibase_test', 'users', 'preferences', 'Changeset 002: preferences column should exist');
SELECT col_default_is('liquibase_test', 'users', 'preferences', '{"theme": "light", "notifications": true}'::jsonb, 'Changeset 002: preferences should have correct default');

-- Test 4: Verify changeset 003 application
SELECT has_table('liquibase_test', 'categories', 'Changeset 003: categories table should exist');
SELECT has_table('liquibase_test', 'products', 'Changeset 003: products table should exist');
SELECT has_table('liquibase_test', 'product_inventory', 'Changeset 003: product_inventory table should exist');

-- Test 5: Verify foreign key relationships
SELECT fk_ok('liquibase_test', 'products', 'category_id', 'liquibase_test', 'categories', 'id', 'Products should reference categories');
SELECT fk_ok('liquibase_test', 'product_inventory', 'product_id', 'liquibase_test', 'products', 'id', 'Inventory should reference products');
SELECT fk_ok('liquibase_test', 'categories', 'parent_id', 'liquibase_test', 'categories', 'id', 'Categories should support self-reference');

-- Test 6: Verify check constraints
SELECT col_has_check('liquibase_test', 'products', 'price', 'Products should have price check constraint');
SELECT col_has_check('liquibase_test', 'products', 'cost', 'Products should have cost check constraint');
SELECT col_has_check('liquibase_test', 'product_inventory', 'quantity', 'Inventory should have quantity check constraint');

-- Test 7: Verify unique constraints
SELECT col_is_unique('liquibase_test', 'categories', 'name', 'Category name should be unique');
SELECT col_is_unique('liquibase_test', 'products', 'sku', 'Product SKU should be unique');
SELECT has_pk('liquibase_test', 'product_inventory', 'Product inventory should have primary key');

SELECT * FROM finish();
ROLLBACK;
```

### DBMate Migration Testing

```sql
-- DBMate Migration Testing Template
-- File: tests/integration/test_dbmate_migrations.sql

-- Test setup for DBMate migrations
CREATE SCHEMA IF NOT EXISTS dbmate_test;
SET search_path TO dbmate_test;

-- DBMate migration files simulation
-- 20240101120000_create_users.sql
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    username VARCHAR(100) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create schema_migrations table (DBMate tracking)
CREATE TABLE schema_migrations (
    version VARCHAR(255) PRIMARY KEY,
    applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO schema_migrations (version) VALUES ('20240101120000');

-- 20240102130000_add_user_roles.sql
CREATE TYPE user_role AS ENUM ('admin', 'user', 'moderator');

ALTER TABLE users ADD COLUMN role user_role DEFAULT 'user';
ALTER TABLE users ADD COLUMN is_verified BOOLEAN DEFAULT FALSE;
ALTER TABLE users ADD COLUMN verification_token VARCHAR(255);

INSERT INTO schema_migrations (version) VALUES ('20240102130000');

-- 20240103140000_create_billing_system.sql
CREATE TABLE billing_plans (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) UNIQUE NOT NULL,
    description TEXT,
    price_cents INTEGER NOT NULL CHECK (price_cents >= 0),
    interval VARCHAR(20) NOT NULL CHECK (interval IN ('month', 'year')),
    features JSONB DEFAULT '[]',
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE user_subscriptions (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    billing_plan_id INTEGER REFERENCES billing_plans(id),
    status VARCHAR(50) NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'cancelled', 'expired')),
    current_period_start TIMESTAMP NOT NULL,
    current_period_end TIMESTAMP NOT NULL,
    cancel_at_period_end BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id)
);

CREATE TABLE billing_events (
    id SERIAL PRIMARY KEY,
    user_subscription_id INTEGER REFERENCES user_subscriptions(id) ON DELETE CASCADE,
    event_type VARCHAR(50) NOT NULL CHECK (event_type IN ('subscription.created', 'subscription.updated', 'subscription.cancelled', 'payment.succeeded', 'payment.failed')),
    event_data JSONB NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO schema_migrations (version) VALUES ('20240103140000');

-- Integration test for DBMate migration sequence
BEGIN;
SELECT plan(18);

-- Test 1: Verify schema_migrations tracking
SELECT has_table('dbmate_test', 'schema_migrations', 'DBMate schema_migrations table should exist');
SELECT results_eq(
    $$SELECT COUNT(*) FROM schema_migrations$$,
    $$VALUES (3)$$,
    'Should have exactly 3 migration entries'
);
SELECT results_eq(
    $$SELECT version FROM schema_migrations ORDER BY version$$,
    $$VALUES ('20240101120000'), ('20240102130000'), ('20240103140000')$$,
    'Migration versions should be in correct order'
);

-- Test 2: Verify migration 20240101120000
SELECT has_table('dbmate_test', 'users', 'Migration 20240101120000: users table should exist');
SELECT col_not_null('dbmate_test', 'users', 'email', 'Migration 20240101120000: email should be not null');
SELECT col_is_unique('dbmate_test', 'users', 'email', 'Migration 20240101120000: email should be unique');

-- Test 3: Verify migration 20240102130000
SELECT has_column('dbmate_test', 'users', 'role', 'Migration 20240102130000: role column should exist');
SELECT has_column('dbmate_test', 'users', 'is_verified', 'Migration 20240102130000: is_verified column should exist');
SELECT col_type_is('dbmate_test', 'users', 'role', 'user_role', 'Migration 20240102130000: role should be user_role enum');
SELECT col_default_is('dbmate_test', 'users', 'role', 'user', 'Migration 20240102130000: role should default to user');

-- Test 4: Verify migration 20240103140000
SELECT has_table('dbmate_test', 'billing_plans', 'Migration 20240103140000: billing_plans table should exist');
SELECT has_table('dbmate_test', 'user_subscriptions', 'Migration 20240103140000: user_subscriptions table should exist');
SELECT has_table('dbmate_test', 'billing_events', 'Migration 20240103140000: billing_events table should exist');

-- Test 5: Verify billing system constraints
SELECT col_has_check('dbmate_test', 'billing_plans', 'price_cents', 'Migration 20240103140000: price_cents should have check constraint');
SELECT col_has_check('dbmate_test', 'billing_plans', 'interval', 'Migration 20240103140000: interval should have check constraint');
SELECT col_has_check('dbmate_test', 'user_subscriptions', 'status', 'Migration 20240103140000: status should have check constraint');

-- Test 6: Verify foreign key relationships
SELECT fk_ok('dbmate_test', 'user_subscriptions', 'user_id', 'dbmate_test', 'users', 'id', 'user_subscriptions should reference users');
SELECT fk_ok('dbmate_test', 'user_subscriptions', 'billing_plan_id', 'dbmate_test', 'billing_plans', 'id', 'user_subscriptions should reference billing_plans');
SELECT fk_ok('dbmate_test', 'billing_events', 'user_subscription_id', 'dbmate_test', 'user_subscriptions', 'id', 'billing_events should reference user_subscriptions');

-- Test 7: Verify unique constraints
SELECT col_is_unique('dbmate_test', 'billing_plans', 'name', 'Billing plan name should be unique');
SELECT has_pk('dbmate_test', 'user_subscriptions', 'user_subscriptions should have primary key');

SELECT * FROM finish();
ROLLBACK;
```

# ====================
# DATA INTEGRITY TESTING
# ====================

## Cross-Table Data Integrity Tests

```sql
-- Data Integrity Testing Template
-- File: tests/integration/test_data_integrity.sql

-- Test setup
CREATE SCHEMA IF NOT EXISTS integrity_test;
SET search_path TO integrity_test;

-- Create test schema
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    username VARCHAR(100) UNIQUE NOT NULL,
    balance DECIMAL(10,2) DEFAULT 0.00 CHECK (balance >= 0),
    status VARCHAR(20) DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'deleted')),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE products (
    id SERIAL PRIMARY KEY,
    sku VARCHAR(50) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    price DECIMAL(10,2) NOT NULL CHECK (price >= 0),
    cost DECIMAL(10,2) DEFAULT 0.00 CHECK (cost >= 0),
    stock_quantity INTEGER NOT NULL DEFAULT 0 CHECK (stock_quantity >= 0),
    reserved_quantity INTEGER NOT NULL DEFAULT 0 CHECK (reserved_quantity >= 0),
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE orders (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    order_number VARCHAR(20) UNIQUE NOT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'confirmed', 'shipped', 'delivered', 'cancelled', 'refunded')),
    subtotal DECIMAL(10,2) NOT NULL DEFAULT 0.00,
    tax_amount DECIMAL(10,2) NOT NULL DEFAULT 0.00,
    shipping_amount DECIMAL(10,2) NOT NULL DEFAULT 0.00,
    total_amount DECIMAL(10,2) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE order_items (
    id SERIAL PRIMARY KEY,
    order_id INTEGER REFERENCES orders(id) ON DELETE CASCADE,
    product_id INTEGER REFERENCES products(id),
    quantity INTEGER NOT NULL CHECK (quantity > 0),
    unit_price DECIMAL(10,2) NOT NULL CHECK (unit_price >= 0),
    discount_amount DECIMAL(10,2) DEFAULT 0.00 CHECK (discount_amount >= 0),
    total_price DECIMAL(10,2) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE user_transactions (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    order_id INTEGER REFERENCES orders(id),
    transaction_type VARCHAR(50) NOT NULL CHECK (transaction_type IN ('order_payment', 'refund', 'credit', 'debit')),
    amount DECIMAL(10,2) NOT NULL,
    balance_after DECIMAL(10,2) NOT NULL,
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Integration test for data integrity
BEGIN;
SELECT plan(25);

-- Test 1: Setup test data
SELECT lives_ok(
    $$INSERT INTO users (email, username, balance) VALUES 
    ('user1@test.com', 'user1', 1000.00),
    ('user2@test.com', 'user2', 500.00)$$,
    'Should insert test users'
);

SELECT lives_ok(
    $$INSERT INTO products (sku, name, price, cost, stock_quantity) VALUES 
    ('SKU001', 'Product 1', 50.00, 30.00, 100),
    ('SKU002', 'Product 2', 75.00, 45.00, 50)$$,
    'Should insert test products'
);

-- Test 2: Order creation with balance validation
SELECT lives_ok(
    $$INSERT INTO orders (user_id, order_number, total_amount) VALUES 
    (1, 'ORD001', 125.00)$$,
    'Should create order with valid total'
);

-- Test 3: Order items validation
SELECT lives_ok(
    $$INSERT INTO order_items (order_id, product_id, quantity, unit_price, total_price) VALUES 
    (1, 1, 1, 50.00, 50.00),
    (1, 2, 1, 75.00, 75.00)$$,
    'Should insert order items'
);

-- Test 4: Verify order total calculation
SELECT results_eq(
    $$SELECT total_amount FROM orders WHERE id = 1$$,
    $$SELECT SUM(total_price) FROM order_items WHERE order_id = 1$$,
    'Order total should match sum of order items'
);

-- Test 5: Verify product stock management
SELECT results_eq(
    $$SELECT stock_quantity FROM products WHERE id = 1$$,
    $$VALUES (99)$$,
    'Product stock should be reduced by order quantity'
);

SELECT results_eq(
    $$SELECT stock_quantity FROM products WHERE id = 2$$,
    $$VALUES (49)$$,
    'Product stock should be reduced by order quantity'
);

-- Test 6: User balance and transaction integrity
SELECT lives_ok(
    $$INSERT INTO user_transactions (user_id, order_id, transaction_type, amount, balance_after) VALUES 
    (1, 1, 'order_payment', -125.00, 875.00)$$,
    'Should record user transaction'
);

SELECT results_eq(
    $$SELECT balance FROM users WHERE id = 1$$,
    $$VALUES (875.00)$$,
    'User balance should be updated after transaction'
);

-- Test 7: Test constraint violations
SELECT throws_ok(
    $$INSERT INTO order_items (order_id, product_id, quantity, unit_price, total_price) VALUES 
    (1, 1, 200, 50.00, 10000.00)$$,
    'P0002',
    'Should not allow order item with quantity exceeding stock'
);

SELECT throws_ok(
    $$INSERT INTO orders (user_id, order_number, total_amount) VALUES 
    (2, 'ORD002', 1000.00)$$,
    'P0002',
    'Should not allow order exceeding user balance'
);

-- Test 8: Test order cancellation workflow
SELECT lives_ok(
    $$UPDATE orders SET status = 'cancelled' WHERE id = 1$$,
    'Should cancel order'
);

SELECT lives_ok(
    $$UPDATE products SET stock_quantity = stock_quantity + 
    (SELECT quantity FROM order_items WHERE order_id = 1 AND product_id = 1) WHERE id = 1$$,
    'Should restore product stock on cancellation'
);

SELECT lives_ok(
    $$UPDATE products SET stock_quantity = stock_quantity + 
    (SELECT quantity FROM order_items WHERE order_id = 1 AND product_id = 2) WHERE id = 2$$,
    'Should restore product stock on cancellation'
);

SELECT lives_ok(
    $$INSERT INTO user_transactions (user_id, order_id, transaction_type, amount, balance_after) VALUES 
    (1, 1, 'refund', 125.00, 1000.00)$$,
    'Should record refund transaction'
);

SELECT results_eq(
    $$SELECT balance FROM users WHERE id = 1$$,
    $$VALUES (1000.00)$$,
    'User balance should be restored after refund'
);

-- Test 9: Verify final data integrity
SELECT results_eq(
    $$SELECT COUNT(*) FROM orders WHERE user_id = 1 AND status = 'cancelled'$$,
    $$VALUES (1)$$,
    'User should have one cancelled order'
);

SELECT results_eq(
    $$SELECT COUNT(*) FROM user_transactions WHERE user_id = 1$$,
    $$VALUES (2)$$,
    'User should have two transactions'
);

SELECT results_eq(
    $$SELECT SUM(amount) FROM user_transactions WHERE user_id = 1$$,
    $$VALUES (0.00)$$,
    'Sum of user transactions should be zero (payment + refund)'
);

SELECT results_eq(
    $$SELECT stock_quantity FROM products WHERE id = 1$$,
    $$VALUES (100)$$,
    'Product 1 stock should be restored to original'
);

SELECT results_eq(
    $$SELECT stock_quantity FROM products WHERE id = 2$$,
    $$VALUES (50)$$,
    'Product 2 stock should be restored to original'
);

-- Test 10: Test complex business rules
-- Insert new order with insufficient stock
SELECT lives_ok(
    $$INSERT INTO orders (user_id, order_number, total_amount) VALUES 
    (2, 'ORD003', 150.00)$$,
    'Should create second order'
);

SELECT lives_ok(
    $$INSERT INTO order_items (order_id, product_id, quantity, unit_price, total_price) VALUES 
    (2, 1, 2, 50.00, 100.00),
    (2, 2, 1, 50.00, 50.00)$$,
    'Should insert order items with different unit price'
);

SELECT results_eq(
    $$SELECT stock_quantity FROM products WHERE id = 1$$,
    $$VALUES (98)$$,
    'Product 1 stock should be reduced'
);

SELECT results_eq(
    $$SELECT stock_quantity FROM products WHERE id = 2$$,
    $$VALUES (49)$$,
    'Product 2 stock should be reduced'
);

-- Test 11: Verify user balance constraint
SELECT lives_ok(
    $$INSERT INTO user_transactions (user_id, order_id, transaction_type, amount, balance_after) VALUES 
    (2, 2, 'order_payment', -150.00, 350.00)$$,
    'Should record payment transaction'
);

SELECT results_eq(
    $$SELECT balance FROM users WHERE id = 2$$,
    $$VALUES (350.00)$$,
    'User 2 balance should be updated'
);

SELECT * FROM finish();
ROLLBACK;
```

## Transaction and Isolation Level Testing

```sql
-- Transaction Isolation Testing Template
-- File: tests/integration/test_transaction_isolation.sql

-- Test setup
CREATE SCHEMA IF NOT EXISTS isolation_test;
SET search_path TO isolation_test;

-- Create test tables
CREATE TABLE accounts (
    id SERIAL PRIMARY KEY,
    account_number VARCHAR(20) UNIQUE NOT NULL,
    user_id INTEGER NOT NULL,
    balance DECIMAL(12,2) NOT NULL DEFAULT 0.00 CHECK (balance >= 0),
    status VARCHAR(20) DEFAULT 'active' CHECK (status IN ('active', 'frozen', 'closed')),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE account_transactions (
    id SERIAL PRIMARY KEY,
    account_id INTEGER REFERENCES accounts(id),
    transaction_type VARCHAR(50) NOT NULL CHECK (transaction_type IN ('deposit', 'withdrawal', 'transfer', 'fee', 'interest')),
    amount DECIMAL(12,2) NOT NULL,
    balance_before DECIMAL(12,2) NOT NULL,
    balance_after DECIMAL(12,2) NOT NULL,
    reference_id VARCHAR(100),
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE transfer_locks (
    id SERIAL PRIMARY KEY,
    from_account_id INTEGER REFERENCES accounts(id),
    to_account_id INTEGER REFERENCES accounts(id),
    amount DECIMAL(12,2) NOT NULL,
    lock_token VARCHAR(64) UNIQUE NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Integration test for transaction isolation
BEGIN;
SELECT plan(20);

-- Test 1: Setup test data
SELECT lives_ok(
    $$INSERT INTO accounts (account_number, user_id, balance) VALUES 
    ('ACC001', 1, 1000.00),
    ('ACC002', 2, 500.00)$$,
    'Should create test accounts'
);

-- Test 2: Test READ COMMITTED isolation level
SET TRANSACTION ISOLATION LEVEL READ COMMITTED;

SELECT lives_ok(
    $$BEGIN;
    UPDATE accounts SET balance = balance - 100.00 WHERE account_number = 'ACC001';
    INSERT INTO account_transactions (account_id, transaction_type, amount, balance_before, balance_after) 
    VALUES (1, 'withdrawal', -100.00, 1000.00, 900.00);
    COMMIT;$$,
    'Should complete READ COMMITTED transaction'
);

SELECT results_eq(
    $$SELECT balance FROM accounts WHERE account_number = 'ACC001'$$,
    $$VALUES (900.00)$$,
    'Account balance should be updated after READ COMMITTED transaction'
);

-- Test 3: Test REPEATABLE READ isolation level
SET TRANSACTION ISOLATION LEVEL REPEATABLE READ;

SELECT lives_ok(
    $$BEGIN;
    SELECT balance FROM accounts WHERE account_number = 'ACC001';
    SELECT balance FROM accounts WHERE account_number = 'ACC001';
    COMMIT;$$,
    'Should read consistent data in REPEATABLE READ'
);

-- Test 4: Test SERIALIZABLE isolation level
SET TRANSACTION ISOLATION LEVEL SERIALIZABLE;

SELECT lives_ok(
    $$BEGIN;
    SELECT SUM(balance) FROM accounts;
    UPDATE accounts SET balance = balance + 50.00 WHERE account_number = 'ACC002';
    COMMIT;$$,
    'Should complete SERIALIZABLE transaction'
);

-- Test 5: Test concurrent transfer with locking
SELECT lives_ok(
    $$INSERT INTO transfer_locks (from_account_id, to_account_id, amount, lock_token, expires_at) VALUES 
    (1, 2, 200.00, 'lock_token_123', CURRENT_TIMESTAMP + INTERVAL '5 minutes')$$,
    'Should create transfer lock'
);

-- Test 6: Test deadlock detection
SELECT lives_ok(
    $$BEGIN;
    UPDATE accounts SET balance = balance - 50.00 WHERE account_number = 'ACC001';
    UPDATE accounts SET balance = balance + 50.00 WHERE account_number = 'ACC002';
    COMMIT;$$,
    'Should handle concurrent updates without deadlock'
);

-- Test 7: Test transaction rollback
SELECT lives_ok(
    $$BEGIN;
    UPDATE accounts SET balance = balance - 300.00 WHERE account_number = 'ACC001';
    INSERT INTO account_transactions (account_id, transaction_type, amount, balance_before, balance_after) 
    VALUES (1, 'withdrawal', -300.00, 900.00, 600.00);
    ROLLBACK;$$,
    'Should rollback transaction'
);

SELECT results_eq(
    $$SELECT balance FROM accounts WHERE account_number = 'ACC001'$$,
    $$VALUES (900.00)$$,
    'Account balance should not change after rollback'
);

SELECT results_eq(
    $$SELECT COUNT(*) FROM account_transactions WHERE account_id = 1 AND amount = -300.00$$,
    $$VALUES (0)$$,
    'Transaction should not exist after rollback'
);

-- Test 8: Test savepoint functionality
SELECT lives_ok(
    $$BEGIN;
    SAVEPOINT sp1;
    UPDATE accounts SET balance = balance - 100.00 WHERE account_number = 'ACC001';
    SAVEPOINT sp2;
    UPDATE accounts SET balance = balance + 100.00 WHERE account_number = 'ACC002';
    ROLLBACK TO SAVEPOINT sp1;
    COMMIT;$$,
    'Should rollback to savepoint'
);

SELECT results_eq(
    $$SELECT balance FROM accounts WHERE account_number = 'ACC001'$$,
    $$VALUES (900.00)$$,
    'Account balance should not change after savepoint rollback'
);

SELECT results_eq(
    $$SELECT balance FROM accounts WHERE account_number = 'ACC002'$$,
    $$VALUES (550.00)$$,
    'Account balance should not change after savepoint rollback'
);

-- Test 9: Test trigger execution within transaction
SELECT lives_ok(
    $$CREATE OR REPLACE FUNCTION update_account_timestamp()
    RETURNS TRIGGER AS $$
    BEGIN
        NEW.updated_at = CURRENT_TIMESTAMP;
        RETURN NEW;
    END;
    $$ LANGUAGE plpgsql;$$,
    'Should create update trigger function'
);

SELECT lives_ok(
    $$CREATE TRIGGER update_accounts_updated_at
    BEFORE UPDATE ON accounts
    FOR EACH ROW
    EXECUTE FUNCTION update_account_timestamp();$$,
    'Should create update trigger'
);

SELECT lives_ok(
    $$BEGIN;
    UPDATE accounts SET status = 'active' WHERE account_number = 'ACC001';
    COMMIT;$$,
    'Should execute trigger within transaction'
);

SELECT isnt_empty(
    $$SELECT updated_at FROM accounts WHERE account_number = 'ACC001' AND updated_at > created_at$$,
    'updated_at should be changed by trigger'
);

-- Test 10: Test transaction with exception handling
SELECT lives_ok(
    $$BEGIN;
    DECLARE
        insufficient_funds EXCEPTION;
        current_balance DECIMAL(12,2);
    BEGIN
        SELECT balance INTO current_balance FROM accounts WHERE account_number = 'ACC001';
        IF current_balance < 2000.00 THEN
            RAISE insufficient_funds;
        END IF;
        UPDATE accounts SET balance = balance - 2000.00 WHERE account_number = 'ACC001';
    EXCEPTION
        WHEN insufficient_funds THEN
            RAISE NOTICE 'Insufficient funds for withdrawal';
    END;
    COMMIT;$$,
    'Should handle transaction exceptions'
);

SELECT results_eq(
    $$SELECT balance FROM accounts WHERE account_number = 'ACC001'$$,
    $$VALUES (900.00)$$,
    'Account balance should not change after exception'
);

-- Test 11: Test concurrent read consistency
SELECT lives_ok(
    $$BEGIN;
    SET TRANSACTION ISOLATION LEVEL REPEATABLE READ;
    PERFORM pg_sleep(0.1); -- Simulate concurrent access
    SELECT COUNT(*) FROM accounts;
    COMMIT;$$,
    'Should maintain read consistency'
);

-- Test 12: Test transfer atomicity
SELECT lives_ok(
    $$BEGIN;
    -- Lock source account
    SELECT balance FROM accounts WHERE account_number = 'ACC001' FOR UPDATE;
    -- Perform transfer
    UPDATE accounts SET balance = balance - 100.00 WHERE account_number = 'ACC001';
    UPDATE accounts SET balance = balance + 100.00 WHERE account_number = 'ACC002';
    -- Record transactions
    INSERT INTO account_transactions (account_id, transaction_type, amount, balance_before, balance_after) 
    VALUES (1, 'transfer', -100.00, 900.00, 800.00);
    INSERT INTO account_transactions (account_id, transaction_type, amount, balance_before, balance_after) 
    VALUES (2, 'transfer', 100.00, 550.00, 650.00);
    COMMIT;$$,
    'Should perform atomic transfer'
);

SELECT results_eq(
    $$SELECT balance FROM accounts WHERE account_number = 'ACC001'$$,
    $$VALUES (800.00)$$,
    'Source account should be debited'
);

SELECT results_eq(
    $$SELECT balance FROM accounts WHERE account_number = 'ACC002'$$,
    $$VALUES (650.00)$$,
    'Destination account should be credited'
);

SELECT results_eq(
    $$SELECT COUNT(*) FROM account_transactions WHERE transaction_type = 'transfer'$$,
    $$VALUES (2)$$,
    'Should have two transfer transaction records'
);

-- Test 13: Test transaction logging
SELECT results_eq(
    $$SELECT COUNT(*) FROM account_transactions WHERE account_id = 1$$,
    $$VALUES (3)$$,
    'Should have complete transaction history'
);

SELECT results_eq(
    $$SELECT SUM(amount) FROM account_transactions WHERE account_id = 1$$,
    $$VALUES (-100.00)$$,
    'Net transaction amount should match balance change'
);

SELECT * FROM finish();
ROLLBACK;
```

# ====================
# CROSS-DATABASE COMPATIBILITY TESTING
# ====================

## PostgreSQL vs MySQL vs SQLite Compatibility

```sql
-- Cross-Database Compatibility Testing Template
-- File: tests/integration/test_cross_database_compatibility.sql

-- Test setup - Common schema definition
-- This section would be executed on each database system

/* PostgreSQL Version */
CREATE SCHEMA IF NOT EXISTS compatibility_test;
SET search_path TO compatibility_test;

CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    username VARCHAR(100) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE products (
    id SERIAL PRIMARY KEY,
    sku VARCHAR(50) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    price DECIMAL(10,2) NOT NULL CHECK (price >= 0),
    stock INTEGER NOT NULL DEFAULT 0 CHECK (stock >= 0),
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE orders (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    order_number VARCHAR(20) UNIQUE NOT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'pending',
    total_amount DECIMAL(10,2) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

/* MySQL Version */
CREATE DATABASE IF NOT EXISTS compatibility_test;
USE compatibility_test;

CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    username VARCHAR(100) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

CREATE TABLE products (
    id INT AUTO_INCREMENT PRIMARY KEY,
    sku VARCHAR(50) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    price DECIMAL(10,2) NOT NULL CHECK (price >= 0),
    stock INT NOT NULL DEFAULT 0 CHECK (stock >= 0),
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

CREATE TABLE orders (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    order_number VARCHAR(20) UNIQUE NOT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'pending',
    total_amount DECIMAL(10,2) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

/* SQLite Version */
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email VARCHAR(255) UNIQUE NOT NULL,
    username VARCHAR(100) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    is_active BOOLEAN DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE products (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sku VARCHAR(50) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    price DECIMAL(10,2) NOT NULL CHECK (price >= 0),
    stock INTEGER NOT NULL DEFAULT 0 CHECK (stock >= 0),
    is_active BOOLEAN DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE orders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    order_number VARCHAR(20) UNIQUE NOT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'pending',
    total_amount DECIMAL(10,2) NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);
```

# ====================
# PYTHON INTEGRATION TESTING FRAMEWORK
# ====================

```python
# Python Database Integration Testing Framework
# File: tests/integration/test_database_integration.py

import pytest
import asyncio
import asyncpg
import aiomysql
import aiosqlite
from typing import List, Dict, Any, Optional
import json
from datetime import datetime, timedelta
import uuid
from unittest.mock import Mock, patch, MagicMock

class TestDatabaseIntegration:
    """Integration tests for database operations"""
    
    @pytest.fixture
    async def postgres_pool(self):
        """PostgreSQL connection pool for integration tests"""
        pool = await asyncpg.create_pool(
            host="localhost",
            port=5432,
            database="integration_test",
            user="test_user",
            password="test_pass",
            min_size=1,
            max_size=10
        )
        yield pool
        await pool.close()
    
    @pytest.fixture
    async def mysql_pool(self):
        """MySQL connection pool for integration tests"""
        pool = await aiomysql.create_pool(
            host="localhost",
            port=3306,
            database="integration_test",
            user="test_user",
            password="test_pass",
            minsize=1,
            maxsize=10
        )
        yield pool
        pool.close()
        await pool.wait_closed()
    
    @pytest.fixture
    async def sqlite_connection(self):
        """SQLite connection for integration tests"""
        conn = await aiosqlite.connect(":memory:")
        yield conn
        await conn.close()
    
    async def test_complete_order_workflow(self, postgres_pool):
        """Test complete order workflow with transaction integrity"""
        async with postgres_pool.acquire() as conn:
            async with conn.transaction():
                # Create user
                user_id = await conn.fetchval("""
                    INSERT INTO users (email, username, password_hash, balance)
                    VALUES ($1, $2, $3, $4)
                    RETURNING id
                """, 'workflow@test.com', 'workflowuser', 'hash', 1000.00)
                
                # Create products
                product1_id = await conn.fetchval("""
                    INSERT INTO products (sku, name, price, stock_quantity)
                    VALUES ($1, $2, $3, $4)
                    RETURNING id
                """, 'SKU_WF1', 'Workflow Product 1', 50.00, 100)
                
                product2_id = await conn.fetchval("""
                    INSERT INTO products (sku, name, price, stock_quantity)
                    VALUES ($1, $2, $3, $4)
                    RETURNING id
                """, 'SKU_WF2', 'Workflow Product 2', 75.00, 50)
                
                # Create order
                order_id = await conn.fetchval("""
                    INSERT INTO orders (user_id, order_number, total_amount, status)
                    VALUES ($1, $2, $3, $4)
                    RETURNING id
                """, user_id, 'ORD_WF001', 200.00, 'pending')
                
                # Add order items
                await conn.execute("""
                    INSERT INTO order_items (order_id, product_id, quantity, unit_price, total_price)
                    VALUES 
                    ($1, $2, $3, $4, $5),
                    ($1, $6, $7, $8, $9)
                """, order_id, product1_id, 2, 50.00, 100.00,
                       order_id, product2_id, 1, 75.00, 75.00)
                
                # Update product stock
                await conn.execute("""
                    UPDATE products 
                    SET stock_quantity = stock_quantity - CASE 
                        WHEN id = $1 THEN 2
                        WHEN id = $2 THEN 1
                    END
                    WHERE id IN ($1, $2)
                """, product1_id, product2_id)
                
                # Update user balance
                await conn.execute("""
                    UPDATE users 
                    SET balance = balance - $1
                    WHERE id = $2
                """, 175.00, user_id)
                
                # Record transaction
                await conn.execute("""
                    INSERT INTO user_transactions (user_id, order_id, transaction_type, amount, balance_after)
                    VALUES ($1, $2, $3, $4, $5)
                """, user_id, order_id, 'order_payment', -175.00, 825.00)
                
                # Update order status
                await conn.execute("""
                    UPDATE orders 
                    SET status = 'confirmed'
                    WHERE id = $1
                """, order_id)
        
        # Verify final state
        async with postgres_pool.acquire() as conn:
            # Verify order
            order = await conn.fetchrow("SELECT * FROM orders WHERE id = $1", order_id)
            assert order['status'] == 'confirmed'
            assert order['total_amount'] == 175.00
            
            # Verify user balance
            user_balance = await conn.fetchval("SELECT balance FROM users WHERE id = $1", user_id)
            assert user_balance == 825.00
            
            # Verify product stock
            product1_stock = await conn.fetchval("SELECT stock_quantity FROM products WHERE id = $1", product1_id)
            product2_stock = await conn.fetchval("SELECT stock_quantity FROM products WHERE id = $1", product2_id)
            assert product1_stock == 98  # 100 - 2
            assert product2_stock == 49  # 50 - 1
            
            # Verify transaction
            transaction = await conn.fetchrow("""
                SELECT * FROM user_transactions 
                WHERE user_id = $1 AND order_id = $2
            """, user_id, order_id)
            assert transaction['transaction_type'] == 'order_payment'
            assert transaction['amount'] == -175.00
    
    async def test_concurrent_order_processing(self, postgres_pool):
        """Test concurrent order processing with proper locking"""
        async def process_order(product_id, quantity, user_id):
            async with postgres_pool.acquire() as conn:
                async with conn.transaction(isolation='serializable'):
                    # Lock product for update
                    product = await conn.fetchrow("""
                        SELECT * FROM products WHERE id = $1 FOR UPDATE
                    """, product_id)
                    
                    if product['stock_quantity'] < quantity:
                        raise ValueError(f"Insufficient stock for product {product_id}")
                    
                    # Create order
                    order_id = await conn.fetchval("""
                        INSERT INTO orders (user_id, order_number, total_amount)
                        VALUES ($1, $2, $3)
                        RETURNING id
                    """, user_id, f"ORD_{uuid.uuid4().hex[:8]}", quantity * product['price'])
                    
                    # Add order item
                    await conn.execute("""
                        INSERT INTO order_items (order_id, product_id, quantity, unit_price, total_price)
                        VALUES ($1, $2, $3, $4, $5)
                    """, order_id, product_id, quantity, product['price'], quantity * product['price'])
                    
                    # Update stock
                    await conn.execute("""
                        UPDATE products 
                        SET stock_quantity = stock_quantity - $1
                        WHERE id = $2
                    """, quantity, product_id)
                    
                    return order_id
        
        # Setup test data
        async with postgres_pool.acquire() as conn:
            user_id = await conn.fetchval("""
                INSERT INTO users (email, username, password_hash, balance)
                VALUES ($1, $2, $3, $4)
                RETURNING id
            """, 'concurrent@test.com', 'concurrentuser', 'hash', 10000.00)
            
            product_id = await conn.fetchval("""
                INSERT INTO products (sku, name, price, stock_quantity)
                VALUES ($1, $2, $3, $4)
                RETURNING id
            """, 'SKU_CONCURRENT', 'Concurrent Product', 100.00, 10)
        
        # Process multiple orders concurrently
        tasks = [
            process_order(product_id, 2, user_id),
            process_order(product_id, 3, user_id),
            process_order(product_id, 1, user_id),
            process_order(product_id, 2, user_id)
        ]
        
        # Run concurrent orders
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Verify results
        async with postgres_pool.acquire() as conn:
            # Check final stock
            final_stock = await conn.fetchval("SELECT stock_quantity FROM products WHERE id = $1", product_id)
            assert final_stock == 2  # 10 - (2+3+1+2) = 2
            
            # Check order count
            order_count = await conn.fetchval("SELECT COUNT(*) FROM orders WHERE user_id = $1", user_id)
            assert order_count == 4
            
            # Check total ordered quantity
            total_quantity = await conn.fetchval("""
                SELECT SUM(quantity) FROM order_items oi
                JOIN orders o ON oi.order_id = o.id
                WHERE o.user_id = $1
            """, user_id)
            assert total_quantity == 8
    
    async def test_migration_rollback(self, postgres_pool):
        """Test database migration rollback functionality"""
        async with postgres_pool.acquire() as conn:
            # Simulate migration up
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS migration_test (
                    id SERIAL PRIMARY KEY,
                    name VARCHAR(100) NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Insert test data
            await conn.execute("""
                INSERT INTO migration_test (name) VALUES ('test1'), ('test2')
            """)
            
            # Simulate migration down (rollback)
            await conn.execute("DROP TABLE IF EXISTS migration_test")
            
            # Verify table was dropped
            table_exists = await conn.fetchval("""
                SELECT EXISTS (
                    SELECT 1 FROM information_schema.tables 
                    WHERE table_schema = 'public' AND table_name = 'migration_test'
                )
            """)
            assert not table_exists
    
    async def test_data_integrity_constraints(self, postgres_pool):
        """Test data integrity constraints across multiple operations"""
        async with postgres_pool.acquire() as conn:
            # Create user
            user_id = await conn.fetchval("""
                INSERT INTO users (email, username, password_hash, balance)
                VALUES ($1, $2, $3, $4)
                RETURNING id
            """, 'integrity@test.com', 'integrityuser', 'hash', 500.00)
            
            # Create product
            product_id = await conn.fetchval("""
                INSERT INTO products (sku, name, price, stock_quantity)
                VALUES ($1, $2, $3, $4)
                RETURNING id
            """, 'SKU_INTEGRITY', 'Integrity Product', 200.00, 5)
            
            # Test 1: Try to create order exceeding user balance
            with pytest.raises(asyncpg.CheckViolationError):
                async with conn.transaction():
                    order_id = await conn.fetchval("""
                        INSERT INTO orders (user_id, order_number, total_amount)
                        VALUES ($1, $2, $3)
                        RETURNING id
                    """, user_id, 'ORD_INTEGRITY_001', 600.00)
            
            # Test 2: Try to create order exceeding product stock
            with pytest.raises(asyncpg.CheckViolationError):
                async with conn.transaction():
                    order_id = await conn.fetchval("""
                        INSERT INTO orders (user_id, order_number, total_amount)
                        VALUES ($1, $2, $3)
                        RETURNING id
                    """, user_id, 'ORD_INTEGRITY_002', 1000.00)
                    
                    await conn.execute("""
                        INSERT INTO order_items (order_id, product_id, quantity, unit_price, total_price)
                        VALUES ($1, $2, $3, $4, $5)
                    """, order_id, product_id, 10, 200.00, 2000.00)
            
            # Test 3: Create valid order
            async with conn.transaction():
                order_id = await conn.fetchval("""
                    INSERT INTO orders (user_id, order_number, total_amount)
                    VALUES ($1, $2, $3)
                    RETURNING id
                """, user_id, 'ORD_INTEGRITY_003', 200.00)
                
                await conn.execute("""
                    INSERT INTO order_items (order_id, product_id, quantity, unit_price, total_price)
                    VALUES ($1, $2, $3, $4, $5)
                """, order_id, product_id, 1, 200.00, 200.00)
                
                # Update user balance
                await conn.execute("""
                    UPDATE users SET balance = balance - 200.00 WHERE id = $1
                """, user_id)
                
                # Update product stock
                await conn.execute("""
                    UPDATE products SET stock_quantity = stock_quantity - 1 WHERE id = $1
                """, product_id)
            
            # Verify final state
            user_balance = await conn.fetchval("SELECT balance FROM users WHERE id = $1", user_id)
            assert user_balance == 300.00
            
            product_stock = await conn.fetchval("SELECT stock_quantity FROM products WHERE id = $1", product_id)
            assert product_stock == 4
    
    async def test_performance_under_load(self, postgres_pool):
        """Test database performance under concurrent load"""
        async def simulate_user_activity(user_id, iterations):
            async with postgres_pool.acquire() as conn:
                for i in range(iterations):
                    # Simulate various database operations
                    await conn.execute("""
                        INSERT INTO user_activity (user_id, activity_type, data)
                        VALUES ($1, $2, $3)
                    """, user_id, 'test_activity', json.dumps({'iteration': i}))
                    
                    # Simulate read operations
                    await conn.fetchrow("""
                        SELECT * FROM users WHERE id = $1
                    """, user_id)
                    
                    # Simulate update operations
                    await conn.execute("""
                        UPDATE users SET last_login_at = CURRENT_TIMESTAMP WHERE id = $1
                    """, user_id)
        
        # Setup test data
        async with postgres_pool.acquire() as conn:
            # Create activity table
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS user_activity (
                    id SERIAL PRIMARY KEY,
                    user_id INTEGER REFERENCES users(id),
                    activity_type VARCHAR(50),
                    data JSONB,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Create test users
            user_ids = []
            for i in range(10):
                user_id = await conn.fetchval("""
                    INSERT INTO users (email, username, password_hash, balance)
                    VALUES ($1, $2, $3, $4)
                    RETURNING id
                """, f'loadtest{i}@test.com', f'loadtestuser{i}', 'hash', 1000.00)
                user_ids.append(user_id)
        
        # Simulate concurrent user activity
        start_time = asyncio.get_event_loop().time()
        
        tasks = []
        for user_id in user_ids:
            tasks.append(simulate_user_activity(user_id, 20))
        
        await asyncio.gather(*tasks)
        
        end_time = asyncio.get_event_loop().time()
        total_time = end_time - start_time
        
        # Verify results
        async with postgres_pool.acquire() as conn:
            total_activities = await conn.fetchval("SELECT COUNT(*) FROM user_activity")
            assert total_activities == 200  # 10 users * 20 iterations
            
            print(f"Performance test completed in {total_time:.2f} seconds")
            print(f"Operations per second: {200/total_time:.2f}")

# Test data factories
class IntegrationTestDataFactory:
    """Factory for creating integration test data"""
    
    @staticmethod
    def create_test_user(overrides=None):
        """Create test user data"""
        default = {
            'email': f'test.user.{uuid.uuid4().hex[:8]}@example.com',
            'username': f'testuser_{uuid.uuid4().hex[:8]}',
            'password_hash': 'hashed_password',
            'balance': 1000.00,
            'created_at': datetime.now()
        }
        if overrides:
            default.update(overrides)
        return default
    
    @staticmethod
    def create_test_product(overrides=None):
        """Create test product data"""
        default = {
            'sku': f'SKU_{uuid.uuid4().hex[:8].upper()}',
            'name': f'Test Product {uuid.uuid4().hex[:8]}',
            'price': round(10.00 + (uuid.uuid4().int % 100), 2),
            'stock_quantity': 10 + (uuid.uuid4().int % 50),
            'created_at': datetime.now()
        }
        if overrides:
            default.update(overrides)
        return default
    
    @staticmethod
    def create_test_order(user_id, overrides=None):
        """Create test order data"""
        default = {
            'user_id': user_id,
            'order_number': f'ORD_{uuid.uuid4().hex[:8].upper()}',
            'total_amount': 50.00,
            'status': 'pending',
            'created_at': datetime.now()
        }
        if overrides:
            default.update(overrides)
        return default

# Migration testing utilities
class MigrationIntegrationTester:
    """Utility class for integration testing of database migrations"""
    
    @staticmethod
    async def test_migration_chain(connection, migrations: List[str]):
        """Test a chain of migrations in sequence"""
        for i, migration in enumerate(migrations):
            try:
                await connection.execute(migration)
                print(f"Migration {i+1} applied successfully")
            except Exception as e:
                print(f"Migration {i+1} failed: {e}")
                raise
    
    @staticmethod
    async def test_rollback_chain(connection, rollbacks: List[str]):
        """Test rollback of migrations in reverse order"""
        for i, rollback in enumerate(reversed(rollbacks)):
            try:
                await connection.execute(rollback)
                print(f"Rollback {i+1} applied successfully")
            except Exception as e:
                print(f"Rollback {i+1} failed: {e}")
                raise
    
    @staticmethod
    async def verify_migration_state(connection, expected_schema: Dict[str, Any]):
        """Verify database schema matches expected state after migration"""
        # Check tables exist
        for table_name in expected_schema.get('tables', []):
            exists = await connection.fetchval("""
                SELECT EXISTS (
                    SELECT 1 FROM information_schema.tables 
                    WHERE table_schema = 'public' AND table_name = $1
                )
            """, table_name)
            assert exists, f"Table {table_name} should exist"
        
        # Check columns exist
        for table_name, columns in expected_schema.get('columns', {}).items():
            for column_name in columns:
                exists = await connection.fetchval("""
                    SELECT EXISTS (
                        SELECT 1 FROM information_schema.columns 
                        WHERE table_schema = 'public' 
                        AND table_name = $1 
                        AND column_name = $2
                    )
                """, table_name, column_name)
                assert exists, f"Column {column_name} in table {table_name} should exist"

# Performance testing utilities
class IntegrationPerformanceTester:
    """Performance testing utilities for integration tests"""
    
    @staticmethod
    async def measure_transaction_performance(pool, transaction_func, iterations=100):
        """Measure performance of database transactions"""
        import time
        
        times = []
        for _ in range(iterations):
            start_time = time.time()
            async with pool.acquire() as conn:
                async with conn.transaction():
                    await transaction_func(conn)
            end_time = time.time()
            times.append(end_time - start_time)
        
        return {
            'min_time': min(times),
            'max_time': max(times),
            'avg_time': sum(times) / len(times),
            'total_time': sum(times),
            'operations_per_second': iterations / sum(times)
        }
    
    @staticmethod
    async def test_concurrent_transaction_limits(pool, max_concurrent=50):
        """Test database behavior under maximum concurrent transactions"""
        async def simple_transaction(conn):
            await conn.execute("SELECT 1")
            await conn.execute("SELECT pg_sleep(0.001)")  # Simulate some work
        
        # Create many concurrent transactions
        tasks = []
        for _ in range(max_concurrent):
            async with pool.acquire() as conn:
                tasks.append(simple_transaction(conn))
        
        start_time = asyncio.get_event_loop().time()
        await asyncio.gather(*tasks, return_exceptions=True)
        end_time = asyncio.get_event_loop().time()
        
        return {
            'total_time': end_time - start_time,
            'avg_time_per_transaction': (end_time - start_time) / max_concurrent,
            'concurrency_level': max_concurrent
        }

# Usage example
if __name__ == "__main__":
    print("SQL Integration Testing Template loaded!")
    print("Components included:")
    print("- Migration testing (Flyway, Liquibase, DBMate)")
    print("- Data integrity testing")
    print("- Transaction isolation testing")
    print("- Cross-database compatibility testing")
    print("- Concurrent operation testing")
    print("- Performance testing under load")
    print("- Integration test data factories")
    print("- Migration testing utilities")
    print("- Performance testing utilities")
    
    print("\nTo use this template:")
    print("1. Set up test databases for each engine")
    print("2. Configure connection parameters")
    print("3. Run integration tests with pytest")
    print("4. Monitor performance and concurrency")
    print("5. Verify data integrity across operations")
    
    print("\nIntegration testing template completed!")
```