# SQL Unit Testing Template
# Comprehensive unit testing patterns for SQL/database projects

"""
SQL Unit Test Patterns
Database-specific testing patterns for PostgreSQL, MySQL, SQLite
"""

-- Database: PostgreSQL Testing Framework
-- Database: MySQL Testing Framework  
-- Database: SQLite Testing Framework
-- Database: Testing Utilities and Assertions

# ====================
# DATABASE UNIT TEST PATTERNS
# ====================

## PostgreSQL Unit Tests

```sql
-- PostgreSQL Unit Test Template
-- File: tests/unit/test_schema_validation.sql

-- Test framework setup
CREATE EXTENSION IF NOT EXISTS pgtap;

-- Schema validation tests
BEGIN;
SELECT plan(10);

-- Test 1: Verify tables exist
SELECT has_table('public', 'users', 'users table should exist');
SELECT has_table('public', 'products', 'products table should exist');
SELECT has_table('public', 'orders', 'orders table should exist');

-- Test 2: Verify column existence and types
SELECT has_column('public', 'users', 'id', 'users should have id column');
SELECT col_type_is('public', 'users', 'id', 'integer', 'id should be integer');
SELECT col_not_null('public', 'users', 'email', 'email should be not null');

-- Test 3: Verify constraints
SELECT col_has_default('public', 'users', 'created_at', 'created_at should have default');
SELECT col_default_is('public', 'users', 'created_at', 'now()', 'created_at default should be now()');

-- Test 4: Verify indexes
SELECT has_index('public', 'users', 'idx_users_email', 'users should have email index');
SELECT index_is_unique('public', 'users', 'idx_users_email', 'email index should be unique');

SELECT * FROM finish();
ROLLBACK;
```

## MySQL Unit Tests

```sql
-- MySQL Unit Test Template
-- File: tests/unit/test_schema_mysql.sql

-- Test database setup
USE test_database;

-- Schema validation tests
DELIMITER //

-- Test procedure for table existence
CREATE PROCEDURE test_table_exists(table_name VARCHAR(64))
BEGIN
    DECLARE table_count INT DEFAULT 0;
    SELECT COUNT(*) INTO table_count 
    FROM information_schema.tables 
    WHERE table_schema = DATABASE() AND table_name = table_name;
    
    IF table_count = 0 THEN
        SIGNAL SQLSTATE '45000' 
        SET MESSAGE_TEXT = CONCAT('Table ', table_name, ' does not exist');
    END IF;
END//

-- Test procedure for column validation
CREATE PROCEDURE test_column_exists(table_name VARCHAR(64), column_name VARCHAR(64), expected_type VARCHAR(64))
BEGIN
    DECLARE column_count INT DEFAULT 0;
    SELECT COUNT(*) INTO column_count 
    FROM information_schema.columns 
    WHERE table_schema = DATABASE() 
    AND table_name = table_name 
    AND column_name = column_name
    AND data_type = expected_type;
    
    IF column_count = 0 THEN
        SIGNAL SQLSTATE '45000' 
        SET MESSAGE_TEXT = CONCAT('Column ', column_name, ' does not exist or has wrong type');
    END IF;
END//

-- Test procedure for constraint validation
CREATE PROCEDURE test_not_null_constraint(table_name VARCHAR(64), column_name VARCHAR(64))
BEGIN
    DECLARE is_nullable VARCHAR(3);
    SELECT is_nullable INTO is_nullable
    FROM information_schema.columns 
    WHERE table_schema = DATABASE() 
    AND table_name = table_name 
    AND column_name = column_name;
    
    IF is_nullable = 'YES' THEN
        SIGNAL SQLSTATE '45000' 
        SET MESSAGE_TEXT = CONCAT('Column ', column_name, ' should be NOT NULL');
    END IF;
END//

DELIMITER ;

-- Execute tests
CALL test_table_exists('users');
CALL test_table_exists('products');
CALL test_column_exists('users', 'id', 'int');
CALL test_column_exists('users', 'email', 'varchar');
CALL test_not_null_constraint('users', 'email');
```

## SQLite Unit Tests

```sql
-- SQLite Unit Test Template
-- File: tests/unit/test_schema_sqlite.sql

-- SQLite testing with in-memory database
ATTACH DATABASE ':memory:' AS test_db;

-- Test table creation
CREATE TABLE test_users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL UNIQUE,
    username TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Schema validation tests
-- Test 1: Verify table structure
SELECT 
    CASE 
        WHEN sql LIKE '%id INTEGER PRIMARY KEY%' THEN 'PASS'
        ELSE 'FAIL: Missing primary key'
    END as test_result
FROM sqlite_master 
WHERE type='table' AND name='test_users';

-- Test 2: Verify column constraints
SELECT 
    CASE 
        WHEN sql LIKE '%email TEXT NOT NULL%' THEN 'PASS'
        ELSE 'FAIL: Missing NOT NULL constraint'
    END as test_result
FROM sqlite_master 
WHERE type='table' AND name='test_users';

-- Test 3: Verify unique constraint
SELECT 
    CASE 
        WHEN sql LIKE '%email TEXT NOT NULL UNIQUE%' THEN 'PASS'
        ELSE 'FAIL: Missing UNIQUE constraint'
    END as test_result
FROM sqlite_master 
WHERE type='table' AND name='test_users';

-- Test 4: Verify default value
SELECT 
    CASE 
        WHEN sql LIKE '%created_at DATETIME DEFAULT CURRENT_TIMESTAMP%' THEN 'PASS'
        ELSE 'FAIL: Missing default value'
    END as test_result
FROM sqlite_master 
WHERE type='table' AND name='test_users';
```

# ====================
# STORED PROCEDURE TESTING
# ====================

## PostgreSQL Stored Procedures

```sql
-- PostgreSQL Stored Procedure Tests
-- File: tests/unit/test_stored_procedures.sql

BEGIN;
SELECT plan(8);

-- Setup test data
INSERT INTO users (email, username, password_hash) VALUES 
('test1@example.com', 'testuser1', 'hash1'),
('test2@example.com', 'testuser2', 'hash2');

INSERT INTO products (name, price, stock) VALUES 
('Product A', 10.00, 100),
('Product B', 20.00, 50);

-- Test stored procedure: create_order
SELECT lives_ok(
    $$SELECT create_order(1, ARRAY[1, 2], ARRAY[1, 2])$$,
    'create_order should execute without errors'
);

-- Test stored procedure: update_user_profile
SELECT lives_ok(
    $$SELECT update_user_profile(1, 'newemail@example.com', 'newusername')$$,
    'update_user_profile should execute without errors'
);

-- Test stored procedure: calculate_total_sales
SELECT results_eq(
    $$SELECT calculate_total_sales('2024-01-01', '2024-12-31')$$,
    $$VALUES (30.00)$$,
    'calculate_total_sales should return correct total'
);

-- Test stored procedure: get_user_with_orders
SELECT set_eq(
    $$SELECT * FROM get_user_with_orders(1)$$,
    $$VALUES (1, 'test1@example.com', 'testuser1')$$,
    'get_user_with_orders should return correct user data'
);

-- Test error handling
SELECT throws_ok(
    $$SELECT create_order(999, ARRAY[1], ARRAY[1])$$,
    'P0002',
    'create_order should throw exception for non-existent user'
);

SELECT throws_ok(
    $$SELECT create_order(1, ARRAY[999], ARRAY[1])$$,
    'P0002',
    'create_order should throw exception for non-existent product'
);

-- Test transaction rollback
SELECT lives_ok(
    $$SELECT create_order(1, ARRAY[1], ARRAY[999])$$,
    'create_order should handle insufficient stock'
);

-- Verify data integrity after procedures
SELECT set_eq(
    $$SELECT COUNT(*) FROM orders WHERE user_id = 1$$,
    $$VALUES (1)$$,
    'User should have exactly one order'
);

SELECT * FROM finish();
ROLLBACK;
```

## MySQL Stored Procedures

```sql
-- MySQL Stored Procedure Tests
-- File: tests/unit/test_mysql_procedures.sql

-- Test procedure for stored procedure validation
DELIMITER //

CREATE PROCEDURE test_create_order_procedure()
BEGIN
    DECLARE order_count_before INT DEFAULT 0;
    DECLARE order_count_after INT DEFAULT 0;
    DECLARE user_id INT DEFAULT 1;
    DECLARE product_id INT DEFAULT 1;
    DECLARE quantity INT DEFAULT 2;
    
    -- Count orders before procedure call
    SELECT COUNT(*) INTO order_count_before FROM orders;
    
    -- Call stored procedure
    CALL create_order(user_id, product_id, quantity);
    
    -- Count orders after procedure call
    SELECT COUNT(*) INTO order_count_after FROM orders;
    
    -- Verify order was created
    IF order_count_after != order_count_before + 1 THEN
        SIGNAL SQLSTATE '45000' 
        SET MESSAGE_TEXT = 'Order was not created successfully';
    END IF;
    
    -- Verify order details
    IF NOT EXISTS (SELECT 1 FROM orders WHERE user_id = user_id AND product_id = product_id AND quantity = quantity) THEN
        SIGNAL SQLSTATE '45000' 
        SET MESSAGE_TEXT = 'Order details are incorrect';
    END IF;
END//

CREATE PROCEDURE test_update_inventory_procedure()
BEGIN
    DECLARE initial_stock INT DEFAULT 0;
    DECLARE final_stock INT DEFAULT 0;
    DECLARE product_id INT DEFAULT 1;
    DECLARE quantity_sold INT DEFAULT 5;
    
    -- Get initial stock
    SELECT stock INTO initial_stock FROM products WHERE id = product_id;
    
    -- Update inventory
    CALL update_inventory(product_id, quantity_sold);
    
    -- Get final stock
    SELECT stock INTO final_stock FROM products WHERE id = product_id;
    
    -- Verify stock was reduced correctly
    IF final_stock != initial_stock - quantity_sold THEN
        SIGNAL SQLSTATE '45000' 
        SET MESSAGE_TEXT = 'Inventory was not updated correctly';
    END IF;
END//

CREATE PROCEDURE test_error_handling_procedure()
BEGIN
    DECLARE exit handler for SQLEXCEPTION
    BEGIN
        -- Expected exception, test passes
        GET DIAGNOSTICS CONDITION 1
            @sqlstate = RETURNED_SQLSTATE,
            @message = MESSAGE_TEXT;
        
        IF @sqlstate != '45000' THEN
            SIGNAL SQLSTATE '45000' 
            SET MESSAGE_TEXT = 'Unexpected error occurred';
        END IF;
    END;
    
    -- Try to create order with invalid data
    CALL create_order(NULL, 1, 1);
END//

DELIMITER ;

-- Execute tests
CALL test_create_order_procedure();
CALL test_update_inventory_procedure();
CALL test_error_handling_procedure();
```

# ====================
# TRIGGER TESTING
# ====================

## PostgreSQL Trigger Tests

```sql
-- PostgreSQL Trigger Testing
-- File: tests/unit/test_triggers.sql

BEGIN;
SELECT plan(12);

-- Setup test data
INSERT INTO users (email, username, password_hash) VALUES 
('trigger_test@example.com', 'triggertest', 'hash');

INSERT INTO products (name, price, stock) VALUES 
('Trigger Product', 15.00, 10);

-- Test BEFORE INSERT trigger: set_created_timestamp
SELECT lives_ok(
    $$INSERT INTO users (email, username, password_hash) VALUES ('newuser@example.com', 'newuser', 'hash')$$,
    'BEFORE INSERT trigger should set created_at timestamp'
);

SELECT isnt_empty(
    $$SELECT created_at FROM users WHERE email = 'newuser@example.com' AND created_at IS NOT NULL$$,
    'created_at should be set by trigger'
);

-- Test AFTER INSERT trigger: log_user_activity
SELECT results_eq(
    $$SELECT COUNT(*) FROM user_activity_log WHERE user_id = (SELECT id FROM users WHERE email = 'newuser@example.com')$$,
    $$VALUES (1)$$,
    'AFTER INSERT trigger should log user activity'
);

-- Test BEFORE UPDATE trigger: update_modified_timestamp
SELECT lives_ok(
    $$UPDATE users SET email = 'updated@example.com' WHERE email = 'trigger_test@example.com'$$,
    'BEFORE UPDATE trigger should update modified_at timestamp'
);

SELECT isnt_empty(
    $$SELECT modified_at FROM users WHERE email = 'updated@example.com' AND modified_at IS NOT NULL$$,
    'modified_at should be updated by trigger'
);

-- Test AFTER UPDATE trigger: audit_user_changes
SELECT results_eq(
    $$SELECT COUNT(*) FROM user_audit_log WHERE user_id = (SELECT id FROM users WHERE email = 'updated@example.com')$$,
    $$VALUES (1)$$,
    'AFTER UPDATE trigger should audit user changes'
);

-- Test BEFORE DELETE trigger: prevent_user_deletion_with_orders
INSERT INTO orders (user_id, total_amount, status) VALUES 
((SELECT id FROM users WHERE email = 'updated@example.com'), 100.00, 'completed');

SELECT throws_ok(
    $$DELETE FROM users WHERE email = 'updated@example.com'$$,
    'P0002',
    'BEFORE DELETE trigger should prevent deletion of users with orders'
);

-- Test AFTER DELETE trigger: cleanup_user_data
-- First delete orders, then user
DELETE FROM orders WHERE user_id = (SELECT id FROM users WHERE email = 'updated@example.com');
SELECT lives_ok(
    $$DELETE FROM users WHERE email = 'updated@example.com'$$,
    'AFTER DELETE trigger should cleanup user data'
);

SELECT results_eq(
    $$SELECT COUNT(*) FROM user_activity_log WHERE user_id = (SELECT id FROM users WHERE email = 'updated@example.com')$$,
    $$VALUES (0)$$,
    'User activity log should be cleaned up after user deletion'
);

-- Test stock management trigger
SELECT lives_ok(
    $$INSERT INTO order_items (order_id, product_id, quantity, price) VALUES 
    (1, (SELECT id FROM products WHERE name = 'Trigger Product'), 2, 15.00)$$,
    'AFTER INSERT trigger should manage product stock'
);

SELECT results_eq(
    $$SELECT stock FROM products WHERE name = 'Trigger Product'$$,
    $$VALUES (8)$$,
    'Product stock should be reduced by order quantity'
);

-- Test rollback functionality
SELECT lives_ok(
    $$DELETE FROM order_items WHERE product_id = (SELECT id FROM products WHERE name = 'Trigger Product')$$,
    'AFTER DELETE trigger should restore product stock'
);

SELECT results_eq(
    $$SELECT stock FROM products WHERE name = 'Trigger Product'$$,
    $$VALUES (10)$$,
    'Product stock should be restored after order item deletion'
);

SELECT * FROM finish();
ROLLBACK;
```

## MySQL Trigger Tests

```sql
-- MySQL Trigger Testing
-- File: tests/unit/test_mysql_triggers.sql

-- Test trigger validation procedures
DELIMITER //

CREATE PROCEDURE test_user_timestamp_triggers()
BEGIN
    DECLARE test_user_id INT DEFAULT 0;
    DECLARE original_created_at DATETIME DEFAULT NULL;
    DECLARE new_created_at DATETIME DEFAULT NULL;
    DECLARE original_modified_at DATETIME DEFAULT NULL;
    DECLARE new_modified_at DATETIME DEFAULT NULL;
    
    -- Insert test user
    INSERT INTO users (email, username, password_hash) VALUES 
    ('triggertest@example.com', 'triggertest', 'hash');
    
    SET test_user_id = LAST_INSERT_ID();
    
    -- Verify created_at was set
    SELECT created_at INTO original_created_at FROM users WHERE id = test_user_id;
    IF original_created_at IS NULL THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'created_at was not set by trigger';
    END IF;
    
    -- Wait a moment
    DO SLEEP(1);
    
    -- Update user
    UPDATE users SET email = 'updated@example.com' WHERE id = test_user_id;
    
    -- Verify modified_at was updated
    SELECT modified_at INTO new_modified_at FROM users WHERE id = test_user_id;
    IF new_modified_at IS NULL OR new_modified_at = original_created_at THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'modified_at was not updated by trigger';
    END IF;
    
    -- Cleanup
    DELETE FROM users WHERE id = test_user_id;
END//

CREATE PROCEDURE test_order_stock_triggers()
BEGIN
    DECLARE initial_stock INT DEFAULT 0;
    DECLARE final_stock INT DEFAULT 0;
    DECLARE test_order_id INT DEFAULT 0;
    DECLARE test_product_id INT DEFAULT 1;
    DECLARE order_quantity INT DEFAULT 5;
    
    -- Get initial stock
    SELECT stock INTO initial_stock FROM products WHERE id = test_product_id;
    
    -- Create order
    INSERT INTO orders (user_id, total_amount, status) VALUES (1, 100.00, 'pending');
    SET test_order_id = LAST_INSERT_ID();
    
    -- Add order item
    INSERT INTO order_items (order_id, product_id, quantity, price) VALUES 
    (test_order_id, test_product_id, order_quantity, 10.00);
    
    -- Verify stock was reduced
    SELECT stock INTO final_stock FROM products WHERE id = test_product_id;
    IF final_stock != initial_stock - order_quantity THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Stock was not reduced by trigger';
    END IF;
    
    -- Delete order item
    DELETE FROM order_items WHERE order_id = test_order_id;
    
    -- Verify stock was restored
    SELECT stock INTO final_stock FROM products WHERE id = test_product_id;
    IF final_stock != initial_stock THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Stock was not restored by trigger';
    END IF;
    
    -- Cleanup
    DELETE FROM orders WHERE id = test_order_id;
END//

CREATE PROCEDURE test_audit_triggers()
BEGIN
    DECLARE test_user_id INT DEFAULT 0;
    DECLARE audit_count_before INT DEFAULT 0;
    DECLARE audit_count_after INT DEFAULT 0;
    
    -- Count audit records before
    SELECT COUNT(*) INTO audit_count_before FROM user_audit_log;
    
    -- Insert test user
    INSERT INTO users (email, username, password_hash) VALUES 
    ('auditest@example.com', 'auditest', 'hash');
    
    SET test_user_id = LAST_INSERT_ID();
    
    -- Update user
    UPDATE users SET email = 'updatedaudit@example.com' WHERE id = test_user_id;
    
    -- Count audit records after
    SELECT COUNT(*) INTO audit_count_after FROM user_audit_log;
    
    -- Verify audit record was created
    IF audit_count_after != audit_count_before + 1 THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Audit record was not created by trigger';
    END IF;
    
    -- Cleanup
    DELETE FROM users WHERE id = test_user_id;
END//

DELIMITER ;

-- Execute trigger tests
CALL test_user_timestamp_triggers();
CALL test_order_stock_triggers();
CALL test_audit_triggers();
```

# ====================
# FUNCTION TESTING
# ====================

## PostgreSQL Function Tests

```sql
-- PostgreSQL Function Testing
-- File: tests/unit/test_functions.sql

BEGIN;
SELECT plan(15);

-- Test scalar functions
SELECT results_eq(
    $$SELECT calculate_discount(100.00, 0.1)$$,
    $$VALUES (90.00)$$,
    'calculate_discount should apply 10% discount'
);

SELECT results_eq(
    $$SELECT calculate_tax(100.00, 0.08)$$,
    $$VALUES (8.00)$$,
    'calculate_tax should calculate 8% tax'
);

SELECT results_eq(
    $$SELECT format_currency(1234.56)$$,
    $$VALUES ('$1,234.56')$$,
    'format_currency should format as USD'
);

-- Test aggregate functions
SELECT set_eq(
    $$SELECT get_user_order_count(1)$$,
    $$VALUES (5)$$,
    'get_user_order_count should return correct count'
);

SELECT results_eq(
    $$SELECT get_user_total_spent(1)$$,
    $$VALUES (500.00)$$,
    'get_user_total_spent should calculate correct total'
);

-- Test string functions
SELECT results_eq(
    $$SELECT normalize_email('Test@Example.COM')$$,
    $$VALUES ('test@example.com')$$,
    'normalize_email should lowercase and trim'
);

SELECT results_eq(
    $$SELECT generate_username('John', 'Doe')$$,
    $$VALUES ('john_doe')$$,
    'generate_username should create username from names'
);

-- Test date/time functions
SELECT results_eq(
    $$SELECT is_business_day('2024-01-15')$$,
    $$VALUES (true)$$,
    'is_business_day should return true for Monday'
);

SELECT results_eq(
    $$SELECT add_business_days('2024-01-15', 5)$$,
    $$VALUES ('2024-01-22')$$,
    'add_business_days should skip weekends'
);

-- Test array functions
SELECT set_eq(
    $$SELECT get_product_categories(1)$$,
    $$VALUES ('{electronics, gadgets}')$$,
    'get_product_categories should return array of categories'
);

-- Test JSON functions
SELECT results_eq(
    $$SELECT get_user_preferences(1)$$,
    $$VALUES ('{"theme": "dark", "notifications": true}')$$,
    'get_user_preferences should return JSON preferences'
);

-- Test conditional functions
SELECT results_eq(
    $$SELECT get_shipping_rate('US', 'standard')$$,
    $$VALUES (5.99)$$,
    'get_shipping_rate should return correct rate for US standard'
);

SELECT results_eq(
    $$SELECT get_shipping_rate('CA', 'express')$$,
    $$VALUES (15.99)$$,
    'get_shipping_rate should return correct rate for CA express'
);

-- Test error handling in functions
SELECT throws_ok(
    $$SELECT calculate_discount(-100.00, 0.1)$$,
    'P0002',
    'calculate_discount should throw error for negative amount'
);

SELECT throws_ok(
    $$SELECT calculate_discount(100.00, 1.5)$$,
    'P0002',
    'calculate_discount should throw error for invalid discount rate'
);

SELECT * FROM finish();
ROLLBACK;
```

# ====================
# PYTHON DATABASE TESTING UTILITIES
# ====================

```python
# Python Database Testing Utilities
# File: tests/unit/test_database_utils.py

import pytest
import sqlite3
import psycopg2
import mysql.connector
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime, timedelta
import json

class TestDatabaseSchema:
    """Test database schema validation"""
    
    def test_postgresql_schema_validation(self, postgres_connection):
        """Test PostgreSQL schema structure"""
        cursor = postgres_connection.cursor()
        
        # Test table existence
        cursor.execute("""
            SELECT table_name 
            FROM information_schema.tables 
            WHERE table_schema = 'public' 
            AND table_name IN ('users', 'products', 'orders')
        """)
        tables = [row[0] for row in cursor.fetchall()]
        assert 'users' in tables
        assert 'products' in tables
        assert 'orders' in tables
        
        # Test column types
        cursor.execute("""
            SELECT column_name, data_type, is_nullable
            FROM information_schema.columns
            WHERE table_name = 'users'
            AND column_name IN ('id', 'email', 'created_at')
        """)
        columns = {row[0]: {'type': row[1], 'nullable': row[2]} for row in cursor.fetchall()}
        assert columns['id']['type'] == 'integer'
        assert columns['email']['nullable'] == 'NO'
        
        cursor.close()
    
    def test_mysql_schema_validation(self, mysql_connection):
        """Test MySQL schema structure"""
        cursor = mysql_connection.cursor()
        
        # Test table existence
        cursor.execute("SHOW TABLES")
        tables = [row[0] for row in cursor.fetchall()]
        assert 'users' in tables
        assert 'products' in tables
        
        # Test column definitions
        cursor.execute("DESCRIBE users")
        columns = {row[0]: {'type': row[1], 'null': row[2]} for row in cursor.fetchall()}
        assert 'id' in columns
        assert columns['email']['null'] == 'NO'
        
        cursor.close()
    
    def test_sqlite_schema_validation(self, sqlite_connection):
        """Test SQLite schema structure"""
        cursor = sqlite_connection.cursor()
        
        # Test table existence
        cursor.execute("""
            SELECT name FROM sqlite_master 
            WHERE type='table' AND name IN ('users', 'products')
        """)
        tables = [row[0] for row in cursor.fetchall()]
        assert 'users' in tables
        assert 'products' in tables
        
        # Test table schema
        cursor.execute("PRAGMA table_info(users)")
        columns = {row[1]: {'type': row[2], 'notnull': row[3]} for row in cursor.fetchall()}
        assert columns['email']['notnull'] == 1
        
        cursor.close()

class TestStoredProcedures:
    """Test stored procedures and functions"""
    
    def test_postgresql_procedure_execution(self, postgres_connection):
        """Test PostgreSQL stored procedure execution"""
        cursor = postgres_connection.cursor()
        
        # Setup test data
        cursor.execute("INSERT INTO users (email, username, password_hash) VALUES (%s, %s, %s)",
                      ('test@example.com', 'testuser', 'hash'))
        user_id = cursor.fetchone()[0]
        
        cursor.execute("INSERT INTO products (name, price, stock) VALUES (%s, %s, %s)",
                      ('Test Product', 10.00, 100))
        product_id = cursor.fetchone()[0]
        
        # Test procedure execution
        cursor.execute("SELECT create_order(%s, %s, %s)",
                      (user_id, product_id, 5))
        order_id = cursor.fetchone()[0]
        
        # Verify order was created
        cursor.execute("SELECT * FROM orders WHERE id = %s", (order_id,))
        order_data = cursor.fetchone()
        assert order_data is not None
        assert order_data[1] == user_id  # user_id
        
        # Verify stock was reduced
        cursor.execute("SELECT stock FROM products WHERE id = %s", (product_id,))
        stock = cursor.fetchone()[0]
        assert stock == 95  # 100 - 5
        
        cursor.close()
    
    def test_mysql_procedure_execution(self, mysql_connection):
        """Test MySQL stored procedure execution"""
        cursor = mysql_connection.cursor()
        
        # Setup test data
        cursor.execute("INSERT INTO users (email, username, password_hash) VALUES (%s, %s, %s)",
                      ('test@example.com', 'testuser', 'hash'))
        mysql_connection.commit()
        user_id = cursor.lastrowid
        
        cursor.execute("INSERT INTO products (name, price, stock) VALUES (%s, %s, %s)",
                      ('Test Product', 10.00, 100))
        mysql_connection.commit()
        product_id = cursor.lastrowid
        
        # Test procedure execution
        cursor.callproc('create_order', [user_id, product_id, 3])
        mysql_connection.commit()
        
        # Verify order was created
        cursor.execute("SELECT * FROM orders WHERE user_id = %s", (user_id,))
        order_data = cursor.fetchone()
        assert order_data is not None
        
        cursor.close()

class TestTriggers:
    """Test database triggers"""
    
    def test_postgresql_triggers(self, postgres_connection):
        """Test PostgreSQL trigger execution"""
        cursor = postgres_connection.cursor()
        
        # Test BEFORE INSERT trigger
        cursor.execute("INSERT INTO users (email, username, password_hash) VALUES (%s, %s, %s)",
                      ('trigger@test.com', 'triggertest', 'hash'))
        user_id = cursor.fetchone()[0]
        
        # Verify created_at was set by trigger
        cursor.execute("SELECT created_at FROM users WHERE id = %s", (user_id,))
        created_at = cursor.fetchone()[0]
        assert created_at is not None
        
        # Test AFTER UPDATE trigger
        original_time = created_at
        cursor.execute("UPDATE users SET email = %s WHERE id = %s",
                      ('updated@test.com', user_id))
        
        cursor.execute("SELECT modified_at FROM users WHERE id = %s", (user_id,))
        modified_at = cursor.fetchone()[0]
        assert modified_at is not None
        assert modified_at != original_time
        
        cursor.close()
    
    def test_mysql_triggers(self, mysql_connection):
        """Test MySQL trigger execution"""
        cursor = mysql_connection.cursor()
        
        # Test BEFORE INSERT trigger
        cursor.execute("INSERT INTO users (email, username, password_hash) VALUES (%s, %s, %s)",
                      ('trigger@test.com', 'triggertest', 'hash'))
        mysql_connection.commit()
        user_id = cursor.lastrowid
        
        # Verify timestamps were set
        cursor.execute("SELECT created_at, modified_at FROM users WHERE id = %s", (user_id,))
        timestamps = cursor.fetchone()
        assert timestamps[0] is not None  # created_at
        assert timestamps[1] is not None  # modified_at
        
        cursor.close()

class TestFunctions:
    """Test database functions"""
    
    def test_postgresql_functions(self, postgres_connection):
        """Test PostgreSQL function execution"""
        cursor = postgres_connection.cursor()
        
        # Test scalar function
        cursor.execute("SELECT calculate_discount(%s, %s)", (100.00, 0.1))
        result = cursor.fetchone()[0]
        assert result == 90.00
        
        # Test aggregate function
        cursor.execute("SELECT get_user_order_count(%s)", (1,))
        result = cursor.fetchone()[0]
        assert isinstance(result, int)
        
        # Test string function
        cursor.execute("SELECT normalize_email(%s)", ('Test@Example.COM',))
        result = cursor.fetchone()[0]
        assert result == 'test@example.com'
        
        cursor.close()
    
    def test_mysql_functions(self, mysql_connection):
        """Test MySQL function execution"""
        cursor = mysql_connection.cursor()
        
        # Test function execution
        cursor.execute("SELECT calculate_tax(%s, %s)", (100.00, 0.08))
        result = cursor.fetchone()[0]
        assert result == 8.00
        
        cursor.close()

class TestConstraints:
    """Test database constraints"""
    
    def test_unique_constraints(self, postgres_connection):
        """Test unique constraint violations"""
        cursor = postgres_connection.cursor()
        
        # Insert first user
        cursor.execute("INSERT INTO users (email, username, password_hash) VALUES (%s, %s, %s)",
                      ('unique@test.com', 'uniqueuser', 'hash'))
        postgres_connection.commit()
        
        # Try to insert duplicate email
        with pytest.raises(psycopg2.IntegrityError):
            cursor.execute("INSERT INTO users (email, username, password_hash) VALUES (%s, %s, %s)",
                          ('unique@test.com', 'anotheruser', 'hash'))
        
        cursor.close()
    
    def test_foreign_key_constraints(self, postgres_connection):
        """Test foreign key constraint violations"""
        cursor = postgres_connection.cursor()
        
        # Try to insert order with non-existent user
        with pytest.raises(psycopg2.IntegrityError):
            cursor.execute("INSERT INTO orders (user_id, total_amount, status) VALUES (%s, %s, %s)",
                          (99999, 100.00, 'pending'))
        
        cursor.close()
    
    def test_check_constraints(self, postgres_connection):
        """Test check constraint violations"""
        cursor = postgres_connection.cursor()
        
        # Try to insert negative price
        with pytest.raises(psycopg2.IntegrityError):
            cursor.execute("INSERT INTO products (name, price, stock) VALUES (%s, %s, %s)",
                          ('Invalid Product', -10.00, 10))
        
        cursor.close()

# ====================
# TEST FIXTURES AND UTILITIES
# ====================

@pytest.fixture
def postgres_connection():
    """PostgreSQL test database connection"""
    conn = psycopg2.connect(
        host="localhost",
        database="test_db",
        user="test_user",
        password="test_pass"
    )
    yield conn
    conn.close()

@pytest.fixture
def mysql_connection():
    """MySQL test database connection"""
    conn = mysql.connector.connect(
        host="localhost",
        database="test_db",
        user="test_user",
        password="test_pass"
    )
    yield conn
    conn.close()

@pytest.fixture
def sqlite_connection():
    """SQLite test database connection"""
    conn = sqlite3.connect(":memory:")
    yield conn
    conn.close()

class DatabaseTestData:
    """Factory for creating database test data"""
    
    @staticmethod
    def create_test_user(overrides=None):
        """Create test user data"""
        default = {
            'email': 'test@example.com',
            'username': 'testuser',
            'password_hash': 'hashed_password',
            'created_at': datetime.now()
        }
        if overrides:
            default.update(overrides)
        return default
    
    @staticmethod
    def create_test_product(overrides=None):
        """Create test product data"""
        default = {
            'name': 'Test Product',
            'price': 10.00,
            'stock': 100,
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
            'total_amount': 50.00,
            'status': 'pending',
            'created_at': datetime.now()
        }
        if overrides:
            default.update(overrides)
        return default

# Test configuration
TEST_CONFIG = {
    'postgresql': {
        'host': 'localhost',
        'port': 5432,
        'database': 'test_db',
        'user': 'test_user',
        'password': 'test_pass'
    },
    'mysql': {
        'host': 'localhost',
        'port': 3306,
        'database': 'test_db',
        'user': 'test_user',
        'password': 'test_pass'
    },
    'sqlite': {
        'database': ':memory:'
    }
}

# Migration test utilities
class MigrationTester:
    """Utility class for testing database migrations"""
    
    @staticmethod
    def test_migration_up(migration_file, connection):
        """Test migration up execution"""
        with open(migration_file, 'r') as f:
            migration_sql = f.read()
        
        cursor = connection.cursor()
        try:
            cursor.execute(migration_sql)
            connection.commit()
            return True
        except Exception as e:
            connection.rollback()
            raise e
        finally:
            cursor.close()
    
    @staticmethod
    def test_migration_down(migration_file, connection):
        """Test migration down execution (rollback)"""
        # Assuming migration file has rollback section
        with open(migration_file, 'r') as f:
            content = f.read()
        
        # Extract rollback SQL (implementation depends on migration format)
        rollback_sql = MigrationTester._extract_rollback_sql(content)
        
        cursor = connection.cursor()
        try:
            cursor.execute(rollback_sql)
            connection.commit()
            return True
        except Exception as e:
            connection.rollback()
            raise e
        finally:
            cursor.close()
    
    @staticmethod
    def _extract_rollback_sql(migration_content):
        """Extract rollback SQL from migration file"""
        # Simple implementation - look for rollback marker
        lines = migration_content.split('\n')
        rollback_start = False
        rollback_sql = []
        
        for line in lines:
            if '-- ROLLBACK' in line or '-- DOWN' in line:
                rollback_start = True
                continue
            if rollback_start:
                rollback_sql.append(line)
        
        return '\n'.join(rollback_sql)

# Performance testing utilities
class PerformanceTester:
    """Utility class for database performance testing"""
    
    @staticmethod
    def measure_query_execution(query, connection, params=None, iterations=100):
        """Measure query execution time"""
        import time
        
        cursor = connection.cursor()
        times = []
        
        for _ in range(iterations):
            start_time = time.time()
            cursor.execute(query, params or ())
            cursor.fetchall()
            end_time = time.time()
            times.append(end_time - start_time)
        
        cursor.close()
        
        return {
            'min_time': min(times),
            'max_time': max(times),
            'avg_time': sum(times) / len(times),
            'total_time': sum(times)
        }
    
    @staticmethod
    def test_index_effectiveness(table_name, column_name, connection):
        """Test if index improves query performance"""
        cursor = connection.cursor()
        
        # Query without index
        query_no_index = f"SELECT * FROM {table_name} WHERE {column_name} = %s"
        
        # Create index
        cursor.execute(f"CREATE INDEX idx_test ON {table_name}({column_name})")
        connection.commit()
        
        # Query with index
        query_with_index = f"SELECT * FROM {table_name} WHERE {column_name} = %s"
        
        # Measure both queries
        params = ('test_value',)
        time_no_index = PerformanceTester.measure_query_execution(query_no_index, connection, params, 50)
        time_with_index = PerformanceQuery_execution(query_with_index, connection, params, 50)
        
        # Cleanup
        cursor.execute(f"DROP INDEX idx_test")
        connection.commit()
        cursor.close()
        
        return {
            'without_index': time_no_index,
            'with_index': time_with_index,
            'improvement': time_no_index['avg_time'] / time_with_index['avg_time']
        }

# Usage example
if __name__ == "__main__":
    print("SQL Unit Testing Template loaded!")
    print("Components included:")
    print("- PostgreSQL, MySQL, SQLite unit tests")
    print("- Stored procedure testing")
    print("- Trigger testing")
    print("- Function testing")
    print("- Schema validation tests")
    print("- Python database testing utilities")
    print("- Migration testing utilities")
    print("- Performance testing utilities")
    print("- Test fixtures and data factories")
    
    print("\nTo use this template:")
    print("1. Copy relevant test sections to your test files")
    print("2. Adapt database connection details")
    print("3. Modify test data to match your schema")
    print("4. Run tests with appropriate database engine")
    
    print("\nUnit testing template completed!")
```