<!--
File: FRAMEWORK-PATTERNS-sql.tpl.md
Purpose: Template for unknown implementation
Template Version: 1.0
-->

# SQL Framework Patterns - {{PROJECT_NAME}}

**Tier**: {{TIER}} | **Stack**: SQL

## 🗄️ SQL's Role in Your Ecosystem

SQL serves as the **data persistence layer** - your "store, retrieve, and analyze data reliably" foundation. It handles database schema design, query optimization, data integrity, and complex data operations.

### **Core Responsibilities**
- **Database Schema Design**: Table structures, relationships, constraints
- **Data Integrity**: Constraints, triggers, validation rules
- **Query Optimization**: Indexes, query plans, performance tuning
- **Data Migration**: Schema evolution and versioning
- **Complex Operations**: Stored procedures, functions, transactions

## 🏗️ Three Pillars Integration

### **1. Universal Principles Applied to SQL**
- **Clean Architecture**: Separation of concerns with views, stored procedures
- **Dependency Management**: Foreign keys, constraints, referential integrity
- **Testing Strategy**: Data validation, query performance testing
- **Configuration Management**: Environment-specific database settings

### **2. Tier-Specific SQL Patterns**

#### **MVP Tier - Simple Data Storage**
**Purpose**: Basic data storage with minimal complexity
**Characteristics**:
- Simple table structures with basic constraints
- Basic CRUD operations
- Minimal indexing
- Simple queries without joins
- No stored procedures

**When to Use**:
- Prototyping database schemas
- Simple applications with basic data needs
- Learning SQL fundamentals
- Internal tools with simple data requirements

**MVP SQL Pattern**:
```sql
-- Simple user table
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    name VARCHAR(100) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Basic CRUD operations
INSERT INTO users (email, name) VALUES ('user@example.com', 'Test User');
SELECT * FROM users WHERE id = 1;
UPDATE users SET name = 'Updated Name' WHERE id = 1;
DELETE FROM users WHERE id = 1;
```

#### **CORE Tier - Production Database**
**Purpose**: Real-world database design with proper architecture
**Characteristics**:
- Normalized schema design
- Proper indexing strategy
- Complex queries with joins
- Stored procedures for common operations
- Transactions for data integrity
- Basic performance optimization

**When to Use**:
- Production applications
- SaaS database backends
- Enterprise internal databases
- Applications with moderate complexity

**CORE SQL Pattern**:
```sql
-- Normalized schema with relationships
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    name VARCHAR(100) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

CREATE TABLE orders (
    id SERIAL PRIMARY KEY,
    user_id INT NOT NULL,
    order_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(20) DEFAULT 'pending',
    total_amount DECIMAL(10, 2) NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_user_id (user_id),
    INDEX idx_order_date (order_date)
);

-- Stored procedure for order creation
DELIMITER //
CREATE PROCEDURE create_order(
    IN p_user_id INT,
    IN p_total_amount DECIMAL(10, 2),
    OUT p_order_id INT
)
BEGIN
    DECLARE EXIT HANDLER FOR SQLEXCEPTION
    BEGIN
        ROLLBACK;
        RESIGNAL;
    END;
    
    START TRANSACTION;
    
    INSERT INTO orders (user_id, total_amount) 
    VALUES (p_user_id, p_total_amount);
    
    SET p_order_id = LAST_INSERT_ID();
    
    COMMIT;
END //
DELIMITER ;

-- Complex query with joins
SELECT 
    u.id AS user_id,
    u.name AS user_name,
    u.email AS user_email,
    COUNT(o.id) AS order_count,
    SUM(o.total_amount) AS total_spent
FROM users u
LEFT JOIN orders o ON u.id = o.user_id
WHERE u.created_at > DATE_SUB(NOW(), INTERVAL 30 DAY)
GROUP BY u.id, u.name, u.email
ORDER BY total_spent DESC
LIMIT 10;
```

#### **FULL Tier - Enterprise Database**
**Purpose**: Large-scale database systems with enterprise requirements
**Characteristics**:
- Advanced schema design with partitioning
- Complex indexing strategies
- Advanced stored procedures and functions
- Comprehensive transaction management
- Performance optimization and tuning
- Security and compliance features
- Advanced data integrity mechanisms

**When to Use**:
- Fortune 500 database systems
- High-traffic applications
- Complex enterprise applications
- Applications with strict compliance requirements

**FULL SQL Pattern**:
```sql
-- Advanced schema with partitioning and constraints
CREATE TABLE orders (
    id BIGINT PRIMARY KEY,
    user_id INT NOT NULL,
    order_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(20) DEFAULT 'pending',
    total_amount DECIMAL(12, 2) NOT NULL,
    payment_method VARCHAR(50),
    shipping_address TEXT,
    billing_address TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE RESTRICT,
    CONSTRAINT chk_status CHECK (status IN ('pending', 'processing', 'shipped', 'delivered', 'cancelled')),
    CONSTRAINT chk_amount CHECK (total_amount > 0)
) PARTITION BY RANGE (YEAR(order_date)) (
    PARTITION p2023 VALUES LESS THAN (2024),
    PARTITION p2024 VALUES LESS THAN (2025),
    PARTITION pmax VALUES LESS THAN MAXVALUE
);

-- Advanced stored procedure with error handling and logging
DELIMITER //
CREATE PROCEDURE process_payment(
    IN p_order_id BIGINT,
    IN p_payment_amount DECIMAL(12, 2),
    IN p_payment_method VARCHAR(50),
    OUT p_success BOOLEAN,
    OUT p_message VARCHAR(255)
)
BEGIN
    DECLARE v_order_total DECIMAL(12, 2);
    DECLARE v_user_id INT;
    DECLARE v_current_status VARCHAR(20);
    
    DECLARE EXIT HANDLER FOR SQLEXCEPTION
    BEGIN
        ROLLBACK;
        SET p_success = FALSE;
        SET p_message = 'Payment processing failed: SQL Exception';
    END;
    
    DECLARE EXIT HANDLER FOR SQLWARNING
    BEGIN
        ROLLBACK;
        SET p_success = FALSE;
        SET p_message = 'Payment processing failed: SQL Warning';
    END;
    
    START TRANSACTION;
    
    -- Validate order
    SELECT total_amount, user_id, status INTO v_order_total, v_user_id, v_current_status
    FROM orders WHERE id = p_order_id FOR UPDATE;
    
    IF v_current_status != 'pending' THEN
        SIGNAL SQLSTATE '45000' 
        SET MESSAGE_TEXT = 'Order is not in pending status';
    END IF;
    
    IF p_payment_amount != v_order_total THEN
        SIGNAL SQLSTATE '45000' 
        SET MESSAGE_TEXT = 'Payment amount does not match order total';
    END IF;
    
    -- Process payment
    INSERT INTO payments (
        order_id, user_id, amount, payment_method, 
        payment_date, status
    ) VALUES (
        p_order_id, v_user_id, p_payment_amount, p_payment_method,
        NOW(), 'completed'
    );
    
    -- Update order status
    UPDATE orders 
    SET status = 'processing', 
        payment_method = p_payment_method,
        updated_at = NOW()
    WHERE id = p_order_id;
    
    -- Log payment
    INSERT INTO payment_logs (
        order_id, user_id, amount, payment_method,
        log_date, log_message
    ) VALUES (
        p_order_id, v_user_id, p_payment_amount, p_payment_method,
        NOW(), 'Payment processed successfully'
    );
    
    COMMIT;
    
    SET p_success = TRUE;
    SET p_message = 'Payment processed successfully';
END //
DELIMITER ;

-- Advanced query with CTEs, window functions, and complex joins
WITH user_order_stats AS (
    SELECT 
        u.id AS user_id,
        u.name AS user_name,
        COUNT(o.id) AS order_count,
        SUM(o.total_amount) AS total_spent,
        AVG(o.total_amount) AS avg_order_value,
        MAX(o.order_date) AS last_order_date
    FROM users u
    JOIN orders o ON u.id = o.user_id
    WHERE o.order_date > DATE_SUB(NOW(), INTERVAL 1 YEAR)
    GROUP BY u.id, u.name
),
user_rankings AS (
    SELECT 
        user_id,
        user_name,
        order_count,
        total_spent,
        avg_order_value,
        last_order_date,
        RANK() OVER (ORDER BY total_spent DESC) AS spend_rank,
        RANK() OVER (ORDER BY order_count DESC) AS frequency_rank
    FROM user_order_stats
)
SELECT 
    ur.user_id,
    ur.user_name,
    ur.order_count,
    ur.total_spent,
    ur.avg_order_value,
    ur.last_order_date,
    ur.spend_rank,
    ur.frequency_rank,
    CASE 
        WHEN ur.spend_rank <= 10 THEN 'VIP'
        WHEN ur.spend_rank <= 50 THEN 'Premium'
        WHEN ur.spend_rank <= 100 THEN 'Standard'
        ELSE 'Basic'
    END AS customer_tier
FROM user_rankings ur
ORDER BY ur.spend_rank, ur.frequency_rank
LIMIT 100;
```

## 🗃️ Blessed Patterns (Never Deviate)

### **Schema Design: Normalized with Strategic Denormalization**
**Why**: Balance between data integrity and performance

**Schema Design Patterns**:
```sql
-- MVP: Simple normalized schema
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    name VARCHAR(100) NOT NULL
);

CREATE TABLE orders (
    id SERIAL PRIMARY KEY,
    user_id INT NOT NULL,
    total_amount DECIMAL(10, 2) NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- CORE: Normalized with proper constraints
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    name VARCHAR(100) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    CONSTRAINT chk_email CHECK (email LIKE '%@%.%')
);

CREATE TABLE addresses (
    id SERIAL PRIMARY KEY,
    user_id INT NOT NULL,
    address_type VARCHAR(20) NOT NULL,
    street VARCHAR(255) NOT NULL,
    city VARCHAR(100) NOT NULL,
    state VARCHAR(100) NOT NULL,
    zip_code VARCHAR(20) NOT NULL,
    country VARCHAR(100) NOT NULL,
    is_default BOOLEAN DEFAULT FALSE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    CONSTRAINT chk_address_type CHECK (address_type IN ('shipping', 'billing'))
);

-- FULL: Advanced schema with partitioning and complex constraints
CREATE TABLE orders (
    id BIGINT PRIMARY KEY,
    user_id INT NOT NULL,
    order_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(20) DEFAULT 'pending',
    total_amount DECIMAL(12, 2) NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE RESTRICT,
    CONSTRAINT chk_status CHECK (status IN ('pending', 'processing', 'shipped', 'delivered', 'cancelled')),
    CONSTRAINT chk_amount CHECK (total_amount > 0),
    INDEX idx_order_date (order_date),
    INDEX idx_user_status (user_id, status)
) PARTITION BY RANGE (YEAR(order_date));
```

### **Indexing: Strategic Indexing for Performance**
**Why**: Optimize query performance without over-indexing

**Indexing Patterns**:
```sql
-- MVP: Basic indexing
CREATE INDEX idx_user_email ON users(email);
CREATE INDEX idx_order_user_id ON orders(user_id);

-- CORE: Composite indexes for common queries
CREATE INDEX idx_order_user_date ON orders(user_id, order_date);
CREATE INDEX idx_order_status_date ON orders(status, order_date);

-- FULL: Advanced indexing strategies
-- Covering index for specific queries
CREATE INDEX idx_order_covering ON orders(user_id, order_date, status, total_amount);

-- Partial index for specific conditions
CREATE INDEX idx_active_users ON users(id) WHERE is_active = TRUE;

-- Functional index for computed values
CREATE INDEX idx_user_name_lower ON users(LOWER(name));
```

### **Transactions: ACID Compliance**
**Why**: Ensure data integrity in complex operations

**Transaction Patterns**:
```sql
-- MVP: Simple transaction
START TRANSACTION;
INSERT INTO users (email, name) VALUES ('user@example.com', 'Test User');
INSERT INTO orders (user_id, total_amount) VALUES (LAST_INSERT_ID(), 100.00);
COMMIT;

-- CORE: Transaction with error handling
START TRANSACTION;

DECLARE EXIT HANDLER FOR SQLEXCEPTION
BEGIN
    ROLLBACK;
    RESIGNAL;
END;

-- Business logic here
INSERT INTO users (email, name) VALUES ('user@example.com', 'Test User');
SET @user_id = LAST_INSERT_ID();

INSERT INTO orders (user_id, total_amount) VALUES (@user_id, 100.00);

COMMIT;

-- FULL: Advanced transaction with savepoints
START TRANSACTION;

SAVEPOINT before_user_insert;
INSERT INTO users (email, name) VALUES ('user@example.com', 'Test User');

SAVEPOINT before_order_insert;
INSERT INTO orders (user_id, total_amount) VALUES (LAST_INSERT_ID(), 100.00);

-- If something goes wrong, rollback to specific savepoint
-- ROLLBACK TO SAVEPOINT before_order_insert;

COMMIT;
```

## 🔧 Stored Procedures and Functions

### **Stored Procedures: Encapsulated Business Logic**
**Why**: Centralize complex operations and ensure consistency

**Stored Procedure Patterns**:
```sql
-- MVP: Simple stored procedure
DELIMITER //
CREATE PROCEDURE get_user_orders(IN user_id INT)
BEGIN
    SELECT * FROM orders WHERE user_id = user_id ORDER BY order_date DESC;
END //
DELIMITER ;

-- CORE: Stored procedure with parameters and error handling
DELIMITER //
CREATE PROCEDURE create_user_with_address(
    IN p_email VARCHAR(255),
    IN p_name VARCHAR(100),
    IN p_street VARCHAR(255),
    IN p_city VARCHAR(100),
    IN p_state VARCHAR(100),
    IN p_zip_code VARCHAR(20),
    IN p_country VARCHAR(100),
    OUT p_user_id INT
)
BEGIN
    DECLARE EXIT HANDLER FOR SQLEXCEPTION
    BEGIN
        ROLLBACK;
        RESIGNAL;
    END;
    
    START TRANSACTION;
    
    INSERT INTO users (email, name) VALUES (p_email, p_name);
    SET p_user_id = LAST_INSERT_ID();
    
    INSERT INTO addresses (
        user_id, address_type, street, city, state, zip_code, country, is_default
    ) VALUES (
        p_user_id, 'shipping', p_street, p_city, p_state, p_zip_code, p_country, TRUE
    );
    
    COMMIT;
END //
DELIMITER ;

-- FULL: Advanced stored procedure with complex logic
DELIMITER //
CREATE PROCEDURE process_monthly_invoices()
BEGIN
    DECLARE done INT DEFAULT FALSE;
    DECLARE order_id INT;
    DECLARE user_id INT;
    DECLARE total_amount DECIMAL(12, 2);
    DECLARE invoice_number VARCHAR(50);
    
    DECLARE cur CURSOR FOR
        SELECT id, user_id, total_amount 
        FROM orders 
        WHERE status = 'completed' 
        AND invoice_id IS NULL 
        AND order_date >= DATE_FORMAT(DATE_SUB(NOW(), INTERVAL 1 MONTH), '%Y-%m-01');
    
    DECLARE CONTINUE HANDLER FOR NOT FOUND SET done = TRUE;
    
    OPEN cur;
    
    read_loop: LOOP
        FETCH cur INTO order_id, user_id, total_amount;
        IF done THEN
            LEAVE read_loop;
        END IF;
        
        -- Generate invoice number
        SET invoice_number = CONCAT('INV-', DATE_FORMAT(NOW(), '%Y%m'), '-', order_id);
        
        -- Create invoice
        INSERT INTO invoices (
            invoice_number, user_id, order_id, amount, 
            issue_date, due_date, status
        ) VALUES (
            invoice_number, user_id, order_id, total_amount,
            NOW(), DATE_ADD(NOW(), INTERVAL 30 DAY), 'pending'
        );
        
        -- Update order with invoice reference
        UPDATE orders SET invoice_id = LAST_INSERT_ID() WHERE id = order_id;
        
        -- Log the operation
        INSERT INTO invoice_logs (
            invoice_id, operation, operation_date, details
        ) VALUES (
            LAST_INSERT_ID(), 'created', NOW(), 
            CONCAT('Invoice created for order ', order_id)
        );
    END LOOP;
    
    CLOSE cur;
END //
DELIMITER ;
```

### **Functions: Reusable Logic**
**Why**: Encapsulate reusable calculations and transformations

**Function Patterns**:
```sql
-- MVP: Simple function
DELIMITER //
CREATE FUNCTION calculate_discount(amount DECIMAL(10, 2)) 
RETURNS DECIMAL(10, 2)
DETERMINISTIC
BEGIN
    IF amount > 1000 THEN
        RETURN amount * 0.10; -- 10% discount
    ELSEIF amount > 500 THEN
        RETURN amount * 0.05; -- 5% discount
    ELSE
        RETURN 0;
    END IF;
END //
DELIMITER ;

-- CORE: Function with complex logic
DELIMITER //
CREATE FUNCTION calculate_order_total(order_id INT) 
RETURNS DECIMAL(12, 2)
READS SQL DATA
BEGIN
    DECLARE subtotal DECIMAL(12, 2);
    DECLARE tax_rate DECIMAL(5, 2);
    DECLARE shipping_cost DECIMAL(10, 2);
    DECLARE discount_amount DECIMAL(10, 2);
    
    -- Get subtotal from order items
    SELECT SUM(price * quantity) INTO subtotal
    FROM order_items WHERE order_id = order_id;
    
    -- Get tax rate based on shipping address
    SELECT tax_rate INTO tax_rate
    FROM addresses a JOIN tax_rates t ON a.state = t.state
    WHERE a.user_id = (SELECT user_id FROM orders WHERE id = order_id)
    AND a.address_type = 'shipping'
    LIMIT 1;
    
    -- Calculate shipping cost
    IF subtotal > 100 THEN
        SET shipping_cost = 0; -- Free shipping
    ELSE
        SET shipping_cost = 9.99;
    END IF;
    
    -- Calculate discount
    SET discount_amount = calculate_discount(subtotal);
    
    -- Return total
    RETURN (subtotal - discount_amount) * (1 + tax_rate) + shipping_cost;
END //
DELIMITER ;

-- FULL: Advanced function with JSON processing
DELIMITER //
CREATE FUNCTION get_user_profile(user_id INT) 
RETURNS JSON
READS SQL DATA
BEGIN
    DECLARE user_data JSON;
    DECLARE order_data JSON;
    DECLARE result JSON;
    
    -- Get user data
    SELECT JSON_OBJECT(
        'id', id,
        'email', email,
        'name', name,
        'created_at', created_at,
        'last_login', last_login
    ) INTO user_data
    FROM users WHERE id = user_id;
    
    -- Get order statistics
    SELECT JSON_OBJECT(
        'total_orders', COUNT(id),
        'total_spent', COALESCE(SUM(total_amount), 0),
        'avg_order_value', COALESCE(AVG(total_amount), 0),
        'last_order_date', MAX(order_date)
    ) INTO order_data
    FROM orders WHERE user_id = user_id;
    
    -- Combine data
    SET result = JSON_OBJECT(
        'user', user_data,
        'orders', order_data,
        'metadata', JSON_OBJECT(
            'generated_at', NOW(),
            'user_id', user_id
        )
    );
    
    RETURN result;
END //
DELIMITER ;
```

## 🧪 Testing Strategy by Tier

### **MVP Testing**
- Basic query validation
- Simple data integrity tests
- Manual testing of CRUD operations

### **CORE Testing**
- Query performance testing
- Data integrity validation
- Stored procedure testing
- Transaction rollback testing

### **FULL Testing**
- All CORE tests plus:
- Load testing with large datasets
- Concurrency testing
- Backup and restore testing
- Disaster recovery testing

## 📊 Performance Optimization

### **Query Optimization**
```sql
-- MVP: Basic query optimization
EXPLAIN SELECT * FROM users WHERE email = 'user@example.com';

-- CORE: Query optimization with indexes
EXPLAIN ANALYZE 
SELECT u.*, COUNT(o.id) as order_count
FROM users u
LEFT JOIN orders o ON u.id = o.user_id
WHERE u.created_at > '2023-01-01'
GROUP BY u.id;

-- FULL: Advanced query optimization
-- Use query hints for complex queries
SELECT /*+ INDEX(users idx_user_email) */ * 
FROM users WHERE email LIKE 'user%';

-- Optimize joins
SELECT u.id, u.name, o.total_amount
FROM users u
INNER JOIN orders o ON u.id = o.user_id
WHERE o.order_date BETWEEN '2023-01-01' AND '2023-12-31'
ORDER BY o.total_amount DESC
LIMIT 100;
```

### **Database Maintenance**
```sql
-- MVP: Basic maintenance
ANALYZE TABLE users;
OPTIMIZE TABLE orders;

-- CORE: Regular maintenance
-- Rebuild indexes
ALTER TABLE users DISABLE KEYS;
ALTER TABLE users ENABLE KEYS;

-- Update statistics
ANALYZE TABLE users, orders;

-- FULL: Advanced maintenance
-- Partition management
ALTER TABLE orders REORGANIZE PARTITION p2023 INTO (
    PARTITION p2023_1 VALUES LESS THAN (2024),
    PARTITION p2023_2 VALUES LESS THAN (2025)
);

-- Index optimization
ALTER TABLE orders ADD INDEX idx_order_date_status (order_date, status);
ALTER TABLE orders DROP INDEX idx_order_date;
```

## 🔒 Security Best Practices

### **SQL Injection Prevention**
```sql
-- Always use parameterized queries
PREPARE stmt FROM 'SELECT * FROM users WHERE email = ?';
SET @email = 'user@example.com';
EXECUTE stmt USING @email;
DEALLOCATE PREPARE stmt;

-- Use stored procedures with parameters
CALL get_user_by_email('user@example.com');
```

### **Data Protection**
```sql
-- Encrypt sensitive data
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    name VARCHAR(100) NOT NULL,
    password_hash VARCHAR(255) NOT NULL, -- Always store hashes, never plain text
    credit_card_number VARCHAR(255), -- Should be encrypted
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Use database-level encryption
-- MySQL: CREATE TABLE sensitive_data (...) ENCRYPTED=YES;
-- PostgreSQL: pgcrypto extension for encryption functions
```

### **Access Control**
```sql
-- MVP: Basic user roles
CREATE ROLE app_user;
CREATE ROLE app_admin;

-- CORE: Granular permissions
GRANT SELECT, INSERT, UPDATE ON users TO app_user;
GRANT ALL PRIVILEGES ON users TO app_admin;

-- FULL: Advanced access control
-- Create application-specific users
CREATE USER 'app_readonly'@'localhost' IDENTIFIED BY 'password';
GRANT SELECT ON database.* TO 'app_readonly'@'localhost';

CREATE USER 'app_readwrite'@'localhost' IDENTIFIED BY 'password';
GRANT SELECT, INSERT, UPDATE ON database.* TO 'app_readwrite'@'localhost';

-- Row-level security (PostgreSQL)
ALTER TABLE orders ENABLE ROW LEVEL SECURITY;
CREATE POLICY user_orders_policy ON orders 
    USING (user_id = current_setting('app.current_user_id')::int);
```

## 📈 Monitoring and Maintenance

### **Database Monitoring**
```sql
-- MVP: Basic monitoring queries
SHOW STATUS LIKE 'Connections';
SHOW PROCESSLIST;

-- CORE: Performance monitoring
SELECT 
    table_name,
    table_rows,
    data_length,
    index_length,
    (data_length + index_length) as total_size
FROM information_schema.TABLES
WHERE table_schema = DATABASE()
ORDER BY total_size DESC;

-- FULL: Advanced monitoring
-- Slow query log analysis
SHOW VARIABLES LIKE 'slow_query_log';
SET GLOBAL slow_query_log = 'ON';
SET GLOBAL long_query_time = 1;

-- Performance schema analysis
SELECT * FROM performance_schema.events_statements_summary_by_digest
ORDER BY sum_timer_wait DESC LIMIT 10;
```

### **Backup and Recovery**
```sql
-- MVP: Basic backup
-- mysqldump -u username -p database_name > backup.sql

-- CORE: Scheduled backups
-- Automated backup script
-- mysqldump --single-transaction -u username -p database_name | gzip > backup_$(date +%Y%m%d).sql.gz

-- FULL: Advanced backup strategy
-- Full backup
-- mysqldump --single-transaction --master-data=2 -u username -p database_name > full_backup.sql

-- Incremental backup
-- Use binary log files for point-in-time recovery

-- Backup verification
-- mysql -u username -p database_name < backup.sql
```

## 🔗 Integration Patterns

### **Application Integration**
```sql
-- MVP: Simple application queries
SELECT * FROM users WHERE id = 1;
INSERT INTO orders (user_id, total_amount) VALUES (1, 100.00);

-- CORE: Parameterized queries from application
-- Using prepared statements in application code

-- FULL: Advanced integration with connection pooling
-- Connection pool configuration
-- Database connection with retry logic
-- Query timeouts and circuit breakers
```

### **ETL Integration**
```sql
-- MVP: Simple data export
SELECT * FROM users INTO OUTFILE '/tmp/users.csv'
FIELDS TERMINATED BY ',' OPTIONALLY ENCLOSED BY '"'
LINES TERMINATED BY '\n';

-- CORE: Data transformation
CREATE TABLE transformed_data AS
SELECT 
    id,
    email,
    name,
    created_at,
    CASE 
        WHEN created_at > DATE_SUB(NOW(), INTERVAL 30 DAY) THEN 'new'
        WHEN created_at > DATE_SUB(NOW(), INTERVAL 90 DAY) THEN 'recent'
        ELSE 'old'
    END AS user_segment
FROM users;

-- FULL: Advanced ETL with stored procedures
DELIMITER //
CREATE PROCEDURE export_user_data()
BEGIN
    -- Create temporary table for export
    CREATE TEMPORARY TABLE temp_user_export AS
    SELECT 
        u.id,
        u.email,
        u.name,
        u.created_at,
        COUNT(o.id) as order_count,
        SUM(o.total_amount) as total_spent,
        MAX(o.order_date) as last_order_date
    FROM users u
    LEFT JOIN orders o ON u.id = o.user_id
    GROUP BY u.id, u.email, u.name, u.created_at;
    
    -- Export to CSV
    SELECT * FROM temp_user_export 
    INTO OUTFILE '/tmp/user_export.csv'
    FIELDS TERMINATED BY ',' OPTIONALLY ENCLOSED BY '"'
    LINES TERMINATED BY '\n';
    
    -- Clean up
    DROP TEMPORARY TABLE temp_user_export;
END //
DELIMITER ;
```

## 🚀 Best Practices Summary

### **MVP Best Practices**
- Keep schema simple and focused
- Use basic constraints for data integrity
- Start with simple queries
- Manual testing and validation

### **CORE Best Practices**
- Normalize schema with strategic denormalization
- Implement proper indexing strategy
- Use stored procedures for complex operations
- Implement transaction management
- Regular database maintenance

### **FULL Best Practices**
- Advanced schema design with partitioning
- Comprehensive indexing strategy
- Advanced stored procedures and functions
- Complete transaction management
- Performance optimization and tuning
- Security and compliance features
- Advanced monitoring and maintenance

---*SQL Framework Patterns - Use this as your canonical reference for all SQL database development*
