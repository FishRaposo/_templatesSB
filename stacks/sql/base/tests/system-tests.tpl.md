# SQL System Testing Template
# System testing patterns for SQL/database projects with E2E workflows, performance, replication, and backup/recovery

"""
SQL System Test Patterns
End-to-end database system testing including performance, replication, backup/recovery, and monitoring
"""

-- Database: System Testing Framework
-- Database: Performance and Load Testing
-- Database: Replication and High Availability Testing
-- Database: Backup and Recovery Testing
-- Database: Monitoring and Alerting Testing
-- Database: Security and Access Control Testing

# ====================
# DATABASE SYSTEM TEST PATTERNS
# ====================

## End-to-End Workflow Testing

### Complete Business Process Testing

```sql
-- E2E Business Process Testing Template
-- File: tests/system/test_e2e_business_processes.sql

-- Test setup
CREATE SCHEMA IF NOT EXISTS e2e_test;
SET search_path TO e2e_test;

-- Create comprehensive business schema
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    username VARCHAR(100) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    first_name VARCHAR(100),
    last_name VARCHAR(100),
    phone VARCHAR(20),
    date_of_birth DATE,
    is_verified BOOLEAN DEFAULT FALSE,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE user_addresses (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    address_type VARCHAR(20) NOT NULL CHECK (address_type IN ('billing', 'shipping', 'both')),
    street_address VARCHAR(255) NOT NULL,
    city VARCHAR(100) NOT NULL,
    state VARCHAR(100),
    postal_code VARCHAR(20) NOT NULL,
    country VARCHAR(100) NOT NULL,
    is_default BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE billing_plans (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) UNIQUE NOT NULL,
    description TEXT,
    price_cents INTEGER NOT NULL CHECK (price_cents >= 0),
    billing_cycle VARCHAR(20) NOT NULL CHECK (billing_cycle IN ('monthly', 'yearly', 'one_time')),
    trial_days INTEGER DEFAULT 0,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE user_subscriptions (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    billing_plan_id INTEGER REFERENCES billing_plans(id),
    status VARCHAR(50) NOT NULL DEFAULT 'active' CHECK (status IN ('trial', 'active', 'cancelled', 'expired', 'suspended')),
    current_period_start TIMESTAMP NOT NULL,
    current_period_end TIMESTAMP NOT NULL,
    trial_end_date TIMESTAMP,
    cancel_at_period_end BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id, billing_plan_id)
);

CREATE TABLE product_categories (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) UNIQUE NOT NULL,
    description TEXT,
    parent_id INTEGER REFERENCES product_categories(id),
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE products (
    id SERIAL PRIMARY KEY,
    category_id INTEGER REFERENCES product_categories(id),
    sku VARCHAR(50) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    price_cents INTEGER NOT NULL CHECK (price_cents >= 0),
    cost_cents INTEGER DEFAULT 0 CHECK (cost_cents >= 0),
    weight_grams INTEGER DEFAULT 0,
    dimensions JSONB DEFAULT '{"length": 0, "width": 0, "height": 0}',
    images JSONB DEFAULT '[]',
    is_active BOOLEAN DEFAULT TRUE,
    is_featured BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE product_inventory (
    product_id INTEGER PRIMARY KEY REFERENCES products(id),
    quantity_available INTEGER NOT NULL DEFAULT 0 CHECK (quantity_available >= 0),
    quantity_reserved INTEGER NOT NULL DEFAULT 0 CHECK (quantity_reserved >= 0),
    reorder_level INTEGER DEFAULT 10,
    reorder_quantity INTEGER DEFAULT 50,
    last_restocked TIMESTAMP,
    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE shopping_carts (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    session_id VARCHAR(255),
    status VARCHAR(50) DEFAULT 'active' CHECK (status IN ('active', 'abandoned', 'converted')),
    total_cents INTEGER DEFAULT 0,
    item_count INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP + INTERVAL '30 days'
);

CREATE TABLE shopping_cart_items (
    id SERIAL PRIMARY KEY,
    cart_id INTEGER REFERENCES shopping_carts(id) ON DELETE CASCADE,
    product_id INTEGER REFERENCES products(id),
    quantity INTEGER NOT NULL CHECK (quantity > 0),
    unit_price_cents INTEGER NOT NULL,
    total_price_cents INTEGER NOT NULL,
    added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(cart_id, product_id)
);

CREATE TABLE payment_methods (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    type VARCHAR(50) NOT NULL CHECK (type IN ('credit_card', 'debit_card', 'paypal', 'bank_transfer')),
    provider VARCHAR(50) NOT NULL,
    last_four VARCHAR(4),
    exp_month INTEGER,
    exp_year INTEGER,
    is_default BOOLEAN DEFAULT FALSE,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE orders (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    billing_address_id INTEGER REFERENCES user_addresses(id),
    shipping_address_id INTEGER REFERENCES user_addresses(id),
    order_number VARCHAR(20) UNIQUE NOT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'confirmed', 'processing', 'shipped', 'delivered', 'cancelled', 'refunded')),
    subtotal_cents INTEGER NOT NULL DEFAULT 0,
    tax_cents INTEGER NOT NULL DEFAULT 0,
    shipping_cents INTEGER NOT NULL DEFAULT 0,
    discount_cents INTEGER NOT NULL DEFAULT 0,
    total_cents INTEGER NOT NULL,
    currency VARCHAR(3) DEFAULT 'USD',
    payment_status VARCHAR(50) DEFAULT 'pending' CHECK (payment_status IN ('pending', 'paid', 'failed', 'refunded')),
    fulfillment_status VARCHAR(50) DEFAULT 'pending' CHECK (fulfillment_status IN ('pending', 'processing', 'shipped', 'delivered', 'returned')),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE order_items (
    id SERIAL PRIMARY KEY,
    order_id INTEGER REFERENCES orders(id) ON DELETE CASCADE,
    product_id INTEGER REFERENCES products(id),
    quantity INTEGER NOT NULL CHECK (quantity > 0),
    unit_price_cents INTEGER NOT NULL,
    discount_cents INTEGER DEFAULT 0,
    tax_cents INTEGER DEFAULT 0,
    total_price_cents INTEGER NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE payments (
    id SERIAL PRIMARY KEY,
    order_id INTEGER REFERENCES orders(id),
    payment_method_id INTEGER REFERENCES payment_methods(id),
    transaction_id VARCHAR(100) UNIQUE,
    amount_cents INTEGER NOT NULL,
    currency VARCHAR(3) DEFAULT 'USD',
    status VARCHAR(50) NOT NULL CHECK (status IN ('pending', 'processing', 'succeeded', 'failed', 'cancelled', 'refunded')),
    gateway_response JSONB,
    failure_reason TEXT,
    processed_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE shipments (
    id SERIAL PRIMARY KEY,
    order_id INTEGER REFERENCES orders(id),
    tracking_number VARCHAR(100),
    carrier VARCHAR(100),
    shipping_method VARCHAR(100),
    weight_grams INTEGER,
    dimensions JSONB,
    status VARCHAR(50) DEFAULT 'preparing' CHECK (status IN ('preparing', 'shipped', 'in_transit', 'delivered', 'returned')),
    shipped_at TIMESTAMP,
    delivered_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- System test for complete E2E business process
BEGIN;
SELECT plan(30);

-- Test 1: Complete user registration and onboarding
SELECT lives_ok(
    $$INSERT INTO users (email, username, password_hash, first_name, last_name, phone, date_of_birth) VALUES 
    ('john.doe@example.com', 'johndoe', '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj/RK.PJ/..G', 'John', 'Doe', '+1234567890', '1990-01-01')$$,
    'Should register new user'
);

SELECT lives_ok(
    $$INSERT INTO user_addresses (user_id, address_type, street_address, city, state, postal_code, country, is_default) VALUES 
    (1, 'both', '123 Main St', 'New York', 'NY', '10001', 'USA', true)$$,
    'Should add user address'
);

-- Test 2: User subscribes to billing plan
SELECT lives_ok(
    $$INSERT INTO billing_plans (name, description, price_cents, billing_cycle, trial_days) VALUES 
    ('Premium Monthly', 'Premium monthly subscription', 999, 'monthly', 7)$$,
    'Should create billing plan'
);

SELECT lives_ok(
    $$INSERT INTO user_subscriptions (user_id, billing_plan_id, status, current_period_start, current_period_end, trial_end_date) VALUES 
    (1, 1, 'trial', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP + INTERVAL '30 days', CURRENT_TIMESTAMP + INTERVAL '7 days')$$,
    'Should create user subscription'
);

-- Test 3: Create product catalog
SELECT lives_ok(
    $$INSERT INTO product_categories (name, description) VALUES 
    ('Electronics', 'Electronic devices and accessories'),
    ('Books', 'Physical and digital books')$$,
    'Should create product categories'
);

SELECT lives_ok(
    $$INSERT INTO products (category_id, sku, name, description, price_cents, cost_cents, stock_quantity) VALUES 
    (1, 'LAPTOP001', 'Premium Laptop', 'High-performance laptop for professionals', 129999, 89999, 50),
    (1, 'MOUSE001', 'Wireless Mouse', 'Ergonomic wireless mouse', 2999, 1999, 200),
    (2, 'BOOK001', 'Database Design Book', 'Comprehensive guide to database design', 4999, 2999, 100)$$,
    'Should create products'
);

SELECT lives_ok(
    $$INSERT INTO product_inventory (product_id, quantity_available, quantity_reserved, reorder_level) VALUES 
    (1, 50, 0, 10),
    (2, 200, 0, 50),
    (3, 100, 0, 20)$$,
    'Should initialize product inventory'
);

-- Test 4: User adds items to shopping cart
SELECT lives_ok(
    $$INSERT INTO shopping_carts (user_id, status) VALUES 
    (1, 'active')$$,
    'Should create shopping cart'
);

SELECT lives_ok(
    $$INSERT INTO shopping_cart_items (cart_id, product_id, quantity, unit_price_cents, total_price_cents) VALUES 
    (1, 1, 1, 129999, 129999),
    (1, 2, 2, 2999, 5998)$$,
    'Should add items to cart'
);

SELECT results_eq(
    $$SELECT total_cents, item_count FROM shopping_carts WHERE id = 1$$,
    $$VALUES (135997, 2)$$,
    'Cart totals should be calculated correctly'
);

-- Test 5: User adds payment method
SELECT lives_ok(
    $$INSERT INTO payment_methods (user_id, type, provider, last_four, exp_month, exp_year, is_default) VALUES 
    (1, 'credit_card', 'stripe', '4242', 12, 2025, true)$$,
    'Should add payment method'
);

-- Test 6: Complete checkout process
SELECT lives_ok(
    $$INSERT INTO orders (user_id, billing_address_id, shipping_address_id, order_number, total_cents, payment_status, fulfillment_status) VALUES 
    (1, 1, 1, 'ORD2024001', 135997, 'pending', 'pending')$$,
    'Should create order from cart'
);

SELECT lives_ok(
    $$INSERT INTO order_items (order_id, product_id, quantity, unit_price_cents, total_price_cents) VALUES 
    (1, 1, 1, 129999, 129999),
    (1, 2, 2, 2999, 5998)$$,
    'Should create order items'
);

-- Test 7: Process payment
SELECT lives_ok(
    $$INSERT INTO payments (order_id, payment_method_id, transaction_id, amount_cents, status) VALUES 
    (1, 1, 'txn_123456789', 135997, 'succeeded')$$,
    'Should process payment'
);

SELECT lives_ok(
    $$UPDATE orders SET payment_status = 'paid', status = 'confirmed' WHERE id = 1$$,
    'Should update order status after payment'
);

-- Test 8: Update inventory after order
SELECT lives_eq(
    $$UPDATE product_inventory SET quantity_available = quantity_available - 1 WHERE product_id = 1$$,
    $$UPDATE product_inventory SET quantity_available = quantity_available - 2 WHERE product_id = 2$$,
    'Should update inventory quantities'
);

SELECT results_eq(
    $$SELECT quantity_available FROM product_inventory WHERE product_id = 1$$,
    $$VALUES (49)$$,
    'Product 1 inventory should be reduced'
);

SELECT results_eq(
    $$SELECT quantity_available FROM product_inventory WHERE product_id = 2$$,
    $$VALUES (198)$$,
    'Product 2 inventory should be reduced'
);

-- Test 9: Create shipment
SELECT lives_ok(
    $$INSERT INTO shipments (order_id, tracking_number, carrier, shipping_method, status) VALUES 
    (1, 'TRK123456789', 'FedEx', 'standard', 'preparing')$$,
    'Should create shipment'
);

SELECT lives_ok(
    $$UPDATE orders SET fulfillment_status = 'processing' WHERE id = 1$$,
    'Should update order fulfillment status'
);

-- Test 10: Complete order fulfillment
SELECT lives_ok(
    $$UPDATE shipments SET status = 'shipped', shipped_at = CURRENT_TIMESTAMP WHERE id = 1$$,
    'Should mark shipment as shipped'
);

SELECT lives_ok(
    $$UPDATE orders SET status = 'shipped', fulfillment_status = 'shipped' WHERE id = 1$$,
    'Should update order to shipped status'
);

SELECT lives_ok(
    $$UPDATE shipments SET status = 'delivered', delivered_at = CURRENT_TIMESTAMP WHERE id = 1$$,
    'Should mark shipment as delivered'
);

SELECT lives_ok(
    $$UPDATE orders SET status = 'delivered', fulfillment_status = 'delivered' WHERE id = 1$$,
    'Should update order to delivered status'
);

-- Test 11: Verify final business state
SELECT results_eq(
    $$SELECT status, payment_status, fulfillment_status FROM orders WHERE id = 1$$,
    $$VALUES ('delivered', 'paid', 'delivered')$$,
    'Order should be in final delivered state'
);

SELECT results_eq(
    $$SELECT status FROM shipments WHERE order_id = 1$$,
    $$VALUES ('delivered')$$,
    'Shipment should be delivered'
);

SELECT results_eq(
    $$SELECT COUNT(*) FROM order_items WHERE order_id = 1$$,
    $$VALUES (2)$$,
    'Should have 2 order items'
);

SELECT results_eq(
    $$SELECT SUM(total_price_cents) FROM order_items WHERE order_id = 1$$,
    $$VALUES (135997)$$,
    'Order items total should match order total'
);

-- Test 12: Test order cancellation workflow
SELECT lives_ok(
    $$INSERT INTO orders (user_id, billing_address_id, shipping_address_id, order_number, total_cents, status) VALUES 
    (1, 1, 1, 'ORD2024002', 5998, 'pending')$$,
    'Should create second order'
);

SELECT lives_ok(
    $$INSERT INTO order_items (order_id, product_id, quantity, unit_price_cents, total_price_cents) VALUES 
    (2, 2, 2, 2999, 5998)$$,
    'Should add items to second order'
);

SELECT lives_ok(
    $$UPDATE orders SET status = 'cancelled' WHERE id = 2$$,
    'Should cancel order'
);

SELECT lives_ok(
    $$UPDATE product_inventory SET quantity_available = quantity_available + 2 WHERE product_id = 2$$,
    'Should restore inventory for cancelled order'
);

SELECT results_eq(
    $$SELECT quantity_available FROM product_inventory WHERE product_id = 2$$,
    $$VALUES (200)$$,
    'Product 2 inventory should be restored'
);

-- Test 13: Test subscription management
SELECT lives_ok(
    $$UPDATE user_subscriptions SET status = 'active' WHERE id = 1$$,
    'Should activate user subscription'
);

SELECT lives_ok(
    $$UPDATE user_subscriptions SET status = 'cancelled', cancel_at_period_end = true WHERE id = 1$$,
    'Should cancel subscription at period end'
);

-- Test 14: Verify data integrity across all tables
SELECT results_eq(
    $$SELECT COUNT(*) FROM users$$,
    $$VALUES (1)$$,
    'Should have exactly 1 user'
);

SELECT results_eq(
    $$SELECT COUNT(*) FROM user_addresses WHERE user_id = 1$$,
    $$VALUES (1)$$,
    'User should have 1 address'
);

SELECT results_eq(
    $$SELECT COUNT(*) FROM user_subscriptions WHERE user_id = 1$$,
    $$VALUES (1)$$,
    'User should have 1 subscription'
);

SELECT results_eq(
    $$SELECT COUNT(*) FROM orders WHERE user_id = 1$$,
    $$VALUES (2)$$,
    'User should have 2 orders'
);

SELECT results_eq(
    $$SELECT COUNT(*) FROM payments WHERE order_id IN (SELECT id FROM orders WHERE user_id = 1)$$,
    $$VALUES (1)$$,
    'User should have 1 payment'
);

SELECT results_eq(
    $$SELECT COUNT(*) FROM shopping_carts WHERE user_id = 1$$,
    $$VALUES (1)$$,
    'User should have 1 shopping cart'
);

SELECT results_eq(
    $$SELECT COUNT(*) FROM payment_methods WHERE user_id = 1$$,
    $$VALUES (1)$$,
    'User should have 1 payment method'
);

-- Test 15: Test complex query performance
SELECT results_eq(
    $$SELECT 
        u.email,
        COUNT(DISTINCT o.id) as order_count,
        SUM(o.total_cents) as total_spent,
        MAX(o.created_at) as last_order_date
    FROM users u
    LEFT JOIN orders o ON u.id = o.user_id
    WHERE u.id = 1
    GROUP BY u.email$$,
    $$VALUES ('john.doe@example.com', 2, 141995, NULL)$$$,
    'Complex user analytics query should return correct results'
);

SELECT * FROM finish();
ROLLBACK;
```

# ====================
# PERFORMANCE AND LOAD TESTING
# ====================

## Database Performance Testing Framework

```sql
-- Performance Testing Template
-- File: tests/system/test_performance.sql

-- Test setup
CREATE SCHEMA IF NOT EXISTS performance_test;
SET search_path TO performance_test;

-- Create performance test tables
CREATE TABLE performance_users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    username VARCHAR(100) UNIQUE NOT NULL,
    data JSONB DEFAULT '{}',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE performance_products (
    id SERIAL PRIMARY KEY,
    sku VARCHAR(50) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    price_cents INTEGER NOT NULL,
    category VARCHAR(100),
    tags JSONB DEFAULT '[]',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE performance_orders (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES performance_users(id),
    order_number VARCHAR(20) UNIQUE NOT NULL,
    total_cents INTEGER NOT NULL,
    status VARCHAR(50) DEFAULT 'pending',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE performance_order_items (
    id SERIAL PRIMARY KEY,
    order_id INTEGER REFERENCES performance_orders(id) ON DELETE CASCADE,
    product_id INTEGER REFERENCES performance_products(id),
    quantity INTEGER NOT NULL,
    unit_price_cents INTEGER NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes for performance testing
CREATE INDEX idx_performance_users_email ON performance_users(email);
CREATE INDEX idx_performance_users_username ON performance_users(username);
CREATE INDEX idx_performance_products_sku ON performance_products(sku);
CREATE INDEX idx_performance_products_category ON performance_products(category);
CREATE INDEX idx_performance_products_price ON performance_products(price_cents);
CREATE INDEX idx_performance_orders_user_id ON performance_orders(user_id);
CREATE INDEX idx_performance_orders_created_at ON performance_orders(created_at);
CREATE INDEX idx_performance_order_items_order_id ON performance_order_items(order_id);
CREATE INDEX idx_performance_order_items_product_id ON performance_order_items(product_id);

-- System test for performance and load
BEGIN;
SELECT plan(25);

-- Test 1: Bulk data insertion performance
SELECT lives_ok(
    $$INSERT INTO performance_users (email, username, data)
    SELECT 
        'user' || i || '@test.com',
        'user' || i,
        jsonb_build_object('index', i, 'random', md5(i::text))
    FROM generate_series(1, 10000) i$$,
    'Should insert 10,000 users efficiently'
);

SELECT lives_ok(
    $$INSERT INTO performance_products (sku, name, description, price_cents, category, tags)
    SELECT 
        'SKU' || LPAD(i::text, 6, '0'),
        'Product ' || i,
        'Description for product ' || i,
        (random() * 10000)::integer,
        CASE (i % 5) 
            WHEN 0 THEN 'Electronics'
            WHEN 1 THEN 'Books'
            WHEN 2 THEN 'Clothing'
            WHEN 3 THEN 'Home'
            ELSE 'Sports'
        END,
        jsonb_build_array('tag' || (i % 10), 'category' || (i % 5))
    FROM generate_series(1, 50000) i$$,
    'Should insert 50,000 products efficiently'
);

-- Test 2: Complex query performance
SELECT results_eq(
    $$SELECT COUNT(*) FROM (
        SELECT p.category, COUNT(*) as product_count, AVG(p.price_cents) as avg_price
        FROM performance_products p
        WHERE p.price_cents BETWEEN 1000 AND 5000
        GROUP BY p.category
        HAVING COUNT(*) > 1000
        ORDER BY avg_price DESC
        LIMIT 10
    ) category_stats$$,
    $$VALUES (5)$$,
    'Complex aggregation query should complete efficiently'
);

-- Test 3: Index performance testing
SELECT results_eq(
    $$SELECT COUNT(*) FROM performance_users WHERE email LIKE '%user999%'$$,
    $$VALUES (21)$$,
    'Indexed email search should be fast'
);

SELECT results_eq(
    $$SELECT COUNT(*) FROM performance_products WHERE category = 'Electronics' AND price_cents BETWEEN 2000 AND 3000$$,
    $$VALUES (2000)$$,
    'Composite indexed search should be fast'
);

-- Test 4: Join performance testing
SELECT lives_ok(
    $$INSERT INTO performance_orders (user_id, order_number, total_cents, created_at)
    SELECT 
        (random() * 9999 + 1)::integer,
        'ORD' || LPAD(i::text, 8, '0'),
        (random() * 50000)::integer,
        CURRENT_TIMESTAMP - (random() * 365)::integer * INTERVAL '1 day'
    FROM generate_series(1, 100000) i$$,
    'Should insert 100,000 orders efficiently'
);

SELECT lives_ok(
    $$INSERT INTO performance_order_items (order_id, product_id, quantity, unit_price_cents)
    SELECT 
        (random() * 99999 + 1)::integer,
        (random() * 49999 + 1)::integer,
        (random() * 5 + 1)::integer,
        (random() * 1000)::integer
    FROM generate_series(1, 300000) i$$,
    'Should insert 300,000 order items efficiently'
);

SELECT results_eq(
    $$SELECT COUNT(*) FROM (
        SELECT u.email, COUNT(o.id) as order_count, SUM(o.total_cents) as total_spent
        FROM performance_users u
        JOIN performance_orders o ON u.id = o.user_id
        WHERE o.created_at >= CURRENT_TIMESTAMP - INTERVAL '30 days'
        GROUP BY u.email
        HAVING COUNT(o.id) > 5
    ) active_users$$,
    $$VALUES (SELECT COUNT(*) FROM performance_users u 
              JOIN performance_orders o ON u.id = o.user_id 
              WHERE o.created_at >= CURRENT_TIMESTAMP - INTERVAL '30 days'
              GROUP BY u.email HAVING COUNT(o.id) > 5)$$$,
    'Complex join query should complete efficiently'
);

-- Test 5: Subquery performance
SELECT results_eq(
    $$SELECT COUNT(*) FROM performance_products p
    WHERE p.id IN (
        SELECT DISTINCT product_id 
        FROM performance_order_items oi
        JOIN performance_orders o ON oi.order_id = o.id
        WHERE o.created_at >= CURRENT_TIMESTAMP - INTERVAL '7 days'
        AND o.total_cents > 10000
    )$$,
    $$VALUES (SELECT COUNT(DISTINCT product_id) FROM performance_order_items oi
              JOIN performance_orders o ON oi.order_id = o.id
              WHERE o.created_at >= CURRENT_TIMESTAMP - INTERVAL '7 days'
              AND o.total_cents > 10000)$$$,
    'Subquery with IN clause should be efficient'
);

-- Test 6: Window function performance
SELECT results_eq(
    $$SELECT COUNT(*) FROM (
        SELECT user_id, 
               COUNT(*) OVER (PARTITION BY user_id) as user_order_count,
               ROW_NUMBER() OVER (PARTITION BY user_id ORDER BY created_at DESC) as order_rank
        FROM performance_orders
        WHERE created_at >= CURRENT_TIMESTAMP - INTERVAL '90 days'
    ) ranked_orders WHERE order_rank <= 5$$,
    $$VALUES (SELECT COUNT(*) FROM (
        SELECT user_id, ROW_NUMBER() OVER (PARTITION BY user_id ORDER BY created_at DESC) as rn
        FROM performance_orders
        WHERE created_at >= CURRENT_TIMESTAMP - INTERVAL '90 days'
    ) t WHERE rn <= 5)$$$,
    'Window function query should be efficient'
);

-- Test 7: JSONB query performance
SELECT results_eq(
    $$SELECT COUNT(*) FROM performance_users WHERE data->>'random' LIKE '%a%'$$,
    $$VALUES (SELECT COUNT(*) FROM performance_users WHERE data->>'random' LIKE '%a%')$$,
    'JSONB query should utilize index efficiently'
);

-- Test 8: Concurrent query performance simulation
SELECT lives_ok(
    $$SELECT COUNT(*) FROM performance_orders WHERE user_id IN (
        SELECT id FROM performance_users WHERE id % 100 = 0
    ) AND created_at >= CURRENT_TIMESTAMP - INTERVAL '1 day'$$,
    'Concurrent query simulation should complete'
);

-- Test 9: Full-text search performance (if enabled)
SELECT lives_ok(
    $$SELECT COUNT(*) FROM performance_products WHERE name ILIKE '%laptop%' OR description ILIKE '%wireless%'$$,
    'Full-text search should complete efficiently'
);

-- Test 10: Aggregation performance
SELECT results_eq(
    $$SELECT COUNT(*) FROM (
        SELECT DATE_TRUNC('day', created_at) as order_date,
               COUNT(*) as daily_orders,
               SUM(total_cents) as daily_revenue,
               AVG(total_cents) as avg_order_value
        FROM performance_orders
        WHERE created_at >= CURRENT_TIMESTAMP - INTERVAL '30 days'
        GROUP BY DATE_TRUNC('day', created_at)
        ORDER BY order_date DESC
    ) daily_stats$$,
    $$VALUES (LEAST(30, (SELECT COUNT(DISTINCT DATE_TRUNC('day', created_at)) FROM performance_orders WHERE created_at >= CURRENT_TIMESTAMP - INTERVAL '30 days')))$$,
    'Daily aggregation should be efficient'
);

-- Test 11: Recursive query performance (if applicable)
SELECT lives_ok(
    $$WITH RECURSIVE date_series AS (
        SELECT CURRENT_TIMESTAMP - INTERVAL '30 days' as date
        UNION ALL
        SELECT date + INTERVAL '1 day'
        FROM date_series
        WHERE date < CURRENT_TIMESTAMP
    )
    SELECT COUNT(*) FROM date_series$$,
    'Recursive date series should complete efficiently'
);

-- Test 12: Cross-table update performance
SELECT lives_ok(
    $$UPDATE performance_products 
    SET price_cents = price_cents * 1.1
    WHERE category = 'Electronics' AND price_cents < 5000$$,
    'Bulk update should complete efficiently'
);

SELECT results_eq(
    $$SELECT COUNT(*) FROM performance_products WHERE category = 'Electronics' AND price_cents BETWEEN 5000 AND 5500$$,
    $$VALUES (SELECT COUNT(*) FROM performance_products WHERE category = 'Electronics' AND price_cents BETWEEN 5000 AND 5500)$$$,
    'Price update should be applied correctly'
);

-- Test 13: Transaction performance
SELECT lives_ok(
    $$BEGIN;
    UPDATE performance_products SET stock_quantity = stock_quantity - 1 WHERE sku = 'SKU000001';
    INSERT INTO performance_order_items (order_id, product_id, quantity, unit_price_cents) 
    VALUES (1, 1, 1, (SELECT price_cents FROM performance_products WHERE id = 1));
    COMMIT;$$,
    'Transaction should complete efficiently'
);

-- Test 14: Vacuum and analyze performance (maintenance)
SELECT lives_ok(
    $$VACUUM ANALYZE performance_products;$$,
    'VACUUM ANALYZE should complete efficiently'
);

-- Test 15: Lock contention simulation
SELECT lives_ok(
    $$SELECT pg_advisory_lock(12345);
    SELECT COUNT(*) FROM performance_orders WHERE total_cents > 50000;
    SELECT pg_advisory_unlock(12345);$$,
    'Advisory lock usage should be efficient'
);

SELECT * FROM finish();
ROLLBACK;
```

# ====================
# REPLICATION AND HIGH AVAILABILITY TESTING
# ====================

## PostgreSQL Replication Testing

```sql
-- Replication Testing Template
-- File: tests/system/test_replication.sql

-- Test setup for replication scenarios
-- Note: This requires a configured replication setup

-- System test for replication functionality
-- This would typically be run against primary/replica setup

/* Primary Database Tests */
-- Test 1: Verify replication slots
SELECT count(*) FROM pg_replication_slots WHERE active = true;

-- Test 2: Verify replication lag
SELECT 
    client_addr,
    state,
    sent_lsn,
    write_lsn,
    flush_lsn,
    replay_lsn,
    write_lag,
    flush_lag,
    replay_lag
FROM pg_stat_replication;

-- Test 3: Create test data on primary
CREATE TABLE IF NOT EXISTS replication_test (
    id SERIAL PRIMARY KEY,
    data TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO replication_test (data) VALUES ('test_replication_data');

-- Test 4: Verify WAL generation
SELECT 
    pg_current_wal_lsn() as current_lsn,
    pg_wal_lsn_diff(pg_current_wal_lsn(), '0/0') as wal_bytes;

/* Replica Database Tests */
-- Test 5: Verify replica is in recovery
SELECT pg_is_in_recovery();

-- Test 6: Verify replica can read data
SELECT COUNT(*) FROM replication_test;

-- Test 7: Verify replica lag (on replica)
SELECT 
    pg_last_wal_receive_lsn(),
    pg_last_wal_replay_lsn(),
    pg_wal_lsn_diff(pg_last_wal_receive_lsn(), pg_last_wal_replay_lsn()) as replay_lag_bytes;

-- Test 8: Test read-only queries on replica
SELECT 
    schemaname,
    tablename,
    n_tup_ins,
    n_tup_upd,
    n_tup_del
FROM pg_stat_user_tables 
WHERE tablename = 'replication_test';
```

## MySQL Replication Testing

```sql
-- MySQL Replication Testing Template
-- File: tests/system/test_mysql_replication.sql

/* Master Database Tests */
-- Test 1: Verify replication status
SHOW MASTER STATUS;

-- Test 2: Verify binlog configuration
SHOW VARIABLES LIKE 'binlog_format';
SHOW VARIABLES LIKE 'log_bin';

-- Test 3: Create test replication data
CREATE TABLE IF NOT EXISTS replication_test (
    id INT AUTO_INCREMENT PRIMARY KEY,
    data VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO replication_test (data) VALUES ('mysql_replication_test');

-- Test 4: Verify slave connections
SHOW PROCESSLIST WHERE Command = 'Binlog Dump';

/* Slave Database Tests */
-- Test 5: Verify slave status
SHOW SLAVE STATUS\G

-- Test 6: Test read-only queries on slave
SELECT COUNT(*) FROM replication_test;

-- Test 7: Verify replication lag
SHOW SLAVE STATUS\G
-- Check Seconds_Behind_Master

-- Test 8: Test slave read performance
SELECT 
    table_schema,
    table_name,
    table_rows,
    data_length,
    index_length
FROM information_schema.tables 
WHERE table_name = 'replication_test';
```

# ====================
# BACKUP AND RECOVERY TESTING
# ====================

## PostgreSQL Backup and Recovery Testing

```sql
-- Backup and Recovery Testing Template
-- File: tests/system/test_backup_recovery.sql

-- Test setup
CREATE SCHEMA IF NOT EXISTS backup_test;
SET search_path TO backup_test;

-- Create test tables for backup/recovery
CREATE TABLE critical_data (
    id SERIAL PRIMARY KEY,
    business_key VARCHAR(100) UNIQUE NOT NULL,
    sensitive_data TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE transaction_log (
    id SERIAL PRIMARY KEY,
    transaction_id VARCHAR(50) UNIQUE NOT NULL,
    user_id INTEGER,
    amount_cents INTEGER NOT NULL,
    transaction_type VARCHAR(50) NOT NULL,
    status VARCHAR(50) DEFAULT 'pending',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    processed_at TIMESTAMP
);

-- System test for backup and recovery
BEGIN;
SELECT plan(20);

-- Test 1: Create test data for backup
SELECT lives_ok(
    $$INSERT INTO critical_data (business_key, sensitive_data) VALUES 
    ('KEY001', 'Critical business data 1'),
    ('KEY002', 'Critical business data 2'),
    ('KEY003', 'Critical business data 3')$$,
    'Should insert critical data'
);

SELECT lives_ok(
    $$INSERT INTO transaction_log (transaction_id, user_id, amount_cents, transaction_type, status) VALUES 
    ('TXN001', 1, 10000, 'payment', 'completed'),
    ('TXN002', 2, 5000, 'refund', 'completed'),
    ('TXN003', 3, 7500, 'payment', 'pending')$$,
    'Should insert transaction data'
);

-- Test 2: Simulate point-in-time backup
SELECT lives_ok(
    $$CREATE TABLE backup_metadata (
        backup_id VARCHAR(50) PRIMARY KEY,
        backup_type VARCHAR(20) NOT NULL,
        start_time TIMESTAMP NOT NULL,
        end_time TIMESTAMP,
        size_bytes BIGINT,
        checksum VARCHAR(64),
        status VARCHAR(20) DEFAULT 'running'
    )$$,
    'Should create backup metadata table'
);

SELECT lives_ok(
    $$INSERT INTO backup_metadata (backup_id, backup_type, start_time) VALUES 
    ('backup_20240101_120000', 'full', CURRENT_TIMESTAMP)$$,
    'Should record backup start'
);

-- Test 3: Simulate backup completion
SELECT lives_ok(
    $$UPDATE backup_metadata SET end_time = CURRENT_TIMESTAMP, size_bytes = 104857600, status = 'completed' WHERE backup_id = 'backup_20240101_120000'$$,
    'Should complete backup'
);

-- Test 4: Test data consistency during backup
SELECT results_eq(
    $$SELECT COUNT(*) FROM critical_data$$,
    $$VALUES (3)$$,
    'Data count should be consistent'
);

SELECT results_eq(
    $$SELECT COUNT(*) FROM transaction_log WHERE status = 'completed'$$,
    $$VALUES (2)$$,
    'Completed transactions should be consistent'
);

-- Test 5: Simulate data corruption and recovery
SELECT lives_ok(
    $$CREATE TABLE corrupted_data AS SELECT * FROM critical_data WHERE id = 1$$,
    'Should simulate corrupted data'
);

SELECT lives_ok(
    $$UPDATE corrupted_data SET sensitive_data = 'CORRUPTED DATA' WHERE id = 1$$,
    'Should corrupt data'
);

-- Test 6: Simulate recovery from backup
SELECT lives_ok(
    $$UPDATE critical_data SET sensitive_data = 'Restored from backup' WHERE id = 1$$,
    'Should restore data from backup'
);

-- Test 7: Test transaction log replay
SELECT lives_ok(
    $$INSERT INTO transaction_log (transaction_id, user_id, amount_cents, transaction_type, status, processed_at) VALUES 
    ('TXN004', 4, 12000, 'payment', 'completed', CURRENT_TIMESTAMP)$$,
    'Should add new transaction after recovery'
);

SELECT results_eq(
    $$SELECT COUNT(*) FROM transaction_log WHERE status = 'completed'$$,
    $$VALUES (3)$$,
    'Completed transactions should include recovered data'
);

-- Test 8: Test incremental backup simulation
SELECT lives_ok(
    $$INSERT INTO backup_metadata (backup_id, backup_type, start_time) VALUES 
    ('backup_20240101_130000', 'incremental', CURRENT_TIMESTAMP)$$,
    'Should start incremental backup'
);

SELECT lives_ok(
    $$UPDATE backup_metadata SET end_time = CURRENT_TIMESTAMP, size_bytes = 10485760, status = 'completed' WHERE backup_id = 'backup_20240101_130000'$$,
    'Should complete incremental backup'
);

-- Test 9: Test backup validation
SELECT results_eq(
    $$SELECT COUNT(*) FROM backup_metadata WHERE status = 'completed'$$,
    $$VALUES (2)$$,
    'Should have completed backups'
);

SELECT results_eq(
    $$SELECT SUM(size_bytes) FROM backup_metadata WHERE status = 'completed'$$,
    $$VALUES (115343360)$$,
    'Total backup size should be correct'
);

-- Test 10: Test disaster recovery simulation
SELECT lives_ok(
    $$CREATE TABLE disaster_recovery_log (
        id SERIAL PRIMARY KEY,
        recovery_point VARCHAR(50),
        recovery_type VARCHAR(20),
        start_time TIMESTAMP,
        end_time TIMESTAMP,
        data_loss_seconds INTEGER,
        status VARCHAR(20)
    )$$,
    'Should create disaster recovery log'
);

SELECT lives_ok(
    $$INSERT INTO disaster_recovery_log (recovery_point, recovery_type, start_time, data_loss_seconds, status) VALUES 
    ('2024-01-01 12:00:00', 'point_in_time', CURRENT_TIMESTAMP, 300, 'running')$$,
    'Should start disaster recovery'
);

SELECT lives_ok(
    $$UPDATE disaster_recovery_log SET end_time = CURRENT_TIMESTAMP, status = 'completed' WHERE id = 1$$,
    'Should complete disaster recovery'
);

-- Test 11: Test backup retention policies
SELECT lives_ok(
    $$ALTER TABLE backup_metadata ADD COLUMN retention_until TIMESTAMP$$,
    'Should add retention policy column'
);

SELECT lives_ok(
    $$UPDATE backup_metadata SET retention_until = CURRENT_TIMESTAMP + INTERVAL '30 days' WHERE backup_type = 'full'$$,
    'Should set retention policy for full backups'
);

SELECT lives_ok(
    $$UPDATE backup_metadata SET retention_until = CURRENT_TIMESTAMP + INTERVAL '7 days' WHERE backup_type = 'incremental'$$,
    'Should set retention policy for incremental backups'
);

-- Test 12: Test recovery time objectives (RTO)
SELECT results_eq(
    $$SELECT EXTRACT(EPOCH FROM (end_time - start_time)) as recovery_time_seconds 
    FROM disaster_recovery_log WHERE id = 1$$,
    $$SELECT EXTRACT(EPOCH FROM (end_time - start_time)) FROM disaster_recovery_log WHERE id = 1$$,
    'Recovery time should be measurable'
);

-- Test 13: Test recovery point objectives (RPO)
SELECT results_eq(
    $$SELECT data_loss_seconds FROM disaster_recovery_log WHERE id = 1$$,
    $$VALUES (300)$$,
    'Data loss should be within RPO'
);

-- Test 14: Test backup corruption detection
SELECT lives_ok(
    $$UPDATE backup_metadata SET checksum = 'invalid_checksum' WHERE backup_id = 'backup_20240101_120000'$$,
    'Should simulate backup corruption'
);

SELECT results_eq(
    $$SELECT COUNT(*) FROM backup_metadata WHERE checksum = 'invalid_checksum'$$,
    $$VALUES (1)$$,
    'Corrupted backup should be detectable'
);

-- Test 15: Test backup restoration validation
SELECT results_eq(
    $$SELECT COUNT(*) FROM critical_data WHERE sensitive_data = 'Restored from backup'$$,
    $$VALUES (1)$$,
    'Restored data should be verifiable'
);

SELECT * FROM finish();
ROLLBACK;
```

# ====================
# MONITORING AND ALERTING TESTING
# ====================

## Database Monitoring System Tests

```sql
-- Monitoring and Alerting Testing Template
-- File: tests/system/test_monitoring.sql

-- Test setup
CREATE SCHEMA IF NOT EXISTS monitoring_test;
SET search_path TO monitoring_test;

-- Create monitoring tables
CREATE TABLE database_metrics (
    id SERIAL PRIMARY KEY,
    metric_name VARCHAR(100) NOT NULL,
    metric_value NUMERIC NOT NULL,
    metric_unit VARCHAR(20),
    tags JSONB DEFAULT '{}',
    recorded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE alert_rules (
    id SERIAL PRIMARY KEY,
    rule_name VARCHAR(100) UNIQUE NOT NULL,
    metric_name VARCHAR(100) NOT NULL,
    threshold_value NUMERIC NOT NULL,
    comparison_operator VARCHAR(10) NOT NULL CHECK (comparison_operator IN ('>', '<', '>=', '<=', '=', '!=')),
    duration_minutes INTEGER DEFAULT 5,
    severity VARCHAR(20) DEFAULT 'warning' CHECK (severity IN ('info', 'warning', 'critical')),
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE alerts (
    id SERIAL PRIMARY KEY,
    rule_id INTEGER REFERENCES alert_rules(id),
    alert_name VARCHAR(100) NOT NULL,
    metric_name VARCHAR(100) NOT NULL,
    metric_value NUMERIC NOT NULL,
    threshold_value NUMERIC NOT NULL,
    severity VARCHAR(20) NOT NULL,
    status VARCHAR(20) DEFAULT 'open' CHECK (status IN ('open', 'acknowledged', 'resolved')),
    message TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    resolved_at TIMESTAMP
);

-- System test for monitoring and alerting
BEGIN;
SELECT plan(20);

-- Test 1: Create monitoring metrics
SELECT lives_ok(
    $$INSERT INTO database_metrics (metric_name, metric_value, metric_unit, tags) VALUES 
    ('cpu_usage', 75.5, 'percent', '{"host": "db-server-1"}'),
    ('memory_usage', 82.3, 'percent', '{"host": "db-server-1"}'),
    ('disk_usage', 68.7, 'percent', '{"host": "db-server-1", "disk": "/var/lib/postgresql"}'),
    ('connection_count', 145, 'count', '{"host": "db-server-1"}'),
    ('query_duration_p95', 250, 'milliseconds', '{"host": "db-server-1"}')$$,
    'Should record database metrics'
);

-- Test 2: Create alert rules
SELECT lives_ok(
    $$INSERT INTO alert_rules (rule_name, metric_name, threshold_value, comparison_operator, severity, duration_minutes) VALUES 
    ('high_cpu_usage', 'cpu_usage', 80, '>', 'warning', 5),
    ('critical_cpu_usage', 'cpu_usage', 90, '>', 'critical', 2),
    ('high_memory_usage', 'memory_usage', 85, '>', 'warning', 10),
    ('critical_memory_usage', 'memory_usage', 95, '>', 'critical', 5),
    ('disk_space_low', 'disk_usage', 85, '>', 'warning', 60)$$,
    'Should create alert rules'
);

-- Test 3: Simulate metric collection
SELECT lives_ok(
    $$INSERT INTO database_metrics (metric_name, metric_value, metric_unit, recorded_at) VALUES 
    ('cpu_usage', 85.2, 'percent', CURRENT_TIMESTAMP - INTERVAL '3 minutes'),
    ('cpu_usage', 91.5, 'percent', CURRENT_TIMESTAMP - INTERVAL '1 minute')$$,
    'Should collect metrics over time'
);

-- Test 4: Test alert generation
SELECT lives_ok(
    $$INSERT INTO alerts (rule_id, alert_name, metric_name, metric_value, threshold_value, severity, message) 
    SELECT id, rule_name, metric_name, 91.5, threshold_value, severity, 'CPU usage exceeded threshold'
    FROM alert_rules 
    WHERE rule_name = 'critical_cpu_usage' AND is_active = true$$,
    'Should generate critical alert'
);

SELECT lives_ok(
    $$INSERT INTO alerts (rule_id, alert_name, metric_name, metric_value, threshold_value, severity, message) 
    SELECT id, rule_name, metric_name, 87.3, threshold_value, severity, 'Memory usage exceeded threshold'
    FROM alert_rules 
    WHERE rule_name = 'high_memory_usage' AND is_active = true$$,
    'Should generate warning alert'
);

-- Test 5: Verify alert counts by severity
SELECT results_eq(
    $$SELECT COUNT(*) FROM alerts WHERE severity = 'critical' AND status = 'open'$$,
    $$VALUES (1)$$,
    'Should have 1 critical alert'
);

SELECT results_eq(
    $$SELECT COUNT(*) FROM alerts WHERE severity = 'warning' AND status = 'open'$$,
    $$VALUES (1)$$,
    'Should have 1 warning alert'
);

-- Test 6: Test alert acknowledgment
SELECT lives_ok(
    $$UPDATE alerts SET status = 'acknowledged' WHERE severity = 'critical'$$,
    'Should acknowledge critical alert'
);

SELECT results_eq(
    $$SELECT COUNT(*) FROM alerts WHERE severity = 'critical' AND status = 'acknowledged'$$,
    $$VALUES (1)$$,
    'Critical alert should be acknowledged'
);

-- Test 7: Test alert resolution
SELECT lives_ok(
    $$UPDATE alerts SET status = 'resolved', resolved_at = CURRENT_TIMESTAMP WHERE severity = 'warning'$$,
    'Should resolve warning alert'
);

SELECT results_eq(
    $$SELECT COUNT(*) FROM alerts WHERE severity = 'warning' AND status = 'resolved'$$,
    $$VALUES (1)$$,
    'Warning alert should be resolved'
);

-- Test 8: Test metric aggregation
SELECT results_eq(
    $$SELECT COUNT(*) FROM (
        SELECT metric_name, AVG(metric_value) as avg_value, MAX(metric_value) as max_value
        FROM database_metrics
        WHERE recorded_at >= CURRENT_TIMESTAMP - INTERVAL '1 hour'
        GROUP BY metric_name
    ) hourly_metrics$$,
    $$VALUES (7)$$,
    'Should aggregate metrics correctly'
);

-- Test 9: Test alerting rule effectiveness
SELECT results_eq(
    $$SELECT COUNT(*) FROM alert_rules WHERE is_active = true$$,
    $$VALUES (5)$$,
    'Should have active alert rules'
);

-- Test 10: Test complex monitoring query
SELECT results_eq(
    $$SELECT COUNT(*) FROM (
        SELECT a.metric_name, COUNT(*) as alert_count
        FROM alerts a
        JOIN alert_rules ar ON a.rule_id = ar.id
        WHERE a.created_at >= CURRENT_TIMESTAMP - INTERVAL '24 hours'
        AND ar.is_active = true
        GROUP BY a.metric_name
    ) recent_alerts$$,
    $$VALUES (2)$$,
    'Should track recent alerts by metric'
);

-- Test 11: Test monitoring dashboard data
SELECT results_eq(
    $$SELECT COUNT(*) FROM (
        SELECT 
            DATE_TRUNC('hour', recorded_at) as hour,
            metric_name,
            AVG(metric_value) as avg_value,
            MAX(metric_value) as max_value,
            MIN(metric_value) as min_value
        FROM database_metrics
        WHERE recorded_at >= CURRENT_TIMESTAMP - INTERVAL '24 hours'
        GROUP BY DATE_TRUNC('hour', recorded_at), metric_name
    ) hourly_dashboard$$,
    $$VALUES (SELECT COUNT(DISTINCT DATE_TRUNC('hour', recorded_at), metric_name) FROM database_metrics WHERE recorded_at >= CURRENT_TIMESTAMP - INTERVAL '24 hours')$$,
    'Dashboard hourly aggregation should be correct'
);

-- Test 12: Test predictive alerting
SELECT lives_ok(
    $$INSERT INTO database_metrics (metric_name, metric_value, metric_unit, recorded_at) VALUES 
    ('disk_usage', 84.5, 'percent', CURRENT_TIMESTAMP - INTERVAL '10 minutes'),
    ('disk_usage', 86.2, 'percent', CURRENT_TIMESTAMP - INTERVAL '5 minutes'),
    ('disk_usage', 88.1, 'percent', CURRENT_TIMESTAMP)$$,
    'Should record trending metrics'
);

SELECT results_eq(
    $$SELECT COUNT(*) FROM database_metrics WHERE metric_name = 'disk_usage' AND metric_value > 85$$,
    $$VALUES (2)$$,
    'Should detect trending issues'
);

-- Test 13: Test alert fatigue prevention
SELECT results_eq(
    $$SELECT COUNT(*) FROM alerts WHERE metric_name = 'cpu_usage' AND created_at >= CURRENT_TIMESTAMP - INTERVAL '1 hour'$$,
    $$VALUES (2)$$,
    'Should track alert frequency'
);

-- Test 14: Test SLA monitoring
SELECT lives_ok(
    $$CREATE TABLE sla_metrics (
        id SERIAL PRIMARY KEY,
        service_name VARCHAR(100) NOT NULL,
        availability_percent NUMERIC NOT NULL,
        response_time_ms NUMERIC NOT NULL,
        error_rate_percent NUMERIC NOT NULL,
        measured_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )$$,
    'Should create SLA metrics table'
);

SELECT lives_ok(
    $$INSERT INTO sla_metrics (service_name, availability_percent, response_time_ms, error_rate_percent) VALUES 
    ('database_service', 99.95, 45, 0.02)$$,
    'Should record SLA metrics'
);

SELECT results_eq(
    $$SELECT COUNT(*) FROM sla_metrics WHERE availability_percent >= 99.9$$,
    $$VALUES (1)$$,
    'SLA should be within acceptable range'
);

-- Test 15: Test capacity planning metrics
SELECT results_eq(
    $$SELECT COUNT(*) FROM (
        SELECT 
            recorded_at::date as metric_date,
            MAX(CASE WHEN metric_name = 'disk_usage' THEN metric_value END) as max_disk_usage,
            MAX(CASE WHEN metric_name = 'memory_usage' THEN metric_value END) as max_memory_usage,
            MAX(CASE WHEN metric_name = 'cpu_usage' THEN metric_value END) as max_cpu_usage
        FROM database_metrics
        WHERE recorded_at >= CURRENT_TIMESTAMP - INTERVAL '7 days'
        GROUP BY recorded_at::date
    ) daily_capacity$$,
    $$VALUES (SELECT COUNT(DISTINCT recorded_at::date) FROM database_metrics WHERE recorded_at >= CURRENT_TIMESTAMP - INTERVAL '7 days')$$,
    'Daily capacity metrics should be calculated correctly'
);

SELECT * FROM finish();
ROLLBACK;
```

# ====================
# SECURITY AND ACCESS CONTROL TESTING
# ====================

## Database Security Testing Framework

```sql
-- Security and Access Control Testing Template
-- File: tests/system/test_security.sql

-- Test setup
CREATE SCHEMA IF NOT EXISTS security_test;
SET search_path TO security_test;

-- Create security test tables
CREATE TABLE user_credentials (
    id SERIAL PRIMARY KEY,
    username VARCHAR(100) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    salt VARCHAR(255) NOT NULL,
    role VARCHAR(50) NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    last_login TIMESTAMP,
    failed_login_attempts INTEGER DEFAULT 0,
    locked_until TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE audit_log (
    id SERIAL PRIMARY KEY,
    user_id INTEGER,
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(100),
    resource_id INTEGER,
    ip_address INET,
    user_agent TEXT,
    success BOOLEAN,
    error_message TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE data_access_log (
    id SERIAL PRIMARY KEY,
    user_id INTEGER,
    table_name VARCHAR(100) NOT NULL,
    operation VARCHAR(20) NOT NULL CHECK (operation IN ('SELECT', 'INSERT', 'UPDATE', 'DELETE')),
    row_count INTEGER DEFAULT 0,
    query_text TEXT,
    execution_time_ms INTEGER,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- System test for security and access control
BEGIN;
SELECT plan(25);

-- Test 1: Create test users with different roles
SELECT lives_ok(
    $$INSERT INTO user_credentials (username, password_hash, salt, role, is_active) VALUES 
    ('admin_user', 'admin_hash_12345', 'admin_salt_12345', 'admin', true),
    ('regular_user', 'user_hash_12345', 'user_salt_12345', 'user', true),
    ('readonly_user', 'readonly_hash_12345', 'readonly_salt_12345', 'readonly', true),
    ('suspended_user', 'suspended_hash_12345', 'suspended_salt_12345', 'user', false)$$,
    'Should create users with different roles'
);

-- Test 2: Test role-based access simulation
SELECT lives_ok(
    $$INSERT INTO audit_log (user_id, action, resource_type, resource_id, success) VALUES 
    (1, 'login', 'user_credentials', 1, true),
    (2, 'login', 'user_credentials', 2, true),
    (3, 'login', 'user_credentials', 3, true)$$,
    'Should log successful logins'
);

SELECT results_eq(
    $$SELECT COUNT(*) FROM audit_log WHERE action = 'login' AND success = true$$,
    $$VALUES (3)$$,
    'Should have 3 successful login attempts'
);

-- Test 3: Test failed login attempts tracking
SELECT lives_ok(
    $$UPDATE user_credentials SET failed_login_attempts = failed_login_attempts + 1 WHERE username = 'regular_user'$$,
    'Should track failed login attempts'
);

SELECT lives_ok(
    $$UPDATE user_credentials SET failed_login_attempts = 5, locked_until = CURRENT_TIMESTAMP + INTERVAL '30 minutes' WHERE username = 'regular_user'$$,
    'Should lock account after multiple failures'
);

SELECT results_eq(
    $$SELECT COUNT(*) FROM user_credentials WHERE failed_login_attempts >= 5 AND locked_until > CURRENT_TIMESTAMP$$,
    $$VALUES (1)$$,
    'Account should be locked'
);

-- Test 4: Test data access logging
SELECT lives_ok(
    $$INSERT INTO data_access_log (user_id, table_name, operation, row_count, execution_time_ms) VALUES 
    (1, 'user_credentials', 'SELECT', 10, 45),
    (2, 'audit_log', 'INSERT', 1, 23),
    (3, 'data_access_log', 'SELECT', 5, 67)$$,
    'Should log data access'
);

SELECT results_eq(
    $$SELECT COUNT(*) FROM data_access_log WHERE user_id IN (1,2,3)$$,
    $$VALUES (3)$$,
    'Should have data access logs'
);

-- Test 5: Test SQL injection prevention simulation
SELECT lives_ok(
    $$INSERT INTO audit_log (user_id, action, resource_type, error_message, success) VALUES 
    (2, 'query_attempt', 'user_credentials', 'SQL injection attempt detected: \' OR 1=1--', false)$$,
    'Should log SQL injection attempts'
);

SELECT results_eq(
    $$SELECT COUNT(*) FROM audit_log WHERE success = false AND error_message LIKE '%SQL injection%'$$,
    $$VALUES (1)$$,
    'SQL injection attempt should be logged'
);

-- Test 6: Test data encryption simulation
SELECT lives_ok(
    $$ALTER TABLE user_credentials ADD COLUMN encrypted_data TEXT$$,
    'Should add encrypted data column'
);

SELECT lives_ok(
    $$UPDATE user_credentials SET encrypted_data = 'encrypted_sensitive_data' WHERE id = 1$$,
    'Should store encrypted data'
);

SELECT results_eq(
    $$SELECT COUNT(*) FROM user_credentials WHERE encrypted_data IS NOT NULL$$,
    $$VALUES (1)$$,
    'Encrypted data should be stored'
);

-- Test 7: Test access control lists simulation
SELECT lives_ok(
    $$CREATE TABLE access_control_list (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES user_credentials(id),
        resource_type VARCHAR(100) NOT NULL,
        resource_id INTEGER,
        permission VARCHAR(50) NOT NULL,
        granted_by INTEGER REFERENCES user_credentials(id),
        granted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        expires_at TIMESTAMP,
        is_active BOOLEAN DEFAULT TRUE
    )$$,
    'Should create access control list table'
);

SELECT lives_ok(
    $$INSERT INTO access_control_list (user_id, resource_type, resource_id, permission, granted_by) VALUES 
    (2, 'user_credentials', 2, 'read_write', 1),
    (3, 'audit_log', NULL, 'read_only', 1)$$,
    'Should grant permissions through ACL'
);

SELECT results_eq(
    $$SELECT COUNT(*) FROM access_control_list WHERE is_active = true$$,
    $$VALUES (2)$$,
    'Active permissions should be recorded'
);

-- Test 8: Test session management
SELECT lives_ok(
    $$CREATE TABLE user_sessions (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES user_credentials(id),
        session_token VARCHAR(255) UNIQUE NOT NULL,
        ip_address INET,
        user_agent TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        expires_at TIMESTAMP NOT NULL,
        is_active BOOLEAN DEFAULT TRUE
    )$$,
    'Should create user sessions table'
);

SELECT lives_ok(
    $$INSERT INTO user_sessions (user_id, session_token, expires_at) VALUES 
    (1, 'session_token_admin', CURRENT_TIMESTAMP + INTERVAL '24 hours'),
    (2, 'session_token_user', CURRENT_TIMESTAMP + INTERVAL '2 hours')$$,
    'Should create user sessions'
);

SELECT results_eq(
    $$SELECT COUNT(*) FROM user_sessions WHERE is_active = true AND expires_at > CURRENT_TIMESTAMP$$,
    $$VALUES (2)$$,
    'Active sessions should be tracked'
);

-- Test 9: Test password policy enforcement
SELECT lives_ok(
    $$CREATE TABLE password_history (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES user_credentials(id),
        password_hash VARCHAR(255) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )$$,
    'Should create password history table'
);

SELECT lives_ok(
    $$INSERT INTO password_history (user_id, password_hash) VALUES 
    (1, 'old_admin_hash_1'),
    (1, 'old_admin_hash_2'),
    (2, 'old_user_hash_1')$$,
    'Should track password history'
);

SELECT results_eq(
    $$SELECT COUNT(*) FROM password_history WHERE user_id = 1$$,
    $$VALUES (2)$$,
    'Password history should be maintained'
);

-- Test 10: Test IP-based access control
SELECT lives_ok(
    $$CREATE TABLE ip_whitelist (
        id SERIAL PRIMARY KEY,
        ip_range CIDR NOT NULL,
        description TEXT,
        is_active BOOLEAN DEFAULT TRUE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )$$,
    'Should create IP whitelist table'
);

SELECT lives_ok(
    $$INSERT INTO ip_whitelist (ip_range, description) VALUES 
    ('192.168.1.0/24', 'Office network'),
    ('10.0.0.0/8', 'Internal network')$$,
    'Should configure IP whitelist'
);

SELECT results_eq(
    $$SELECT COUNT(*) FROM ip_whitelist WHERE is_active = true$$,
    $$VALUES (2)$$,
    'IP whitelist should be configured'
);

-- Test 11: Test rate limiting simulation
SELECT lives_ok(
    $$CREATE TABLE rate_limit_log (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES user_credentials(id),
        action VARCHAR(100) NOT NULL,
        request_count INTEGER DEFAULT 1,
        window_start TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        window_end TIMESTAMP,
        is_blocked BOOLEAN DEFAULT FALSE
    )$$,
    'Should create rate limit log table'
);

SELECT lives_ok(
    $$INSERT INTO rate_limit_log (user_id, action, request_count, window_end) VALUES 
    (2, 'api_request', 105, CURRENT_TIMESTAMP + INTERVAL '1 hour')$$,
    'Should log rate limit violations'
);

SELECT results_eq(
    $$SELECT COUNT(*) FROM rate_limit_log WHERE is_blocked = true OR request_count > 100$$,
    $$VALUES (1)$$,
    'Rate limit violations should be tracked'
);

-- Test 12: Test data anonymization
SELECT lives_ok(
    $$CREATE TABLE anonymized_data (
        id SERIAL PRIMARY KEY,
        original_id INTEGER,
        anonymized_value TEXT,
        anonymization_method VARCHAR(50),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )$$,
    'Should create anonymized data table'
);

SELECT lives_ok(
    $$INSERT INTO anonymized_data (original_id, anonymized_value, anonymization_method) VALUES 
    (1, 'anon_user_1', 'hashing'),
    (2, 'anon_user_2', 'tokenization')$$,
    'Should store anonymized data'
);

SELECT results_eq(
    $$SELECT COUNT(*) FROM anonymized_data$$,
    $$VALUES (2)$$,
    'Anonymized data should be stored'
);

-- Test 13: Test security audit trail
SELECT results_eq(
    $$SELECT COUNT(*) FROM audit_log WHERE user_id IS NOT NULL$$,
    $$VALUES (4)$$,
    'Security audit trail should be complete'
);

SELECT results_eq(
    $$SELECT COUNT(*) FROM audit_log WHERE success = false$$,
    $$VALUES (1)$$,
    'Failed security events should be logged'
);

-- Test 14: Test privilege escalation detection
SELECT lives_ok(
    $$INSERT INTO audit_log (user_id, action, resource_type, success) VALUES 
    (3, 'privilege_escalation_attempt', 'user_credentials', false)$$,
    'Should log privilege escalation attempts'
);

SELECT results_eq(
    $$SELECT COUNT(*) FROM audit_log WHERE action = 'privilege_escalation_attempt'$$,
    $$VALUES (1)$$,
    'Privilege escalation should be detected'
);

-- Test 15: Test data access pattern analysis
SELECT results_eq(
    $$SELECT COUNT(*) FROM (
        SELECT user_id, COUNT(*) as access_count
        FROM data_access_log
        WHERE created_at >= CURRENT_TIMESTAMP - INTERVAL '1 hour'
        GROUP BY user_id
        HAVING COUNT(*) > 100
    ) suspicious_access$$,
    $$VALUES (0)$$,
    'Suspicious access patterns should be analyzable'
);

SELECT * FROM finish();
ROLLBACK;
```

# ====================
# PYTHON SYSTEM TESTING FRAMEWORK
# ====================

```python
# Python System Testing Framework
# File: tests/system/test_database_system.py

import pytest
import asyncio
import asyncpg
import aiomysql
import aiosqlite
import psycopg2
import mysql.connector
import sqlite3
from typing import List, Dict, Any, Optional
import json
import time
import uuid
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, MagicMock
import subprocess
import os

class TestDatabaseSystem:
    """System-level tests for database infrastructure"""
    
    @pytest.fixture
    async def postgres_pool(self):
        """PostgreSQL connection pool for system tests"""
        pool = await asyncpg.create_pool(
            host="localhost",
            port=5432,
            database="system_test",
            user="system_user",
            password="system_pass",
            min_size=1,
            max_size=20
        )
        yield pool
        await pool.close()
    
    async def test_database_backup_and_restore(self, postgres_pool):
        """Test complete database backup and restore workflow"""
        async with postgres_pool.acquire() as conn:
            # Create test schema
            await conn.execute("""
                CREATE SCHEMA IF NOT EXISTS backup_test;
                SET search_path TO backup_test;
                
                CREATE TABLE critical_data (
                    id SERIAL PRIMARY KEY,
                    business_key VARCHAR(100) UNIQUE NOT NULL,
                    sensitive_data TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """)
            
            # Insert test data
            await conn.execute("""
                INSERT INTO critical_data (business_key, sensitive_data) VALUES 
                ('KEY001', 'Critical business data 1'),
                ('KEY002', 'Critical business data 2'),
                ('KEY003', 'Critical business data 3')
            """)
            
            # Simulate backup (pg_dump)
            backup_file = f"/tmp/db_backup_{uuid.uuid4().hex}.sql"
            try:
                # Run pg_dump
                result = subprocess.run([
                    'pg_dump', 
                    '-h', 'localhost',
                    '-U', 'system_user',
                    '-d', 'system_test',
                    '-n', 'backup_test',
                    '-f', backup_file
                ], capture_output=True, text=True, env={**os.environ, 'PGPASSWORD': 'system_pass'})
                
                assert result.returncode == 0, f"Backup failed: {result.stderr}"
                assert os.path.exists(backup_file), "Backup file was not created"
                
                # Simulate data corruption
                await conn.execute("""
                    UPDATE critical_data SET sensitive_data = 'CORRUPTED DATA' WHERE id = 1
                """)
                
                # Simulate restore (drop and recreate)
                await conn.execute("DROP SCHEMA IF EXISTS backup_test CASCADE")
                
                # Run pg_restore
                result = subprocess.run([
                    'psql',
                    '-h', 'localhost',
                    '-U', 'system_user',
                    '-d', 'system_test',
                    '-f', backup_file
                ], capture_output=True, text=True, env={**os.environ, 'PGPASSWORD': 'system_pass'})
                
                assert result.returncode == 0, f"Restore failed: {result.stderr}"
                
                # Verify restored data
                count = await conn.fetchval("SELECT COUNT(*) FROM backup_test.critical_data")
                assert count == 3, "Data was not fully restored"
                
                # Verify data integrity
                corrupted = await conn.fetchval("""
                    SELECT COUNT(*) FROM backup_test.critical_data 
                    WHERE sensitive_data = 'CORRUPTED DATA'
                """)
                assert corrupted == 0, "Corrupted data was not replaced"
                
            finally:
                # Cleanup
                if os.path.exists(backup_file):
                    os.remove(backup_file)
    
    async def test_database_performance_benchmark(self, postgres_pool):
        """Test database performance under various load conditions"""
        async with postgres_pool.acquire() as conn:
            # Setup test tables
            await conn.execute("""
                CREATE SCHEMA IF NOT EXISTS performance_test;
                SET search_path TO performance_test;
                
                CREATE TABLE benchmark_data (
                    id SERIAL PRIMARY KEY,
                    data TEXT,
                    category VARCHAR(50),
                    value INTEGER,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
                
                CREATE INDEX idx_benchmark_category ON benchmark_data(category);
                CREATE INDEX idx_benchmark_value ON benchmark_data(value);
            """)
            
            # Performance test configurations
            test_configs = [
                {"name": "bulk_insert", "iterations": 1000, "batch_size": 100},
                {"name": "indexed_query", "iterations": 1000, "query_type": "indexed"},
                {"name": "full_scan", "iterations": 100, "query_type": "full_scan"},
                {"name": "join_query", "iterations": 500, "query_type": "join"}
            ]
            
            results = {}
            
            for config in test_configs:
                start_time = time.time()
                
                if config["name"] == "bulk_insert":
                    # Test bulk insert performance
                    for i in range(0, config["iterations"], config["batch_size"]):
                        values = []
                        for j in range(batch_size):
                            values.append(f"('data_{i+j}', 'category_{j % 10}', {j})")
                        
                        await conn.execute(f"""
                            INSERT INTO benchmark_data (data, category, value) 
                            VALUES {', '.join(values)}
                        """)
                
                elif config["name"] == "indexed_query":
                    # Test indexed query performance
                    for i in range(config["iterations"]):
                        await conn.fetch("""
                            SELECT * FROM benchmark_data 
                            WHERE category = $1 AND value > $2
                        """, f"category_{i % 10}", i)
                
                elif config["name"] == "full_scan":
                    # Test full table scan performance
                    for i in range(config["iterations"]):
                        await conn.fetch("""
                            SELECT COUNT(*), AVG(value) FROM benchmark_data 
                            WHERE created_at > $1
                        """, datetime.now() - timedelta(minutes=i))
                
                elif config["name"] == "join_query":
                    # Create additional table for join testing
                    await conn.execute("""
                        CREATE TABLE IF NOT EXISTS benchmark_metadata (
                            id SERIAL PRIMARY KEY,
                            data_id INTEGER REFERENCES benchmark_data(id),
                            metadata TEXT,
                            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                        )
                    """)
                    
                    # Test join query performance
                    for i in range(config["iterations"]):
                        await conn.fetch("""
                            SELECT b.*, m.metadata 
                            FROM benchmark_data b
                            LEFT JOIN benchmark_metadata m ON b.id = m.data_id
                            WHERE b.category = $1
                        """, f"category_{i % 10}")
                
                end_time = time.time()
                results[config["name"]] = {
                    "total_time": end_time - start_time,
                    "avg_time_per_operation": (end_time - start_time) / config["iterations"],
                    "operations_per_second": config["iterations"] / (end_time - start_time)
                }
            
            # Verify performance meets expectations
            assert results["bulk_insert"]["operations_per_second"] > 1000, "Bulk insert performance too slow"
            assert results["indexed_query"]["operations_per_second"] > 5000, "Indexed query performance too slow"
            assert results["full_scan"]["operations_per_second"] > 50, "Full scan performance too slow"
            
            print(f"Performance benchmark results:")
            for test_name, metrics in results.items():
                print(f"  {test_name}: {metrics['operations_per_second']:.2f} ops/sec")
    
    async def test_database_high_availability(self, postgres_pool):
        """Test database high availability and failover scenarios"""
        # This test would typically be run against a HA setup with multiple nodes
        async with postgres_pool.acquire() as conn:
            # Test connection resilience
            connection_attempts = 0
            max_attempts = 5
            
            while connection_attempts < max_attempts:
                try:
                    # Test basic connectivity
                    result = await conn.fetchval("SELECT 1")
                    assert result == 1, "Database connectivity test failed"
                    break
                except Exception as e:
                    connection_attempts += 1
                    if connection_attempts >= max_attempts:
                        raise Exception(f"Database unavailable after {max_attempts} attempts: {e}")
                    await asyncio.sleep(1)  # Wait before retry
            
            # Test transaction resilience
            async with conn.transaction():
                # Create test data
                await conn.execute("""
                    CREATE TABLE IF NOT EXISTS ha_test (
                        id SERIAL PRIMARY KEY,
                        data TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                
                await conn.execute("""
                    INSERT INTO ha_test (data) VALUES ('HA test data')
                """)
                
                # Verify data persistence
                count = await conn.fetchval("SELECT COUNT(*) FROM ha_test")
                assert count > 0, "HA test data not persisted"
            
            # Test read replica connectivity (if configured)
            try:
                # This would typically connect to a read replica
                replica_result = await conn.fetchval("""
                    SELECT pg_is_in_recovery()
                """)
                print(f"Read replica status: {'In recovery' if replica_result else 'Primary'}")
            except:
                print("Read replica not configured for this test")
    
    async def test_database_monitoring_integration(self, postgres_pool):
        """Test database monitoring and alerting integration"""
        async with postgres_pool.acquire() as conn:
            # Create monitoring tables
            await conn.execute("""
                CREATE SCHEMA IF NOT EXISTS monitoring;
                SET search_path TO monitoring;
                
                CREATE TABLE system_metrics (
                    id SERIAL PRIMARY KEY,
                    metric_name VARCHAR(100) NOT NULL,
                    metric_value NUMERIC NOT NULL,
                    metric_unit VARCHAR(20),
                    tags JSONB DEFAULT '{}',
                    recorded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
                
                CREATE TABLE alert_rules (
                    id SERIAL PRIMARY KEY,
                    rule_name VARCHAR(100) UNIQUE NOT NULL,
                    metric_name VARCHAR(100) NOT NULL,
                    threshold_value NUMERIC NOT NULL,
                    comparison_operator VARCHAR(10) NOT NULL,
                    severity VARCHAR(20) DEFAULT 'warning',
                    is_active BOOLEAN DEFAULT TRUE
                );
            """)
            
            # Simulate metric collection
            metrics = [
                ('connection_count', 150, 'count'),
                ('query_duration_p95', 250, 'milliseconds'),
                ('disk_usage', 75.5, 'percent'),
                ('memory_usage', 82.3, 'percent'),
                ('cpu_usage', 65.7, 'percent')
            ]
            
            for metric_name, value, unit in metrics:
                await conn.execute("""
                    INSERT INTO system_metrics (metric_name, metric_value, metric_unit)
                    VALUES ($1, $2, $3)
                """, metric_name, value, unit)
            
            # Create alert rules
            alert_rules = [
                ('high_cpu_usage', 'cpu_usage', 80, '>', 'warning'),
                ('critical_cpu_usage', 'cpu_usage', 90, '>', 'critical'),
                ('high_memory_usage', 'memory_usage', 85, '>', 'warning'),
                ('disk_space_low', 'disk_usage', 85, '>', 'warning')
            ]
            
            for rule_name, metric_name, threshold, operator, severity in alert_rules:
                await conn.execute("""
                    INSERT INTO alert_rules (rule_name, metric_name, threshold_value, comparison_operator, severity)
                    VALUES ($1, $2, $3, $4, $5)
                """, rule_name, metric_name, threshold, operator, severity)
            
            # Test alert generation logic
            alerts = await conn.fetch("""
                SELECT ar.rule_name, ar.metric_name, ar.threshold_value, ar.severity, sm.metric_value
                FROM alert_rules ar
                JOIN system_metrics sm ON ar.metric_name = sm.metric_name
                WHERE ar.is_active = true
                AND (
                    (ar.comparison_operator = '>' AND sm.metric_value > ar.threshold_value) OR
                    (ar.comparison_operator = '<' AND sm.metric_value < ar.threshold_value)
                )
                AND sm.recorded_at = (SELECT MAX(recorded_at) FROM system_metrics WHERE metric_name = sm.metric_name)
            """)
            
            # Verify alerts were generated correctly
            alert_count = len(alerts)
            assert alert_count > 0, "No alerts generated when thresholds exceeded"
            
            # Verify alert details
            for alert in alerts:
                assert alert['metric_value'] > alert['threshold_value'], "Alert condition not met"
                assert alert['severity'] in ['warning', 'critical'], "Invalid alert severity"
            
            print(f"Generated {alert_count} alerts from monitoring system")

# System test utilities
class SystemTestUtils:
    """Utility functions for system testing"""
    
    @staticmethod
    async def simulate_database_load(pool, duration_seconds=60, concurrent_connections=10):
        """Simulate database load for testing"""
        async def worker_task():
            async with pool.acquire() as conn:
                end_time = time.time() + duration_seconds
                while time.time() < end_time:
                    # Simulate various database operations
                    await conn.execute("SELECT 1")
                    await conn.execute("SELECT pg_sleep(0.001)")
                    await asyncio.sleep(0.1)
        
        # Create multiple concurrent workers
        tasks = [worker_task() for _ in range(concurrent_connections)]
        await asyncio.gather(*tasks)
    
    @staticmethod
    async def measure_query_performance(pool, query: str, params: tuple = None, iterations: int = 100):
        """Measure query performance over multiple iterations"""
        times = []
        
        async with pool.acquire() as conn:
            for _ in range(iterations):
                start_time = time.time()
                await conn.fetch(query, *(params or ()))
                end_time = time.time()
                times.append(end_time - start_time)
        
        return {
            'min_time': min(times),
            'max_time': max(times),
            'avg_time': sum(times) / len(times),
            'p95_time': sorted(times)[int(len(times) * 0.95)],
            'p99_time': sorted(times)[int(len(times) * 0.99)]
        }
    
    @staticmethod
    def check_database_health(host: str, port: int, database: str, user: str, password: str) -> Dict[str, Any]:
        """Check overall database health status"""
        try:
            conn = psycopg2.connect(
                host=host,
                port=port,
                database=database,
                user=user,
                password=password
            )
            
            with conn.cursor() as cur:
                # Check connection count
                cur.execute("SELECT count(*) FROM pg_stat_activity WHERE state = 'active'")
                active_connections = cur.fetchone()[0]
                
                # Check database size
                cur.execute("SELECT pg_database_size(current_database())")
                db_size = cur.fetchone()[0]
                
                # Check transaction rate
                cur.execute("""
                    SELECT sum(xact_commit + xact_rollback) 
                    FROM pg_stat_database 
                    WHERE datname = current_database()
                """)
                transaction_count = cur.fetchone()[0]
                
                # Check cache hit ratio
                cur.execute("""
                    SELECT 
                        sum(blks_hit) / (sum(blks_hit) + sum(blks_read)) * 100 as cache_hit_ratio
                    FROM pg_stat_database 
                    WHERE datname = current_database()
                """)
                cache_hit_ratio = cur.fetchone()[0]
                
            conn.close()
            
            return {
                'status': 'healthy',
                'active_connections': active_connections,
                'database_size_bytes': db_size,
                'transaction_count': transaction_count,
                'cache_hit_ratio': cache_hit_ratio
            }
            
        except Exception as e:
            return {
                'status': 'unhealthy',
                'error': str(e)
            }

# Usage example
if __name__ == "__main__":
    print("SQL System Testing Template loaded!")
    print("Components included:")
    print("- End-to-end business process testing")
    print("- Performance and load testing")
    print("- Replication and high availability testing")
    print("- Backup and recovery testing")
    print("- Monitoring and alerting testing")
    print("- Security and access control testing")
    print("- System test utilities and helpers")
    print("- Database health checking")
    print("- Performance benchmarking")
    
    print("\nTo use this template:")
    print("1. Set up test database infrastructure")
    print("2. Configure connection parameters")
    print("3. Run system tests with pytest")
    print("4. Monitor performance and health metrics")
    print("5. Validate backup/recovery procedures")
    print("6. Test high availability scenarios")
    
    print("\nSystem testing template completed!")
```