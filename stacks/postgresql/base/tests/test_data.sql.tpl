-- File: test_data.sql.tpl
-- Purpose: Test data and seed data for PostgreSQL
-- Generated for: {{PROJECT_NAME}}
-- Tier: base
-- Stack: postgresql
-- Category: testing

-- ============================================================================
-- Clear existing data (use with caution!)
-- ============================================================================

TRUNCATE TABLE item_tags, items, tags, refresh_tokens, users CASCADE;


-- ============================================================================
-- Seed Users
-- ============================================================================

INSERT INTO users (email, username, full_name, hashed_password, role, is_active, email_verified)
VALUES
    ('admin@example.com', 'admin', 'Admin User', '$2b$12$hashed_password_here', 'admin', true, true),
    ('john@example.com', 'john_doe', 'John Doe', '$2b$12$hashed_password_here', 'user', true, true),
    ('jane@example.com', 'jane_smith', 'Jane Smith', '$2b$12$hashed_password_here', 'user', true, true),
    ('bob@example.com', 'bob_wilson', 'Bob Wilson', '$2b$12$hashed_password_here', 'moderator', true, false),
    ('alice@example.com', 'alice_brown', 'Alice Brown', '$2b$12$hashed_password_here', 'user', false, true);


-- ============================================================================
-- Seed Tags
-- ============================================================================

INSERT INTO tags (name, slug, description)
VALUES
    ('Technology', 'technology', 'Technology related items'),
    ('Books', 'books', 'Book items'),
    ('Electronics', 'electronics', 'Electronic devices'),
    ('Furniture', 'furniture', 'Furniture items'),
    ('Clothing', 'clothing', 'Clothing and accessories'),
    ('Food', 'food', 'Food and beverages'),
    ('Sports', 'sports', 'Sports equipment'),
    ('Music', 'music', 'Musical instruments and music'),
    ('Art', 'art', 'Art and crafts'),
    ('Education', 'education', 'Educational materials');


-- ============================================================================
-- Seed Items
-- ============================================================================

INSERT INTO items (name, description, price, tax, status, owner_id, is_available, tags)
SELECT
    'Item ' || generate_series,
    'Description for item ' || generate_series,
    (random() * 1000)::numeric(10,2),
    (random() * 50)::numeric(10,2),
    CASE (random() * 2)::int
        WHEN 0 THEN 'draft'
        WHEN 1 THEN 'published'
        ELSE 'archived'
    END,
    (SELECT id FROM users ORDER BY random() LIMIT 1),
    random() > 0.2,
    ARRAY(SELECT name FROM tags ORDER BY random() LIMIT (random() * 3)::int + 1)
FROM generate_series(1, 100);


-- ============================================================================
-- Link Items to Tags
-- ============================================================================

INSERT INTO item_tags (item_id, tag_id)
SELECT DISTINCT
    i.id,
    t.id
FROM items i
CROSS JOIN LATERAL unnest(i.tags) AS tag_name
JOIN tags t ON t.name = tag_name
ON CONFLICT DO NOTHING;


-- ============================================================================
-- Update Tag Usage Counts
-- ============================================================================

UPDATE tags
SET usage_count = (
    SELECT COUNT(*)
    FROM item_tags
    WHERE tag_id = tags.id
);


-- ============================================================================
-- Add Sample Metadata
-- ============================================================================

UPDATE items
SET metadata = jsonb_build_object(
    'featured', random() > 0.8,
    'rating', (random() * 5)::numeric(3,2),
    'views', (random() * 1000)::int,
    'likes', (random() * 100)::int
);


-- ============================================================================
-- Verification Queries
-- ============================================================================

-- Count records
SELECT 'users' as table_name, COUNT(*) as count FROM users
UNION ALL
SELECT 'tags', COUNT(*) FROM tags
UNION ALL
SELECT 'items', COUNT(*) FROM items
UNION ALL
SELECT 'item_tags', COUNT(*) FROM item_tags;


-- Sample data check
SELECT
    u.username,
    COUNT(i.id) as item_count,
    COUNT(DISTINCT it.tag_id) as unique_tags
FROM users u
LEFT JOIN items i ON i.owner_id = u.id
LEFT JOIN item_tags it ON it.item_id = i.id
GROUP BY u.id, u.username
ORDER BY item_count DESC;
