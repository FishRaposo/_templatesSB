-- File: functions.sql.tpl
-- Purpose: PostgreSQL stored procedures and functions
-- Generated for: {{PROJECT_NAME}}
-- Tier: base
-- Stack: postgresql
-- Category: functions

-- ============================================================================
-- Update Timestamp Function
-- ============================================================================

CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION update_updated_at_column() IS 'Automatically update updated_at timestamp';


-- ============================================================================
-- User Functions
-- ============================================================================

CREATE OR REPLACE FUNCTION create_user(
    p_email VARCHAR,
    p_username VARCHAR,
    p_hashed_password VARCHAR,
    p_full_name VARCHAR DEFAULT NULL
)
RETURNS TABLE(id BIGINT, uuid UUID, email VARCHAR, username VARCHAR) AS $$
DECLARE
    v_user_id BIGINT;
    v_user_uuid UUID;
BEGIN
    INSERT INTO users (email, username, hashed_password, full_name)
    VALUES (p_email, p_username, p_hashed_password, p_full_name)
    RETURNING users.id, users.uuid INTO v_user_id, v_user_uuid;
    
    RETURN QUERY SELECT v_user_id, v_user_uuid, p_email, p_username;
END;
$$ LANGUAGE plpgsql;


CREATE OR REPLACE FUNCTION get_user_by_email_or_username(
    p_identifier VARCHAR
)
RETURNS SETOF users AS $$
BEGIN
    RETURN QUERY
    SELECT * FROM users
    WHERE email = p_identifier OR username = p_identifier
    LIMIT 1;
END;
$$ LANGUAGE plpgsql;


CREATE OR REPLACE FUNCTION update_last_login(
    p_user_id BIGINT
)
RETURNS VOID AS $$
BEGIN
    UPDATE users
    SET last_login_at = CURRENT_TIMESTAMP
    WHERE id = p_user_id;
END;
$$ LANGUAGE plpgsql;


-- ============================================================================
-- Item Functions
-- ============================================================================

CREATE OR REPLACE FUNCTION get_user_items(
    p_user_id BIGINT,
    p_limit INTEGER DEFAULT 100,
    p_offset INTEGER DEFAULT 0
)
RETURNS SETOF items AS $$
BEGIN
    RETURN QUERY
    SELECT * FROM items
    WHERE owner_id = p_user_id
    ORDER BY created_at DESC
    LIMIT p_limit
    OFFSET p_offset;
END;
$$ LANGUAGE plpgsql;


CREATE OR REPLACE FUNCTION search_items(
    p_query TEXT,
    p_limit INTEGER DEFAULT 100,
    p_offset INTEGER DEFAULT 0
)
RETURNS TABLE(
    id BIGINT,
    name VARCHAR,
    description TEXT,
    price NUMERIC,
    similarity REAL
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        i.id,
        i.name,
        i.description,
        i.price,
        GREATEST(
            similarity(i.name, p_query),
            similarity(COALESCE(i.description, ''), p_query)
        ) as similarity
    FROM items i
    WHERE 
        i.name ILIKE '%' || p_query || '%'
        OR i.description ILIKE '%' || p_query || '%'
    ORDER BY similarity DESC, i.created_at DESC
    LIMIT p_limit
    OFFSET p_offset;
END;
$$ LANGUAGE plpgsql;


-- ============================================================================
-- Tag Functions
-- ============================================================================

CREATE OR REPLACE FUNCTION increment_tag_usage(
    p_tag_id BIGINT
)
RETURNS VOID AS $$
BEGIN
    UPDATE tags
    SET usage_count = usage_count + 1
    WHERE id = p_tag_id;
END;
$$ LANGUAGE plpgsql;


CREATE OR REPLACE FUNCTION decrement_tag_usage(
    p_tag_id BIGINT
)
RETURNS VOID AS $$
BEGIN
    UPDATE tags
    SET usage_count = GREATEST(usage_count - 1, 0)
    WHERE id = p_tag_id;
END;
$$ LANGUAGE plpgsql;


CREATE OR REPLACE FUNCTION get_or_create_tag(
    p_name VARCHAR
)
RETURNS BIGINT AS $$
DECLARE
    v_tag_id BIGINT;
    v_slug VARCHAR;
BEGIN
    -- Generate slug from name
    v_slug := lower(regexp_replace(p_name, '[^a-zA-Z0-9]+', '-', 'g'));
    
    -- Try to get existing tag
    SELECT id INTO v_tag_id FROM tags WHERE name = p_name;
    
    -- Create if doesn't exist
    IF v_tag_id IS NULL THEN
        INSERT INTO tags (name, slug)
        VALUES (p_name, v_slug)
        RETURNING id INTO v_tag_id;
    END IF;
    
    RETURN v_tag_id;
END;
$$ LANGUAGE plpgsql;


-- ============================================================================
-- Statistics Functions
-- ============================================================================

CREATE OR REPLACE FUNCTION get_user_statistics(
    p_user_id BIGINT
)
RETURNS TABLE(
    total_items BIGINT,
    published_items BIGINT,
    draft_items BIGINT,
    total_value NUMERIC
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        COUNT(*)::BIGINT as total_items,
        COUNT(*) FILTER (WHERE status = 'published')::BIGINT as published_items,
        COUNT(*) FILTER (WHERE status = 'draft')::BIGINT as draft_items,
        COALESCE(SUM(price), 0) as total_value
    FROM items
    WHERE owner_id = p_user_id;
END;
$$ LANGUAGE plpgsql;


CREATE OR REPLACE FUNCTION get_popular_tags(
    p_limit INTEGER DEFAULT 10
)
RETURNS TABLE(
    id BIGINT,
    name VARCHAR,
    usage_count INTEGER
) AS $$
BEGIN
    RETURN QUERY
    SELECT t.id, t.name, t.usage_count
    FROM tags t
    ORDER BY usage_count DESC, name ASC
    LIMIT p_limit;
END;
$$ LANGUAGE plpgsql;


-- ============================================================================
-- Utility Functions
-- ============================================================================

CREATE OR REPLACE FUNCTION clean_expired_refresh_tokens()
RETURNS INTEGER AS $$
DECLARE
    v_deleted INTEGER;
BEGIN
    DELETE FROM refresh_tokens
    WHERE expires_at < CURRENT_TIMESTAMP
    OR is_revoked = TRUE;
    
    GET DIAGNOSTICS v_deleted = ROW_COUNT;
    RETURN v_deleted;
END;
$$ LANGUAGE plpgsql;


CREATE OR REPLACE FUNCTION get_database_size()
RETURNS TABLE(
    database_name NAME,
    size TEXT
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        datname as database_name,
        pg_size_pretty(pg_database_size(datname)) as size
    FROM pg_database
    WHERE datname = current_database();
END;
$$ LANGUAGE plpgsql;


CREATE OR REPLACE FUNCTION get_table_sizes()
RETURNS TABLE(
    table_name TEXT,
    row_count BIGINT,
    total_size TEXT,
    table_size TEXT,
    indexes_size TEXT
) AS $$
BEGIN
    RETURN QUERY
    SELECT
        schemaname || '.' || tablename as table_name,
        n_live_tup as row_count,
        pg_size_pretty(pg_total_relation_size(schemaname || '.' || tablename)) as total_size,
        pg_size_pretty(pg_relation_size(schemaname || '.' || tablename)) as table_size,
        pg_size_pretty(pg_total_relation_size(schemaname || '.' || tablename) - pg_relation_size(schemaname || '.' || tablename)) as indexes_size
    FROM pg_stat_user_tables
    ORDER BY pg_total_relation_size(schemaname || '.' || tablename) DESC;
END;
$$ LANGUAGE plpgsql;
