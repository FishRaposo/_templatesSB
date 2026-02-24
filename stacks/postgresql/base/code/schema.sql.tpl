-- File: schema.sql.tpl
-- Purpose: PostgreSQL schema definitions with best practices
-- Generated for: {{PROJECT_NAME}}
-- Tier: base
-- Stack: postgresql
-- Category: schema

-- ============================================================================
-- Extensions
-- ============================================================================

-- Enable UUID generation
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Enable full-text search
CREATE EXTENSION IF NOT EXISTS "pg_trgm";

-- Enable JSONB operations
CREATE EXTENSION IF NOT EXISTS "btree_gin";

-- Enable cryptographic functions
CREATE EXTENSION IF NOT EXISTS "pgcrypto";


-- ============================================================================
-- Custom Types
-- ============================================================================

CREATE TYPE user_role AS ENUM ('user', 'admin', 'moderator');
CREATE TYPE item_status AS ENUM ('draft', 'published', 'archived');


-- ============================================================================
-- Users Table
-- ============================================================================

CREATE TABLE users (
    id BIGSERIAL PRIMARY KEY,
    uuid UUID DEFAULT uuid_generate_v4() UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    username VARCHAR(50) UNIQUE NOT NULL,
    full_name VARCHAR(100),
    hashed_password VARCHAR(255) NOT NULL,
    role user_role DEFAULT 'user' NOT NULL,
    is_active BOOLEAN DEFAULT TRUE NOT NULL,
    email_verified BOOLEAN DEFAULT FALSE NOT NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL,
    last_login_at TIMESTAMPTZ,
    metadata JSONB DEFAULT '{}'::JSONB,
    
    -- Constraints
    CONSTRAINT users_email_check CHECK (email ~* '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$'),
    CONSTRAINT users_username_check CHECK (username ~* '^[a-zA-Z0-9_]{3,50}$')
);

-- Indexes
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_users_created_at ON users(created_at DESC);
CREATE INDEX idx_users_metadata_gin ON users USING GIN (metadata);

-- Full-text search index
CREATE INDEX idx_users_full_name_trgm ON users USING GIN (full_name gin_trgm_ops);

-- Comments
COMMENT ON TABLE users IS 'User accounts and authentication';
COMMENT ON COLUMN users.uuid IS 'External UUID for API exposure';
COMMENT ON COLUMN users.metadata IS 'Additional user metadata in JSON format';


-- ============================================================================
-- Items Table (Example Resource)
-- ============================================================================

CREATE TABLE items (
    id BIGSERIAL PRIMARY KEY,
    uuid UUID DEFAULT uuid_generate_v4() UNIQUE NOT NULL,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    price NUMERIC(10, 2) NOT NULL CHECK (price >= 0),
    tax NUMERIC(10, 2) DEFAULT 0 CHECK (tax >= 0),
    status item_status DEFAULT 'draft' NOT NULL,
    owner_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    is_available BOOLEAN DEFAULT TRUE NOT NULL,
    tags TEXT[] DEFAULT '{}',
    metadata JSONB DEFAULT '{}'::JSONB,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL,
    published_at TIMESTAMPTZ,
    
    -- Constraints
    CONSTRAINT items_name_check CHECK (length(name) >= 1)
);

-- Indexes
CREATE INDEX idx_items_owner_id ON items(owner_id);
CREATE INDEX idx_items_status ON items(status);
CREATE INDEX idx_items_created_at ON items(created_at DESC);
CREATE INDEX idx_items_price ON items(price);
CREATE INDEX idx_items_tags_gin ON items USING GIN (tags);
CREATE INDEX idx_items_metadata_gin ON items USING GIN (metadata);

-- Full-text search index on name and description
CREATE INDEX idx_items_name_trgm ON items USING GIN (name gin_trgm_ops);
CREATE INDEX idx_items_description_trgm ON items USING GIN (description gin_trgm_ops);

-- Partial index for available items
CREATE INDEX idx_items_available ON items(owner_id, created_at DESC) WHERE is_available = TRUE;

-- Comments
COMMENT ON TABLE items IS 'Items/products managed by users';
COMMENT ON COLUMN items.tags IS 'Array of tags for categorization';
COMMENT ON COLUMN items.metadata IS 'Additional item metadata in JSON format';


-- ============================================================================
-- Tags Table (Many-to-Many Example)
-- ============================================================================

CREATE TABLE tags (
    id BIGSERIAL PRIMARY KEY,
    name VARCHAR(50) UNIQUE NOT NULL,
    slug VARCHAR(50) UNIQUE NOT NULL,
    description TEXT,
    usage_count INTEGER DEFAULT 0 NOT NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL,
    
    CONSTRAINT tags_name_check CHECK (length(name) >= 1),
    CONSTRAINT tags_slug_check CHECK (slug ~* '^[a-z0-9-]+$')
);

CREATE INDEX idx_tags_name ON tags(name);
CREATE INDEX idx_tags_slug ON tags(slug);
CREATE INDEX idx_tags_usage_count ON tags(usage_count DESC);


-- ============================================================================
-- Item-Tag Association Table
-- ============================================================================

CREATE TABLE item_tags (
    item_id BIGINT NOT NULL REFERENCES items(id) ON DELETE CASCADE,
    tag_id BIGINT NOT NULL REFERENCES tags(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL,
    
    PRIMARY KEY (item_id, tag_id)
);

CREATE INDEX idx_item_tags_item_id ON item_tags(item_id);
CREATE INDEX idx_item_tags_tag_id ON item_tags(tag_id);


-- ============================================================================
-- Refresh Tokens Table
-- ============================================================================

CREATE TABLE refresh_tokens (
    id BIGSERIAL PRIMARY KEY,
    token VARCHAR(500) UNIQUE NOT NULL,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL,
    is_revoked BOOLEAN DEFAULT FALSE NOT NULL,
    revoked_at TIMESTAMPTZ,
    user_agent TEXT,
    ip_address INET,
    
    CONSTRAINT refresh_tokens_expiry_check CHECK (expires_at > created_at)
);

CREATE INDEX idx_refresh_tokens_user_id ON refresh_tokens(user_id);
CREATE INDEX idx_refresh_tokens_token ON refresh_tokens(token);
CREATE INDEX idx_refresh_tokens_expires_at ON refresh_tokens(expires_at) WHERE is_revoked = FALSE;


-- ============================================================================
-- Audit Log Table
-- ============================================================================

CREATE TABLE audit_logs (
    id BIGSERIAL PRIMARY KEY,
    table_name VARCHAR(50) NOT NULL,
    record_id BIGINT NOT NULL,
    action VARCHAR(10) NOT NULL CHECK (action IN ('INSERT', 'UPDATE', 'DELETE')),
    old_data JSONB,
    new_data JSONB,
    changed_by BIGINT REFERENCES users(id) ON DELETE SET NULL,
    changed_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL,
    ip_address INET
);

CREATE INDEX idx_audit_logs_table_record ON audit_logs(table_name, record_id);
CREATE INDEX idx_audit_logs_changed_by ON audit_logs(changed_by);
CREATE INDEX idx_audit_logs_changed_at ON audit_logs(changed_at DESC);

-- Partition by month for better performance
CREATE TABLE audit_logs_template (LIKE audit_logs INCLUDING ALL);

COMMENT ON TABLE audit_logs IS 'Audit trail for data changes';
