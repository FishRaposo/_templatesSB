-- File: triggers.sql.tpl
-- Purpose: PostgreSQL triggers for automation and auditing
-- Generated for: {{PROJECT_NAME}}
-- Tier: base
-- Stack: postgresql
-- Category: triggers

-- ============================================================================
-- Updated At Triggers
-- ============================================================================

-- Trigger for users table
CREATE TRIGGER update_users_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Trigger for items table
CREATE TRIGGER update_items_updated_at
    BEFORE UPDATE ON items
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();


-- ============================================================================
-- Audit Log Triggers
-- ============================================================================

CREATE OR REPLACE FUNCTION log_user_changes()
RETURNS TRIGGER AS $$
BEGIN
    IF (TG_OP = 'DELETE') THEN
        INSERT INTO audit_logs (table_name, record_id, action, old_data, changed_by)
        VALUES ('users', OLD.id, 'DELETE', row_to_json(OLD), current_setting('app.user_id', TRUE)::BIGINT);
        RETURN OLD;
    ELSIF (TG_OP = 'UPDATE') THEN
        INSERT INTO audit_logs (table_name, record_id, action, old_data, new_data, changed_by)
        VALUES ('users', NEW.id, 'UPDATE', row_to_json(OLD), row_to_json(NEW), current_setting('app.user_id', TRUE)::BIGINT);
        RETURN NEW;
    ELSIF (TG_OP = 'INSERT') THEN
        INSERT INTO audit_logs (table_name, record_id, action, new_data, changed_by)
        VALUES ('users', NEW.id, 'INSERT', row_to_json(NEW), current_setting('app.user_id', TRUE)::BIGINT);
        RETURN NEW;
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER audit_users
    AFTER INSERT OR UPDATE OR DELETE ON users
    FOR EACH ROW
    EXECUTE FUNCTION log_user_changes();


CREATE OR REPLACE FUNCTION log_item_changes()
RETURNS TRIGGER AS $$
BEGIN
    IF (TG_OP = 'DELETE') THEN
        INSERT INTO audit_logs (table_name, record_id, action, old_data, changed_by)
        VALUES ('items', OLD.id, 'DELETE', row_to_json(OLD), current_setting('app.user_id', TRUE)::BIGINT);
        RETURN OLD;
    ELSIF (TG_OP = 'UPDATE') THEN
        INSERT INTO audit_logs (table_name, record_id, action, old_data, new_data, changed_by)
        VALUES ('items', NEW.id, 'UPDATE', row_to_json(OLD), row_to_json(NEW), current_setting('app.user_id', TRUE)::BIGINT);
        RETURN NEW;
    ELSIF (TG_OP = 'INSERT') THEN
        INSERT INTO audit_logs (table_name, record_id, action, new_data, changed_by)
        VALUES ('items', NEW.id, 'INSERT', row_to_json(NEW), current_setting('app.user_id', TRUE)::BIGINT);
        RETURN NEW;
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER audit_items
    AFTER INSERT OR UPDATE OR DELETE ON items
    FOR EACH ROW
    EXECUTE FUNCTION log_item_changes();


-- ============================================================================
-- Tag Usage Count Triggers
-- ============================================================================

CREATE OR REPLACE FUNCTION update_tag_usage_on_insert()
RETURNS TRIGGER AS $$
BEGIN
    PERFORM increment_tag_usage(NEW.tag_id);
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER item_tags_insert
    AFTER INSERT ON item_tags
    FOR EACH ROW
    EXECUTE FUNCTION update_tag_usage_on_insert();


CREATE OR REPLACE FUNCTION update_tag_usage_on_delete()
RETURNS TRIGGER AS $$
BEGIN
    PERFORM decrement_tag_usage(OLD.tag_id);
    RETURN OLD;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER item_tags_delete
    AFTER DELETE ON item_tags
    FOR EACH ROW
    EXECUTE FUNCTION update_tag_usage_on_delete();


-- ============================================================================
-- Validation Triggers
-- ============================================================================

CREATE OR REPLACE FUNCTION validate_item_price()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.price < 0 THEN
        RAISE EXCEPTION 'Item price cannot be negative';
    END IF;
    
    IF NEW.tax IS NOT NULL AND NEW.tax < 0 THEN
        RAISE EXCEPTION 'Item tax cannot be negative';
    END IF;
    
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER validate_item_price_trigger
    BEFORE INSERT OR UPDATE ON items
    FOR EACH ROW
    EXECUTE FUNCTION validate_item_price();


-- ============================================================================
-- Auto-populate Triggers
-- ============================================================================

CREATE OR REPLACE FUNCTION set_published_at()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.status = 'published' AND (OLD IS NULL OR OLD.status != 'published') THEN
        NEW.published_at = CURRENT_TIMESTAMP;
    ELSIF NEW.status != 'published' THEN
        NEW.published_at = NULL;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER set_item_published_at
    BEFORE INSERT OR UPDATE ON items
    FOR EACH ROW
    EXECUTE FUNCTION set_published_at();


-- ============================================================================
-- Notification Triggers (Example for LISTEN/NOTIFY)
-- ============================================================================

CREATE OR REPLACE FUNCTION notify_item_changes()
RETURNS TRIGGER AS $$
DECLARE
    payload JSON;
BEGIN
    IF TG_OP = 'INSERT' THEN
        payload = json_build_object(
            'operation', 'INSERT',
            'id', NEW.id,
            'owner_id', NEW.owner_id,
            'name', NEW.name
        );
        PERFORM pg_notify('item_changes', payload::text);
    ELSIF TG_OP = 'UPDATE' THEN
        payload = json_build_object(
            'operation', 'UPDATE',
            'id', NEW.id,
            'owner_id', NEW.owner_id,
            'name', NEW.name
        );
        PERFORM pg_notify('item_changes', payload::text);
    ELSIF TG_OP = 'DELETE' THEN
        payload = json_build_object(
            'operation', 'DELETE',
            'id', OLD.id,
            'owner_id', OLD.owner_id
        );
        PERFORM pg_notify('item_changes', payload::text);
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER notify_item_changes_trigger
    AFTER INSERT OR UPDATE OR DELETE ON items
    FOR EACH ROW
    EXECUTE FUNCTION notify_item_changes();
