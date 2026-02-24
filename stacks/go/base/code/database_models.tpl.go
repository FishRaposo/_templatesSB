// File: database_models.tpl.go
// Purpose: GORM model definitions with common patterns
// Generated for: {{PROJECT_NAME}}

package models

import (
	"time"

	"gorm.io/gorm"
)

// Base model with common fields
type BaseModel struct {
	ID        uint           `gorm:"primarykey" json:"id"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"deleted_at,omitempty"`
}

// User model with authentication fields
type User struct {
	BaseModel
	Email        string     `gorm:"size:255;uniqueIndex;not null" json:"email"`
	Username     string     `gorm:"size:50;uniqueIndex;not null" json:"username"`
	PasswordHash string     `gorm:"size:255;not null" json:"-"`
	FullName     string     `gorm:"size:100" json:"full_name,omitempty"`
	AvatarURL    string     `gorm:"size:500" json:"avatar_url,omitempty"`
	IsActive     bool       `gorm:"default:true" json:"is_active"`
	IsVerified   bool       `gorm:"default:false" json:"is_verified"`
	IsSuperuser  bool       `gorm:"default:false" json:"is_superuser"`
	LastLoginAt  *time.Time `json:"last_login_at,omitempty"`
	Metadata     JSON       `gorm:"type:jsonb" json:"metadata,omitempty"`

	// Relationships
	Sessions []Session `gorm:"foreignKey:UserID" json:"sessions,omitempty"`
	Posts    []Post    `gorm:"foreignKey:AuthorID" json:"posts,omitempty"`
}

// TableName specifies the table name for User
func (User) TableName() string {
	return "users"
}

// Session model for token management
type Session struct {
	BaseModel
	UserID    uint      `gorm:"index;not null" json:"user_id"`
	TokenHash string    `gorm:"size:255;uniqueIndex;not null" json:"-"`
	ExpiresAt time.Time `gorm:"not null" json:"expires_at"`
	IPAddress string    `gorm:"size:45" json:"ip_address,omitempty"`
	UserAgent string    `gorm:"size:500" json:"user_agent,omitempty"`
	IsRevoked bool      `gorm:"default:false" json:"is_revoked"`

	// Relationships
	User User `gorm:"foreignKey:UserID" json:"user,omitempty"`
}

// TableName specifies the table name for Session
func (Session) TableName() string {
	return "sessions"
}

// Post model for content
type Post struct {
	BaseModel
	AuthorID    uint       `gorm:"index;not null" json:"author_id"`
	Title       string     `gorm:"size:200;not null" json:"title"`
	Slug        string     `gorm:"size:220;uniqueIndex;not null" json:"slug"`
	Content     string     `gorm:"type:text;not null" json:"content"`
	Excerpt     string     `gorm:"size:500" json:"excerpt,omitempty"`
	Status      string     `gorm:"size:20;default:'draft'" json:"status"` // draft, published, archived
	PublishedAt *time.Time `json:"published_at,omitempty"`
	ViewCount   int        `gorm:"default:0" json:"view_count"`
	Metadata    JSON       `gorm:"type:jsonb" json:"metadata,omitempty"`

	// Relationships
	Author User  `gorm:"foreignKey:AuthorID" json:"author,omitempty"`
	Tags   []Tag `gorm:"many2many:post_tags" json:"tags,omitempty"`
}

// TableName specifies the table name for Post
func (Post) TableName() string {
	return "posts"
}

// Tag model for categorization
type Tag struct {
	BaseModel
	Name        string `gorm:"size:50;uniqueIndex;not null" json:"name"`
	Slug        string `gorm:"size:60;uniqueIndex;not null" json:"slug"`
	Description string `gorm:"size:200" json:"description,omitempty"`
	Color       string `gorm:"size:7" json:"color,omitempty"` // Hex color

	// Relationships
	Posts []Post `gorm:"many2many:post_tags" json:"posts,omitempty"`
}

// TableName specifies the table name for Tag
func (Tag) TableName() string {
	return "tags"
}

// AuditLog for tracking changes
type AuditLog struct {
	ID         uint      `gorm:"primarykey" json:"id"`
	UserID     *uint     `gorm:"index" json:"user_id,omitempty"`
	Action     string    `gorm:"size:50;not null" json:"action"` // create, update, delete
	EntityType string    `gorm:"size:50;not null" json:"entity_type"`
	EntityID   string    `gorm:"size:50;not null" json:"entity_id"`
	OldValues  JSON      `gorm:"type:jsonb" json:"old_values,omitempty"`
	NewValues  JSON      `gorm:"type:jsonb" json:"new_values,omitempty"`
	IPAddress  string    `gorm:"size:45" json:"ip_address,omitempty"`
	CreatedAt  time.Time `json:"created_at"`

	// Relationships
	User *User `gorm:"foreignKey:UserID" json:"user,omitempty"`
}

// TableName specifies the table name for AuditLog
func (AuditLog) TableName() string {
	return "audit_logs"
}

// JSON type for JSONB fields
type JSON map[string]interface{}

// AutoMigrate runs migrations for all models
func AutoMigrate(db *gorm.DB) error {
	return db.AutoMigrate(
		&User{},
		&Session{},
		&Post{},
		&Tag{},
		&AuditLog{},
	)
}

// Hooks

// BeforeCreate hook for User
func (u *User) BeforeCreate(tx *gorm.DB) error {
	if u.Metadata == nil {
		u.Metadata = make(JSON)
	}
	return nil
}

// BeforeUpdate hook for Post - update slug if title changed
func (p *Post) BeforeCreate(tx *gorm.DB) error {
	if p.Slug == "" && p.Title != "" {
		p.Slug = generateSlug(p.Title)
	}
	return nil
}

// Helper function to generate slug (implement as needed)
func generateSlug(title string) string {
	// Implement slug generation logic
	return title // Placeholder
}
