// File: repository.tpl.go
// Purpose: Generic repository pattern for GORM
// Generated for: {{PROJECT_NAME}}

package repository

import (
	"context"

	"gorm.io/gorm"
)

// Repository provides generic CRUD operations
type Repository[T any] struct {
	db *gorm.DB
}

// NewRepository creates a new repository instance
func NewRepository[T any](db *gorm.DB) *Repository[T] {
	return &Repository[T]{db: db}
}

// Get retrieves a single record by ID
func (r *Repository[T]) Get(ctx context.Context, id uint) (*T, error) {
	var entity T
	err := r.db.WithContext(ctx).First(&entity, id).Error
	if err != nil {
		return nil, err
	}
	return &entity, nil
}

// GetBy retrieves a single record by arbitrary conditions
func (r *Repository[T]) GetBy(ctx context.Context, conditions map[string]interface{}) (*T, error) {
	var entity T
	query := r.db.WithContext(ctx)
	for key, value := range conditions {
		query = query.Where(key+" = ?", value)
	}
	err := query.First(&entity).Error
	if err != nil {
		return nil, err
	}
	return &entity, nil
}

// List retrieves multiple records with pagination and filtering
func (r *Repository[T]) List(ctx context.Context, skip, limit int, orderBy string, filters map[string]interface{}) ([]T, error) {
	var entities []T
	query := r.db.WithContext(ctx)

	for key, value := range filters {
		if value != nil {
			query = query.Where(key+" = ?", value)
		}
	}

	if orderBy != "" {
		query = query.Order(orderBy)
	}

	query = query.Offset(skip).Limit(limit)
	err := query.Find(&entities).Error
	return entities, err
}

// Count returns the number of records matching the filters
func (r *Repository[T]) Count(ctx context.Context, filters map[string]interface{}) (int64, error) {
	var count int64
	query := r.db.WithContext(ctx).Model(new(T))

	for key, value := range filters {
		if value != nil {
			query = query.Where(key+" = ?", value)
		}
	}

	err := query.Count(&count).Error
	return count, err
}

// Create inserts a new record
func (r *Repository[T]) Create(ctx context.Context, entity *T) error {
	return r.db.WithContext(ctx).Create(entity).Error
}

// Update modifies an existing record
func (r *Repository[T]) Update(ctx context.Context, id uint, updates map[string]interface{}) error {
	return r.db.WithContext(ctx).Model(new(T)).Where("id = ?", id).Updates(updates).Error
}

// Save saves all changes to an existing record
func (r *Repository[T]) Save(ctx context.Context, entity *T) error {
	return r.db.WithContext(ctx).Save(entity).Error
}

// Delete removes a record by ID
func (r *Repository[T]) Delete(ctx context.Context, id uint) error {
	return r.db.WithContext(ctx).Delete(new(T), id).Error
}

// BulkCreate inserts multiple records
func (r *Repository[T]) BulkCreate(ctx context.Context, entities []T) error {
	return r.db.WithContext(ctx).Create(&entities).Error
}

// Transaction executes a function within a transaction
func (r *Repository[T]) Transaction(ctx context.Context, fn func(tx *gorm.DB) error) error {
	return r.db.WithContext(ctx).Transaction(fn)
}

// Usage:
// type User struct {
//     ID    uint   `gorm:"primaryKey"`
//     Email string `gorm:"uniqueIndex"`
//     Name  string
// }
//
// userRepo := NewRepository[User](db)
// user, err := userRepo.Get(ctx, 1)
// users, err := userRepo.List(ctx, 0, 10, "created_at DESC", nil)
