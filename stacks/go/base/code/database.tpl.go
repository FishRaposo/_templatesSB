// File: database.tpl.go
// Purpose: Database connection and repository patterns using pgx
// Generated for: {{PROJECT_NAME}}

package database

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type Config struct {
	Host     string
	Port     int
	User     string
	Password string
	Database string
	MaxConns int32
}

var pool *pgxpool.Pool

func Connect(ctx context.Context, cfg Config) error {
	connString := fmt.Sprintf(
		"postgres://%s:%s@%s:%d/%s?pool_max_conns=%d",
		cfg.User, cfg.Password, cfg.Host, cfg.Port, cfg.Database, cfg.MaxConns,
	)

	config, err := pgxpool.ParseConfig(connString)
	if err != nil {
		return fmt.Errorf("parse config: %w", err)
	}

	config.MaxConns = cfg.MaxConns
	config.MinConns = 2
	config.MaxConnLifetime = time.Hour
	config.MaxConnIdleTime = 30 * time.Minute

	pool, err = pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}

	return pool.Ping(ctx)
}

func GetPool() *pgxpool.Pool {
	return pool
}

func Close() {
	if pool != nil {
		pool.Close()
	}
}

// Generic Repository interface
type Repository[T any] interface {
	GetByID(ctx context.Context, id string) (*T, error)
	GetAll(ctx context.Context, limit, offset int) ([]T, error)
	Create(ctx context.Context, entity *T) error
	Update(ctx context.Context, entity *T) error
	Delete(ctx context.Context, id string) error
}

// Transaction helper
func WithTransaction(ctx context.Context, fn func(ctx context.Context) error) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}

	defer func() {
		if p := recover(); p != nil {
			tx.Rollback(ctx)
			panic(p)
		}
	}()

	if err := fn(ctx); err != nil {
		tx.Rollback(ctx)
		return err
	}

	return tx.Commit(ctx)
}
