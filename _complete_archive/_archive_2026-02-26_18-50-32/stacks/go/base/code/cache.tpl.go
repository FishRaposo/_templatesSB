// File: cache.tpl.go
// Purpose: Redis caching utilities using go-redis
// Generated for: {{PROJECT_NAME}}

package cache

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

type Config struct {
	Host       string
	Port       int
	DB         int
	Password   string
	KeyPrefix  string
	DefaultTTL time.Duration
}

func DefaultConfig() Config {
	return Config{
		Host:       "localhost",
		Port:       6379,
		DB:         0,
		KeyPrefix:  "app:",
		DefaultTTL: time.Hour,
	}
}

type RedisCache struct {
	client *redis.Client
	config Config
}

func New(config Config) *RedisCache {
	client := redis.NewClient(&redis.Options{
		Addr:     fmt.Sprintf("%s:%d", config.Host, config.Port),
		Password: config.Password,
		DB:       config.DB,
	})

	return &RedisCache{
		client: client,
		config: config,
	}
}

func (c *RedisCache) key(k string) string {
	return c.config.KeyPrefix + k
}

func (c *RedisCache) Ping(ctx context.Context) error {
	return c.client.Ping(ctx).Err()
}

func (c *RedisCache) Get(ctx context.Context, key string, dest interface{}) error {
	val, err := c.client.Get(ctx, c.key(key)).Result()
	if err != nil {
		return err
	}
	return json.Unmarshal([]byte(val), dest)
}

func (c *RedisCache) Set(ctx context.Context, key string, value interface{}, ttl time.Duration) error {
	if ttl == 0 {
		ttl = c.config.DefaultTTL
	}

	data, err := json.Marshal(value)
	if err != nil {
		return err
	}

	return c.client.Set(ctx, c.key(key), data, ttl).Err()
}

func (c *RedisCache) Delete(ctx context.Context, key string) error {
	return c.client.Del(ctx, c.key(key)).Err()
}

func (c *RedisCache) DeletePattern(ctx context.Context, pattern string) (int64, error) {
	keys, err := c.client.Keys(ctx, c.key(pattern)).Result()
	if err != nil {
		return 0, err
	}
	if len(keys) == 0 {
		return 0, nil
	}
	return c.client.Del(ctx, keys...).Result()
}

func (c *RedisCache) Exists(ctx context.Context, key string) (bool, error) {
	n, err := c.client.Exists(ctx, c.key(key)).Result()
	return n > 0, err
}

func (c *RedisCache) Incr(ctx context.Context, key string) (int64, error) {
	return c.client.Incr(ctx, c.key(key)).Result()
}

func (c *RedisCache) Expire(ctx context.Context, key string, ttl time.Duration) error {
	return c.client.Expire(ctx, c.key(key), ttl).Err()
}

// GetOrSet gets a value from cache, or sets it using the factory function
func (c *RedisCache) GetOrSet(ctx context.Context, key string, dest interface{}, ttl time.Duration, factory func() (interface{}, error)) error {
	err := c.Get(ctx, key, dest)
	if err == nil {
		return nil
	}
	if err != redis.Nil {
		return err
	}

	value, err := factory()
	if err != nil {
		return err
	}

	if err := c.Set(ctx, key, value, ttl); err != nil {
		return err
	}

	// Copy value to dest
	data, _ := json.Marshal(value)
	return json.Unmarshal(data, dest)
}

// CacheKey generates a cache key from arguments
func CacheKey(prefix string, args ...interface{}) string {
	data, _ := json.Marshal(args)
	hash := md5.Sum(data)
	return fmt.Sprintf("%s:%s", prefix, hex.EncodeToString(hash[:])[:12])
}

func (c *RedisCache) Close() error {
	return c.client.Close()
}

// Usage:
// cache := New(DefaultConfig())
// ctx := context.Background()
//
// // Set and get
// cache.Set(ctx, "user:123", user, time.Minute*5)
// var user User
// cache.Get(ctx, "user:123", &user)
//
// // Get or set
// cache.GetOrSet(ctx, "user:123", &user, time.Minute*5, func() (interface{}, error) {
//     return db.GetUser(ctx, "123")
// })
