"""
File: cache.tpl.py
Purpose: Redis caching utilities with async support
Generated for: {{PROJECT_NAME}}
"""

import json
import hashlib
from typing import Any, Callable, Optional, TypeVar, Union
from functools import wraps
from datetime import timedelta
import redis.asyncio as redis
from pydantic import BaseModel

T = TypeVar("T")


class CacheConfig(BaseModel):
    host: str = "localhost"
    port: int = 6379
    db: int = 0
    password: Optional[str] = None
    key_prefix: str = "app:"
    default_ttl: int = 3600  # 1 hour


class RedisCache:
    def __init__(self, config: CacheConfig):
        self.config = config
        self.client: Optional[redis.Redis] = None

    async def connect(self):
        self.client = redis.Redis(
            host=self.config.host,
            port=self.config.port,
            db=self.config.db,
            password=self.config.password,
            decode_responses=True,
        )

    async def disconnect(self):
        if self.client:
            await self.client.close()

    def _key(self, key: str) -> str:
        return f"{self.config.key_prefix}{key}"

    async def get(self, key: str) -> Optional[Any]:
        """Get a value from cache"""
        value = await self.client.get(self._key(key))
        if value:
            return json.loads(value)
        return None

    async def set(
        self,
        key: str,
        value: Any,
        ttl: Optional[int] = None,
    ) -> None:
        """Set a value in cache"""
        ttl = ttl or self.config.default_ttl
        await self.client.setex(
            self._key(key),
            ttl,
            json.dumps(value, default=str),
        )

    async def delete(self, key: str) -> None:
        """Delete a key from cache"""
        await self.client.delete(self._key(key))

    async def delete_pattern(self, pattern: str) -> int:
        """Delete all keys matching a pattern"""
        keys = await self.client.keys(self._key(pattern))
        if keys:
            return await self.client.delete(*keys)
        return 0

    async def exists(self, key: str) -> bool:
        """Check if a key exists"""
        return await self.client.exists(self._key(key)) > 0

    async def incr(self, key: str, amount: int = 1) -> int:
        """Increment a counter"""
        return await self.client.incrby(self._key(key), amount)

    async def expire(self, key: str, ttl: int) -> None:
        """Set TTL on existing key"""
        await self.client.expire(self._key(key), ttl)


# Decorator for caching function results
def cached(
    cache: RedisCache,
    key_prefix: str,
    ttl: int = 3600,
    key_builder: Optional[Callable[..., str]] = None,
):
    """Decorator to cache function results"""
    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @wraps(func)
        async def wrapper(*args, **kwargs) -> T:
            # Build cache key
            if key_builder:
                cache_key = key_builder(*args, **kwargs)
            else:
                key_data = json.dumps({"args": args, "kwargs": kwargs}, sort_keys=True, default=str)
                key_hash = hashlib.md5(key_data.encode()).hexdigest()[:12]
                cache_key = f"{key_prefix}:{key_hash}"

            # Try to get from cache
            cached_value = await cache.get(cache_key)
            if cached_value is not None:
                return cached_value

            # Execute function and cache result
            result = await func(*args, **kwargs)
            await cache.set(cache_key, result, ttl)
            return result

        return wrapper
    return decorator


# Global cache instance (configure at startup)
cache: Optional[RedisCache] = None


async def init_cache(config: CacheConfig) -> RedisCache:
    global cache
    cache = RedisCache(config)
    await cache.connect()
    return cache


# Usage:
# cache = await init_cache(CacheConfig())
# 
# @cached(cache, "users", ttl=300)
# async def get_user(user_id: str):
#     return await db.fetch_user(user_id)
