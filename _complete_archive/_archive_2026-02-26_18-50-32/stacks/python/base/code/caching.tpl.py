"""
File: caching.tpl.py
Purpose: Redis caching patterns with decorators and cache management
Generated for: {{PROJECT_NAME}}
"""

import functools
import hashlib
import json
import pickle
from datetime import timedelta
from typing import Any, Callable, Optional, TypeVar, Union

import redis.asyncio as redis

# Type variables
T = TypeVar("T")
F = TypeVar("F", bound=Callable[..., Any])


# ============================================================================
# Redis Client Manager
# ============================================================================

class RedisManager:
    """Manage Redis connections."""
    
    _client: Optional[redis.Redis] = None
    
    @classmethod
    async def get_client(cls) -> redis.Redis:
        """Get or create Redis client."""
        if cls._client is None:
            cls._client = redis.from_url(
                "redis://localhost:6379/0",
                encoding="utf-8",
                decode_responses=True,
            )
        return cls._client
    
    @classmethod
    async def close(cls):
        """Close Redis connection."""
        if cls._client:
            await cls._client.close()
            cls._client = None


# ============================================================================
# Cache Key Builder
# ============================================================================

class CacheKeyBuilder:
    """Build consistent cache keys."""
    
    def __init__(self, prefix: str = "app"):
        self.prefix = prefix
    
    def build(self, *parts: str) -> str:
        """Build a cache key from parts."""
        return ":".join([self.prefix, *parts])
    
    def from_function(
        self,
        func: Callable,
        args: tuple,
        kwargs: dict,
        key_prefix: Optional[str] = None,
    ) -> str:
        """Build cache key from function call."""
        prefix = key_prefix or f"{func.__module__}.{func.__name__}"
        
        # Create a hash of arguments
        key_parts = [prefix]
        
        if args:
            key_parts.append(self._hash_value(args))
        
        if kwargs:
            sorted_kwargs = sorted(kwargs.items())
            key_parts.append(self._hash_value(sorted_kwargs))
        
        return self.build(*key_parts)
    
    def _hash_value(self, value: Any) -> str:
        """Create a hash of a value."""
        try:
            serialized = json.dumps(value, sort_keys=True, default=str)
        except (TypeError, ValueError):
            serialized = str(value)
        return hashlib.md5(serialized.encode()).hexdigest()[:12]


key_builder = CacheKeyBuilder()


# ============================================================================
# Cache Serializers
# ============================================================================

class JSONSerializer:
    """JSON serializer for cache values."""
    
    @staticmethod
    def serialize(value: Any) -> str:
        return json.dumps(value, default=str)
    
    @staticmethod
    def deserialize(data: str) -> Any:
        return json.loads(data)


class PickleSerializer:
    """Pickle serializer for complex objects."""
    
    @staticmethod
    def serialize(value: Any) -> bytes:
        return pickle.dumps(value)
    
    @staticmethod
    def deserialize(data: bytes) -> Any:
        return pickle.loads(data)


# ============================================================================
# Cache Decorators
# ============================================================================

def cached(
    ttl: Union[int, timedelta] = 300,
    key_prefix: Optional[str] = None,
    serializer: Any = JSONSerializer,
    condition: Optional[Callable[..., bool]] = None,
):
    """
    Cache decorator for async functions.
    
    Args:
        ttl: Time to live in seconds or timedelta
        key_prefix: Custom key prefix
        serializer: Serializer class
        condition: Optional condition function to determine if result should be cached
    """
    if isinstance(ttl, timedelta):
        ttl = int(ttl.total_seconds())
    
    def decorator(func: F) -> F:
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            # Build cache key
            cache_key = key_builder.from_function(func, args, kwargs, key_prefix)
            
            # Get Redis client
            client = await RedisManager.get_client()
            
            # Try to get from cache
            cached_value = await client.get(cache_key)
            if cached_value is not None:
                return serializer.deserialize(cached_value)
            
            # Call the function
            result = await func(*args, **kwargs)
            
            # Check condition
            if condition is not None and not condition(result):
                return result
            
            # Store in cache
            serialized = serializer.serialize(result)
            await client.set(cache_key, serialized, ex=ttl)
            
            return result
        
        # Add cache management methods
        wrapper.cache_key = lambda *a, **kw: key_builder.from_function(func, a, kw, key_prefix)
        wrapper.invalidate = lambda *a, **kw: _invalidate_cache(
            key_builder.from_function(func, a, kw, key_prefix)
        )
        
        return wrapper
    
    return decorator


def cached_property(ttl: int = 300, key_prefix: Optional[str] = None):
    """Cache decorator for instance methods with object-specific keys."""
    
    def decorator(func: F) -> F:
        @functools.wraps(func)
        async def wrapper(self, *args, **kwargs):
            # Include object ID in cache key
            obj_id = getattr(self, "id", id(self))
            prefix = f"{key_prefix or func.__name__}:{obj_id}"
            
            cache_key = key_builder.from_function(func, args, kwargs, prefix)
            client = await RedisManager.get_client()
            
            cached_value = await client.get(cache_key)
            if cached_value is not None:
                return JSONSerializer.deserialize(cached_value)
            
            result = await func(self, *args, **kwargs)
            
            serialized = JSONSerializer.serialize(result)
            await client.set(cache_key, serialized, ex=ttl)
            
            return result
        
        return wrapper
    
    return decorator


async def _invalidate_cache(key: str):
    """Invalidate a cache key."""
    client = await RedisManager.get_client()
    await client.delete(key)


# ============================================================================
# Cache Manager
# ============================================================================

class CacheManager:
    """High-level cache management."""
    
    def __init__(self, prefix: str = "cache"):
        self.prefix = prefix
        self.key_builder = CacheKeyBuilder(prefix)
    
    async def get(self, key: str) -> Optional[Any]:
        """Get a value from cache."""
        client = await RedisManager.get_client()
        cache_key = self.key_builder.build(key)
        value = await client.get(cache_key)
        if value:
            return JSONSerializer.deserialize(value)
        return None
    
    async def set(
        self,
        key: str,
        value: Any,
        ttl: int = 300,
    ):
        """Set a value in cache."""
        client = await RedisManager.get_client()
        cache_key = self.key_builder.build(key)
        serialized = JSONSerializer.serialize(value)
        await client.set(cache_key, serialized, ex=ttl)
    
    async def delete(self, key: str):
        """Delete a cache key."""
        client = await RedisManager.get_client()
        cache_key = self.key_builder.build(key)
        await client.delete(cache_key)
    
    async def delete_pattern(self, pattern: str):
        """Delete all keys matching a pattern."""
        client = await RedisManager.get_client()
        full_pattern = self.key_builder.build(pattern)
        
        cursor = 0
        while True:
            cursor, keys = await client.scan(cursor, match=full_pattern)
            if keys:
                await client.delete(*keys)
            if cursor == 0:
                break
    
    async def get_or_set(
        self,
        key: str,
        factory: Callable[[], Any],
        ttl: int = 300,
    ) -> Any:
        """Get from cache or compute and cache."""
        value = await self.get(key)
        if value is not None:
            return value
        
        value = await factory() if asyncio.iscoroutinefunction(factory) else factory()
        await self.set(key, value, ttl)
        return value
    
    async def exists(self, key: str) -> bool:
        """Check if a key exists."""
        client = await RedisManager.get_client()
        cache_key = self.key_builder.build(key)
        return await client.exists(cache_key) > 0
    
    async def ttl(self, key: str) -> int:
        """Get TTL for a key."""
        client = await RedisManager.get_client()
        cache_key = self.key_builder.build(key)
        return await client.ttl(cache_key)
    
    async def increment(self, key: str, amount: int = 1) -> int:
        """Increment a counter."""
        client = await RedisManager.get_client()
        cache_key = self.key_builder.build(key)
        return await client.incrby(cache_key, amount)
    
    async def clear_all(self):
        """Clear all cache keys with this prefix."""
        await self.delete_pattern("*")


# Import asyncio for type checking
import asyncio

# Global cache manager instance
cache = CacheManager()


# ============================================================================
# Specialized Caches
# ============================================================================

class UserCache:
    """Specialized cache for user data."""
    
    TTL = 300  # 5 minutes
    
    @staticmethod
    async def get_user(user_id: int) -> Optional[dict]:
        key = f"user:{user_id}"
        return await cache.get(key)
    
    @staticmethod
    async def set_user(user_id: int, user_data: dict):
        key = f"user:{user_id}"
        await cache.set(key, user_data, ttl=UserCache.TTL)
    
    @staticmethod
    async def invalidate_user(user_id: int):
        key = f"user:{user_id}"
        await cache.delete(key)
    
    @staticmethod
    async def invalidate_all():
        await cache.delete_pattern("user:*")


class SessionCache:
    """Cache for user sessions."""
    
    TTL = 86400  # 24 hours
    
    @staticmethod
    async def get_session(token_hash: str) -> Optional[dict]:
        key = f"session:{token_hash}"
        return await cache.get(key)
    
    @staticmethod
    async def set_session(token_hash: str, session_data: dict, ttl: int = TTL):
        key = f"session:{token_hash}"
        await cache.set(key, session_data, ttl=ttl)
    
    @staticmethod
    async def delete_session(token_hash: str):
        key = f"session:{token_hash}"
        await cache.delete(key)
    
    @staticmethod
    async def delete_user_sessions(user_id: int):
        await cache.delete_pattern(f"session:*:user:{user_id}")


class RateLimitCache:
    """Cache for rate limiting."""
    
    @staticmethod
    async def check_rate_limit(
        key: str,
        limit: int,
        window: int,
    ) -> tuple[bool, int]:
        """
        Check if rate limit is exceeded.
        
        Returns:
            Tuple of (is_allowed, remaining_requests)
        """
        client = await RedisManager.get_client()
        cache_key = f"ratelimit:{key}"
        
        current = await client.get(cache_key)
        if current is None:
            await client.set(cache_key, 1, ex=window)
            return True, limit - 1
        
        count = int(current)
        if count >= limit:
            return False, 0
        
        await client.incr(cache_key)
        return True, limit - count - 1
