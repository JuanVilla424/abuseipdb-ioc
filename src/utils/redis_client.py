"""
Redis client for IOC caching with daily update limits.

Provides Redis integration with rate limiting for production use.
"""

import json
import logging
from datetime import datetime, date, timezone
from typing import Optional, Dict, Any, List
import redis.asyncio as redis
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from src.db.models import APIUsageTracking
from src.core.config import settings


class DateTimeEncoder(json.JSONEncoder):
    """Custom JSON encoder for datetime objects."""

    def default(self, obj):
        if isinstance(obj, (datetime, date)):
            return obj.isoformat()
        return super().default(obj)


logger = logging.getLogger(__name__)


class RedisIOCCache:
    """Redis cache for IOC data with daily update limits."""

    def __init__(self, redis_url: str):
        """
        Initialize Redis cache client.

        Args:
            redis_url: Redis connection URL
        """
        self.redis_url = redis_url
        self._redis: Optional[redis.Redis] = None

    async def connect(self):
        """Establish Redis connection."""
        if not self._redis:
            self._redis = redis.from_url(self.redis_url, decode_responses=True)
            try:
                await self._redis.ping()
                logger.info("Redis connection established")
            except Exception as e:
                logger.error(f"Redis connection failed: {e}")
                self._redis = None
                raise

    async def disconnect(self):
        """Close Redis connection."""
        if self._redis:
            await self._redis.close()
            self._redis = None

    async def get_iocs(self, key: str = "blacklist_iocs") -> Optional[List[Dict[str, Any]]]:
        """
        Get IOCs from Redis cache.

        Args:
            key: Cache key name

        Returns:
            List of IOC dictionaries or None if not found
        """
        if not self._redis:
            return None

        try:
            cached_data = await self._redis.get(key)
            if cached_data:
                data = json.loads(cached_data)
                logger.info(f"Retrieved {len(data.get('iocs', []))} IOCs from Redis cache")
                return data.get("iocs", [])
        except Exception as e:
            logger.error(f"Redis get error: {e}")

        return None

    async def set_iocs(
        self,
        iocs: List[Dict[str, Any]],
        key: str = "blacklist_iocs",
        ttl: int = 86400,  # 24 hours
    ) -> bool:
        """
        Store IOCs in Redis cache.

        Args:
            iocs: List of IOC dictionaries
            key: Cache key name
            ttl: Time to live in seconds

        Returns:
            bool: True if stored successfully, False if error
        """
        if not self._redis:
            logger.warning("Redis not connected, cannot cache IOCs")
            return False

        try:
            cache_data = {
                "iocs": iocs,
                "cached_at": datetime.now(timezone.utc).isoformat(),
                "count": len(iocs),
            }

            await self._redis.setex(key, ttl, json.dumps(cache_data, cls=DateTimeEncoder))
            logger.info(f"Cached {len(iocs)} IOCs in Redis with {ttl}s TTL")
            return True

        except Exception as e:
            logger.error(f"Redis set error: {e}")
            return False

    async def get_cache_info(self, key: str = "blacklist_iocs") -> Optional[Dict[str, Any]]:
        """
        Get cache metadata.

        Args:
            key: Cache key name

        Returns:
            Cache info dictionary or None
        """
        if not self._redis:
            return None

        try:
            cached_data = await self._redis.get(key)
            if cached_data:
                data = json.loads(cached_data)
                return {
                    "cached_at": data.get("cached_at"),
                    "count": data.get("count", 0),
                    "ttl": await self._redis.ttl(key),
                }
        except Exception as e:
            logger.error(f"Redis cache info error: {e}")

        return None

    async def get(self, key: str) -> Optional[Any]:
        """
        Get generic data from Redis cache.

        Args:
            key: Cache key name

        Returns:
            Cached data or None if not found
        """
        if not self._redis:
            return None

        try:
            cached_data = await self._redis.get(key)
            if cached_data:
                return json.loads(cached_data)
        except Exception as e:
            logger.error(f"Redis get error for key {key}: {e}")

        return None

    async def set(self, key: str, data: Any, ttl: int = 3600) -> bool:
        """
        Store generic data in Redis cache.

        Args:
            key: Cache key name
            data: Data to store
            ttl: Time to live in seconds

        Returns:
            bool: True if stored successfully, False if error
        """
        if not self._redis:
            logger.warning("Redis not connected, cannot cache data")
            return False

        try:
            await self._redis.setex(key, ttl, json.dumps(data, cls=DateTimeEncoder))
            logger.debug(f"Cached data in Redis key {key} with {ttl}s TTL")
            return True

        except Exception as e:
            logger.error(f"Redis set error for key {key}: {e}")
            return False

    async def clear_cache(self, key: str = "blacklist_iocs") -> bool:
        """
        Clear specific cache key.

        Args:
            key: Cache key to clear

        Returns:
            bool: True if cleared successfully
        """
        if not self._redis:
            return False

        try:
            result = await self._redis.delete(key)
            logger.info(f"Cleared cache key: {key}")
            return bool(result)
        except Exception as e:
            logger.error(f"Redis clear error: {e}")
            return False


# Global Redis client instance
redis_cache: Optional[RedisIOCCache] = None


async def get_redis_cache() -> Optional[RedisIOCCache]:
    """Get Redis cache instance."""
    global redis_cache

    if not settings.REDIS_URL:
        return None

    if not redis_cache:
        redis_cache = RedisIOCCache(settings.REDIS_URL)
        await redis_cache.connect()

    return redis_cache
