"""
Rate limiting utilities.
"""

import asyncio
import time
from typing import Dict
from collections import defaultdict, deque


class TokenBucket:
    """
    Token bucket rate limiter implementation.
    """

    def __init__(self, capacity: int, refill_rate: float):
        """
        Initialize token bucket.

        Args:
            capacity: Maximum number of tokens
            refill_rate: Tokens added per second
        """
        self.capacity = capacity
        self.refill_rate = refill_rate
        self.tokens = capacity
        self.last_refill = time.time()
        self._lock = asyncio.Lock()

    async def consume(self, tokens: int = 1) -> bool:
        """
        Try to consume tokens from bucket.

        Args:
            tokens: Number of tokens to consume

        Returns:
            bool: True if tokens were consumed
        """
        async with self._lock:
            now = time.time()
            time_passed = now - self.last_refill

            # Refill tokens
            new_tokens = time_passed * self.refill_rate
            self.tokens = min(self.capacity, self.tokens + new_tokens)
            self.last_refill = now

            # Check if we can consume
            if self.tokens >= tokens:
                self.tokens -= tokens
                return True

            return False

    async def wait_for_tokens(self, tokens: int = 1) -> None:
        """
        Wait until tokens are available.

        Args:
            tokens: Number of tokens needed
        """
        while not await self.consume(tokens):
            await asyncio.sleep(0.1)


class SlidingWindowRateLimit:
    """
    Sliding window rate limiter.
    """

    def __init__(self, max_requests: int, window_seconds: int):
        """
        Initialize sliding window rate limiter.

        Args:
            max_requests: Maximum requests in window
            window_seconds: Window size in seconds
        """
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests: Dict[str, deque] = defaultdict(deque)
        self._lock = asyncio.Lock()

    async def is_allowed(self, key: str) -> bool:
        """
        Check if request is allowed for key.

        Args:
            key: Identifier for rate limiting

        Returns:
            bool: True if request is allowed
        """
        async with self._lock:
            now = time.time()
            window_start = now - self.window_seconds

            # Remove old requests
            while self.requests[key] and self.requests[key][0] < window_start:
                self.requests[key].popleft()

            # Check if under limit
            if len(self.requests[key]) < self.max_requests:
                self.requests[key].append(now)
                return True

            return False

    async def time_until_allowed(self, key: str) -> float:
        """
        Get time until next request is allowed.

        Args:
            key: Identifier for rate limiting

        Returns:
            Seconds until next request allowed
        """
        async with self._lock:
            if len(self.requests[key]) < self.max_requests:
                return 0.0

            # Time until oldest request expires
            oldest_request = self.requests[key][0]
            return oldest_request + self.window_seconds - time.time()


class DailyRateLimit:
    """
    Daily rate limiter for API usage tracking.
    """

    def __init__(self, daily_limit: int):
        """
        Initialize daily rate limiter.

        Args:
            daily_limit: Maximum requests per day
        """
        self.daily_limit = daily_limit
        self.usage: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
        self._lock = asyncio.Lock()

    def _get_today_key(self) -> str:
        """Get today's date key."""
        return time.strftime("%Y-%m-%d")

    async def increment_usage(self, key: str) -> int:
        """
        Increment usage counter for key.

        Args:
            key: Identifier for tracking

        Returns:
            Current usage count for today
        """
        async with self._lock:
            today = self._get_today_key()
            self.usage[key][today] += 1
            return self.usage[key][today]

    async def get_usage(self, key: str) -> int:
        """
        Get current usage for key today.

        Args:
            key: Identifier for tracking

        Returns:
            Usage count for today
        """
        today = self._get_today_key()
        return self.usage[key][today]

    async def is_under_limit(self, key: str) -> bool:
        """
        Check if key is under daily limit.

        Args:
            key: Identifier for checking

        Returns:
            bool: True if under limit
        """
        usage = await self.get_usage(key)
        return usage < self.daily_limit

    async def get_remaining(self, key: str) -> int:
        """
        Get remaining requests for today.

        Args:
            key: Identifier for checking

        Returns:
            Remaining requests
        """
        usage = await self.get_usage(key)
        return max(0, self.daily_limit - usage)
