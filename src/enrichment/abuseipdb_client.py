"""
AbuseIPDB API client with rate limiting and caching.

This module provides async integration with AbuseIPDB API v2 for IP enrichment.
"""

import asyncio
import logging
from datetime import datetime, date, timedelta, timezone
from typing import Optional, Dict, Any, List
import httpx
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update
from src.db.models import APIUsageTracking, AbuseIPDBCache

logger = logging.getLogger(__name__)


class AbuseIPDBClient:
    """
    Async client for AbuseIPDB API v2 with rate limiting.

    Implements intelligent caching and rate limiting to stay within
    the free tier limit of 1,000 requests per day.
    """

    BASE_URL = "https://api.abuseipdb.com/api/v2"

    def __init__(self, api_key: str, rate_limit: int = 1000):
        """
        Initialize AbuseIPDB client.

        Args:
            api_key: AbuseIPDB API key
            rate_limit: Daily request limit (default: 1000 for free tier)
        """
        self.api_key = api_key
        self.rate_limit = rate_limit
        self.headers = {
            "Key": api_key,
            "Accept": "application/json",
        }
        self._semaphore = asyncio.Semaphore(5)  # Max 5 concurrent requests

    async def check_rate_limit(self, db: AsyncSession) -> bool:
        """
        Check if we're within the daily rate limit.

        Args:
            db: Database session

        Returns:
            bool: True if we can make more requests, False if limit reached
        """
        today = date.today()

        # Get or create today's usage record
        stmt = select(APIUsageTracking).where(APIUsageTracking.date == today)
        result = await db.execute(stmt)
        usage = result.scalar_one_or_none()

        if not usage:
            usage = APIUsageTracking(date=today, requests_count=0)
            db.add(usage)
            await db.commit()
            return True

        return usage.requests_count < self.rate_limit

    async def increment_usage(self, db: AsyncSession, success: bool = True) -> None:
        """
        Increment API usage counter.

        Args:
            db: Database session
            success: Whether the request was successful
        """
        today = date.today()

        stmt = (
            update(APIUsageTracking)
            .where(APIUsageTracking.date == today)
            .values(
                requests_count=APIUsageTracking.requests_count + 1,
                successful_requests=APIUsageTracking.successful_requests + (1 if success else 0),
                failed_requests=APIUsageTracking.failed_requests + (0 if success else 1),
            )
        )
        await db.execute(stmt)
        await db.commit()

    async def get_cached_data(
        self, db: AsyncSession, ip_address: str, cache_ttl_hours: int = 24
    ) -> Optional[AbuseIPDBCache]:
        """
        Get cached AbuseIPDB data if available and fresh.

        Args:
            db: Database session
            ip_address: IP address to lookup
            cache_ttl_hours: Cache validity in hours

        Returns:
            Cached data if available and fresh, None otherwise
        """
        cutoff_time = datetime.now(timezone.utc) - timedelta(hours=cache_ttl_hours)

        stmt = (
            select(AbuseIPDBCache)
            .where(AbuseIPDBCache.ip_address == ip_address)
            .where(AbuseIPDBCache.last_checked >= cutoff_time)
        )
        result = await db.execute(stmt)
        return result.scalar_one_or_none()

    async def check_ip(
        self, ip_address: str, max_age_days: int = 90, verbose: bool = False
    ) -> Dict[str, Any]:
        """
        Check IP reputation with AbuseIPDB.

        Args:
            ip_address: IP address to check
            max_age_days: How far back to check (max 365)
            verbose: Include detailed report information

        Returns:
            API response data

        Raises:
            httpx.HTTPError: On API request failure
        """
        params = {
            "ipAddress": ip_address,
            "maxAgeInDays": min(max_age_days, 365),
            "verbose": "" if verbose else None,
        }

        # Remove None values
        params = {k: v for k, v in params.items() if v is not None}

        async with self._semaphore:  # Rate limiting
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"{self.BASE_URL}/check",
                    headers=self.headers,
                    params=params,
                    timeout=30.0,
                )
                response.raise_for_status()
                return response.json()

    async def check_ip_with_cache(
        self, db: AsyncSession, ip_address: str, force_refresh: bool = False
    ) -> Optional[AbuseIPDBCache]:
        """
        Check IP with caching and rate limiting.

        Args:
            db: Database session
            ip_address: IP address to check
            force_refresh: Force API call even if cached

        Returns:
            Enrichment data or None if rate limited
        """
        # Check cache first unless forced refresh
        if not force_refresh:
            cached = await self.get_cached_data(db, ip_address)
            if cached:
                logger.info(f"Using cached data for IP {ip_address}")
                return cached

        # Check rate limit
        if not await self.check_rate_limit(db):
            logger.warning("AbuseIPDB daily rate limit reached")
            return None

        try:
            # Make API request
            logger.info(f"Fetching fresh data for IP {ip_address}")
            response = await self.check_ip(ip_address)

            # Increment usage counter
            await self.increment_usage(db, success=True)

            # Parse and cache response
            data = response.get("data", {})

            # Check if cache entry exists
            stmt = select(AbuseIPDBCache).where(AbuseIPDBCache.ip_address == ip_address)
            result = await db.execute(stmt)
            cache_entry = result.scalar_one_or_none()

            if cache_entry:
                # Update existing entry
                cache_entry.abuse_confidence_score = data.get("abuseConfidenceScore", 0)
                cache_entry.country_code = data.get("countryCode")
                cache_entry.usage_type = data.get("usageType")
                cache_entry.isp = data.get("isp")
                cache_entry.domain = data.get("domain")
                cache_entry.total_reports = data.get("totalReports", 0)
                cache_entry.num_distinct_users = data.get("numDistinctUsers", 0)
                cache_entry.last_reported_at = data.get("lastReportedAt")
                cache_entry.extra_data = data
                cache_entry.last_checked = datetime.now(timezone.utc)
            else:
                # Create new entry
                cache_entry = AbuseIPDBCache(
                    ip_address=ip_address,
                    abuse_confidence_score=data.get("abuseConfidenceScore", 0),
                    country_code=data.get("countryCode"),
                    usage_type=data.get("usageType"),
                    isp=data.get("isp"),
                    domain=data.get("domain"),
                    total_reports=data.get("totalReports", 0),
                    num_distinct_users=data.get("numDistinctUsers", 0),
                    last_reported_at=data.get("lastReportedAt"),
                    extra_data=data,
                )
                db.add(cache_entry)

            await db.commit()
            await db.refresh(cache_entry)
            return cache_entry

        except httpx.HTTPError as e:
            logger.error(f"AbuseIPDB API error for IP {ip_address}: {str(e)}")
            await self.increment_usage(db, success=False)
            return None
        except Exception as e:
            logger.error(f"Unexpected error checking IP {ip_address}: {str(e)}")
            return None

    async def bulk_check_ips(
        self, db: AsyncSession, ip_addresses: List[str], batch_size: int = 10
    ) -> Dict[str, Optional[AbuseIPDBCache]]:
        """
        Check multiple IPs with rate limiting and caching.

        Args:
            db: Database session
            ip_addresses: List of IP addresses to check
            batch_size: Number of IPs to process concurrently

        Returns:
            Dictionary mapping IP addresses to enrichment data
        """
        results = {}

        for i in range(0, len(ip_addresses), batch_size):
            batch = ip_addresses[i : i + batch_size]

            # Check rate limit before processing batch
            if not await self.check_rate_limit(db):
                logger.warning("Rate limit reached during bulk check")
                break

            # Process batch concurrently
            tasks = [self.check_ip_with_cache(db, ip) for ip in batch]

            batch_results = await asyncio.gather(*tasks, return_exceptions=True)

            for ip, result in zip(batch, batch_results):
                if isinstance(result, Exception):
                    logger.error(f"Error processing IP {ip}: {result}")
                    results[ip] = None
                else:
                    results[ip] = result

            # Small delay between batches to avoid hitting rate limits
            await asyncio.sleep(0.5)

        return results
