"""
Background worker for processing IOCs with geolocation and enrichment.

This worker continuously processes IOCs from the database and caches
the results for fast TAXII2 endpoint responses.
"""

import asyncio
import logging
import os
import socket
from datetime import datetime, timezone
from typing import List, Dict, Any
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from src.db.database import AsyncSessionLocal
from src.db.models import ReportedIPs, AbuseIPDBCache
from src.core.correlation import IOCCorrelationEngine
from src.enrichment.abuseipdb_client import AbuseIPDBClient
from src.core.config import settings
from src.utils.redis_client import get_redis_cache

logger = logging.getLogger(__name__)


class IOCProcessor:
    """Background processor for IOCs."""

    def __init__(self):
        self.correlation_engine = IOCCorrelationEngine()
        self.abuseipdb_client = AbuseIPDBClient(settings.ABUSEIPDB_API_KEY)
        self.running = False
        self.processing = False  # Flag to prevent concurrent processing
        self.process_interval = 300  # Process every 5 minutes
        self.batch_size = 100  # Process in batches to avoid memory issues

    async def start(self):
        """Start the background processor."""
        self.running = True
        logger.info("IOC Processor started")

        while self.running:
            try:
                # Skip if already processing
                if self.processing:
                    logger.warning("IOC processing already in progress, skipping this cycle")
                else:
                    await self._process_iocs()
            except Exception as e:
                logger.error(f"Error in IOC processor: {e}")
                self.processing = False  # Reset flag on error

            # Wait before next processing cycle
            await asyncio.sleep(self.process_interval)

    async def stop(self):
        """Stop the background processor."""
        self.running = False
        logger.info("IOC Processor stopped")

    async def _process_iocs(self):
        """Process IOCs and cache results."""
        # Set processing flag to prevent concurrent execution
        self.processing = True
        start_time = datetime.now(timezone.utc)
        lock_acquired = False

        try:
            async with AsyncSessionLocal() as db:
                # Get Redis cache
                redis_cache = await get_redis_cache()
                if not redis_cache:
                    logger.error("Redis cache not available")
                    return

                # Try to acquire distributed lock
                lock_key = "ioc_processor_lock"
                lock_ttl = 900  # 15 minutes TTL for the lock

                # Check if lock exists
                existing_lock = await redis_cache._redis.get(lock_key)
                if existing_lock:
                    logger.warning(
                        f"Another IOC processor is running (lock held by: {existing_lock}). Skipping this cycle."
                    )
                    return

                # Acquire lock with instance identifier
                instance_id = f"{socket.gethostname()}-{os.getpid()}"
                lock_acquired = await redis_cache._redis.set(
                    lock_key, instance_id, nx=True, ex=lock_ttl
                )

                if not lock_acquired:
                    logger.warning("Could not acquire lock, another processor may be running")
                    return

                logger.info(
                    f"Starting IOC processing cycle at {start_time.isoformat()} (lock acquired by {instance_id})"
                )

                # 1. Get all local IOCs
                local_iocs = await self._get_local_iocs(db)
                logger.info(f"Found {len(local_iocs)} local IOCs")

                # 2. Get AbuseIPDB blacklist
                abuseipdb_iocs = await self._get_abuseipdb_blacklist(db)
                logger.info(f"Found {len(abuseipdb_iocs)} AbuseIPDB IOCs")

                # 3. Combine all IOCs
                all_iocs = local_iocs + abuseipdb_iocs
                logger.info(f"Total IOCs to process: {len(all_iocs)}")

                # 4. Get cached enrichment data
                external_data = await self._get_cached_enrichments(db, all_iocs)

                # 5. Process IOCs in batches
                processed_iocs = []
                for i in range(0, len(all_iocs), self.batch_size):
                    batch = all_iocs[i : i + self.batch_size]
                    logger.info(f"Processing batch {i//self.batch_size + 1} ({len(batch)} IOCs)")

                    for ioc in batch:
                        try:
                            ip_address = ioc["ip_address"]
                            external_ioc_data = external_data.get(ip_address)

                            # For AbuseIPDB blacklist items without cache
                            if ioc.get("source") == "abuseipdb" and not external_ioc_data:
                                external_ioc_data = {
                                    "abuse_confidence_score": ioc["confidence"],
                                    "country_code": None,
                                    "isp": None,
                                    "usage_type": None,
                                    "total_reports": 1,
                                    "last_reported_at": ioc["reported_at"],
                                }

                            # Correlate and enrich
                            correlated = self.correlation_engine.correlate_ioc(
                                ioc, external_ioc_data
                            )
                            enriched = await self.correlation_engine.enrich_with_geolocation(
                                correlated
                            )
                            processed_iocs.append(enriched)

                        except Exception as e:
                            logger.error(f"Error processing IOC {ioc.get('ip_address')}: {e}")
                            processed_iocs.append(ioc)  # Add unprocessed

                # 6. Cache processed IOCs
                await redis_cache.cache_iocs(
                    processed_iocs, key="preprocessed_iocs", ttl=600
                )  # 10 min TTL
                logger.info(f"Cached {len(processed_iocs)} processed IOCs")

                # 7. Also cache by confidence level
                high_confidence = [ioc for ioc in processed_iocs if ioc.get("confidence", 0) >= 80]
                await redis_cache.cache_iocs(high_confidence, key="high_confidence_iocs", ttl=600)
                logger.info(f"Cached {len(high_confidence)} high confidence IOCs")

                # Calculate processing time
                end_time = datetime.now(timezone.utc)
                duration = (end_time - start_time).total_seconds()
                logger.info(f"IOC processing completed in {duration:.2f} seconds")

        except Exception as e:
            logger.error(f"Error in _process_iocs: {e}")
            raise
        finally:
            # Always reset processing flag
            self.processing = False

            # Release Redis lock if acquired
            if lock_acquired and redis_cache and redis_cache._redis:
                try:
                    await redis_cache._redis.delete(lock_key)
                    logger.info("Released IOC processor lock")
                except Exception as e:
                    logger.error(f"Error releasing lock: {e}")

    async def _get_local_iocs(self, db: AsyncSession) -> List[Dict[str, Any]]:
        """Get IOCs from local database."""
        query = select(ReportedIPs).order_by(ReportedIPs.reported_at.desc())
        result = await db.execute(query)
        local_iocs = result.scalars().all()

        return [
            {
                "ip_address": ioc.ip_address,
                "confidence": ioc.confidence,
                "reported_at": ioc.reported_at,
                "report_id": ioc.report_id,
                "categories": ioc.categories or [],
                "created_at": ioc.created_at,
                "source": "local",
            }
            for ioc in local_iocs
        ]

    async def _get_abuseipdb_blacklist(self, db: AsyncSession) -> List[Dict[str, Any]]:
        """Get IOCs from AbuseIPDB blacklist."""
        try:
            response = await self.abuseipdb_client.get_blacklist(
                db=db,
                confidence_minimum=50,
                limit=10000,
            )

            if not response.get("data"):
                return []

            # Get existing local IPs to avoid duplicates
            query = select(ReportedIPs.ip_address)
            result = await db.execute(query)
            local_ips = set(result.scalars().all())

            abuseipdb_iocs = []
            for item in response["data"]:
                ip_address = item.get("ipAddress")
                if ip_address not in local_ips:
                    abuseipdb_iocs.append(
                        {
                            "ip_address": ip_address,
                            "confidence": item.get("abuseConfidenceScore", 50),
                            "reported_at": datetime.now(timezone.utc),
                            "report_id": f"ABUSEIPDB-{item.get('abuseConfidenceScore', 50)}",
                            "categories": ["abuseipdb-blacklist"],
                            "created_at": datetime.now(timezone.utc),
                            "source": "abuseipdb",
                        }
                    )

            return abuseipdb_iocs

        except Exception as e:
            logger.error(f"Error fetching AbuseIPDB blacklist: {e}")
            return []

    async def _get_cached_enrichments(
        self, db: AsyncSession, iocs: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Get cached enrichment data from database."""
        ip_addresses = [ioc["ip_address"] for ioc in iocs]

        query = select(AbuseIPDBCache).where(AbuseIPDBCache.ip_address.in_(ip_addresses))
        result = await db.execute(query)
        cached_enrichments = result.scalars().all()

        external_data = {}
        for enrichment in cached_enrichments:
            external_data[enrichment.ip_address] = {
                "abuse_confidence_score": enrichment.abuse_confidence_score,
                "country_code": enrichment.country_code,
                "isp": enrichment.isp,
                "usage_type": enrichment.usage_type,
                "total_reports": enrichment.total_reports,
                "last_reported_at": enrichment.last_reported_at,
            }

        return external_data


# Global processor instance
ioc_processor = IOCProcessor()


async def start_ioc_processor():
    """Start the IOC processor task."""
    await ioc_processor.start()


async def stop_ioc_processor():
    """Stop the IOC processor task."""
    await ioc_processor.stop()
