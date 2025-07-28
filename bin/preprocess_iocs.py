#!/usr/bin/env python3
"""
Pre-process IOCs from PostgreSQL with geolocation enrichment.
This script should run periodically (cron) to prepare IOCs for Elasticsearch.
"""

import asyncio
import logging
from datetime import datetime, timezone
from typing import List, Dict, Any

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from src.db.database import get_db
from src.db.models import ReportedIPs, AbuseIPDBCache
from src.core.correlation import IOCCorrelationEngine
from src.utils.geolocation import GeolocationService
from src.utils.redis_client import get_redis_cache
from src.enrichment.abuseipdb_client import AbuseIPDBClient
from src.core.config import settings

# Setup logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


class IOCPreProcessor:
    """Pre-process and cache IOCs with geolocation."""

    def __init__(self):
        self.correlation_engine = IOCCorrelationEngine()
        self.geo_service = GeolocationService()
        self.abuseipdb_client = AbuseIPDBClient(settings.ABUSEIPDB_API_KEY)

    async def process_all_iocs(self, db: AsyncSession) -> Dict[str, Any]:
        """Process all IOCs from database with enrichment."""
        stats = {
            "total": 0,
            "processed": 0,
            "geo_enriched": 0,
            "cached": 0,
            "errors": 0,
            "start_time": datetime.now(timezone.utc),
        }

        try:
            # Get ALL IOCs from PostgreSQL
            logger.info("Fetching all IOCs from reported_ips table...")
            query = select(ReportedIPs).order_by(ReportedIPs.reported_at.desc())
            result = await db.execute(query)
            local_iocs = result.scalars().all()
            stats["total"] = len(local_iocs)
            logger.info(f"Found {stats['total']} IOCs to process")

            # Get existing enrichment data from cache
            ip_addresses = [ioc.ip_address for ioc in local_iocs]
            cache_query = select(AbuseIPDBCache).where(AbuseIPDBCache.ip_address.in_(ip_addresses))
            cache_result = await db.execute(cache_query)
            cached_enrichments = {e.ip_address: e for e in cache_result.scalars().all()}

            # Process in batches to avoid memory issues
            batch_size = 100
            processed_iocs = []

            for i in range(0, len(local_iocs), batch_size):
                batch = local_iocs[i : i + batch_size]
                logger.info(f"Processing batch {i//batch_size + 1} ({len(batch)} IOCs)...")

                for ioc in batch:
                    try:
                        # Convert to dict
                        local_data = {
                            "ip_address": ioc.ip_address,
                            "confidence": ioc.confidence,
                            "reported_at": ioc.reported_at,
                            "report_id": ioc.report_id,
                            "categories": ioc.categories or [],
                            "created_at": ioc.created_at,
                        }

                        # Get cached enrichment if available
                        external_data = None
                        if ioc.ip_address in cached_enrichments:
                            cache = cached_enrichments[ioc.ip_address]
                            external_data = {
                                "abuse_confidence_score": cache.abuse_confidence_score,
                                "country_code": cache.country_code,
                                "isp": cache.isp,
                                "usage_type": cache.usage_type,
                                "total_reports": cache.total_reports,
                                "last_reported_at": cache.last_reported_at,
                            }

                        # Correlate
                        correlated = self.correlation_engine.correlate_ioc(
                            local_data, external_data
                        )

                        # Enrich with geolocation
                        enriched = await self.correlation_engine.enrich_with_geolocation(correlated)

                        if enriched.get("enrichment", {}).get("geolocation"):
                            stats["geo_enriched"] += 1

                        processed_iocs.append(enriched)
                        stats["processed"] += 1

                    except Exception as e:
                        logger.error(f"Error processing IOC {ioc.ip_address}: {e}")
                        stats["errors"] += 1

                # Small delay to avoid overwhelming geo service
                await asyncio.sleep(0.1)

            # Cache processed IOCs in Redis
            redis_cache = await get_redis_cache()
            if redis_cache:
                try:
                    # Store with special key for pre-processed data
                    success = await redis_cache.set_iocs(
                        processed_iocs, key="preprocessed_iocs", ttl=86400  # 24 hours
                    )
                    if success:
                        stats["cached"] = len(processed_iocs)
                        logger.info(f"Cached {stats['cached']} pre-processed IOCs in Redis")
                except Exception as e:
                    logger.error(f"Failed to cache IOCs: {e}")

            # Store processing metadata
            await self._save_processing_stats(db, stats)

        except Exception as e:
            logger.error(f"Critical error in pre-processing: {e}")
            stats["errors"] += 1

        stats["end_time"] = datetime.now(timezone.utc)
        stats["duration"] = (stats["end_time"] - stats["start_time"]).total_seconds()

        return stats

    async def _save_processing_stats(self, db: AsyncSession, stats: Dict[str, Any]):
        """Save processing statistics to database."""
        try:
            # Create table if not exists
            await db.execute(
                text(
                    """
                CREATE TABLE IF NOT EXISTS ioc_preprocessing_stats (
                    id SERIAL PRIMARY KEY,
                    processed_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                    total_iocs INTEGER,
                    processed_iocs INTEGER,
                    geo_enriched INTEGER,
                    cached_iocs INTEGER,
                    errors INTEGER,
                    duration_seconds FLOAT
                )
            """
                )
            )

            # Insert stats
            await db.execute(
                text(
                    """
                INSERT INTO ioc_preprocessing_stats
                (total_iocs, processed_iocs, geo_enriched, cached_iocs, errors, duration_seconds)
                VALUES (:total, :processed, :geo, :cached, :errors, :duration)
            """
                ),
                {
                    "total": stats["total"],
                    "processed": stats["processed"],
                    "geo": stats["geo_enriched"],
                    "cached": stats["cached"],
                    "errors": stats["errors"],
                    "duration": stats.get("duration", 0),
                },
            )

            await db.commit()
            logger.info("Saved preprocessing statistics to database")

        except Exception as e:
            logger.error(f"Failed to save stats: {e}")


async def main():
    """Main entry point."""
    logger.info("Starting IOC pre-processing...")

    processor = IOCPreProcessor()

    async for db in get_db():
        stats = await processor.process_all_iocs(db)

        logger.info("Pre-processing completed!")
        logger.info(f"Total IOCs: {stats['total']}")
        logger.info(f"Processed: {stats['processed']}")
        logger.info(f"Geo-enriched: {stats['geo_enriched']}")
        logger.info(f"Cached: {stats['cached']}")
        logger.info(f"Errors: {stats['errors']}")
        logger.info(f"Duration: {stats.get('duration', 0):.2f} seconds")

        break


if __name__ == "__main__":
    asyncio.run(main())
