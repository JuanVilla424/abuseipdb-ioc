#!/usr/bin/env python3
"""
Automatic IOC processing service that runs on system startup.

This service continuously processes IOCs from PostgreSQL and AbuseIPDB,
caching them in Redis for TAXII/Elasticsearch consumption.
"""

import asyncio
import logging
import signal
import sys
from datetime import datetime, timezone
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from src.core.config import settings
from bin.preprocess_iocs import IOCPreProcessor

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler(project_root / "logs" / "startup_processor.log"),
        logging.StreamHandler(sys.stdout),
    ],
)
logger = logging.getLogger(__name__)


class IOCStartupService:
    """Automatic IOC processing service."""

    def __init__(self):
        self.processor = IOCPreProcessor()
        self.running = True
        self.processing_interval = settings.IOC_PROCESSING_INTERVAL or 3600  # Default 1 hour

    async def startup_processing(self):
        """Run initial IOC processing on startup."""
        logger.info("🚀 Starting IOC processing service...")
        logger.info(f"Processing interval: {self.processing_interval} seconds")

        try:
            # Import here to avoid circular imports
            from src.db.database import get_db

            # Run initial processing
            logger.info("Running initial IOC processing...")
            async for db in get_db():
                stats = await self.processor.process_all_iocs(db)

                logger.info("✅ Initial processing completed!")
                logger.info(
                    f"Total IOCs: {stats['total']} (Local: {stats['local_iocs']}, AbuseIPDB: {stats['abuseipdb_iocs']})"
                )
                logger.info(f"Processed: {stats['processed']}")
                logger.info(f"Geo-enriched: {stats['geo_enriched']}")
                logger.info(f"Cached: {stats['cached']}")
                logger.info(f"Errors: {stats['errors']}")
                logger.info(f"Duration: {stats.get('duration', 0):.2f} seconds")
                break

        except Exception as e:
            logger.error(f"❌ Initial processing failed: {e}")

    async def continuous_processing(self):
        """Run continuous IOC processing."""
        logger.info("🔄 Starting continuous processing loop...")

        while self.running:
            try:
                await asyncio.sleep(self.processing_interval)

                if not self.running:
                    break

                logger.info("🔄 Running scheduled IOC processing...")

                # Import here to avoid circular imports
                from src.db.database import get_db

                async for db in get_db():
                    stats = await self.processor.process_all_iocs(db)

                    logger.info("✅ Scheduled processing completed!")
                    logger.info(
                        f"Total IOCs: {stats['total']} (Local: {stats['local_iocs']}, AbuseIPDB: {stats['abuseipdb_iocs']})"
                    )
                    logger.info(f"Processed: {stats['processed']}")
                    logger.info(f"Geo-enriched: {stats['geo_enriched']}")
                    logger.info(f"Cached: {stats['cached']}")
                    logger.info(f"Errors: {stats['errors']}")
                    logger.info(f"Duration: {stats.get('duration', 0):.2f} seconds")
                    break

            except Exception as e:
                logger.error(f"❌ Scheduled processing failed: {e}")
                logger.info(f"Retrying in {self.processing_interval} seconds...")

    def stop(self):
        """Stop the service gracefully."""
        logger.info("🛑 Stopping IOC processing service...")
        self.running = False

    async def run(self):
        """Main service loop."""

        # Setup signal handlers
        def signal_handler(signum, frame):
            logger.info(f"Received signal {signum}")
            self.stop()

        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

        try:
            # Run startup processing
            await self.startup_processing()

            # Start continuous processing
            await self.continuous_processing()

        except KeyboardInterrupt:
            logger.info("Received keyboard interrupt")
        except Exception as e:
            logger.error(f"Service error: {e}")
        finally:
            logger.info("IOC processing service stopped")


async def main():
    """Main entry point."""
    # Ensure logs directory exists
    logs_dir = project_root / "logs"
    logs_dir.mkdir(exist_ok=True)

    service = IOCStartupService()
    await service.run()


if __name__ == "__main__":
    asyncio.run(main())
