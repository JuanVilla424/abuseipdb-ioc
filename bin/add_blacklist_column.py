#!/usr/bin/env python3
"""
Add missing blacklist_requests column to api_usage_tracking table.
"""

import asyncio
import logging
from sqlalchemy import text
from src.db.database import get_db

# Setup logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


async def add_blacklist_column():
    """Add blacklist_requests column if it doesn't exist."""

    async for db in get_db():
        try:
            # Check if column exists
            check_query = text(
                """
                SELECT column_name
                FROM information_schema.columns
                WHERE table_name='api_usage_tracking'
                AND column_name='blacklist_requests'
            """
            )

            result = await db.execute(check_query)
            column_exists = result.fetchone() is not None

            if column_exists:
                logger.info("Column blacklist_requests already exists")
            else:
                logger.info("Adding blacklist_requests column...")

                # Add the column
                alter_query = text(
                    """
                    ALTER TABLE api_usage_tracking
                    ADD COLUMN blacklist_requests INTEGER DEFAULT 0
                """
                )

                await db.execute(alter_query)
                await db.commit()

                logger.info("Successfully added blacklist_requests column")

            # Also check and add redis_updates column if missing
            check_redis_query = text(
                """
                SELECT column_name
                FROM information_schema.columns
                WHERE table_name='api_usage_tracking'
                AND column_name='redis_updates'
            """
            )

            result = await db.execute(check_redis_query)
            redis_column_exists = result.fetchone() is not None

            if redis_column_exists:
                logger.info("Column redis_updates already exists")
            else:
                logger.info("Adding redis_updates column...")

                # Add the column
                alter_redis_query = text(
                    """
                    ALTER TABLE api_usage_tracking
                    ADD COLUMN redis_updates INTEGER DEFAULT 0
                """
                )

                await db.execute(alter_redis_query)
                await db.commit()

                logger.info("Successfully added redis_updates column")

        except Exception as e:
            logger.error(f"Error adding columns: {e}")
            await db.rollback()
            raise

        break


if __name__ == "__main__":
    asyncio.run(add_blacklist_column())
