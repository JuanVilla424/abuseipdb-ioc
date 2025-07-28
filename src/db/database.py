"""
Database connection and session management.

Provides async database connectivity with proper connection pooling.
"""

import logging
from typing import AsyncGenerator
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.pool import NullPool
from sqlalchemy import text
from src.core.config import settings

logger = logging.getLogger(__name__)


# Create async engine with connection pooling
engine = create_async_engine(
    settings.database_url,
    echo=False,
    poolclass=NullPool,  # Use NullPool for async connections
)

# Create async session factory
AsyncSessionLocal = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)


async def ensure_database_schema() -> None:
    """
    Ensure all required database columns exist.

    This function checks and creates missing columns in the api_usage_tracking table
    to support blacklist requests and redis updates tracking.
    """
    async with AsyncSessionLocal() as session:
        try:
            # Check and add blacklist_requests column if missing
            check_blacklist_query = text(
                """
                SELECT column_name
                FROM information_schema.columns
                WHERE table_name='api_usage_tracking'
                AND column_name='blacklist_requests'
            """
            )

            result = await session.execute(check_blacklist_query)
            if not result.fetchone():
                logger.info("Adding blacklist_requests column to api_usage_tracking table")
                alter_blacklist_query = text(
                    """
                    ALTER TABLE api_usage_tracking
                    ADD COLUMN blacklist_requests INTEGER DEFAULT 0
                """
                )
                await session.execute(alter_blacklist_query)
                await session.commit()
                logger.info("Successfully added blacklist_requests column")

            # Check and add redis_updates column if missing
            check_redis_query = text(
                """
                SELECT column_name
                FROM information_schema.columns
                WHERE table_name='api_usage_tracking'
                AND column_name='redis_updates'
            """
            )

            result = await session.execute(check_redis_query)
            if not result.fetchone():
                logger.info("Adding redis_updates column to api_usage_tracking table")
                alter_redis_query = text(
                    """
                    ALTER TABLE api_usage_tracking
                    ADD COLUMN redis_updates INTEGER DEFAULT 0
                """
                )
                await session.execute(alter_redis_query)
                await session.commit()
                logger.info("Successfully added redis_updates column")

        except Exception as e:
            logger.error(f"Error ensuring database schema: {e}")
            await session.rollback()
            raise
        finally:
            await session.close()


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """
    Dependency to get database session.

    Yields:
        AsyncSession: Database session for async operations
    """
    async with AsyncSessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()
