"""
Database connection and session management.

Provides async database connectivity with proper connection pooling.
"""

from typing import AsyncGenerator
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.pool import NullPool
from src.core.config import settings


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
