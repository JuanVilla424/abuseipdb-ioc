#!/usr/bin/env python3
"""
Database initialization script.

Creates database tables based on SQLAlchemy models.
Only creates new tables - doesn't modify existing ones.
"""

import asyncio
import sys
import os

# Add src to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from sqlalchemy.ext.asyncio import create_async_engine
from src.core.config import settings
from src.db.models import Base


async def init_db():
    """Initialize database by creating tables."""
    try:
        engine = create_async_engine(settings.database_url, echo=True)

        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

        await engine.dispose()
        print("✅ Database tables created successfully!")

    except Exception as e:
        print(f"❌ Error initializing database: {e}")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(init_db())
