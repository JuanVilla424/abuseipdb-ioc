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
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
src_path = os.path.join(project_root, "src")
sys.path.insert(0, src_path)

from sqlalchemy.ext.asyncio import create_async_engine
from core.config import settings
from db.models import Base


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
