#!/usr/bin/env python3
"""Check database for reported_ips data"""
import asyncio
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy import select, func, text
import sys

sys.path.insert(0, "/home/na0nh/Projects/abuseipdb-ioc")

from src.db.models import ReportedIPs
from src.core.config import settings


async def check_database():
    # Create async engine
    DATABASE_URL = f"postgresql+asyncpg://{settings.POSTGRES_USER}:{settings.POSTGRES_PASSWORD}@{settings.POSTGRES_HOST}:{settings.POSTGRES_PORT}/{settings.POSTGRES_DB}"
    print(
        f"Connecting to database: {settings.POSTGRES_DB} at {settings.POSTGRES_HOST}:{settings.POSTGRES_PORT}"
    )

    engine = create_async_engine(DATABASE_URL, echo=True)

    async with AsyncSession(engine) as session:
        try:
            # Check if table exists
            print("\n=== Checking if reported_ips table exists ===")
            result = await session.execute(
                text(
                    """
                SELECT EXISTS (
                    SELECT FROM information_schema.tables
                    WHERE table_schema = 'public'
                    AND table_name = 'reported_ips'
                );
            """
                )
            )
            exists = result.scalar()
            print(f"Table reported_ips exists: {exists}")

            if exists:
                # Count records
                print("\n=== Counting records in reported_ips ===")
                count_result = await session.execute(select(func.count()).select_from(ReportedIPs))
                count = count_result.scalar()
                print(f"Total records in reported_ips: {count}")

                # Get sample records
                if count > 0:
                    print("\n=== Sample records ===")
                    sample_result = await session.execute(select(ReportedIPs).limit(5))
                    samples = sample_result.scalars().all()
                    for ip in samples:
                        print(
                            f"IP: {ip.ip_address}, Confidence: {ip.confidence}, Reported: {ip.reported_at}"
                        )

            # Check other tables
            print("\n=== Checking all tables in database ===")
            tables_result = await session.execute(
                text(
                    """
                SELECT table_name
                FROM information_schema.tables
                WHERE table_schema = 'public'
                ORDER BY table_name;
            """
                )
            )
            tables = tables_result.fetchall()
            print("Tables found:")
            for table in tables:
                print(f"  - {table[0]}")

        except Exception as e:
            print(f"\nERROR: {type(e).__name__}: {e}")
            import traceback

            traceback.print_exc()

    await engine.dispose()


if __name__ == "__main__":
    asyncio.run(check_database())
