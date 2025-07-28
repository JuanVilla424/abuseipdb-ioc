#!/usr/bin/env python3
"""Test date handling to find the issue"""
import asyncio
from datetime import datetime, timezone
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy import select
import sys

sys.path.insert(0, "/home/na0nh/Projects/abuseipdb-ioc")

from src.db.models import ReportedIPs
from src.core.config import settings


async def test_dates():
    # Create async engine
    DATABASE_URL = f"postgresql+asyncpg://{settings.POSTGRES_USER}:{settings.POSTGRES_PASSWORD}@{settings.POSTGRES_HOST}:{settings.POSTGRES_PORT}/{settings.POSTGRES_DB}"
    engine = create_async_engine(DATABASE_URL, echo=True)

    async with AsyncSession(engine) as session:
        try:
            # Test 1: Simple query
            print("\n=== Test 1: Simple query ===")
            result = await session.execute(select(ReportedIPs).limit(1))
            ip = result.scalar_one_or_none()
            if ip:
                print(f"IP: {ip.ip_address}")
                print(f"Reported at: {ip.reported_at} (type: {type(ip.reported_at)})")
                print(
                    f"Timezone aware: {ip.reported_at.tzinfo is not None if ip.reported_at else 'None'}"
                )

            # Test 2: Date comparison
            print("\n=== Test 2: Date comparison ===")
            now_utc = datetime.now(timezone.utc)
            print(f"Current time: {now_utc} (type: {type(now_utc)})")
            print(f"Timezone: {now_utc.tzinfo}")

            # Test the actual query that's failing
            print("\n=== Test 3: Actual failing query ===")
            from datetime import timedelta

            seven_days_ago = datetime.now(timezone.utc) - timedelta(days=7)
            print(f"Seven days ago: {seven_days_ago}")

            query = select(ReportedIPs).where(ReportedIPs.reported_at >= seven_days_ago).limit(5)
            result = await session.execute(query)
            ips = result.scalars().all()
            print(f"Found {len(ips)} IPs")

        except Exception as e:
            print(f"\nERROR: {type(e).__name__}: {e}")
            import traceback

            traceback.print_exc()

    await engine.dispose()


if __name__ == "__main__":
    asyncio.run(test_dates())
