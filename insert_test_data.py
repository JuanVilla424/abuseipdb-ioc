#!/usr/bin/env python3
"""Insert test data into reported_ips table"""
import asyncio
from datetime import datetime, timezone, timedelta
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy import text
import sys

sys.path.insert(0, "/home/na0nh/Projects/abuseipdb-ioc")

from src.core.config import settings

# Some known malicious IPs for testing
TEST_IPS = [
    ("192.203.230.10", 90, ["malware", "botnet"]),  # Known malicious
    ("185.220.101.45", 85, ["tor", "proxy"]),  # Tor exit node
    ("45.155.205.86", 95, ["brute-force", "ssh"]),  # Brute force
    ("193.142.146.88", 80, ["scan", "exploit"]),  # Scanner
    ("194.165.16.72", 75, ["spam", "email"]),  # Spammer
]


async def insert_test_data():
    DATABASE_URL = f"postgresql+asyncpg://{settings.POSTGRES_USER}:{settings.POSTGRES_PASSWORD}@{settings.POSTGRES_HOST}:{settings.POSTGRES_PORT}/{settings.POSTGRES_DB}"
    engine = create_async_engine(DATABASE_URL, echo=True)

    async with AsyncSession(engine) as session:
        try:
            print("Inserting test data into reported_ips...")

            for i, (ip, confidence, categories) in enumerate(TEST_IPS):
                # Vary the reported times
                reported_at = datetime.now(timezone.utc) - timedelta(days=i, hours=i * 2)

                await session.execute(
                    text(
                        """
                    INSERT INTO reported_ips (ip_address, reported_at, report_id, categories, confidence, created_at)
                    VALUES (:ip, :reported_at, :report_id, :categories, :confidence, :created_at)
                    ON CONFLICT (ip_address) DO UPDATE SET
                        reported_at = EXCLUDED.reported_at,
                        confidence = EXCLUDED.confidence,
                        categories = EXCLUDED.categories
                """
                    ),
                    {
                        "ip": ip,
                        "reported_at": reported_at,
                        "report_id": f"TEST-{i+1:03d}",
                        "categories": categories,
                        "confidence": confidence,
                        "created_at": datetime.now(timezone.utc),
                    },
                )

            await session.commit()
            print(f"Successfully inserted {len(TEST_IPS)} test IPs")

            # Verify insertion
            result = await session.execute(text("SELECT COUNT(*) FROM reported_ips"))
            count = result.scalar()
            print(f"Total IPs in database: {count}")

        except Exception as e:
            print(f"ERROR: {type(e).__name__}: {e}")
            await session.rollback()
            import traceback

            traceback.print_exc()

    await engine.dispose()


if __name__ == "__main__":
    asyncio.run(insert_test_data())
