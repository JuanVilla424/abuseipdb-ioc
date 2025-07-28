#!/usr/bin/env python3
"""Insert test data into reported_ips table"""
import asyncio
import json
from datetime import datetime, timezone, timedelta
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy import text
import sys

sys.path.insert(0, "/home/na0nh/Projects/abuseipdb-ioc")

from src.core.config import settings

# Test IOCs covering different threat categories for dev environment
TEST_IPS = [
    # High confidence threats
    ("192.203.230.10", 95, [4, 15]),  # DDoS + Exploitation
    ("185.220.101.45", 90, [5, 18]),  # Brute Force + SSH
    ("45.155.205.86", 88, [14, 21]),  # Port Scan + Web Attack
    ("193.142.146.88", 92, [16, 22]),  # SQL Injection + SSH
    ("194.165.16.72", 85, [4, 5]),  # DDoS + Brute Force
    # Medium confidence threats
    ("103.85.24.155", 78, [14]),  # Port Scanning
    ("45.227.255.190", 82, [21]),  # Web Application Attack
    ("89.248.165.228", 75, [18]),  # SSH Attack
    ("46.161.27.144", 80, [5]),  # Brute Force
    ("198.51.100.42", 77, [4]),  # DDoS
    # Recent threats (last 7 days)
    ("1.2.3.4", 85, [15, 16]),  # Exploitation + Collection
    ("5.6.7.8", 90, [4, 14]),  # DDoS + Reconnaissance
    ("9.10.11.12", 88, [21, 22]),  # Web + SSH attacks
    ("13.14.15.16", 92, [5, 18]),  # Brute Force variants
    ("17.18.19.20", 95, [15, 21]),  # Advanced exploitation
    # Older threats for freshness testing
    ("100.101.102.103", 83, [14]),  # Old scanner
    ("104.105.106.107", 87, [4]),  # Old DDoS source
    ("108.109.110.111", 79, [5]),  # Old brute forcer
    ("112.113.114.115", 81, [21]),  # Old web attacker
    ("116.117.118.119", 76, [18]),  # Old SSH attacker
]


async def insert_test_data():
    DATABASE_URL = f"postgresql+asyncpg://{settings.POSTGRES_USER}:{settings.POSTGRES_PASSWORD}@{settings.POSTGRES_HOST}:{settings.POSTGRES_PORT}/{settings.POSTGRES_DB}"
    engine = create_async_engine(DATABASE_URL, echo=True)

    async with AsyncSession(engine) as session:
        try:
            print("Inserting test data into reported_ips...")

            for i, (ip, confidence, categories) in enumerate(TEST_IPS):
                # Vary the reported times - recent ones first, older ones later
                if i < 5:  # High confidence - very recent
                    reported_at = datetime.now(timezone.utc) - timedelta(hours=i)
                elif i < 10:  # Medium confidence - last few days
                    reported_at = datetime.now(timezone.utc) - timedelta(days=i - 4)
                elif i < 15:  # Recent threats - last week
                    reported_at = datetime.now(timezone.utc) - timedelta(days=i - 9)
                else:  # Older threats - weeks ago
                    reported_at = datetime.now(timezone.utc) - timedelta(days=15 + (i - 15) * 3)

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
                        "categories": json.dumps(categories),
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
