#!/usr/bin/env python3
"""Test AbuseIPDB blacklist endpoint"""
import httpx
import json
import sys

sys.path.insert(0, "/home/na0nh/Projects/abuseipdb-ioc")
from src.core.config import settings


async def test_blacklist():
    headers = {"Key": settings.ABUSEIPDB_API_KEY, "Accept": "application/json"}

    params = {"confidenceMinimum": 75, "limit": 5}

    async with httpx.AsyncClient() as client:
        try:
            print("Testing AbuseIPDB blacklist endpoint...")
            response = await client.get(
                "https://api.abuseipdb.com/api/v2/blacklist",
                headers=headers,
                params=params,
                timeout=30.0,
            )

            print(f"Status: {response.status_code}")
            print(f"Headers: {dict(response.headers)}")
            print(f"Raw response: {response.text[:500]}...")

            if response.status_code == 200:
                try:
                    data = response.json()
                    print(f"\nParsed data: {json.dumps(data, indent=2)[:1000]}...")
                except Exception as e:
                    print(f"JSON parse error: {e}")

        except Exception as e:
            print(f"Request error: {e}")


if __name__ == "__main__":
    import asyncio

    asyncio.run(test_blacklist())
