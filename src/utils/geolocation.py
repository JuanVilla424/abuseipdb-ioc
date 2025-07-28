"""
IP Geolocation utilities using multiple sources.

Provides geolocation services with fallback options and caching.
"""

import asyncio
import logging
import json
from typing import Optional, Dict, Any
import httpx
import ipaddress
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


class GeolocationService:
    """IP Geolocation service with multiple providers."""

    def __init__(self):
        self.timeout = 10.0

    async def get_geolocation(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """
        Get geolocation for IP address using multiple fallback sources.

        Args:
            ip_address: IP address to geolocate

        Returns:
            Geolocation data dictionary or None
        """
        # Validate IP address
        try:
            ip_obj = ipaddress.ip_address(ip_address)
            if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_multicast:
                logger.debug(f"Skipping geolocation for private/local IP: {ip_address}")
                return None
        except ValueError:
            logger.error(f"Invalid IP address: {ip_address}")
            return None

        # Try multiple services in order of preference
        services = [self._get_from_ipapi, self._get_from_ipwhois, self._get_from_geojs]

        for service in services:
            try:
                result = await service(ip_address)
                if result:
                    logger.info(f"Geolocation found for {ip_address} via {service.__name__}")
                    # Add 1-second delay to be respectful to API limits
                    await asyncio.sleep(1.0)
                    return result
            except Exception as e:
                logger.warning(
                    f"Geolocation service {service.__name__} failed for {ip_address}: {e}"
                )
                continue

        logger.warning(f"No geolocation data found for {ip_address}")
        return None

    async def _get_from_ipapi(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """Get geolocation from ip-api.com (free, no key required)."""
        url = f"http://ip-api.com/json/{ip_address}?fields=status,message,continent,continentCode,country,countryCode,region,regionName,city,lat,lon,timezone,isp,org"

        async with httpx.AsyncClient() as client:
            response = await client.get(url, timeout=self.timeout)
            response.raise_for_status()
            data = response.json()

            if data.get("status") == "success":
                return {
                    "country_code": data.get("countryCode"),
                    "country_name": data.get("country"),
                    "region": data.get("regionName"),
                    "city": data.get("city"),
                    "latitude": data.get("lat"),
                    "longitude": data.get("lon"),
                    "continent": data.get("continent"),
                    "isp": data.get("isp"),
                    "org": data.get("org"),
                    "timezone": data.get("timezone"),
                    "source": "ip-api.com",
                }
        return None

    async def _get_from_ipwhois(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """Get geolocation from ipwhois.app (free, no key required)."""
        url = f"http://ipwhois.app/json/{ip_address}"

        async with httpx.AsyncClient() as client:
            response = await client.get(url, timeout=self.timeout)
            response.raise_for_status()
            data = response.json()

            if data.get("success"):
                return {
                    "country_code": data.get("country_code"),
                    "country_name": data.get("country"),
                    "region": data.get("region"),
                    "city": data.get("city"),
                    "latitude": data.get("latitude"),
                    "longitude": data.get("longitude"),
                    "continent": data.get("continent"),
                    "isp": data.get("isp"),
                    "org": data.get("org"),
                    "timezone": data.get("timezone"),
                    "source": "ipwhois.app",
                }
        return None

    async def _get_from_geojs(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """Get geolocation from geojs.io (free, no key required)."""
        url = f"https://get.geojs.io/v1/ip/geo/{ip_address}.json"

        async with httpx.AsyncClient() as client:
            response = await client.get(url, timeout=self.timeout)
            response.raise_for_status()
            data = response.json()

            if "country_code" in data:
                return {
                    "country_code": data.get("country_code"),
                    "country_name": data.get("country"),
                    "region": data.get("region"),
                    "city": data.get("city"),
                    "latitude": float(data.get("latitude")) if data.get("latitude") else None,
                    "longitude": float(data.get("longitude")) if data.get("longitude") else None,
                    "continent": data.get("continent_code"),
                    "timezone": data.get("timezone"),
                    "source": "geojs.io",
                }
        return None

    def get_country_threat_level(self, country_code: str) -> str:
        """
        Get threat level based on country code.

        Args:
            country_code: ISO 2-letter country code

        Returns:
            Threat level string
        """
        # High-risk countries (based on common threat intelligence)
        high_risk = {"CN", "RU", "KP", "IR", "PK", "BD", "VN", "ID"}
        medium_risk = {"BR", "IN", "TR", "EG", "MX", "TH", "PH", "MY"}

        if country_code in high_risk:
            return "high"
        elif country_code in medium_risk:
            return "medium"
        else:
            return "low"


# Global geolocation service instance
geolocation_service = GeolocationService()


async def enrich_with_geolocation(ip_address: str) -> Optional[Dict[str, Any]]:
    """
    Convenience function to get geolocation for an IP.

    Args:
        ip_address: IP address to geolocate

    Returns:
        Geolocation data with threat assessment
    """
    geo_data = await geolocation_service.get_geolocation(ip_address)
    if geo_data:
        # Add threat level assessment
        country_code = geo_data.get("country_code")
        if country_code:
            geo_data["threat_level"] = geolocation_service.get_country_threat_level(country_code)

        # Add timestamp
        geo_data["enriched_at"] = datetime.now(timezone.utc).isoformat()

    return geo_data
