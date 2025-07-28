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
    """IP Geolocation service with multiple providers and dynamic rate limiting."""

    def __init__(self):
        self.timeout = 10.0
        self.base_delay = 1.0  # Base delay in seconds
        self.max_delay = 30.0  # Maximum delay in seconds
        self.current_delay = self.base_delay
        self.consecutive_errors = 0
        self.last_success_time = None

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
                # Apply dynamic delay before making the request
                logger.debug(
                    f"Waiting {self.current_delay:.2f}s before geolocation request for {ip_address}"
                )
                await asyncio.sleep(self.current_delay)

                result = await service(ip_address)
                if result:
                    logger.info(f"Geolocation found for {ip_address} via {service.__name__}")
                    # Success: reduce delay and reset error counter
                    self._handle_success()
                    return result
            except httpx.HTTPStatusError as e:
                if e.response.status_code == 429:  # Rate limit exceeded
                    self._handle_rate_limit_error(service.__name__)
                    logger.warning(
                        f"Rate limit hit for {service.__name__}, current delay: {self.current_delay:.2f}s"
                    )
                    # Wait additional time for rate limit recovery
                    await asyncio.sleep(self.current_delay)
                    continue
                else:
                    self._handle_error(service.__name__, str(e))
                    continue
            except Exception as e:
                self._handle_error(service.__name__, str(e))
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

    def _handle_success(self):
        """Handle successful geolocation request."""
        self.consecutive_errors = 0
        self.last_success_time = datetime.now(timezone.utc)
        # Gradually reduce delay on success (exponential decay)
        self.current_delay = max(self.base_delay, self.current_delay * 0.9)
        if self.current_delay > self.base_delay:
            logger.debug(f"Reduced geolocation delay to {self.current_delay:.2f}s")

    def _handle_error(self, service_name: str, error_msg: str):
        """Handle geolocation request error."""
        self.consecutive_errors += 1
        logger.warning(f"Geolocation service {service_name} failed: {error_msg}")

        # Increase delay on consecutive errors (exponential backoff)
        if self.consecutive_errors >= 3:
            self.current_delay = min(self.max_delay, self.current_delay * 1.5)
            logger.warning(
                f"Increased geolocation delay to {self.current_delay:.2f}s due to consecutive errors"
            )

    def _handle_rate_limit_error(self, service_name: str):
        """Handle rate limit error with aggressive backoff."""
        self.consecutive_errors += 1
        # More aggressive backoff for rate limits
        self.current_delay = min(self.max_delay, self.current_delay * 2.0)
        logger.warning(
            f"Rate limit detected for {service_name}, increased delay to {self.current_delay:.2f}s"
        )


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
