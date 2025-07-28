"""
IOC Correlation Engine.

Implements intelligence fusion with weighted confidence scoring,
prioritizing local detections over external enrichment.
"""

import logging
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from src.core.config import settings
from src.utils.geolocation import enrich_with_geolocation
from src.schemas.ioc import GeolocationData, ProviderData

logger = logging.getLogger(__name__)


class IOCCorrelationEngine:
    """
    Correlation engine for fusing local and external intelligence.

    Implements weighted scoring algorithm that prioritizes local
    threat intelligence while incorporating external validation.
    """

    def __init__(
        self, local_weight: float = None, external_weight: float = None, local_boost: int = None
    ):
        """
        Initialize correlation engine with configurable weights.

        Args:
            local_weight: Weight for local intelligence (0.0-1.0)
            external_weight: Weight for external intelligence (0.0-1.0)
            local_boost: Minimum boost for high-confidence local detections
        """
        self.local_weight = local_weight or settings.LOCAL_CONFIDENCE_WEIGHT
        self.external_weight = external_weight or settings.EXTERNAL_CONFIDENCE_WEIGHT
        self.local_boost = local_boost or settings.LOCAL_CONFIDENCE_BOOST

        # Validate weights sum to 1.0
        if abs(self.local_weight + self.external_weight - 1.0) > 0.001:
            raise ValueError("Local and external weights must sum to 1.0")

    def calculate_weighted_confidence(
        self, local_confidence: int, abuseipdb_confidence: Optional[int] = None
    ) -> int:
        """
        Calculate weighted confidence score prioritizing local observations.

        Args:
            local_confidence: Confidence from reported_ips table (0-100)
            abuseipdb_confidence: Confidence from AbuseIPDB (0-100)

        Returns:
            Final weighted confidence score (0-100)
        """
        # If no external data, use local confidence with boost if applicable
        if abuseipdb_confidence is None:
            if local_confidence >= 75:
                return max(local_confidence, 85)
            return local_confidence

        # Calculate weighted score
        weighted_score = (local_confidence * self.local_weight) + (
            abuseipdb_confidence * self.external_weight
        )

        # Apply boost for high-confidence local detections
        if local_confidence >= 75:
            weighted_score = max(weighted_score, 85)

        # Ensure score is within valid range
        return min(int(weighted_score), 100)

    def calculate_freshness_score(
        self, reported_at: datetime, last_seen: Optional[datetime] = None
    ) -> float:
        """
        Calculate freshness score based on detection recency.

        Args:
            reported_at: When the IP was reported locally
            last_seen: Most recent observation time

        Returns:
            Freshness score (0.0-1.0), where 1.0 is most recent
        """
        reference_time = last_seen or datetime.now(timezone.utc)

        # Handle both timezone-aware and naive datetimes
        if reported_at.tzinfo is None:
            # If reported_at is naive, assume UTC
            reported_at = reported_at.replace(tzinfo=timezone.utc)

        if reference_time.tzinfo is None:
            reference_time = reference_time.replace(tzinfo=timezone.utc)

        age_days = (reference_time - reported_at).days

        # Freshness decay curve
        if age_days <= 1:
            return 1.0
        if age_days <= 7:
            return 0.9
        if age_days <= 30:
            return 0.7
        if age_days <= 90:
            return 0.5
        if age_days <= 180:
            return 0.3
        return 0.1

    def map_categories_to_stix(self, categories: List[Any]) -> List[str]:
        """
        Map internal categories to STIX 2.x threat labels.

        Args:
            categories: List of category IDs or names from JSONB

        Returns:
            List of STIX threat type labels
        """
        # AbuseIPDB category mapping to STIX labels
        category_mapping = {
            # Network attacks
            1: "malicious-activity",  # DNS Compromise
            2: "malicious-activity",  # DNS Poisoning
            3: "anonymization",  # Fraud Orders
            4: "malicious-activity",  # DDoS Attack
            5: "anonymization",  # FTP Brute-Force
            6: "malicious-activity",  # Ping of Death
            7: "phishing",  # Phishing
            8: "fraud",  # Fraud VoIP
            9: "anonymization",  # Open Proxy
            10: "malicious-activity",  # Web Spam
            11: "malicious-activity",  # Email Spam
            12: "malicious-activity",  # Blog Spam
            13: "anonymization",  # VPN IP
            14: "malicious-activity",  # Port Scan
            15: "malicious-activity",  # Hacking
            16: "malicious-activity",  # SQL Injection
            17: "malicious-activity",  # Spoofing
            18: "malicious-activity",  # Brute-Force
            19: "malicious-activity",  # Bad Web Bot
            20: "malicious-activity",  # Exploited Host
            21: "malicious-activity",  # Web App Attack
            22: "malicious-activity",  # SSH
            23: "malicious-activity",  # IoT Targeted
        }

        stix_labels = set()

        for category in categories:
            # Handle both numeric and string categories
            if isinstance(category, dict):
                cat_id = category.get("id") or category.get("category_id")
            else:
                cat_id = int(category) if str(category).isdigit() else None

            if cat_id and cat_id in category_mapping:
                stix_labels.add(category_mapping[cat_id])

        # Always include malicious-activity for local detections
        if not stix_labels:
            stix_labels.add("malicious-activity")

        return sorted(list(stix_labels))

    def correlate_ioc(
        self, local_data: Dict[str, Any], external_data: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Correlate local and external intelligence for a single IOC.

        Args:
            local_data: Data from reported_ips table
            external_data: Data from AbuseIPDB cache

        Returns:
            Correlated IOC with enhanced metadata
        """
        # Extract local data
        ip_address = local_data.get("ip_address")
        local_confidence = local_data.get("confidence", 75)
        reported_at = local_data.get("reported_at")
        categories = local_data.get("categories", [])

        # Extract external data if available
        external_confidence = None
        country_code = None
        isp = None

        if external_data:
            external_confidence = external_data.get("abuse_confidence_score")
            country_code = external_data.get("country_code")
            isp = external_data.get("isp")

        # Calculate weighted confidence
        final_confidence = self.calculate_weighted_confidence(local_confidence, external_confidence)

        # Calculate freshness
        freshness_score = self.calculate_freshness_score(reported_at)

        # Map categories to STIX labels
        stix_labels = self.map_categories_to_stix(categories)

        # Build correlated IOC with enhanced fields
        # Handle datetime serialization
        reported_at_str = None
        if reported_at:
            # Ensure timezone-aware for serialization
            if hasattr(reported_at, "tzinfo") and reported_at.tzinfo is None:
                reported_at = reported_at.replace(tzinfo=timezone.utc)
            reported_at_str = reported_at.isoformat()

        # Calculate validity period (default 30 days for IOCs)
        valid_until = None
        if reported_at:
            if hasattr(reported_at, "tzinfo") and reported_at.tzinfo is None:
                reported_at = reported_at.replace(tzinfo=timezone.utc)
            # IOCs expire after 30 days by default
            from datetime import timedelta

            valid_until = (reported_at + timedelta(days=30)).isoformat()

        # Build provider information
        providers = []
        if external_data:
            providers.append(
                {
                    "name": "AbuseIPDB",
                    "source": "blacklist-api",
                    "confidence": external_confidence,
                    "first_seen": external_data.get("last_reported_at"),
                    "last_seen": external_data.get("last_reported_at"),
                    "reference_url": f"https://www.abuseipdb.com/check/{ip_address}",
                }
            )

        # Always include local provider
        providers.append(
            {
                "name": "Local Detection",
                "source": "reported_ips",
                "confidence": local_confidence,
                "first_seen": reported_at_str,
                "last_seen": reported_at_str,
            }
        )

        # Map categories to threat types and kill chain phases
        threat_types = self._map_categories_to_threat_types(categories)
        kill_chain_phases = self._map_categories_to_kill_chain(categories)

        correlated_ioc = {
            "ip_address": ip_address,
            "confidence": final_confidence,
            "local_confidence": local_confidence,
            "external_confidence": external_confidence,
            "freshness_score": freshness_score,
            "reported_at": reported_at_str,
            "valid_from": reported_at_str,
            "valid_until": valid_until,
            "categories": categories,
            "labels": stix_labels,  # Changed from stix_labels to labels for consistency
            "threat_types": threat_types,
            "kill_chain_phases": kill_chain_phases,
            "source_priority": "local_primary",
            "provider": "Local Detection" if not external_data else "AbuseIPDB",
            "enrichment": {
                "isp": isp,
                "has_external_validation": external_data is not None,
                "geolocation": None,  # Will be populated by geolocation service
                "providers": providers,
            },
        }

        # Add external enrichment data
        if external_data:
            correlated_ioc["enrichment"].update(
                {
                    "usage_type": external_data.get("usage_type"),
                    "domain": external_data.get("domain"),
                    "abuse_confidence_score": external_confidence,
                    "total_reports": external_data.get("total_reports"),
                    "last_reported_at": external_data.get("last_reported_at"),
                }
            )

        # Add report ID if available
        if "report_id" in local_data:
            correlated_ioc["report_id"] = local_data["report_id"]

        return correlated_ioc

    def _map_categories_to_threat_types(self, categories: List[Any]) -> List[str]:
        """Map categories to Elasticsearch threat types."""
        category_to_threat = {
            4: "ddos",
            5: "brute-force",
            14: "reconnaissance",
            15: "exploit",
            16: "data-collection",
            18: "credential-access",
            21: "web-attack",
            22: "remote-access",
        }

        threat_types = []
        for cat in categories:
            if isinstance(cat, int):
                cat_id = cat
            elif isinstance(cat, dict):
                cat_id = cat.get("id", cat)
            else:
                # cat is a string (like "abuseipdb-blacklist"), try to convert to int
                cat_id = int(cat) if str(cat).isdigit() else None

            if cat_id and cat_id in category_to_threat:
                threat_types.append(category_to_threat[cat_id])

        return list(set(threat_types))  # Remove duplicates

    def _map_categories_to_kill_chain(self, categories: List[Any]) -> List[str]:
        """Map categories to MITRE ATT&CK kill chain phases."""
        category_to_killchain = {
            14: "reconnaissance",
            15: "initial-access",
            5: "credential-access",
            18: "credential-access",
            16: "collection",
            4: "impact",
            21: "initial-access",
            22: "persistence",
        }

        phases = []
        for cat in categories:
            if isinstance(cat, int):
                cat_id = cat
            elif isinstance(cat, dict):
                cat_id = cat.get("id", cat)
            else:
                # cat is a string (like "abuseipdb-blacklist"), try to convert to int
                cat_id = int(cat) if str(cat).isdigit() else None

            if cat_id and cat_id in category_to_killchain:
                phases.append(category_to_killchain[cat_id])

        return list(set(phases))  # Remove duplicates

    async def enrich_with_geolocation(self, correlated_ioc: Dict[str, Any]) -> Dict[str, Any]:
        """Enrich IOC with geolocation data."""
        try:
            geo_data = await enrich_with_geolocation(correlated_ioc["ip_address"])
            if geo_data:
                # Convert to GeolocationData format
                geolocation = {
                    "country_code": geo_data.get("country_code"),
                    "country_name": geo_data.get("country_name"),
                    "region": geo_data.get("region"),
                    "city": geo_data.get("city"),
                    "latitude": geo_data.get("latitude"),
                    "longitude": geo_data.get("longitude"),
                    "continent": geo_data.get("continent"),
                }

                correlated_ioc["enrichment"]["geolocation"] = geolocation

                # Update ISP if not already present
                if not correlated_ioc["enrichment"].get("isp") and geo_data.get("isp"):
                    correlated_ioc["enrichment"]["isp"] = geo_data.get("isp")

        except Exception as e:
            logger.warning(f"Geolocation enrichment failed for {correlated_ioc['ip_address']}: {e}")

        return correlated_ioc

    def bulk_correlate(
        self, local_iocs: List[Dict[str, Any]], external_data: Dict[str, Optional[Dict[str, Any]]]
    ) -> List[Dict[str, Any]]:
        """
        Correlate multiple IOCs in bulk.

        Args:
            local_iocs: List of IOCs from reported_ips table
            external_data: Dictionary mapping IP addresses to external data

        Returns:
            List of correlated IOCs sorted by confidence and freshness
        """
        correlated_iocs = []

        for local_ioc in local_iocs:
            ip_address = local_ioc.get("ip_address")
            external_ioc = external_data.get(ip_address)

            correlated = self.correlate_ioc(local_ioc, external_ioc)
            correlated_iocs.append(correlated)

        # Sort by confidence (descending) and freshness (descending)
        correlated_iocs.sort(key=lambda x: (x["confidence"], x["freshness_score"]), reverse=True)

        return correlated_iocs

    def filter_by_confidence(
        self, iocs: List[Dict[str, Any]], min_confidence: int = None
    ) -> List[Dict[str, Any]]:
        """
        Filter IOCs by minimum confidence threshold.

        Args:
            iocs: List of correlated IOCs
            min_confidence: Minimum confidence score (0-100)

        Returns:
            Filtered list of IOCs meeting confidence threshold
        """
        threshold = min_confidence or settings.ABUSEIPDB_CONFIDENCE_MINIMUM
        return [ioc for ioc in iocs if ioc["confidence"] >= threshold]

    def get_priority_iocs(
        self, iocs: List[Dict[str, Any]], limit: int = 100, min_freshness: float = 0.5
    ) -> List[Dict[str, Any]]:
        """
        Get highest priority IOCs based on confidence and freshness.

        Args:
            iocs: List of correlated IOCs
            limit: Maximum number of IOCs to return
            min_freshness: Minimum freshness score (0.0-1.0)

        Returns:
            Priority-sorted list of IOCs
        """
        # Filter by freshness
        fresh_iocs = [ioc for ioc in iocs if ioc["freshness_score"] >= min_freshness]

        # Sort by priority: confidence * freshness
        fresh_iocs.sort(key=lambda x: x["confidence"] * x["freshness_score"], reverse=True)

        return fresh_iocs[:limit]
