"""
STIX 2.x export functionality.

Converts correlated IOCs to STIX 2.1 format for SIEM integration.
"""

from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
import stix2


class STIXExporter:
    """Export IOCs in STIX 2.1 format."""

    @staticmethod
    def create_indicator(ioc: Dict[str, Any]) -> stix2.Indicator:
        """
        Create STIX Indicator object from correlated IOC.

        Args:
            ioc: Correlated IOC data

        Returns:
            STIX Indicator object
        """
        # Create pattern for IP indicator
        pattern = f"[ipv4-addr:value = '{ioc['ip_address']}']"

        # Custom properties for local intelligence
        custom_properties = {
            "x_local_detection": True,
            "x_local_confidence": ioc.get("local_confidence", 75),
            "x_source_priority": "local_primary",
            "x_freshness_score": ioc.get("freshness_score", 1.0),
        }

        # Add optional properties
        if ioc.get("report_id"):
            custom_properties["x_report_id"] = ioc["report_id"]

        if ioc.get("external_confidence") is not None:
            custom_properties["x_abuseipdb_confidence"] = ioc["external_confidence"]

        if ioc.get("enrichment", {}).get("country_code"):
            custom_properties["x_country_code"] = ioc["enrichment"]["country_code"]

        if ioc.get("enrichment", {}).get("isp"):
            custom_properties["x_isp"] = ioc["enrichment"]["isp"]

        # Create indicator
        indicator = stix2.Indicator(
            pattern=pattern,
            pattern_type="stix",
            labels=ioc.get("stix_labels", ["malicious-activity"]),
            confidence=ioc.get("confidence", 75),
            created=ioc.get("reported_at", datetime.now(timezone.utc)),
            modified=datetime.now(timezone.utc),
            custom_properties=custom_properties,
            allow_custom=True,
        )

        return indicator

    @staticmethod
    def create_bundle(iocs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Create STIX Bundle containing multiple indicators.

        Args:
            iocs: List of correlated IOCs

        Returns:
            STIX Bundle as dictionary
        """
        # Create indicators
        indicators = []
        for ioc in iocs:
            try:
                indicator = STIXExporter.create_indicator(ioc)
                indicators.append(indicator)
            except Exception as e:
                # Log error but continue processing
                print(f"Error creating indicator for {ioc.get('ip_address')}: {e}")

        # Create bundle
        bundle = stix2.Bundle(objects=indicators, allow_custom=True)

        # Convert to dictionary for JSON serialization
        return bundle.serialize(pretty=True)

    @staticmethod
    def create_sighting(
        indicator_id: str, ip_address: str, observed_time: datetime, count: int = 1
    ) -> stix2.Sighting:
        """
        Create STIX Sighting for an indicator.

        Args:
            indicator_id: STIX ID of the indicator
            ip_address: Observed IP address
            observed_time: When the sighting occurred
            count: Number of times observed

        Returns:
            STIX Sighting object
        """
        sighting = stix2.Sighting(
            sighting_of_ref=indicator_id,
            count=count,
            observed_data_refs=[],
            first_seen=observed_time,
            last_seen=observed_time,
            custom_properties={"x_ip_address": ip_address, "x_source": "local_detection"},
            allow_custom=True,
        )

        return sighting

    @staticmethod
    def create_attack_pattern(categories: List[Any]) -> Optional[stix2.AttackPattern]:
        """
        Create STIX Attack Pattern from categories.

        Args:
            categories: List of attack categories

        Returns:
            STIX AttackPattern object or None
        """
        # Map categories to attack patterns
        attack_mapping = {
            4: "DDoS",
            5: "Brute Force",
            14: "Port Scanning",
            15: "Exploitation",
            16: "SQL Injection",
            18: "Brute Force",
            21: "Web Application Attack",
            22: "SSH Attack",
        }

        attack_names = []
        for cat in categories:
            cat_id = cat if isinstance(cat, int) else cat.get("id")
            if cat_id in attack_mapping:
                attack_names.append(attack_mapping[cat_id])

        if not attack_names:
            return None

        attack_pattern = stix2.AttackPattern(
            name=" / ".join(set(attack_names)),
            description=f"Attack patterns observed: {', '.join(set(attack_names))}",
            allow_custom=True,
        )

        return attack_pattern

    @staticmethod
    def export_to_file(
        iocs: List[Dict[str, Any]], filepath: str, bundle_id: Optional[str] = None
    ) -> None:
        """
        Export IOCs to STIX file.

        Args:
            iocs: List of correlated IOCs
            filepath: Output file path
            bundle_id: Optional bundle ID
        """
        bundle_data = STIXExporter.create_bundle(iocs)

        with open(filepath, "w") as f:
            f.write(bundle_data)
