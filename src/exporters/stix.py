"""
STIX 2.x export functionality.

Converts correlated IOCs to STIX 2.1 format for SIEM integration.
"""

from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
import stix2
import json


class STIXExporter:
    """Export IOCs in STIX 2.1 format."""

    @staticmethod
    def create_indicator(ioc: Dict[str, Any]) -> stix2.Indicator:
        """
        Create STIX 2.1 Indicator object from correlated IOC following official standard.

        Args:
            ioc: Correlated IOC data

        Returns:
            STIX Indicator object
        """
        # Handle both dict and Pydantic object
        if hasattr(ioc, "dict"):
            ioc_data = ioc.dict()
        else:
            ioc_data = ioc

        # Create STIX 2.1 compliant pattern for IP indicator
        pattern = f"[ipv4-addr:value = '{ioc_data['ip_address']}']"

        # Standard STIX 2.1 labels for malicious activity
        labels = ["malicious-activity"]

        # Add specific labels based on categories if available
        categories = ioc_data.get("categories", [])
        if categories:
            # Map AbuseIPDB categories to STIX labels
            category_map = {
                4: "ddos",
                5: "credential-access",
                14: "reconnaissance",
                15: "initial-access",
                16: "collection",
                18: "credential-access",
                21: "initial-access",
                22: "credential-access",
            }
            for cat in categories:
                cat_id = cat if isinstance(cat, int) else cat.get("id", cat)
                if cat_id in category_map:
                    labels.append(category_map[cat_id])

        # Remove duplicates while preserving order
        labels = list(dict.fromkeys(labels))

        # External references for provenance
        external_refs = []
        if ioc_data.get("report_id"):
            external_refs.append(
                {"source_name": "AbuseIPDB-IOC", "external_id": ioc_data["report_id"]}
            )

        # Create standard STIX 2.1 indicator
        indicator = stix2.Indicator(
            pattern=pattern,
            pattern_type="stix",
            labels=labels,
            confidence=ioc_data.get("confidence", 75),
            created=ioc_data.get("reported_at", datetime.now(timezone.utc)),
            modified=datetime.now(timezone.utc),
            valid_from=ioc_data.get("reported_at", datetime.now(timezone.utc)),
            external_references=external_refs if external_refs else None,
        )

        return indicator

    @staticmethod
    def create_bundle(iocs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Create STIX 2.1 Bundle containing multiple indicators following official standard.

        Args:
            iocs: List of correlated IOCs

        Returns:
            STIX Bundle as dictionary with 'objects' array for Elasticsearch
        """
        # Create indicators
        indicators = []
        for ioc in iocs:
            try:
                indicator = STIXExporter.create_indicator(ioc)
                indicators.append(indicator)
            except Exception as e:
                # Log error but continue processing
                ip = (
                    ioc.ip_address
                    if hasattr(ioc, "ip_address")
                    else ioc.get("ip_address", "unknown")
                )
                print(f"Error creating indicator for {ip}: {e}")

        # Create standard STIX 2.1 bundle
        bundle = stix2.Bundle(objects=indicators)

        # Convert to dictionary for JSON serialization
        bundle_dict = json.loads(bundle.serialize())
        return bundle_dict

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
