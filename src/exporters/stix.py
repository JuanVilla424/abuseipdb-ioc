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
    def create_indicator(ioc: Dict[str, Any]) -> Dict[str, Any]:
        """
        Create Elasticsearch-compatible STIX 2.1 Indicator object from correlated IOC.

        Args:
            ioc: Correlated IOC data

        Returns:
            STIX Indicator dictionary compatible with Elasticsearch Custom Threat Intelligence
        """
        # Handle both dict and Pydantic object
        if hasattr(ioc, "dict"):
            ioc_data = ioc.dict()
        else:
            ioc_data = ioc

        # Create STIX 2.1 compliant pattern for IP indicator
        pattern = f"[ipv4-addr:value = '{ioc_data['ip_address']}']"

        # Use labels from correlation engine or fallback to standard
        labels = ioc_data.get("labels", ["malicious-activity"])

        # Ensure malicious-activity is always present
        if "malicious-activity" not in labels:
            labels.insert(0, "malicious-activity")

        # External references for provenance with provider information
        external_refs = []

        # Add report reference
        if ioc_data.get("report_id"):
            source_name = "Local-Detection"
            if ioc_data.get("provider") == "AbuseIPDB":
                source_name = "AbuseIPDB"

            external_refs.append(
                {
                    "source_name": source_name,
                    "external_id": ioc_data["report_id"],
                    "url": (
                        f"https://www.abuseipdb.com/check/{ioc_data['ip_address']}"
                        if source_name == "AbuseIPDB"
                        else None
                    ),
                }
            )

        # Add provider references from enrichment
        providers = ioc_data.get("enrichment", {}).get("providers", [])
        for provider in providers:
            if provider.get("reference_url"):
                external_refs.append(
                    {
                        "source_name": provider["name"],
                        "url": provider["reference_url"],
                        "description": f"Threat intelligence from {provider['source']}",
                    }
                )

        # Parse dates
        def parse_date(date_str):
            if isinstance(date_str, str):
                return datetime.fromisoformat(date_str.replace("Z", "+00:00"))
            elif isinstance(date_str, datetime):
                return date_str
            return datetime.now(timezone.utc)

        created_date = parse_date(ioc_data.get("reported_at", ioc_data.get("valid_from")))
        valid_from_date = parse_date(ioc_data.get("valid_from", ioc_data.get("reported_at")))
        valid_until_date = None
        if ioc_data.get("valid_until"):
            valid_until_date = parse_date(ioc_data["valid_until"])

        # Create Elasticsearch-compatible STIX indicator
        indicator = {
            "type": "indicator",
            "spec_version": "2.1",
            "id": f"indicator--{ioc_data['ip_address'].replace('.', '-')}",
            "created": created_date.isoformat(),
            "modified": datetime.now(timezone.utc).isoformat(),
            "pattern": pattern,
            "pattern_type": "stix",
            "pattern_version": "2.1",
            "valid_from": valid_from_date.isoformat(),
            "labels": labels,
            "confidence": ioc_data.get("confidence", 75),
            "lang": "en",
            "revoked": False,
        }

        # Add valid_until if present (required for IOC expiration)
        if valid_until_date:
            indicator["valid_until"] = valid_until_date.isoformat()

        # Add external references
        if external_refs:
            indicator["external_references"] = external_refs

        # Add kill chain phases if available
        kill_chain_phases = ioc_data.get("kill_chain_phases", [])
        if kill_chain_phases:
            indicator["kill_chain_phases"] = [
                {"kill_chain_name": "mitre-attack", "phase_name": phase}
                for phase in kill_chain_phases
            ]

        # Add custom properties for Elasticsearch
        custom_properties = {
            "x_elastic_provider": ioc_data.get("provider", "Local Detection"),
            "x_elastic_confidence_score": ioc_data.get("confidence", 75),
            "x_elastic_threat_types": ioc_data.get("threat_types", []),
            "x_elastic_freshness_score": ioc_data.get("freshness_score", 1.0),
        }

        # Add geolocation data
        geolocation = ioc_data.get("enrichment", {}).get("geolocation")
        if geolocation:
            lat = geolocation.get("latitude")
            lon = geolocation.get("longitude")

            custom_properties.update(
                {
                    "x_elastic_geo_country_code": geolocation.get("country_code"),
                    "x_elastic_geo_country_name": geolocation.get("country_name"),
                    "x_elastic_geo_city": geolocation.get("city"),
                }
            )

            # Add coordinates in multiple ECS-compatible formats
            if lat and lon:
                custom_properties.update(
                    {
                        # STIX custom format (mantener para compatibilidad)
                        "x_elastic_geo_coordinates": {"lat": lat, "lon": lon},
                        # ECS geo_point format estándar - object format
                        "x_elastic_geo_location": {"lat": lat, "lon": lon},
                        # ECS geo_point format - array format [lon, lat]
                        "x_elastic_geo_point": [lon, lat],
                    }
                )

        # Add network information
        enrichment = ioc_data.get("enrichment", {})
        if enrichment.get("isp"):
            custom_properties["x_elastic_isp"] = enrichment["isp"]
        if enrichment.get("usage_type"):
            custom_properties["x_elastic_usage_type"] = enrichment["usage_type"]

        # Filter out None values from custom properties
        custom_properties = {k: v for k, v in custom_properties.items() if v is not None}
        indicator.update(custom_properties)

        return indicator

    @staticmethod
    def create_bundle(iocs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Create Elasticsearch-compatible STIX 2.1 Bundle with envelope wrapper.

        Args:
            iocs: List of correlated IOCs

        Returns:
            STIX Bundle as dictionary with 'objects' array for Elasticsearch Custom Threat Intelligence
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

        # Create STIX 2.1 bundle with proper metadata
        bundle_id = f"bundle--{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"
        current_time = datetime.now(timezone.utc).isoformat()

        bundle = {
            "type": "bundle",
            "id": bundle_id,
            "spec_version": "2.1",
            "created": current_time,
            "modified": current_time,
            "objects": indicators,
        }

        return bundle

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
