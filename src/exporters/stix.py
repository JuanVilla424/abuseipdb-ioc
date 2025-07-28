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

        # Calculate weighted confidence score
        confidence_score = ioc_data.get("final_confidence_score", ioc_data.get("confidence", 75))

        # Determine provider based on source
        source = ioc_data.get("source", "local")
        provider = "AbuseIPDB" if source == "abuseipdb" else "Local Detection"

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
            "confidence": int(
                confidence_score
            ),  # Use the weighted confidence score calculated above
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

        # Add custom properties for Elasticsearch Custom Threat Intelligence
        custom_properties = {
            # ECS threat.indicator fields
            "x_elastic_provider": ioc_data.get("provider", provider),
            "x_elastic_confidence_score": confidence_score,
            "x_elastic_threat_types": ioc_data.get("threat_types", []),
            "x_elastic_freshness_score": ioc_data.get("freshness_score", 1.0),
            "x_elastic_dual_source": ioc_data.get("dual_source", False),
            "x_elastic_local_confidence": ioc_data.get("local_confidence", 0),
            "x_elastic_external_confidence": ioc_data.get("external_confidence", 0),
            # Core threat.indicator ECS fields
            "threat.indicator.type": "ipv4-addr",
            "threat.indicator.first_seen": valid_from_date.isoformat(),
            "threat.indicator.last_seen": datetime.now(timezone.utc).isoformat(),
            "threat.indicator.modified_at": datetime.now(timezone.utc).isoformat(),
            "threat.indicator.sightings": 1,
            "threat.indicator.provider": provider,
            "threat.indicator.confidence": confidence_score,
            "threat.indicator.ip": ioc_data["ip_address"],
            "threat.indicator.marking.tlp": "GREEN",  # Default TLP marking
        }

        # Add description from external references or create default
        if external_refs and external_refs[0].get("source_name"):
            custom_properties["threat.indicator.description"] = (
                f"Malicious IP detected by {external_refs[0]['source_name']}"
            )
        else:
            custom_properties["threat.indicator.description"] = (
                f"Malicious IP address {ioc_data['ip_address']} detected by local systems"
            )

        # Add reference URL
        if external_refs and external_refs[0].get("url"):
            custom_properties["threat.indicator.reference"] = external_refs[0]["url"]

        # Add geolocation data with ECS compliance
        geolocation = ioc_data.get("enrichment", {}).get("geolocation")
        if geolocation:
            lat = geolocation.get("latitude")
            lon = geolocation.get("longitude")

            # ECS geo fields
            custom_properties.update(
                {
                    "threat.indicator.geo.country_iso_code": geolocation.get("country_code"),
                    "threat.indicator.geo.country_name": geolocation.get("country_name"),
                    "threat.indicator.geo.city_name": geolocation.get("city"),
                    "threat.indicator.geo.region_name": geolocation.get("region"),
                    "threat.indicator.geo.continent_code": geolocation.get("continent"),
                }
            )

            # Add coordinates in ECS-compatible formats
            if lat and lon:
                custom_properties.update(
                    {
                        # ECS geo_point format - object format
                        "threat.indicator.geo.location": {"lat": lat, "lon": lon},
                        # Legacy formats for compatibility
                        "x_elastic_geo_coordinates": {"lat": lat, "lon": lon},
                        "x_elastic_geo_location": {"lat": lat, "lon": lon},
                        "x_elastic_geo_point": [lon, lat],
                    }
                )

        # Add network information
        enrichment = ioc_data.get("enrichment", {})
        if enrichment.get("isp"):
            custom_properties["threat.indicator.as.organization.name"] = enrichment["isp"]
            custom_properties["x_elastic_isp"] = enrichment["isp"]  # Legacy compatibility
        if enrichment.get("usage_type"):
            custom_properties["x_elastic_usage_type"] = enrichment["usage_type"]

        # Add threat indicator tags based on categories and threat types
        tags = []
        threat_types = ioc_data.get("threat_types", [])
        if threat_types:
            tags.extend(threat_types)

        # Add category-based tags
        categories = ioc_data.get("categories", [])
        for category in categories:
            if isinstance(category, str) and category not in tags:
                tags.append(category)

        # Add source-based tags
        if ioc_data.get("dual_source"):
            tags.append("dual-source")
        if ioc_data.get("source") == "abuseipdb":
            tags.append("abuseipdb-blacklist")
        else:
            tags.append("local-detection")

        if tags:
            custom_properties["threat.indicator.tags"] = tags

        # Add scanner stats if available (for compatibility)
        total_reports = enrichment.get("total_reports", 0)
        if total_reports and total_reports > 0:
            custom_properties["threat.indicator.scanner_stats"] = total_reports

        # Add AS number if available from geolocation
        if geolocation and geolocation.get("org"):
            # Try to extract AS number from org field (common format: "AS15169 Google LLC")
            org = geolocation.get("org", "")
            if org.startswith("AS") and " " in org:
                try:
                    as_number = int(org.split(" ")[0][2:])  # Extract number after "AS"
                    custom_properties["threat.indicator.as.number"] = as_number
                except (ValueError, IndexError):
                    pass

        # Filter out None values from custom properties
        custom_properties = {k: v for k, v in custom_properties.items() if v is not None}
        indicator.update(custom_properties)

        # Add ECS event fields as root-level properties (not part of STIX indicator)
        indicator.update(
            {
                "event.category": "threat",
                "event.type": ["indicator"],
                "event.kind": "enrichment",
            }
        )

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
