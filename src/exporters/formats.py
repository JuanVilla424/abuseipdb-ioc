"""
Export formatters for various output formats.
"""

import csv
import json
from io import StringIO
from typing import List, Dict, Any


class ExportFormatters:
    """Formatters for different export formats."""

    @staticmethod
    def to_json(iocs: List[Dict[str, Any]], pretty: bool = True) -> str:
        """
        Export IOCs as JSON.

        Args:
            iocs: List of correlated IOCs
            pretty: Pretty print JSON

        Returns:
            JSON string
        """
        return json.dumps(
            {"total": len(iocs), "indicators": iocs}, indent=2 if pretty else None, default=str
        )

    @staticmethod
    def to_csv(iocs: List[Dict[str, Any]]) -> str:
        """
        Export IOCs as CSV.

        Args:
            iocs: List of correlated IOCs

        Returns:
            CSV string
        """
        output = StringIO()

        if not iocs:
            return ""

        # Define CSV fields
        fieldnames = [
            "ip_address",
            "confidence",
            "local_confidence",
            "external_confidence",
            "reported_at",
            "country_code",
            "isp",
            "stix_labels",
            "categories",
        ]

        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()

        for ioc in iocs:
            row = {
                "ip_address": ioc.get("ip_address"),
                "confidence": ioc.get("confidence"),
                "local_confidence": ioc.get("local_confidence"),
                "external_confidence": ioc.get("external_confidence", ""),
                "reported_at": ioc.get("reported_at"),
                "country_code": ioc.get("enrichment", {}).get("country_code", ""),
                "isp": ioc.get("enrichment", {}).get("isp", ""),
                "stix_labels": "|".join(ioc.get("stix_labels", [])),
                "categories": "|".join(str(c) for c in ioc.get("categories", [])),
            }
            writer.writerow(row)

        return output.getvalue()

    @staticmethod
    def to_txt(iocs: List[Dict[str, Any]], include_metadata: bool = False) -> str:
        """
        Export IOCs as plain text (one per line).

        Args:
            iocs: List of correlated IOCs
            include_metadata: Include confidence scores

        Returns:
            Plain text string
        """
        lines = []

        for ioc in iocs:
            if include_metadata:
                line = f"{ioc['ip_address']} # Confidence: {ioc['confidence']}%"
                if ioc.get("enrichment", {}).get("country_code"):
                    line += f" Country: {ioc['enrichment']['country_code']}"
                lines.append(line)
            else:
                lines.append(ioc["ip_address"])

        return "\n".join(lines)

    @staticmethod
    def to_elastic_bulk(iocs: List[Dict[str, Any]], index_name: str = "threats") -> str:
        """
        Export IOCs in Elasticsearch bulk format.

        Args:
            iocs: List of correlated IOCs
            index_name: Elasticsearch index name

        Returns:
            Bulk API formatted string
        """
        lines = []

        for ioc in iocs:
            # Index metadata
            meta = {"index": {"_index": index_name, "_id": ioc["ip_address"]}}
            lines.append(json.dumps(meta))

            # Document
            doc = {
                "@timestamp": ioc.get("reported_at"),
                "ip": ioc["ip_address"],
                "confidence": ioc["confidence"],
                "local_confidence": ioc["local_confidence"],
                "external_confidence": ioc.get("external_confidence"),
                "tags": ioc.get("stix_labels", []),
                "geo": {"country_iso_code": ioc.get("enrichment", {}).get("country_code")},
                "network": {"name": ioc.get("enrichment", {}).get("isp")},
                "threat": {
                    "indicator": {
                        "ip": ioc["ip_address"],
                        "confidence": ioc["confidence"],
                        "type": "ipv4-addr",
                    }
                },
            }
            lines.append(json.dumps(doc))

        return "\n".join(lines) + "\n"
