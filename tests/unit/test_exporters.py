"""
Unit tests for export formatters.
"""

import json
import csv
from io import StringIO
import pytest
from src.exporters.formats import ExportFormatters


class TestExportFormatters:
    """Test export formatting functionality."""

    @pytest.fixture
    def sample_iocs(self):
        """Sample IOC data for testing."""
        return [
            {
                "ip_address": "192.168.1.1",
                "confidence": 85,
                "local_confidence": 80,
                "external_confidence": 70,
                "reported_at": "2024-01-01T12:00:00",
                "stix_labels": ["malicious-activity", "anonymization"],
                "categories": [4, 14],
                "enrichment": {
                    "country_code": "US",
                    "isp": "Test ISP",
                    "has_external_validation": True,
                },
            },
            {
                "ip_address": "10.0.0.1",
                "confidence": 75,
                "local_confidence": 75,
                "external_confidence": None,
                "reported_at": "2024-01-02T12:00:00",
                "stix_labels": ["malicious-activity"],
                "categories": [22],
                "enrichment": {"country_code": None, "isp": None, "has_external_validation": False},
            },
        ]

    def test_json_export(self, sample_iocs):
        """Test JSON export format."""
        result = ExportFormatters.to_json(sample_iocs)
        data = json.loads(result)

        assert data["total"] == 2
        assert len(data["indicators"]) == 2
        assert data["indicators"][0]["ip_address"] == "192.168.1.1"
        assert data["indicators"][0]["confidence"] == 85

    def test_csv_export(self, sample_iocs):
        """Test CSV export format."""
        result = ExportFormatters.to_csv(sample_iocs)

        # Parse CSV
        reader = csv.DictReader(StringIO(result))
        rows = list(reader)

        assert len(rows) == 2
        assert rows[0]["ip_address"] == "192.168.1.1"
        assert rows[0]["confidence"] == "85"
        assert rows[0]["country_code"] == "US"
        assert rows[1]["country_code"] == ""

    def test_txt_export(self, sample_iocs):
        """Test plain text export format."""
        # Without metadata
        result = ExportFormatters.to_txt(sample_iocs, include_metadata=False)
        lines = result.split("\n")
        assert lines[0] == "192.168.1.1"
        assert lines[1] == "10.0.0.1"

        # With metadata
        result = ExportFormatters.to_txt(sample_iocs, include_metadata=True)
        lines = result.split("\n")
        assert "Confidence: 85%" in lines[0]
        assert "Country: US" in lines[0]
        assert "Confidence: 75%" in lines[1]

    def test_elastic_bulk_export(self, sample_iocs):
        """Test Elasticsearch bulk format export."""
        result = ExportFormatters.to_elastic_bulk(sample_iocs, "test-index")
        lines = result.strip().split("\n")

        # Should have 2 lines per IOC (metadata + document)
        assert len(lines) == 4

        # Check first IOC metadata
        meta = json.loads(lines[0])
        assert meta["index"]["_index"] == "test-index"
        assert meta["index"]["_id"] == "192.168.1.1"

        # Check first IOC document
        doc = json.loads(lines[1])
        assert doc["ip"] == "192.168.1.1"
        assert doc["confidence"] == 85
        assert doc["geo"]["country_iso_code"] == "US"
        assert doc["threat"]["indicator"]["type"] == "ipv4-addr"
