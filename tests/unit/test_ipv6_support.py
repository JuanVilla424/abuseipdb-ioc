"""
Test IPv6 support across all components.
"""

import pytest
from datetime import datetime, timezone
from src.utils.validators import get_ip_version, extract_ips_from_text, is_valid_ip
from src.exporters.stix import STIXExporter
from src.exporters.formats import ExportFormatters
from src.core.correlation import IOCCorrelationEngine


class TestIPv6Support:
    """Test IPv6 support in all components."""

    def test_ip_version_detection(self):
        """Test IP version detection for IPv4 and IPv6."""
        # IPv4 tests
        assert get_ip_version("192.168.1.1") == 4
        assert get_ip_version("10.0.0.1") == 4
        assert get_ip_version("127.0.0.1") == 4

        # IPv6 tests
        assert get_ip_version("2001:db8::1") == 6
        assert get_ip_version("::1") == 6
        assert get_ip_version("2001:0db8:85a3:0000:0000:8a2e:0370:7334") == 6
        assert get_ip_version("fe80::1%lo0") == 6
        assert get_ip_version("::ffff:192.0.2.1") == 6

    def test_ip_validation(self):
        """Test IP validation for IPv4 and IPv6."""
        # Valid IPv4
        assert is_valid_ip("192.168.1.1") is True
        assert is_valid_ip("10.0.0.1") is True

        # Valid IPv6
        assert is_valid_ip("2001:db8::1") is True
        assert is_valid_ip("::1") is True
        assert is_valid_ip("2001:0db8:85a3:0000:0000:8a2e:0370:7334") is True
        assert is_valid_ip("fe80::1%lo0") is True

        # Invalid IPs
        assert is_valid_ip("not.an.ip") is False
        assert is_valid_ip("999.999.999.999") is False
        assert is_valid_ip("gggg::1") is False

    def test_ip_extraction_from_text(self):
        """Test extracting both IPv4 and IPv6 from text."""
        test_text = "Found IPs: 192.168.1.1, 2001:db8::1, and ::1 in logs"
        extracted = extract_ips_from_text(test_text)

        assert "192.168.1.1" in extracted
        assert "2001:db8::1" in extracted
        assert "::1" in extracted
        assert len(extracted) == 3

    def test_stix_pattern_generation_ipv4(self):
        """Test STIX pattern generation for IPv4."""
        ipv4_ioc = {
            "ip_address": "192.168.1.1",
            "confidence": 85,
            "reported_at": datetime.now(timezone.utc).isoformat(),
        }

        indicator = STIXExporter.create_indicator(ipv4_ioc)
        assert indicator["pattern"] == "[ipv4-addr:value = '192.168.1.1']"
        assert indicator["pattern_type"] == "stix"

    def test_stix_pattern_generation_ipv6(self):
        """Test STIX pattern generation for IPv6."""
        ipv6_ioc = {
            "ip_address": "2001:db8::1",
            "confidence": 90,
            "reported_at": datetime.now(timezone.utc).isoformat(),
        }

        indicator = STIXExporter.create_indicator(ipv6_ioc)
        assert indicator["pattern"] == "[ipv6-addr:value = '2001:db8::1']"
        assert indicator["pattern_type"] == "stix"

    def test_stix_pattern_generation_ipv6_variations(self):
        """Test STIX pattern generation for various IPv6 formats."""
        ipv6_variations = [
            "2001:0db8:85a3:0000:0000:8a2e:0370:7334",  # Full
            "2001:db8:85a3::8a2e:370:7334",  # Compressed
            "::1",  # Loopback
            "::",  # All zeros
            "::ffff:192.0.2.1",  # IPv4-mapped
        ]

        for ipv6 in ipv6_variations:
            ioc = {
                "ip_address": ipv6,
                "confidence": 85,
                "reported_at": datetime.now(timezone.utc).isoformat(),
            }

            indicator = STIXExporter.create_indicator(ioc)
            expected_pattern = f"[ipv6-addr:value = '{ipv6}']"
            assert indicator["pattern"] == expected_pattern

    def test_export_formats_ipv6(self):
        """Test export formats with IPv6 IOCs."""
        ipv6_iocs = [
            {
                "ip_address": "2001:db8::1",
                "confidence": 85,
                "reported_at": datetime.now(timezone.utc),
                "categories": ["malware"],
                "report_id": "test-001",
            },
            {
                "ip_address": "::1",
                "confidence": 90,
                "reported_at": datetime.now(timezone.utc),
                "categories": ["scanning"],
                "report_id": "test-002",
            },
        ]

        # Test JSON export
        json_data = ExportFormatters.to_json(ipv6_iocs)
        assert "2001:db8::1" in json_data
        assert "::1" in json_data

        # Test CSV export
        csv_data = ExportFormatters.to_csv(ipv6_iocs)
        assert "2001:db8::1" in csv_data
        assert "::1" in csv_data

        # Test TXT export
        txt_data = ExportFormatters.to_txt(ipv6_iocs)
        assert "2001:db8::1" in txt_data
        assert "::1" in txt_data

    def test_correlation_engine_ipv6(self):
        """Test correlation engine with IPv6 IOCs."""
        engine = IOCCorrelationEngine()

        local_ioc = {
            "ip_address": "2001:db8::1",
            "confidence": 85,
            "reported_at": datetime.now(timezone.utc),
            "categories": [{"id": 18, "name": "Malware"}],
            "report_id": "local-001",
        }

        external_ioc = {
            "abuse_confidence_score": 95,
            "country_code": "US",
            "isp": "Test ISP",
            "total_reports": 10,
        }

        # Test correlation
        result = engine.correlate_ioc(local_ioc, external_ioc)

        assert result["ip_address"] == "2001:db8::1"
        assert result["confidence"] >= 85
        assert "enrichment" in result

    def test_invalid_ip_handling(self):
        """Test proper error handling for invalid IPs."""
        with pytest.raises(ValueError):
            get_ip_version("invalid.ip.address")

        with pytest.raises(ValueError):
            get_ip_version("gggg::invalid::ipv6")
