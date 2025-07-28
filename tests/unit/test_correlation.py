"""
Unit tests for IOC correlation engine.
"""

from datetime import datetime, timedelta, timezone
from src.core.correlation import IOCCorrelationEngine


class TestIOCCorrelationEngine:
    """Test IOC correlation functionality."""

    def test_weighted_confidence_calculation(self):
        """Test weighted confidence score calculation."""
        engine = IOCCorrelationEngine()

        # Test with both local and external confidence
        score = engine.calculate_weighted_confidence(80, 60)
        assert score == 76  # (80 * 0.8) + (60 * 0.2) = 64 + 12 = 76

        # Test with low local confidence
        score = engine.calculate_weighted_confidence(50, 90)
        assert score == 58  # (50 * 0.8) + (90 * 0.2) = 40 + 18 = 58

        # Test with no external data
        score = engine.calculate_weighted_confidence(70, None)
        assert score == 70

        # Test boost for high local confidence with both sources
        score = engine.calculate_weighted_confidence(75, 50)
        assert score == 70  # (75 * 0.8) + (50 * 0.2) = 60 + 10 = 70

    def test_freshness_score_calculation(self):
        """Test freshness score calculation."""
        engine = IOCCorrelationEngine()
        now = datetime.now(timezone.utc)

        # Test very fresh (today)
        score = engine.calculate_freshness_score(now)
        assert score == 1.0

        # Test 3 days old
        three_days_ago = now - timedelta(days=3)
        score = engine.calculate_freshness_score(three_days_ago)
        assert score == 0.9

        # Test 15 days old
        fifteen_days_ago = now - timedelta(days=15)
        score = engine.calculate_freshness_score(fifteen_days_ago)
        assert score == 0.7

        # Test very old (1 year)
        one_year_ago = now - timedelta(days=365)
        score = engine.calculate_freshness_score(one_year_ago)
        assert score == 0.1

    def test_category_to_stix_mapping(self):
        """Test category mapping to STIX labels."""
        engine = IOCCorrelationEngine()

        # Test numeric categories
        labels = engine.map_categories_to_stix([4, 14, 22])
        assert "malicious-activity" in labels

        # Test dictionary categories
        cat_dicts = [{"id": 7}, {"id": 13}]
        labels = engine.map_categories_to_stix(cat_dicts)
        assert "phishing" in labels
        assert "anonymization" in labels

        # Test empty categories
        labels = engine.map_categories_to_stix([])
        assert labels == ["malicious-activity"]

    def test_ioc_correlation(self):
        """Test single IOC correlation."""
        engine = IOCCorrelationEngine()

        local_data = {
            "ip_address": "192.168.1.1",
            "confidence": 80,
            "reported_at": datetime.now(timezone.utc),
            "categories": [4, 14],
            "report_id": "test-123",
        }

        external_data = {"abuse_confidence_score": 70, "country_code": "US", "isp": "Test ISP"}

        result = engine.correlate_ioc(local_data, external_data)

        assert result["ip_address"] == "192.168.1.1"
        assert result["confidence"] == 78  # (80 * 0.8) + (70 * 0.2) = 64 + 14 = 78
        assert result["local_confidence"] == 80
        assert result["external_confidence"] == 70
        # When both local and external data exist, providers should include both
        provider_names = [p["name"] for p in result["enrichment"]["providers"]]
        assert "Local Detection" in provider_names
        assert "AbuseIPDB" in provider_names
        assert result["source_priority"] == "local_primary"
        assert "malicious-activity" in result["labels"]
