"""
Models for enrichment and caching tables.

These are new tables created specifically for the IOC management system.
"""

from sqlalchemy import Column, String, Integer, DateTime, ForeignKey, Date, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import relationship
from .base import Base


class AbuseIPDBCache(Base):
    """
    Cache table for AbuseIPDB API responses.

    Stores enrichment data from AbuseIPDB to minimize API calls
    and provide fast access to external intelligence.
    """

    __tablename__ = "abuseipdb_cache"

    ip_address = Column(
        String(45), ForeignKey("reported_ips.ip_address", ondelete="CASCADE"), primary_key=True
    )
    abuse_confidence_score = Column(Integer, nullable=False)
    country_code = Column(String(2))
    usage_type = Column(String(100))
    isp = Column(String(255))
    domain = Column(String(255))
    total_reports = Column(Integer, default=0)
    num_distinct_users = Column(Integer, default=0)
    last_reported_at = Column(DateTime(timezone=True))
    extra_data = Column(JSONB, default=dict)
    last_checked = Column(DateTime(timezone=True), server_default=func.current_timestamp())
    created_at = Column(DateTime(timezone=True), server_default=func.current_timestamp())
    updated_at = Column(
        DateTime(timezone=True),
        server_default=func.current_timestamp(),
        onupdate=func.current_timestamp(),
    )

    # Relationship to reported_ips (read-only reference)
    reported_ip = relationship("ReportedIPs", backref="abuse_cache", passive_deletes=True)


class APIUsageTracking(Base):
    """
    Track AbuseIPDB API usage for rate limiting.

    Ensures we stay within limits and track different types of calls.
    """

    __tablename__ = "api_usage_tracking"

    id = Column(Integer, primary_key=True)
    date = Column(Date, nullable=False, unique=True, default=func.current_date())
    requests_count = Column(Integer, default=0)
    successful_requests = Column(Integer, default=0)
    failed_requests = Column(Integer, default=0)
    blacklist_requests = Column(Integer, default=0)  # Track blacklist API calls
    redis_updates = Column(Integer, default=0)  # Track Redis cache updates
    created_at = Column(DateTime(timezone=True), server_default=func.current_timestamp())
    updated_at = Column(
        DateTime(timezone=True),
        server_default=func.current_timestamp(),
        onupdate=func.current_timestamp(),
    )
