"""
Models for existing database tables.

IMPORTANT: These models are READ-ONLY. Do not modify the existing table structure.
"""

from sqlalchemy import Column, String, Integer, DateTime, func
from sqlalchemy.dialects.postgresql import JSONB
from .base import Base


class ReportedIPs(Base):
    """
    Existing reported_ips table model (READ-ONLY).

    This table contains high-confidence local threat intelligence
    from actual attack observations. This is the PRIMARY data source.
    """

    __tablename__ = "reported_ips"
    __table_args__ = {"extend_existing": True}

    ip_address = Column(String(45), primary_key=True)
    reported_at = Column(DateTime(timezone=True), nullable=False)
    report_id = Column(String(255))
    categories = Column(JSONB)
    confidence = Column(Integer, default=75)
    created_at = Column(DateTime(timezone=True), server_default=func.current_timestamp())
