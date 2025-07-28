"""
Pydantic schemas for IOC data validation and serialization.
"""

from datetime import datetime
from typing import List, Optional, Any
from pydantic import BaseModel, Field, validator
import ipaddress


class IOCBase(BaseModel):
    """Base schema for IOC data."""

    ip_address: str = Field(..., description="IP address indicator")
    confidence: int = Field(..., ge=0, le=100, description="Confidence score (0-100)")

    @validator("ip_address")
    def validate_ip(cls, v):
        """Validate IP address format."""
        try:
            ipaddress.ip_address(v)
            return v
        except ValueError:
            raise ValueError(f"Invalid IP address: {v}")


class LocalIOC(IOCBase):
    """Schema for local IOC from reported_ips table."""

    reported_at: datetime
    report_id: Optional[str] = None
    categories: List[Any] = Field(default_factory=list)
    created_at: datetime

    class Config:
        orm_mode = True


class EnrichmentData(BaseModel):
    """Schema for enrichment data from AbuseIPDB."""

    country_code: Optional[str] = None
    isp: Optional[str] = None
    usage_type: Optional[str] = None
    has_external_validation: bool = False
    abuse_confidence_score: Optional[int] = None
    total_reports: Optional[int] = None
    last_reported_at: Optional[datetime] = None


class CorrelatedIOC(IOCBase):
    """Schema for correlated IOC with enrichment."""

    local_confidence: int
    external_confidence: Optional[int] = None
    freshness_score: float = Field(..., ge=0, le=1)
    reported_at: datetime
    categories: List[Any] = Field(default_factory=list)
    stix_labels: List[str] = Field(default_factory=list)
    source_priority: str = "local_primary"
    enrichment: EnrichmentData
    report_id: Optional[str] = None


class IOCListResponse(BaseModel):
    """Response schema for IOC list endpoints."""

    total: int
    items: List[CorrelatedIOC]
    page: int = 1
    page_size: int = 100


class BulkCheckRequest(BaseModel):
    """Request schema for bulk IP checks."""

    ip_addresses: List[str] = Field(..., max_items=100)
    force_refresh: bool = Field(default=False)

    @validator("ip_addresses")
    def validate_ips(cls, v):
        """Validate all IP addresses."""
        for ip in v:
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                raise ValueError(f"Invalid IP address: {ip}")
        return v


class ExportFormat(BaseModel):
    """Supported export formats."""

    format: str = Field(..., regex="^(json|stix|csv|txt)$")
    include_enrichment: bool = True


class APIHealth(BaseModel):
    """API health check response."""

    status: str
    database: bool
    abuseipdb: bool
    timestamp: datetime
    daily_requests_used: int
    daily_requests_limit: int
