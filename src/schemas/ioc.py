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
        from_attributes = True


class GeolocationData(BaseModel):
    """Schema for IP geolocation information."""

    country_code: Optional[str] = None
    country_name: Optional[str] = None
    region: Optional[str] = None
    city: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    continent: Optional[str] = None


class ProviderData(BaseModel):
    """Schema for threat intelligence provider information."""

    name: str = Field(..., description="Provider name (e.g., 'AbuseIPDB', 'Local Detection')")
    source: str = Field(..., description="Source system or feed name")
    confidence: Optional[int] = Field(None, ge=0, le=100, description="Provider confidence score")
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    reference_url: Optional[str] = None


class EnrichmentData(BaseModel):
    """Schema for enrichment data from external sources."""

    # Network information
    isp: Optional[str] = None
    usage_type: Optional[str] = None
    domain: Optional[str] = None

    # Threat intelligence
    has_external_validation: bool = False
    abuse_confidence_score: Optional[int] = None
    total_reports: Optional[int] = None
    last_reported_at: Optional[datetime] = None

    # Geolocation
    geolocation: Optional[GeolocationData] = None

    # Provider information
    providers: List[ProviderData] = Field(default_factory=list)


class CorrelatedIOC(IOCBase):
    """Standard IOC schema following industry best practices and Elasticsearch compatibility."""

    # Core IOC fields
    reported_at: datetime = Field(..., description="When the IOC was first reported")
    categories: List[Any] = Field(default_factory=list, description="Threat categories")
    report_id: Optional[str] = Field(None, description="Source report identifier")

    # Confidence scoring (industry standard 0-100)
    local_confidence: Optional[int] = Field(
        None, ge=0, le=100, description="Local confidence score"
    )
    external_confidence: Optional[int] = Field(
        None, ge=0, le=100, description="External source confidence"
    )

    # Freshness and validity (Elasticsearch requirements)
    freshness_score: Optional[float] = Field(None, ge=0, le=1, description="IOC freshness score")
    valid_until: Optional[datetime] = Field(None, description="When this IOC expires")
    valid_from: Optional[datetime] = Field(None, description="When this IOC becomes valid")

    # Source and priority information
    source_priority: Optional[str] = Field(None, description="Source priority classification")
    provider: Optional[str] = Field(None, description="Primary threat intelligence provider")

    # Standard STIX labels for interoperability
    labels: List[str] = Field(
        default_factory=lambda: ["malicious-activity"], description="STIX 2.1 compliant labels"
    )

    # Threat classification for Elasticsearch
    threat_types: List[str] = Field(default_factory=list, description="Elastic threat types")
    kill_chain_phases: List[str] = Field(
        default_factory=list, description="MITRE ATT&CK kill chain phases"
    )

    # Enrichment data with geolocation and providers
    enrichment: Optional[EnrichmentData] = None


class IOCListResponse(BaseModel):
    """Response schema for IOC list endpoints."""

    total: int
    items: List[CorrelatedIOC]
    page: int = 1
    page_size: int = 100


class STIXBundleResponse(BaseModel):
    """Response schema for STIX bundle format."""

    type: str = "bundle"
    id: str
    spec_version: str = "2.1"
    created: datetime
    modified: datetime
    objects: List[dict]


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

    format: str = Field(..., pattern="^(json|stix|csv|txt)$")
    include_enrichment: bool = True


class APIHealth(BaseModel):
    """API health check response."""

    status: str
    database: bool
    abuseipdb: bool
    timestamp: datetime
    daily_requests_used: int
    daily_requests_limit: int
