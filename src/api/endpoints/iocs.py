"""
IOC API endpoints.

Provides REST API for querying and enriching IOCs.
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from src.db.database import get_db
from src.db.models import ReportedIPs, AbuseIPDBCache
from src.schemas.ioc import IOCListResponse, CorrelatedIOC, BulkCheckRequest
from src.enrichment.abuseipdb_client import AbuseIPDBClient
from src.core.correlation import IOCCorrelationEngine
from src.core.config import settings
from src.exporters.stix import STIXExporter
from src.exporters.formats import ExportFormatters

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/iocs", tags=["IOCs"])

# Initialize services
abuseipdb_client = AbuseIPDBClient(settings.ABUSEIPDB_API_KEY)
correlation_engine = IOCCorrelationEngine()


@router.get("/", response_model=IOCListResponse)
async def get_iocs(
    db: AsyncSession = Depends(get_db),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    min_confidence: Optional[int] = Query(None, ge=0, le=100),
    include_enrichment: bool = Query(True),
    fresh_only: bool = Query(False),
) -> IOCListResponse:
    """
    Get IOCs from local database with optional enrichment.

    Args:
        skip: Number of records to skip
        limit: Maximum number of records to return
        min_confidence: Minimum confidence score filter
        include_enrichment: Include AbuseIPDB enrichment data
        fresh_only: Only return IOCs reported in last 7 days
    """
    try:
        # Build query for local IOCs
        query = select(ReportedIPs).offset(skip).limit(limit)

        # Apply freshness filter if requested
        if fresh_only:
            seven_days_ago = datetime.now(timezone.utc) - timedelta(days=7)
            query = query.where(ReportedIPs.reported_at >= seven_days_ago)

        # Apply confidence filter
        if min_confidence:
            query = query.where(ReportedIPs.confidence >= min_confidence)

        # Order by reported_at descending (most recent first)
        query = query.order_by(ReportedIPs.reported_at.desc())

        # Execute query
        result = await db.execute(query)
        local_iocs = result.scalars().all()

        # Get total count
        count_query = select(func.count()).select_from(ReportedIPs)
        if fresh_only:
            count_query = count_query.where(ReportedIPs.reported_at >= seven_days_ago)
        if min_confidence:
            count_query = count_query.where(ReportedIPs.confidence >= min_confidence)

        total_result = await db.execute(count_query)
        total_count = total_result.scalar()

        # Convert to dictionaries
        local_data = []
        for ioc in local_iocs:
            local_data.append(
                {
                    "ip_address": ioc.ip_address,
                    "confidence": ioc.confidence,
                    "reported_at": ioc.reported_at,
                    "report_id": ioc.report_id,
                    "categories": ioc.categories or [],
                    "created_at": ioc.created_at,
                }
            )

        # Get enrichment data if requested
        external_data = {}
        if include_enrichment and local_data:
            ip_addresses = [ioc["ip_address"] for ioc in local_data]

            # Fetch cached enrichment data
            cache_query = select(AbuseIPDBCache).where(AbuseIPDBCache.ip_address.in_(ip_addresses))
            cache_result = await db.execute(cache_query)
            cached_enrichments = cache_result.scalars().all()

            for enrichment in cached_enrichments:
                external_data[enrichment.ip_address] = {
                    "abuse_confidence_score": enrichment.abuse_confidence_score,
                    "country_code": enrichment.country_code,
                    "isp": enrichment.isp,
                    "usage_type": enrichment.usage_type,
                    "total_reports": enrichment.total_reports,
                    "last_reported_at": enrichment.last_reported_at,
                }

        # If no local data, try to get from AbuseIPDB blacklist
        if not local_data and include_enrichment:
            logger.info("No local IOCs found, fetching from AbuseIPDB blacklist")
            try:
                # Check rate limit first
                if await abuseipdb_client.check_rate_limit(db):
                    blacklist_response = await abuseipdb_client.get_blacklist(
                        confidence_minimum=min_confidence or 75,
                        limit=skip + limit,  # Get enough to paginate
                    )

                    # Convert blacklist to our format
                    blacklist_data = blacklist_response.get("data", [])
                    # Handle pagination
                    paginated_data = (
                        blacklist_data[skip : skip + limit] if skip < len(blacklist_data) else []
                    )

                    for item in paginated_data:
                        ioc_data = {
                            "ip_address": item.get("ipAddress"),
                            "confidence": item.get("abuseConfidenceScore", 0),
                            "reported_at": datetime.now(timezone.utc),
                            "report_id": f"ABUSEIPDB-{item.get('ipAddress')}",
                            "categories": [],
                            "created_at": datetime.now(timezone.utc),
                        }
                        local_data.append(ioc_data)

                        # Add to external data
                        external_data[item.get("ipAddress")] = {
                            "abuse_confidence_score": item.get("abuseConfidenceScore", 0),
                            "country_code": item.get("countryCode"),
                            "usage_type": item.get("usageType"),
                            "isp": item.get("isp"),
                            "total_reports": item.get("totalReports", 0),
                            "last_reported_at": item.get("lastReportedAt"),
                        }

                    total_count = len(blacklist_data)
                else:
                    logger.warning("Rate limit reached, cannot fetch from AbuseIPDB")
            except Exception as e:
                logger.error(f"Error fetching from AbuseIPDB blacklist: {e}")

        # Correlate IOCs
        correlated = correlation_engine.bulk_correlate(local_data, external_data)

        # Apply confidence filter to correlated results
        if min_confidence:
            correlated = correlation_engine.filter_by_confidence(correlated, min_confidence)

        # Log response details
        logger.info(
            f"Returning {len(correlated)} IOCs out of {total_count} total (page {skip // limit + 1}, size {limit})"
        )
        logger.debug(f"First 3 IPs returned: {[ioc.get('ip_address') for ioc in correlated[:3]]}")

        return IOCListResponse(
            total=total_count, items=correlated, page=skip // limit + 1, page_size=limit
        )

    except Exception as e:
        logger.error(f"Error fetching IOCs: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/{ip_address}", response_model=CorrelatedIOC)
async def get_ioc(
    ip_address: str,
    db: AsyncSession = Depends(get_db),
    enrich: bool = Query(True),
    force_refresh: bool = Query(False),
) -> CorrelatedIOC:
    """
    Get single IOC with enrichment.

    Args:
        ip_address: IP address to lookup
        enrich: Include AbuseIPDB enrichment
        force_refresh: Force fresh enrichment data
    """
    # Get local IOC
    result = await db.execute(select(ReportedIPs).where(ReportedIPs.ip_address == ip_address))
    local_ioc = result.scalar_one_or_none()

    if not local_ioc:
        raise HTTPException(status_code=404, detail="IOC not found")

    # Convert to dictionary
    local_data = {
        "ip_address": local_ioc.ip_address,
        "confidence": local_ioc.confidence,
        "reported_at": local_ioc.reported_at,
        "report_id": local_ioc.report_id,
        "categories": local_ioc.categories or [],
        "created_at": local_ioc.created_at,
    }

    # Get enrichment if requested
    external_data = None
    if enrich:
        cache_entry = await abuseipdb_client.check_ip_with_cache(
            db, ip_address, force_refresh=force_refresh
        )

        if cache_entry:
            external_data = {
                "abuse_confidence_score": cache_entry.abuse_confidence_score,
                "country_code": cache_entry.country_code,
                "isp": cache_entry.isp,
                "usage_type": cache_entry.usage_type,
                "total_reports": cache_entry.total_reports,
                "last_reported_at": cache_entry.last_reported_at,
            }

    # Correlate
    correlated = correlation_engine.correlate_ioc(local_data, external_data)

    return correlated


@router.post("/enrich/bulk")
async def bulk_enrich(
    request: BulkCheckRequest, db: AsyncSession = Depends(get_db)
) -> Dict[str, Any]:
    """
    Bulk enrich multiple IPs with AbuseIPDB data.

    Args:
        request: Bulk check request with IP addresses
    """
    results = await abuseipdb_client.bulk_check_ips(db, request.ip_addresses, batch_size=10)

    enriched_count = sum(1 for v in results.values() if v is not None)

    return {
        "total": len(request.ip_addresses),
        "enriched": enriched_count,
        "results": {
            ip: {
                "enriched": result is not None,
                "data": (
                    {
                        "abuse_confidence_score": result.abuse_confidence_score,
                        "country_code": result.country_code,
                        "isp": result.isp,
                    }
                    if result
                    else None
                ),
            }
            for ip, result in results.items()
        },
    }


@router.get("/export/{format}")
async def export_iocs(
    format: str,
    db: AsyncSession = Depends(get_db),
    min_confidence: Optional[int] = Query(None, ge=0, le=100),
    limit: int = Query(1000, ge=1, le=10000),
    include_enrichment: bool = Query(True),
):
    """
    Export IOCs in various formats.

    Args:
        format: Export format (json, stix, csv, txt)
        min_confidence: Minimum confidence filter
        limit: Maximum IOCs to export
        include_enrichment: Include enrichment data
    """
    if format not in ["json", "stix", "csv", "txt"]:
        raise HTTPException(status_code=400, detail="Invalid export format")

    # Get IOCs
    response = await get_iocs(
        db=db,
        skip=0,
        limit=limit,
        min_confidence=min_confidence,
        include_enrichment=include_enrichment,
    )

    iocs = response.items

    # Export based on format
    if format == "json":
        content = ExportFormatters.to_json(iocs)
        media_type = "application/json"
        filename = f"iocs_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.json"

    elif format == "stix":
        content = STIXExporter.create_bundle(iocs)
        media_type = "application/json"
        filename = f"iocs_stix_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.json"

    elif format == "csv":
        content = ExportFormatters.to_csv(iocs)
        media_type = "text/csv"
        filename = f"iocs_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.csv"

    else:  # txt
        content = ExportFormatters.to_txt(iocs, include_metadata=True)
        media_type = "text/plain"
        filename = f"iocs_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.txt"

    return Response(
        content=content,
        media_type=media_type,
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )
