"""
TAXII 2.1 Server endpoints for Elasticsearch Custom Threat Intelligence integration.

Implements TAXII 2.1 specification for threat intelligence sharing.
"""

import logging
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from src.db.database import get_db
from src.db.models import ReportedIPs, AbuseIPDBCache, APIUsageTracking
from src.exporters.stix import STIXExporter
from src.core.config import settings
from src.core.correlation import IOCCorrelationEngine
from src.enrichment.abuseipdb_client import AbuseIPDBClient

logger = logging.getLogger(__name__)

# TAXII 2.1 router
taxii_router = APIRouter(tags=["TAXII 2.1"])


@taxii_router.get("/taxii2")
async def taxii_discovery(request: Request) -> Dict[str, Any]:
    """
    TAXII 2.1 Discovery endpoint.

    Returns information about available API roots.
    """
    base_url = str(request.base_url).rstrip("/")

    return {
        "title": "AbuseIPDB IOC TAXII 2.1 Server",
        "description": "TAXII 2.1 server providing threat intelligence IOCs from AbuseIPDB and local detections",
        "contact": "security@example.com",
        "default": f"{base_url}/taxii2/iocs",
        "api_roots": [f"{base_url}/taxii2/iocs"],
    }


@taxii_router.get("/taxii2/iocs")
async def taxii_root_information(request: Request) -> Dict[str, Any]:
    """
    TAXII 2.1 Root Information endpoint.

    Returns information about this TAXII root.
    """
    base_url = str(request.base_url).rstrip("/")

    return {
        "title": "AbuseIPDB IOC TAXII Root",
        "description": "Threat intelligence IOCs from AbuseIPDB and local security detections",
        "versions": ["application/taxii+json;version=2.1"],
        "max_content_length": 10485760,  # 10MB
    }


@taxii_router.get("/taxii2/iocs/collections")
async def get_collections(request: Request) -> Dict[str, Any]:
    """
    TAXII 2.1 Collections endpoint.

    Returns available collections.
    """
    base_url = str(request.base_url).rstrip("/")

    collections = [
        {
            "id": "ioc-indicators",
            "title": "IOC Indicators",
            "description": "IP-based indicators of compromise from AbuseIPDB and local detections",
            "can_read": True,
            "can_write": False,
            "media_types": ["application/stix+json;version=2.1"],
        },
        {
            "id": "high-confidence-iocs",
            "title": "High Confidence IOCs",
            "description": "High confidence IOCs (>= 80% confidence score)",
            "can_read": True,
            "can_write": False,
            "media_types": ["application/stix+json;version=2.1"],
        },
    ]

    return {"collections": collections}


@taxii_router.get("/taxii2/iocs/collections/{collection_id}")
async def get_collection(collection_id: str, request: Request) -> Dict[str, Any]:
    """
    TAXII 2.1 Collection Information endpoint.

    Returns information about a specific collection.
    """
    collections_map = {
        "ioc-indicators": {
            "id": "ioc-indicators",
            "title": "IOC Indicators",
            "description": "IP-based indicators of compromise from AbuseIPDB and local detections",
            "can_read": True,
            "can_write": False,
            "media_types": ["application/stix+json;version=2.1"],
        },
        "high-confidence-iocs": {
            "id": "high-confidence-iocs",
            "title": "High Confidence IOCs",
            "description": "High confidence IOCs (>= 80% confidence score)",
            "can_read": True,
            "can_write": False,
            "media_types": ["application/stix+json;version=2.1"],
        },
    }

    if collection_id not in collections_map:
        raise HTTPException(status_code=404, detail="Collection not found")

    return collections_map[collection_id]


@taxii_router.get("/taxii2/iocs/collections/{collection_id}/objects")
async def get_collection_objects(
    collection_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    limit: int = Query(100, ge=1, le=10000, description="Maximum objects to return"),
    added_after: Optional[str] = Query(None, description="Filter objects added after this date"),
    match_id: Optional[str] = Query(None, description="Filter by specific object ID"),
    match_type: Optional[str] = Query(None, description="Filter by object type"),
    match_version: Optional[str] = Query(None, description="Filter by object version"),
) -> Dict[str, Any]:
    """
    TAXII 2.1 Get Objects endpoint.

    Returns STIX objects from the specified collection.
    """
    if collection_id not in ["ioc-indicators", "high-confidence-iocs", "abuseipdb-iocs"]:
        raise HTTPException(status_code=404, detail="Collection not found")

    # Set minimum confidence based on collection
    min_confidence = 80 if collection_id == "high-confidence-iocs" else 0

    try:
        # Check for pre-processed IOCs in Redis first
        from src.utils.redis_client import get_redis_cache

        redis_cache = await get_redis_cache()

        if redis_cache:
            cached_iocs = await redis_cache.get_iocs(key="preprocessed_iocs")
            if cached_iocs:
                logger.info(f"Using {len(cached_iocs)} pre-processed IOCs from cache")

                # Filter by confidence if needed
                if min_confidence:
                    cached_iocs = [
                        ioc for ioc in cached_iocs if ioc.get("confidence", 0) >= min_confidence
                    ]

                # Apply limit only for TAXII response
                total_objects = len(cached_iocs)
                paginated_objects = cached_iocs[:limit] if limit else cached_iocs

                # Create STIX bundle
                bundle = STIXExporter.create_bundle(paginated_objects)

                # TAXII 2.1 envelope format
                envelope = {"more": total_objects > limit if limit else False, "data": bundle}

                logger.info(
                    f"TAXII 2.1: Returned {len(bundle['objects'])} of {total_objects} pre-processed objects from collection {collection_id}"
                )

                return envelope

        # Fallback to real-time processing if no cache
        logger.info("No pre-processed cache found, processing in real-time...")

        # Initialize services
        correlation_engine = IOCCorrelationEngine()
        abuseipdb_client = AbuseIPDBClient(settings.ABUSEIPDB_API_KEY)

        # 1️⃣ Get ALL IOCs from PostgreSQL tables (LOCAL SOURCE)
        logger.info("Fetching local IOCs from reported_ips table...")
        query = select(ReportedIPs)
        if min_confidence:
            query = query.where(ReportedIPs.confidence >= min_confidence)
        query = query.order_by(ReportedIPs.reported_at.desc())

        result = await db.execute(query)
        local_iocs = result.scalars().all()

        # Convert local IOCs to dictionaries
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
                    "source": "local",  # Mark as local source
                }
            )
        logger.info(f"Found {len(local_data)} local IOCs")

        # 2️⃣ Get IOCs from AbuseIPDB blacklist (EXTERNAL SOURCE)
        logger.info("Fetching IOCs from AbuseIPDB blacklist...")
        try:
            blacklist_response = await abuseipdb_client.get_blacklist(
                db=db,
                confidence_minimum=50,  # Confidence ≥50 as requested
                limit=10000,  # Maximum available
            )

            # Convert AbuseIPDB blacklist to our format
            abuseipdb_data = []
            if blacklist_response.get("data"):
                for item in blacklist_response["data"]:
                    # Avoid duplicates with local data
                    ip_address = item.get("ipAddress")
                    if not any(local_ioc["ip_address"] == ip_address for local_ioc in local_data):
                        abuseipdb_data.append(
                            {
                                "ip_address": ip_address,
                                "confidence": item.get("abuseConfidenceScore", 50),
                                "reported_at": datetime.now(timezone.utc),  # Mark as fresh
                                "report_id": f"ABUSEIPDB-{item.get('abuseConfidenceScore', 50)}",
                                "categories": ["abuseipdb-blacklist"],
                                "created_at": datetime.now(timezone.utc),
                                "source": "abuseipdb",  # Mark as external source
                            }
                        )
                logger.info(f"Found {len(abuseipdb_data)} unique AbuseIPDB blacklist IOCs")
            else:
                logger.info("No AbuseIPDB blacklist data available (likely rate limited)")
        except Exception as e:
            logger.error(f"Error fetching AbuseIPDB blacklist: {e}")
            abuseipdb_data = []

        # 3️⃣ Combine both sources
        all_iocs = local_data + abuseipdb_data
        logger.info(
            f"Total IOCs to process: {len(all_iocs)} (Local: {len(local_data)}, AbuseIPDB: {len(abuseipdb_data)})"
        )

        # Get cached enrichment data from abuseipdb_cache table for ALL IPs
        all_ip_addresses = [ioc["ip_address"] for ioc in all_iocs]
        cache_query = select(AbuseIPDBCache).where(AbuseIPDBCache.ip_address.in_(all_ip_addresses))
        cache_result = await db.execute(cache_query)
        cached_enrichments = cache_result.scalars().all()

        external_data = {}
        for enrichment in cached_enrichments:
            external_data[enrichment.ip_address] = {
                "abuse_confidence_score": enrichment.abuse_confidence_score,
                "country_code": enrichment.country_code,
                "isp": enrichment.isp,
                "usage_type": enrichment.usage_type,
                "total_reports": enrichment.total_reports,
                "last_reported_at": enrichment.last_reported_at,
            }

        # 4️⃣ Correlate ALL IOCs (local + AbuseIPDB) with cached data
        correlated = []
        for ioc in all_iocs:
            ip_address = ioc["ip_address"]
            external_ioc_data = external_data.get(ip_address)

            # For AbuseIPDB blacklist items, they already have abuse confidence
            if ioc.get("source") == "abuseipdb" and not external_ioc_data:
                external_ioc_data = {
                    "abuse_confidence_score": ioc["confidence"],
                    "country_code": None,
                    "isp": None,
                    "usage_type": None,
                    "total_reports": 1,  # At least 1 report to be in blacklist
                    "last_reported_at": ioc["reported_at"],
                }

            try:
                individual_correlated = correlation_engine.correlate_ioc(ioc, external_ioc_data)
                enriched_ioc = await correlation_engine.enrich_with_geolocation(
                    individual_correlated
                )
                correlated.append(enriched_ioc)
            except Exception as e:
                logger.error(f"TAXII correlation failed for {ip_address}: {e}")
                correlated.append(ioc)

        # Apply limit only for TAXII response (not for DB query!)
        total_objects = len(correlated)
        paginated_objects = correlated[:limit] if limit else correlated

        # Create STIX bundle with paginated objects
        bundle = STIXExporter.create_bundle(paginated_objects)

        # TAXII 2.1 envelope format (correcto según especificación)
        envelope = {
            "more": total_objects > limit if limit else False,  # More objects available?
            "data": bundle,  # Bundle completo con objects dentro
        }

        logger.info(
            f"TAXII 2.1: Returned {len(bundle['objects'])} of {total_objects} total objects from collection {collection_id}"
        )

        return envelope

    except Exception as e:
        logger.error(f"TAXII 2.1 collection objects error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@taxii_router.get("/taxii2/iocs/collections/{collection_id}/manifest")
async def get_collection_manifest(
    collection_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    limit: int = Query(100, ge=1, le=10000),
    added_after: Optional[str] = Query(None),
) -> Dict[str, Any]:
    """
    TAXII 2.1 Get Manifest endpoint.

    Returns manifest information about objects in the collection.
    """
    if collection_id not in ["ioc-indicators", "high-confidence-iocs"]:
        raise HTTPException(status_code=404, detail="Collection not found")

    min_confidence = 80 if collection_id == "high-confidence-iocs" else 0

    try:
        # Get IOCs directly from PostgreSQL
        query = select(ReportedIPs).limit(limit)
        if min_confidence:
            query = query.where(ReportedIPs.confidence >= min_confidence)
        query = query.order_by(ReportedIPs.reported_at.desc())

        result = await db.execute(query)
        local_iocs = result.scalars().all()

        # Create manifest entries
        objects = []
        for ioc in local_iocs:
            objects.append(
                {
                    "id": f"indicator--{ioc.ip_address.replace('.', '-')}",
                    "date_added": (
                        ioc.reported_at.isoformat()
                        if ioc.reported_at
                        else datetime.now(timezone.utc).isoformat()
                    ),
                    "version": "1",
                    "media_type": "application/stix+json;version=2.1",
                }
            )

        return {"more": len(objects) >= limit, "objects": objects}

    except Exception as e:
        logger.error(f"TAXII 2.1 manifest error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@taxii_router.get("/taxii2/iocs/status/{status_id}")
async def get_status(status_id: str) -> Dict[str, Any]:
    """
    TAXII 2.1 Status endpoint (for write operations).

    Since this is a read-only server, this is mainly for compliance.
    """
    return {
        "id": status_id,
        "status": "complete",
        "request_timestamp": datetime.now(timezone.utc).isoformat(),
        "total_count": 0,
        "success_count": 0,
        "failure_count": 0,
    }
