"""
Health check endpoints.
"""

import logging
from datetime import date, datetime, timedelta
from typing import Dict, Any
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, text, func
from src.db.database import get_db
from src.db.models import APIUsageTracking, ReportedIPs, AbuseIPDBCache
from src.schemas.ioc import APIHealth
from src.core.config import settings

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1", tags=["Health"])


@router.get("/health", response_model=APIHealth)
async def health_check(db: AsyncSession = Depends(get_db)) -> APIHealth:
    """
    Check API health and service status.

    Returns:
        Health status including database connectivity and API usage
    """
    health_status = {
        "status": "healthy",
        "database": False,
        "abuseipdb": True,  # Assume healthy unless we check
        "timestamp": datetime.utcnow(),
        "daily_requests_used": 0,
        "daily_requests_limit": settings.ABUSEIPDB_RATE_LIMIT,
    }

    # Check database connectivity
    try:
        await db.execute(text("SELECT 1"))
        health_status["database"] = True

        # Get today's API usage
        today = date.today()
        result = await db.execute(select(APIUsageTracking).where(APIUsageTracking.date == today))
        usage = result.scalar_one_or_none()

        if usage:
            health_status["daily_requests_used"] = usage.requests_count

    except Exception as e:
        logger.error(f"Database health check failed: {str(e)}")
        health_status["status"] = "degraded"

    # Set overall status
    if not health_status["database"]:
        health_status["status"] = "unhealthy"
    elif health_status["daily_requests_used"] >= health_status["daily_requests_limit"]:
        health_status["status"] = "degraded"
        health_status["abuseipdb"] = False

    return health_status


@router.get("/stats")
async def get_stats(db: AsyncSession = Depends(get_db)) -> Dict[str, Any]:
    """
    Get system statistics.

    Returns:
        Statistics about IOCs and API usage
    """
    try:
        # Count total IOCs
        total_iocs_result = await db.execute(select(func.count()).select_from(ReportedIPs))
        total_iocs = total_iocs_result.scalar()

        # Count enriched IOCs
        enriched_iocs_result = await db.execute(select(func.count()).select_from(AbuseIPDBCache))
        enriched_iocs = enriched_iocs_result.scalar()

        # Get recent API usage (last 7 days)
        seven_days_ago = date.today() - timedelta(days=7)
        usage_result = await db.execute(
            select(
                func.sum(APIUsageTracking.requests_count).label("total_requests"),
                func.sum(APIUsageTracking.successful_requests).label("successful_requests"),
                func.sum(APIUsageTracking.failed_requests).label("failed_requests"),
            ).where(APIUsageTracking.date >= seven_days_ago)
        )
        usage_stats = usage_result.first()

        return {
            "iocs": {
                "total": total_iocs,
                "enriched": enriched_iocs,
                "enrichment_percentage": round(
                    (enriched_iocs / total_iocs * 100) if total_iocs > 0 else 0, 2
                ),
            },
            "api_usage": {
                "last_7_days": {
                    "total_requests": usage_stats.total_requests or 0,
                    "successful_requests": usage_stats.successful_requests or 0,
                    "failed_requests": usage_stats.failed_requests or 0,
                },
                "daily_limit": settings.ABUSEIPDB_RATE_LIMIT,
            },
        }

    except Exception as e:
        logger.error(f"Error getting stats: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error")
