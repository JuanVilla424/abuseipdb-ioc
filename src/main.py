"""
Main FastAPI application.
"""

import asyncio
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from src.core.config import settings, get_version
from src.core.logging import setup_logging
from src.api.endpoints import iocs, health, taxii
from src.db.database import engine, ensure_database_schema
from src.workers.ioc_processor import ioc_processor

# Setup logging
setup_logging()

# Global task for IOC processor
ioc_processor_task = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler."""
    global ioc_processor_task

    # Startup
    await ensure_database_schema()

    # Start IOC processor in background
    ioc_processor_task = asyncio.create_task(ioc_processor.start())

    yield

    # Shutdown
    # Stop IOC processor
    if ioc_processor_task:
        await ioc_processor.stop()
        ioc_processor_task.cancel()
        try:
            await ioc_processor_task
        except asyncio.CancelledError:
            pass

    await engine.dispose()


# Create FastAPI app
app = FastAPI(
    title="AbuseIPDB IOC Management System",
    version=get_version(),
    description="IOC Management System with AbuseIPDB Integration",
    lifespan=lifespan,
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(health.router)
app.include_router(iocs.router)
app.include_router(taxii.taxii_router)


# No redirect needed anymore


@app.get("/")
async def root():
    """Root endpoint."""
    return {
        "name": "AbuseIPDB IOC Management System",
        "version": get_version(),
        "docs": "/docs",
        "health": "/api/v1/health",
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("src.main:app", host=settings.API_HOST, port=settings.API_PORT, reload=True)
