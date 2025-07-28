"""
Configuration module for AbuseIPDB IOC Management System.

This module handles all configuration settings using pydantic-settings
for environment variable management and validation.
"""

import os
import tomllib
from pathlib import Path
from typing import Optional
from pydantic_settings import BaseSettings, SettingsConfigDict


def get_version() -> str:
    """Read version from pyproject.toml dynamically."""
    try:
        # Get the project root directory
        project_root = Path(__file__).parent.parent.parent
        pyproject_path = project_root / "pyproject.toml"

        if pyproject_path.exists():
            with open(pyproject_path, "rb") as f:
                data = tomllib.load(f)
                return data.get("tool", {}).get("poetry", {}).get("version", "1.0.0")
        return "1.0.0"
    except Exception:
        return "1.0.0"


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", case_sensitive=True
    )

    # Database Configuration (Existing - READ ONLY)
    POSTGRES_HOST: str = "localhost"
    POSTGRES_PORT: int = 5432
    POSTGRES_DB: str
    POSTGRES_USER: str
    POSTGRES_PASSWORD: str

    # AbuseIPDB Configuration
    ABUSEIPDB_API_KEY: str
    ABUSEIPDB_CONFIDENCE_MINIMUM: int = 75
    ABUSEIPDB_DAILY_LIMIT: int = 10  # Max AbuseIPDB API calls per day (auto-saves to Redis)

    # IOC Scoring Weights
    LOCAL_CONFIDENCE_WEIGHT: float = 0.8  # 80% weight for local detections (your attack reality)
    EXTERNAL_CONFIDENCE_WEIGHT: float = 0.2  # 20% weight for external sources (global context)
    LOCAL_CONFIDENCE_BOOST: int = 10

    # API Configuration
    API_HOST: str = "0.0.0.0"
    API_PORT: int = 8000
    API_SECRET_KEY: str
    API_RATE_LIMIT: int = 100

    # Logging Configuration
    LOG_LEVEL: str = "INFO"
    LOG_FILE: str = "logs/abuseipdb_ioc.log"

    # Redis Cache Configuration (Optional)
    REDIS_URL: Optional[str] = None
    CACHE_TTL: int = 3600  # 1 hour default

    @property
    def database_url(self) -> str:
        """Construct PostgreSQL database URL."""
        return (
            f"postgresql+asyncpg://{self.POSTGRES_USER}:{self.POSTGRES_PASSWORD}"
            f"@{self.POSTGRES_HOST}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}"
        )

    @property
    def sync_database_url(self) -> str:
        """Construct synchronous PostgreSQL database URL for Alembic."""
        return (
            f"postgresql://{self.POSTGRES_USER}:{self.POSTGRES_PASSWORD}"
            f"@{self.POSTGRES_HOST}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}"
        )


settings = Settings()
