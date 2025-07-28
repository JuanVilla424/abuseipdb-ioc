"""
Logging configuration for the application.

Sets up file-based logging with proper formatting and rotation.
"""

import logging
import logging.handlers
from pathlib import Path
from src.core.config import settings


def setup_logging() -> None:
    """
    Configure application-wide logging.

    Creates log directory if needed and sets up file handler
    with rotation and appropriate formatting.
    """
    # Create logs directory if it doesn't exist
    log_dir = Path(settings.LOG_FILE).parent
    log_dir.mkdir(parents=True, exist_ok=True)

    # Create root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, settings.LOG_LEVEL.upper()))

    # Remove existing handlers
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

    # File handler with rotation
    file_handler = logging.handlers.RotatingFileHandler(
        filename=settings.LOG_FILE,
        maxBytes=10 * 1024 * 1024,  # 10MB
        backupCount=5,
        encoding="utf-8",
    )

    # Console handler for development
    console_handler = logging.StreamHandler()

    # Formatter
    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
    )

    file_handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)

    # Add handlers
    root_logger.addHandler(file_handler)
    root_logger.addHandler(console_handler)

    # Set specific loggers
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)

    # Log startup
    root_logger.info("AbuseIPDB IOC Management System starting up")
    root_logger.info(f"Log level: {settings.LOG_LEVEL}")
    root_logger.info(f"Log file: {settings.LOG_FILE}")
