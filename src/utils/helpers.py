"""
Helper utilities for common operations.
"""

import hashlib
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List


def generate_uuid() -> str:
    """
    Generate a UUID4 string.

    Returns:
        UUID string
    """
    return str(uuid.uuid4())


def generate_stix_id(object_type: str) -> str:
    """
    Generate STIX-compliant ID.

    Args:
        object_type: STIX object type (e.g., 'indicator', 'bundle')

    Returns:
        STIX ID string
    """
    return f"{object_type}--{generate_uuid()}"


def utc_now() -> datetime:
    """
    Get current UTC datetime with timezone info.

    Returns:
        UTC datetime
    """
    return datetime.now(timezone.utc)


def hash_string(text: str, algorithm: str = "sha256") -> str:
    """
    Hash a string using specified algorithm.

    Args:
        text: Text to hash
        algorithm: Hash algorithm (md5, sha1, sha256)

    Returns:
        Hexadecimal hash string
    """
    if algorithm == "md5":
        return hashlib.md5(text.encode()).hexdigest()
    if algorithm == "sha1":
        return hashlib.sha1(text.encode()).hexdigest()
    if algorithm == "sha256":
        return hashlib.sha256(text.encode()).hexdigest()
    raise ValueError(f"Unsupported hash algorithm: {algorithm}")


def chunk_list(items: List[Any], chunk_size: int) -> List[List[Any]]:
    """
    Split list into chunks of specified size.

    Args:
        items: List to chunk
        chunk_size: Size of each chunk

    Returns:
        List of chunks
    """
    chunks = []
    for i in range(0, len(items), chunk_size):
        chunks.append(items[i : i + chunk_size])
    return chunks


def safe_get(dictionary: Dict[str, Any], key: str, default: Any = None) -> Any:
    """
    Safely get value from dictionary with default.

    Args:
        dictionary: Dictionary to search
        key: Key to find
        default: Default value if key not found

    Returns:
        Value or default
    """
    return dictionary.get(key, default)


def format_bytes(bytes_value: int) -> str:
    """
    Format bytes into human readable string.

    Args:
        bytes_value: Number of bytes

    Returns:
        Formatted string (e.g., "1.2 MB")
    """
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if bytes_value < 1024.0:
            return f"{bytes_value:.1f} {unit}"
        bytes_value /= 1024.0
    return f"{bytes_value:.1f} PB"


def clean_dict(
    data: Dict[str, Any], remove_none: bool = True, remove_empty: bool = False
) -> Dict[str, Any]:
    """
    Clean dictionary by removing None/empty values.

    Args:
        data: Dictionary to clean
        remove_none: Remove None values
        remove_empty: Remove empty strings/lists/dicts

    Returns:
        Cleaned dictionary
    """
    cleaned = {}

    for key, value in data.items():
        if remove_none and value is None:
            continue

        if remove_empty:
            if value in ("", [], {}):
                continue

        cleaned[key] = value

    return cleaned


def truncate_string(text: str, max_length: int, suffix: str = "...") -> str:
    """
    Truncate string to maximum length with suffix.

    Args:
        text: String to truncate
        max_length: Maximum length
        suffix: Suffix to add if truncated

    Returns:
        Truncated string
    """
    if len(text) <= max_length:
        return text

    return text[: max_length - len(suffix)] + suffix
