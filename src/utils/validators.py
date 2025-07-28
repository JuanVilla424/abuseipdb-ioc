"""
Validation utilities for IP addresses and other inputs.
"""

import ipaddress
import re
from typing import List


def is_valid_ip(ip_str: str) -> bool:
    """
    Validate if string is a valid IP address.

    Args:
        ip_str: String to validate

    Returns:
        bool: True if valid IP address
    """
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False


def is_private_ip(ip_str: str) -> bool:
    """
    Check if IP address is in private range.

    Args:
        ip_str: IP address string

    Returns:
        bool: True if private IP
    """
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private
    except ValueError:
        return False


def is_public_ip(ip_str: str) -> bool:
    """
    Check if IP address is public (not private, loopback, etc.).

    Args:
        ip_str: IP address string

    Returns:
        bool: True if public IP
    """
    try:
        ip = ipaddress.ip_address(ip_str)
        return not (ip.is_private or ip.is_loopback or ip.is_multicast or ip.is_reserved)
    except ValueError:
        return False


def validate_confidence_score(score: int) -> bool:
    """
    Validate confidence score is within valid range.

    Args:
        score: Confidence score

    Returns:
        bool: True if valid score (0-100)
    """
    return 0 <= score <= 100


def sanitize_ip_list(ip_list: List[str]) -> List[str]:
    """
    Sanitize and validate list of IP addresses.

    Args:
        ip_list: List of IP address strings

    Returns:
        List of valid IP addresses
    """
    valid_ips = []
    for ip in ip_list:
        if is_valid_ip(ip.strip()):
            valid_ips.append(ip.strip())
    return valid_ips


def extract_ips_from_text(text: str) -> List[str]:
    """
    Extract IP addresses from text using regex.

    Args:
        text: Text containing IP addresses

    Returns:
        List of found IP addresses
    """
    # Regex pattern for IPv4 addresses
    ipv4_pattern = r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"

    found_ips = re.findall(ipv4_pattern, text)
    return [ip for ip in found_ips if is_valid_ip(ip)]
