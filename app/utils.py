import json
import ipaddress
from typing import Any


def to_json(data: Any) -> str:
    return json.dumps(data, indent=2)


def from_json(data: str) -> Any:
    return json.loads(data)


def is_internal_ip(ip: str) -> bool:
    """Check if IP address is internal (RFC 1918 or loopback)."""
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private or ip_obj.is_loopback
    except (ValueError, TypeError):
        return False


def is_valid_ip(ip: str) -> bool:
    """Check if string is a valid IP address."""
    try:
        ipaddress.ip_address(ip)
        return True
    except (ValueError, TypeError):
        return False