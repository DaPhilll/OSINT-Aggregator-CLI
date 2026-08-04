"""Detects the type of an indicator (IP, domain, URL, email, or hash)."""
import ipaddress
import re

EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
HASH_PATTERN = re.compile(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$")
DOMAIN_PATTERN = re.compile(
    r"^(?=.{1,253}$)(?:(?!-)[A-Za-z0-9-]{1,63}(?<!-)\.)+[A-Za-z]{2,}$"
)


def detect_type(indicator):
    """Return the detected indicator type, or None if unrecognized."""
    value = indicator.strip()

    if value.startswith(("http://", "https://")):
        return "url"

    try:
        ipaddress.ip_address(value)
        return "ip"
    except ValueError:
        pass

    if EMAIL_PATTERN.match(value):
        return "email"

    if HASH_PATTERN.match(value):
        return "hash"

    if DOMAIN_PATTERN.match(value):
        return "domain"

    return None
