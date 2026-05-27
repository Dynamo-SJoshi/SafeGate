from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse


ALLOWED_SCHEMES = {"http", "https"}
BLOCKED_HOSTNAMES = {
    "localhost",
    "localhost.localdomain",
}


def validate_and_normalize_url(raw_url: str) -> str:
    if not raw_url:
        raise ValueError("URL is required.")

    if len(raw_url) > 2048:
        raise ValueError("URL is too long.")

    parsed = urlparse(raw_url.strip())
    if parsed.scheme.lower() not in ALLOWED_SCHEMES:
        raise ValueError("Only http and https URLs are allowed.")

    if not parsed.hostname:
        raise ValueError("URL must include a hostname.")

    if parsed.username or parsed.password:
        raise ValueError("Userinfo in URLs is not allowed.")

    hostname = parsed.hostname.lower()
    if hostname in BLOCKED_HOSTNAMES or hostname.endswith(".local"):
        raise ValueError("Local hostnames are not allowed.")

    _assert_hostname_resolves_to_public_addresses(hostname)

    return raw_url.strip()


def _assert_hostname_resolves_to_public_addresses(hostname: str) -> None:
    try:
        address_info = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ValueError("Hostname could not be resolved.") from exc

    resolved_addresses = set()
    for entry in address_info:
        sockaddr = entry[4]
        if not sockaddr:
            continue
        ip_text = sockaddr[0]
        try:
            ip_obj = ipaddress.ip_address(ip_text)
        except ValueError as exc:
            raise ValueError("Resolved address is invalid.") from exc

        if _is_blocked_ip(ip_obj):
            raise ValueError(f"Hostname resolves to blocked address: {ip_obj}")

        resolved_addresses.add(str(ip_obj))

    if not resolved_addresses:
        raise ValueError("Hostname did not resolve to any usable IP address.")


def _is_blocked_ip(ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return any(
        [
            ip_obj.is_private,
            ip_obj.is_loopback,
            ip_obj.is_link_local,
            ip_obj.is_multicast,
            ip_obj.is_reserved,
            ip_obj.is_unspecified,
        ]
    )
