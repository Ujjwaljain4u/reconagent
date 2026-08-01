from __future__ import annotations

import ipaddress
import socket


class SsrfBlockedError(Exception):
    """Raised when a target resolves to a private/internal/reserved IP —
    refusing to make the request rather than letting the server fetch
    something on the internal network or cloud metadata endpoint on the
    user's behalf."""


def assert_public_host(hostname: str) -> None:
    """Resolves hostname and raises SsrfBlockedError if it points at a
    private, loopback, link-local, or otherwise non-public IP range.

    This matters specifically because several collectors make an outbound
    HTTP request directly to a user-supplied domain (web_metadata.py being
    the clearest example). Without this check, someone could enter
    '169.254.169.254' (cloud metadata endpoint, a well-known SSRF target)
    or an internal hostname as the "domain" target, and the server would
    dutifully fetch it on their behalf — a real SSRF vulnerability, not a
    theoretical one, especially relevant once this is deployed publicly.
    """
    try:
        ip_str = socket.gethostbyname(hostname)
    except Exception as e:  # noqa: BLE001
        raise SsrfBlockedError(f"could not resolve {hostname}: {e}") from e

    ip = ipaddress.ip_address(ip_str)
    if (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    ):
        raise SsrfBlockedError(
            f"{hostname} resolves to {ip_str}, a private/internal/reserved address — refusing to fetch it"
        )