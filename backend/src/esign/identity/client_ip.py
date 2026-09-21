"""Which address to record as the client's.

The IP in an audit event is evidence, so it may not be whatever the caller asked us to write down.
``X-Forwarded-For`` is a client-supplied header: anyone can send one. It is believed only when the
peer we are actually talking to is a configured proxy (``TRUSTED_PROXY_CIDRS``), and then only as
far back as the chain stays inside trusted addresses.

The function is pure and total: it never raises, never logs and returns ``None`` only when there is
no usable peer address at all.
"""

from __future__ import annotations

from functools import lru_cache
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network, ip_address, ip_network
from typing import Final

__all__ = ["client_ip", "parse_trusted_proxies"]

IpAddress = IPv4Address | IPv6Address
IpNetwork = IPv4Network | IPv6Network

#: Only the rightmost entries of a forwarded chain can be trustworthy, and a header is attacker
#: controlled, so a long one is truncated rather than walked.
_MAX_FORWARDED_ENTRIES: Final = 32


def parse_trusted_proxies(cidrs: tuple[str, ...]) -> tuple[IpNetwork, ...]:
    """Parse the configured proxy ranges. Raises ``ValueError`` on a malformed entry.

    Call it once at startup so a typo in configuration is loud there rather than silently
    widening -- or narrowing -- what the service believes about every request afterwards.
    """
    return tuple(ip_network(entry.strip(), strict=False) for entry in cidrs if entry.strip())


@lru_cache(maxsize=8)
def _trusted(cidrs: tuple[str, ...]) -> tuple[IpNetwork, ...]:
    try:
        return parse_trusted_proxies(cidrs)
    except ValueError:
        # Misconfiguration must not make the service believe a forwarded header.
        return ()


def _parse(value: str | None) -> IpAddress | None:
    """One address, tolerating ``host:port`` and ``[v6]:port`` forms. ``None`` if unusable."""
    if not value:
        return None
    text = value.strip()
    if not text:
        return None
    if text.startswith("["):
        closing = text.find("]")
        if closing < 0:
            return None
        text = text[1:closing]
    elif text.count(":") == 1:
        text = text.split(":", 1)[0]
    try:
        return ip_address(text)
    except ValueError:
        return None


def _is_trusted(addr: IpAddress, trusted: tuple[IpNetwork, ...]) -> bool:
    return any(addr.version == net.version and addr in net for net in trusted)


def client_ip(
    peer: str | None,
    forwarded_for: str | None = None,
    trusted_proxy_cidrs: tuple[str, ...] = (),
) -> str | None:
    """The address to record for a request.

    ``peer`` is the transport-level address of whoever connected -- the one thing the client cannot
    forge. When it is not a configured proxy, the forwarded header is ignored entirely. When it is,
    the chain is walked from the right and the first address outside the trusted ranges is the
    client; a malformed entry stops the walk and the proxy's own address is recorded, because a
    chain we cannot parse is a chain we cannot trust.
    """
    peer_addr = _parse(peer)
    if peer_addr is None:
        return None
    trusted = _trusted(tuple(trusted_proxy_cidrs))
    if not trusted or not _is_trusted(peer_addr, trusted):
        return str(peer_addr)
    if not forwarded_for:
        return str(peer_addr)
    entries = forwarded_for.split(",")[-_MAX_FORWARDED_ENTRIES:]
    for raw in reversed(entries):
        addr = _parse(raw)
        if addr is None:
            return str(peer_addr)
        if not _is_trusted(addr, trusted):
            return str(addr)
    return str(peer_addr)
