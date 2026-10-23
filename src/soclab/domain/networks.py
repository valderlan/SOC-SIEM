"""Network helpers shared by the Stage 3 response policy."""

from __future__ import annotations

from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network, ip_address, ip_network

IPAddress = IPv4Address | IPv6Address
IPNetwork = IPv4Network | IPv6Network

# Loopback, link-local and RFC1918 ranges: blocking them would cut the lab itself
# off (localhost, Wazuh manager, administrative VLANs). Override with
# SOCLAB_PROTECTED_NETWORKS when the lab layout differs.
DEFAULT_PROTECTED_NETWORKS = (
    "127.0.0.0/8,::1/128,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,"
    "169.254.0.0/16,fc00::/7,fe80::/10"
)


def parse_network_list(value: str) -> tuple[IPNetwork, ...]:
    """Parse a comma-separated CIDR list; raise ValueError on bad input."""
    networks: list[IPNetwork] = []
    for item in value.split(","):
        token = item.strip()
        if not token:
            continue
        try:
            networks.append(ip_network(token, strict=False))
        except ValueError as exc:
            raise ValueError(f"Invalid protected network: {token}") from exc
    return tuple(networks)


def is_protected(value: str | IPAddress, networks: tuple[IPNetwork, ...]) -> bool:
    """Return True when the address must never be blocked.

    Unparseable values fail closed (treated as protected).
    """
    try:
        address = ip_address(str(value))
    except ValueError:
        return True
    return any(
        address.version == network.version and address in network for network in networks
    )
