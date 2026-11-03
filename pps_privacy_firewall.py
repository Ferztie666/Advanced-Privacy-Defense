"""Pure nftables policy compiler for PPS privacy mode.

This module only renders a narrowly scoped ruleset. It never invokes nft,
changes routes, or touches the host. Applying the ruleset is deliberately
left to the future session manager after integration testing.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass


TABLE_FAMILY = "inet"
TABLE_NAME = "pps_guard"
DEFAULT_WG_INTERFACE = "wg-pps"


@dataclass(frozen=True)
class FirewallPolicy:
    endpoint_ip: str
    endpoint_port: int
    wg_interface: str = DEFAULT_WG_INTERFACE
    allow_dhcpv4: bool = True


def _interface_name(value: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", value):
        raise ValueError("Nama interface tidak valid.")
    return value


def validate_policy(policy: FirewallPolicy) -> FirewallPolicy:
    try:
        endpoint = ipaddress.ip_address(policy.endpoint_ip)
    except ValueError as exc:
        raise ValueError("Endpoint harus berupa alamat IP numerik.") from exc
    if endpoint.is_unspecified or endpoint.is_multicast or endpoint.is_loopback or endpoint.is_link_local:
        raise ValueError("Kelas alamat endpoint tidak diizinkan.")
    if isinstance(policy.endpoint_port, bool) or not isinstance(policy.endpoint_port, int) or not 1 <= policy.endpoint_port <= 65535:
        raise ValueError("Port endpoint tidak valid.")
    _interface_name(policy.wg_interface)
    if not isinstance(policy.allow_dhcpv4, bool):
        raise ValueError("allow_dhcpv4 harus boolean.")
    return policy


def render_nftables(policy: FirewallPolicy) -> str:
    """Render a fail-closed OUTPUT guard; does not apply it.

    No generic established/related exception is used: that could preserve
    pre-existing direct connections across activation. Replies to traffic
    sent through WireGuard are accepted by conntrack on the return path and
    do not require a broad OUTPUT exception.
    """
    validate_policy(policy)
    endpoint = ipaddress.ip_address(policy.endpoint_ip)
    family = "ip6" if endpoint.version == 6 else "ip"
    lines = [
        f"add table {TABLE_FAMILY} {TABLE_NAME}",
        f"add chain {TABLE_FAMILY} {TABLE_NAME} output {{ type filter hook output priority -150; policy drop; }}",
        f'add rule {TABLE_FAMILY} {TABLE_NAME} output oifname "lo" accept',
        f'add rule {TABLE_FAMILY} {TABLE_NAME} output oifname "{policy.wg_interface}" accept',
    ]
    if policy.allow_dhcpv4:
        lines.append(f"add rule {TABLE_FAMILY} {TABLE_NAME} output meta nfproto ipv4 udp sport 68 udp dport 67 accept")
    lines.append(
        f"add rule {TABLE_FAMILY} {TABLE_NAME} output {family} daddr {endpoint} udp dport {policy.endpoint_port} accept"
    )
    return "\n".join(lines) + "\n"


def render_owned_table_delete() -> str:
    """Render deletion of only PPS's exact table; caller must verify ownership."""
    return f"delete table {TABLE_FAMILY} {TABLE_NAME}\n"
