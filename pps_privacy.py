"""Strict, side-effect-free validation for PPS full-tunnel WireGuard profiles.

This module intentionally does not bring interfaces up or alter routes/firewalls.
"""
from __future__ import annotations

import base64
import configparser
import ipaddress
import re
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class WireGuardProfile:
    interface: str
    endpoint_ip: str
    endpoint_port: int
    ipv4_full_tunnel: bool
    ipv6_full_tunnel: bool


def _key(value: str, label: str) -> None:
    try:
        decoded = base64.b64decode(value, validate=True)
    except Exception as exc:
        raise ValueError(f"{label} bukan key WireGuard base64 yang valid.") from exc
    if len(decoded) != 32:
        raise ValueError(f"{label} harus berukuran 32 byte.")


def parse_wireguard_profile(path: str | Path) -> WireGuardProfile:
    """Parse a deliberately narrow, safe subset of wg-quick configuration."""
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise ValueError("Profil harus file biasa; symlink/special file ditolak.")
    if path.stat().st_size > 64 * 1024:
        raise ValueError("Profil WireGuard melebihi batas 64 KiB.")
    raw = path.read_text(encoding="utf-8")
    if "\x00" in raw:
        raise ValueError("Profil mengandung byte NUL.")
    parser = configparser.ConfigParser(
        strict=True, interpolation=None, delimiters=("=",), comment_prefixes=("#", ";"),
        inline_comment_prefixes=("#", ";"), empty_lines_in_values=False,
    )
    parser.optionxform = str.lower
    try:
        parser.read_string(raw)
    except configparser.Error as exc:
        raise ValueError(f"Format profil WireGuard tidak valid: {exc}") from exc

    if set(parser.sections()) != {"Interface", "Peer"}:
        raise ValueError("PPS hanya menerima tepat satu [Interface] dan satu [Peer].")
    interface = dict(parser.items("Interface"))
    peer = dict(parser.items("Peer"))
    allowed_interface = {"privatekey", "address", "mtu"}
    allowed_peer = {"publickey", "presharedkey", "allowedips", "endpoint", "persistentkeepalive"}
    unexpected = (set(interface) - allowed_interface) | (set(peer) - allowed_peer)
    if unexpected:
        raise ValueError("Direktif profil tidak didukung/ditolak: " + ", ".join(sorted(unexpected)))
    if "privatekey" not in interface:
        raise ValueError("[Interface] wajib memiliki PrivateKey.")
    _key(interface["privatekey"], "PrivateKey")
    if "publickey" not in peer:
        raise ValueError("[Peer] wajib memiliki PublicKey.")
    _key(peer["publickey"], "PublicKey")
    if "presharedkey" in peer:
        _key(peer["presharedkey"], "PresharedKey")
    if "address" not in interface:
        raise ValueError("[Interface] wajib memiliki Address.")
    addresses = [x.strip() for x in interface["address"].split(",") if x.strip()]
    if not addresses:
        raise ValueError("Address kosong.")
    try:
        for address in addresses:
            ipaddress.ip_interface(address)
    except ValueError as exc:
        raise ValueError("Address interface tidak valid.") from exc
    if "mtu" in interface and not interface["mtu"].isdigit():
        raise ValueError("MTU harus berupa angka.")
    if "allowedips" not in peer:
        raise ValueError("[Peer] wajib memiliki AllowedIPs.")
    try:
        networks = [ipaddress.ip_network(x.strip(), strict=False)
                    for x in peer["allowedips"].split(",") if x.strip()]
    except ValueError as exc:
        raise ValueError("AllowedIPs tidak valid.") from exc
    v4 = any(n.version == 4 and n.prefixlen == 0 for n in networks)
    v6 = any(n.version == 6 and n.prefixlen == 0 for n in networks)
    if not (v4 and v6):
        raise ValueError("PPS memerlukan full-tunnel dual-stack: AllowedIPs harus mencakup 0.0.0.0/0 dan ::/0.")
    endpoint = peer.get("endpoint", "")
    match = re.fullmatch(r"\[([0-9a-fA-F:]+)\]:(\d{1,5})|([^:\[\]]+):(\d{1,5})", endpoint)
    if not match:
        raise ValueError("Endpoint wajib berupa alamat IP numerik dan port UDP; hostname ditolak untuk mencegah bootstrap DNS.")
    host = match.group(1) or match.group(3)
    port = int(match.group(2) or match.group(4))
    try:
        endpoint_ip = ipaddress.ip_address(host)
    except ValueError as exc:
        raise ValueError("Endpoint harus berupa IPv4/IPv6 numerik.") from exc
    if not 1 <= port <= 65535:
        raise ValueError("Port Endpoint di luar rentang.")
    if "persistentkeepalive" in peer:
        keepalive = peer["persistentkeepalive"]
        if not keepalive.isdigit() or not 0 <= int(keepalive) <= 65535:
            raise ValueError("PersistentKeepalive tidak valid.")
    return WireGuardProfile(
        interface="wg-pps", endpoint_ip=str(endpoint_ip), endpoint_port=port,
        ipv4_full_tunnel=v4, ipv6_full_tunnel=v6,
    )
