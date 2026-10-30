"""Strict, side-effect-free validation for PPS full-tunnel WireGuard profiles.

This module intentionally does not bring interfaces up or alter routes/firewalls.
"""
from __future__ import annotations

import base64
import configparser
import ipaddress
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class WireGuardProfile:
    interface: str
    endpoint_ip: str
    endpoint_port: int
    ipv4_full_tunnel: bool
    ipv6_full_tunnel: bool
    ipv6_policy: str


def _key(value: str, label: str) -> None:
    try:
        decoded = base64.b64decode(value, validate=True)
    except Exception as exc:
        raise ValueError(f"{label} bukan key WireGuard base64 yang valid.") from exc
    if len(decoded) != 32:
        raise ValueError(f"{label} harus berukuran 32 byte.")


def _read_profile(path: Path) -> str:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise ValueError(f"Profil tidak dapat dibuka dengan aman: {exc}") from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise ValueError("Profil harus berupa file biasa; special file ditolak.")
        if info.st_mode & 0o077:
            raise ValueError("Izin profil terlalu terbuka; gunakan chmod 600 pada file profil.")
        if info.st_size > 64 * 1024:
            raise ValueError("Profil WireGuard melebihi batas 64 KiB.")
        chunks = []
        total = 0
        while True:
            chunk = os.read(fd, min(8192, 65537 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > 64 * 1024:
                raise ValueError("Profil WireGuard melebihi batas 64 KiB.")
        try:
            return b"".join(chunks).decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError("Profil harus berupa UTF-8 valid.") from exc
    finally:
        os.close(fd)


def parse_wireguard_profile(path: str | Path) -> WireGuardProfile:
    """Parse a deliberately narrow, safe subset of wg-quick configuration."""
    raw = _read_profile(Path(path))
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

    addresses = [x.strip() for x in interface.get("address", "").split(",") if x.strip()]
    if not addresses:
        raise ValueError("[Interface] wajib memiliki Address.")
    try:
        parsed_addresses = [ipaddress.ip_interface(address) for address in addresses]
    except ValueError as exc:
        raise ValueError("Address interface tidak valid.") from exc

    if "mtu" in interface:
        mtu = interface["mtu"]
        if not mtu.isdigit() or not 576 <= int(mtu) <= 9000:
            raise ValueError("MTU harus berupa angka antara 576 dan 9000.")

    if "allowedips" not in peer:
        raise ValueError("[Peer] wajib memiliki AllowedIPs.")
    try:
        networks = [ipaddress.ip_network(x.strip(), strict=False)
                    for x in peer["allowedips"].split(",") if x.strip()]
    except ValueError as exc:
        raise ValueError("AllowedIPs tidak valid.") from exc
    if not networks:
        raise ValueError("AllowedIPs kosong.")
    v4 = any(n.version == 4 and n.prefixlen == 0 for n in networks)
    v6 = any(n.version == 6 and n.prefixlen == 0 for n in networks)
    partial_v4 = any(n.version == 4 for n in networks) and not v4
    partial_v6 = any(n.version == 6 for n in networks) and not v6
    if not v4:
        raise ValueError("PPS memerlukan full-tunnel IPv4 (0.0.0.0/0).")
    if partial_v4 or partial_v6:
        raise ValueError("Split-tunnel/AllowedIPs parsial belum didukung.")
    if not any(a.version == 4 for a in parsed_addresses):
        raise ValueError("Full-tunnel IPv4 memerlukan Address IPv4 pada interface.")
    if v6 and not any(a.version == 6 for a in parsed_addresses):
        raise ValueError("Full-tunnel IPv6 memerlukan Address IPv6 pada interface.")

    endpoint = peer.get("endpoint", "")
    match = re.fullmatch(r"\[([0-9a-fA-F:]+)\]:(\d{1,5})|([^:\[\]]+):(\d{1,5})", endpoint)
    if not match:
        raise ValueError("Endpoint wajib berupa alamat IP numerik dan port UDP; hostname ditolak untuk mencegah bootstrap DNS.")
    host = match.group(1) or match.group(3)
    port = int(match.group(2) or match.group(4))
    try:
        endpoint_ip = ipaddress.ip_address(host)
    except ValueError as exc:
        raise ValueError("Endpoint harus berupa IPv4/IPv6 numerik tanpa zone ID.") from exc
    if endpoint_ip.is_unspecified or endpoint_ip.is_multicast or endpoint_ip.is_loopback or endpoint_ip.is_link_local:
        raise ValueError("Endpoint tidak boleh berupa alamat unspecified, multicast, loopback, atau link-local.")
    if not 1 <= port <= 65535:
        raise ValueError("Port Endpoint di luar rentang.")
    if "persistentkeepalive" in peer:
        keepalive = peer["persistentkeepalive"]
        if not keepalive.isdigit() or not 0 <= int(keepalive) <= 65535:
            raise ValueError("PersistentKeepalive tidak valid.")

    return WireGuardProfile(
        interface="wg-pps", endpoint_ip=str(endpoint_ip), endpoint_port=port,
        ipv4_full_tunnel=True, ipv6_full_tunnel=v6,
        ipv6_policy="tunnel" if v6 else "block-outside-tunnel",
    )
