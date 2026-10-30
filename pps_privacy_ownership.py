"""Strict, side-effect-free verifier for a PPS-owned nftables table.

Input is the JSON document produced by: nft -j list table inet pps_guard
This module never invokes nft or changes firewall state. Unknown JSON shapes
fail closed; nftables-version compatibility must be verified in integration tests.
"""
from __future__ import annotations

import json
from typing import Any

from pps_privacy_firewall import (
    FirewallPolicy,
    TABLE_FAMILY,
    TABLE_NAME,
    validate_policy,
)


class OwnershipVerificationError(ValueError):
    """Raised when nftables output is malformed or cannot prove exact ownership."""


def _match(left: dict[str, Any], right: Any) -> dict[str, Any]:
    return {"match": {"op": "==", "left": left, "right": right}}


def _accept() -> dict[str, Any]:
    return {"accept": None}


def _payload(protocol: str, field: str) -> dict[str, Any]:
    return {"payload": {"protocol": protocol, "field": field}}


def _expected_rules(policy: FirewallPolicy) -> list[list[dict[str, Any]]]:
    validate_policy(policy)
    rules = [
        [_match({"meta": {"key": "oifname"}}, "lo"), _accept()],
        [_match({"meta": {"key": "oifname"}}, policy.wg_interface), _accept()],
    ]
    if policy.allow_dhcpv4:
        rules.append([
            _match({"meta": {"key": "nfproto"}}, "ipv4"),
            _match(_payload("udp", "sport"), 68),
            _match(_payload("udp", "dport"), 67),
            _accept(),
        ])
    endpoint = "ip6" if ":" in policy.endpoint_ip else "ip"
    rules.append([
        _match(_payload(endpoint, "daddr"), policy.endpoint_ip),
        _match(_payload("udp", "dport"), policy.endpoint_port),
        _accept(),
    ])
    return rules


def _strip_handles(value: Any) -> Any:
    if isinstance(value, list):
        return [_strip_handles(item) for item in value]
    if isinstance(value, dict):
        return {
            key: _strip_handles(item)
            for key, item in value.items()
            if key != "handle"
        }
    return value


def verify_owned_table(document: str | dict[str, Any], policy: FirewallPolicy) -> bool:
    """Return True only for the exact table/chain/rules generated for policy.

    Extra chains, rules, tables, sets, maps, counters, comments, or unknown
    objects are rejected. Kernel-assigned handles are ignored. A parser failure
    is not evidence of ownership and raises OwnershipVerificationError.
    """
    validate_policy(policy)
    try:
        parsed = json.loads(document) if isinstance(document, str) else document
    except (TypeError, json.JSONDecodeError) as exc:
        raise OwnershipVerificationError("Output nft JSON tidak valid.") from exc
    if not isinstance(parsed, dict) or not isinstance(parsed.get("nftables"), list):
        raise OwnershipVerificationError("Struktur nft JSON tidak dikenal.")

    tables: list[dict[str, Any]] = []
    chains: list[dict[str, Any]] = []
    rules: list[dict[str, Any]] = []
    for item in parsed["nftables"]:
        if not isinstance(item, dict) or len(item) != 1:
            raise OwnershipVerificationError("Objek nft JSON tidak dikenal.")
        kind, value = next(iter(item.items()))
        if kind == "metainfo":
            continue
        if kind not in {"table", "chain", "rule"} or not isinstance(value, dict):
            raise OwnershipVerificationError("Objek tambahan tidak diizinkan.")
        if value.get("family") != TABLE_FAMILY or value.get("table") not in (None, TABLE_NAME):
            raise OwnershipVerificationError("Ditemukan objek di luar tabel PPS.")
        if kind == "table":
            tables.append(value)
        elif kind == "chain":
            chains.append(value)
        else:
            rules.append(value)

    if len(tables) != 1 or len(chains) != 1:
        raise OwnershipVerificationError("Tabel/chain hilang atau duplikat.")
    table = _strip_handles(tables[0])
    chain = _strip_handles(chains[0])
    expected_table = {"family": TABLE_FAMILY, "name": TABLE_NAME}
    expected_chain = {
        "family": TABLE_FAMILY,
        "table": TABLE_NAME,
        "name": "output",
        "type": "filter",
        "hook": "output",
        "prio": -150,
        "policy": "drop",
    }
    if table != expected_table or chain != expected_chain:
        raise OwnershipVerificationError("Identitas atau konfigurasi tabel/chain tidak cocok.")

    actual_rules: list[Any] = []
    for rule in rules:
        if rule.get("chain") != "output":
            raise OwnershipVerificationError("Rule berada di chain yang tidak dikenal.")
        actual_rules.append(_strip_handles(rule))
    expected = [
        {"family": TABLE_FAMILY, "table": TABLE_NAME, "chain": "output", "expr": expr}
        for expr in _expected_rules(policy)
    ]
    if actual_rules != expected:
        raise OwnershipVerificationError("Ruleset berbeda dari policy PPS yang diharapkan.")
    return True
