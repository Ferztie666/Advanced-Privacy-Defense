"""Read-only nftables inventory for positive PPS-table absence proof.

Only a complete, strictly parsed `nft -j list tables` response can prove that
inet/pps_guard is absent. If present, the existing exact-table verifier is run.
No firewall changes, shell, or privilege escalation occur here.
"""
from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass
from typing import Callable

from pps_nft_inspect import InspectionStatus, inspect_pps_table
from pps_privacy_firewall import FirewallPolicy
from pps_privacy_session import GuardStatus


@dataclass(frozen=True)
class InventoryResult:
    status: GuardStatus
    message: str


Runner = Callable[..., subprocess.CompletedProcess]
_MAX_OUTPUT = 256 * 1024


def _target_table_present(stdout: str) -> bool | None:
    """Return True/False only for a complete recognized nft table inventory."""
    if not isinstance(stdout, str):
        return None
    try:
        if len(stdout.encode("utf-8")) > _MAX_OUTPUT:
            return None
        document = json.loads(stdout)
    except (UnicodeError, TypeError, json.JSONDecodeError):
        return None
    if not isinstance(document, dict) or set(document) != {"nftables"}:
        return None
    entries = document["nftables"]
    if not isinstance(entries, list):
        return None

    target_count = 0
    for item in entries:
        if not isinstance(item, dict) or len(item) != 1:
            return None
        kind, value = next(iter(item.items()))
        if kind == "metainfo":
            if not isinstance(value, dict):
                return None
            # Known nft JSON metainfo fields only; tolerate versions that omit them.
            if set(value) - {"version", "release_name", "json_schema_version"}:
                return None
            continue
        if kind != "table" or not isinstance(value, dict):
            return None
        if set(value) - {"family", "name", "handle"}:
            return None
        if not isinstance(value.get("family"), str) or not value["family"]:
            return None
        if not isinstance(value.get("name"), str) or not value["name"]:
            return None
        if "handle" in value and (
            isinstance(value["handle"], bool) or not isinstance(value["handle"], int)
        ):
            return None
        if value["family"] == "inet" and value["name"] == "pps_guard":
            target_count += 1
    if target_count > 1:
        return None
    return target_count == 1


def inspect_guard_inventory(
    policy: FirewallPolicy,
    *,
    nft_path: str | None = None,
    timeout: float = 3.0,
    runner: Runner = subprocess.run,
) -> InventoryResult:
    """Determine guard state without ever treating command failure as absence."""
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not 0.1 <= timeout <= 15:
        raise ValueError("Timeout inspeksi harus berada pada rentang 0.1–15 detik.")
    executable = nft_path or shutil.which("nft")
    if not executable:
        return InventoryResult(GuardStatus.UNKNOWN, "Executable nft tidak ditemukan.")
    if not isinstance(executable, str) or not executable.startswith("/"):
        return InventoryResult(GuardStatus.UNKNOWN, "Path executable nft harus absolut.")
    try:
        completed = runner(
            [executable, "-j", "list", "tables"],
            shell=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="strict",
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.SubprocessError, UnicodeError) as exc:
        return InventoryResult(GuardStatus.UNKNOWN, f"Inventaris nft gagal: {type(exc).__name__}.")
    if completed.returncode != 0:
        return InventoryResult(GuardStatus.UNKNOWN, "Inventaris nft gagal; ABSENT tidak dapat disimpulkan.")
    present = _target_table_present(completed.stdout)
    if present is None:
        return InventoryResult(GuardStatus.UNKNOWN, "Inventaris nft malformed, tidak lengkap, atau tidak dikenal.")
    if not present:
        return InventoryResult(GuardStatus.ABSENT, "Inventaris lengkap; tabel inet/pps_guard tidak ditemukan.")

    exact = inspect_pps_table(
        policy, nft_path=executable, timeout=timeout, runner=runner,
    )
    if exact.status == InspectionStatus.OWNED:
        return InventoryResult(GuardStatus.OWNED, exact.message)
    if exact.status == InspectionStatus.FOREIGN_OR_MODIFIED:
        return InventoryResult(GuardStatus.FOREIGN_OR_MODIFIED, exact.message)
    return InventoryResult(GuardStatus.UNKNOWN, exact.message)
