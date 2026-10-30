"""Read-only nftables inspection boundary.

Runs only: nft -j list table inet pps_guard
No shell, no privilege escalation, no firewall mutations. Command failures are
UNKNOWN rather than ABSENT: failure must never authorize destructive cleanup.
"""
from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from enum import Enum
from typing import Callable, Sequence

from pps_privacy_firewall import FirewallPolicy
from pps_privacy_ownership import OwnershipVerificationError, verify_owned_table


class InspectionStatus(str, Enum):
    OWNED = "owned"
    FOREIGN_OR_MODIFIED = "foreign-or-modified"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class InspectionResult:
    status: InspectionStatus
    message: str


Runner = Callable[..., subprocess.CompletedProcess]


def inspect_pps_table(
    policy: FirewallPolicy,
    *,
    nft_path: str | None = None,
    timeout: float = 3.0,
    runner: Runner = subprocess.run,
) -> InspectionResult:
    """Inspect exact PPS table without modifying it.

    A missing executable, timeout, non-zero exit, oversized output, decoding
    error, or unrecognized nft JSON is UNKNOWN. A successfully retrieved but
    non-matching table is FOREIGN_OR_MODIFIED. Only an exact match is OWNED.
    """
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not 0.1 <= timeout <= 15:
        raise ValueError("Timeout inspeksi harus berada pada rentang 0.1–15 detik.")
    executable = nft_path or shutil.which("nft")
    if not executable:
        return InspectionResult(InspectionStatus.UNKNOWN, "Executable nft tidak ditemukan.")
    if not isinstance(executable, str) or not executable.startswith("/"):
        return InspectionResult(InspectionStatus.UNKNOWN, "Path executable nft harus absolut.")
    argv: Sequence[str] = (executable, "-j", "list", "table", "inet", "pps_guard")
    try:
        completed = runner(
            list(argv),
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
        return InspectionResult(InspectionStatus.UNKNOWN, f"Inspeksi nft gagal: {type(exc).__name__}.")
    stdout = completed.stdout
    if not isinstance(stdout, str) or len(stdout.encode("utf-8")) > 256 * 1024:
        return InspectionResult(InspectionStatus.UNKNOWN, "Output nft tidak valid atau melebihi batas 256 KiB.")
    if completed.returncode != 0:
        # Do not infer table absence from localized or version-specific stderr.
        return InspectionResult(InspectionStatus.UNKNOWN, "Perintah nft gagal; status tabel tidak dapat dipastikan.")
    try:
        verify_owned_table(stdout, policy)
    except OwnershipVerificationError as exc:
        return InspectionResult(InspectionStatus.FOREIGN_OR_MODIFIED, str(exc))
    except (TypeError, ValueError) as exc:
        return InspectionResult(InspectionStatus.UNKNOWN, f"Policy/output tidak dapat diverifikasi: {type(exc).__name__}.")
    return InspectionResult(InspectionStatus.OWNED, "Struktur tabel sesuai persis dengan policy PPS.")
