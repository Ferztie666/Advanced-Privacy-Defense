"""Testable PPS privacy-session transaction core.

No system commands are executed here. A future Linux backend must implement the
backend contract and receive separate integration/security review before use.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Protocol


class SessionState(str, Enum):
    OFF = "off"
    ACTIVE = "active"
    GUARDED_RECOVERY = "guarded-recovery"


@dataclass(frozen=True)
class SessionResult:
    state: SessionState
    ok: bool
    message: str


class PrivacyBackend(Protocol):
    def guard_exists(self) -> bool: ...
    def guard_is_owned_and_expected(self) -> bool: ...
    def install_guard(self) -> None: ...
    def interface_is_up(self) -> bool: ...
    def bring_interface_up(self) -> None: ...
    def verify_handshake(self) -> bool: ...
    def verify_full_tunnel_routes(self) -> bool: ...
    def verify_egress(self) -> bool: ...
    def bring_interface_down(self) -> None: ...
    def remove_owned_guard(self) -> None: ...


class PrivacySession:
    """Orchestrates strict order; all effects are delegated to an injected backend.

    Ownership means more than the table name: a backend must compare the complete
    PPS-owned nftables table against the exact expected structure before allowing
    removal. This core intentionally cannot perform that inspection itself.
    """

    def __init__(self, backend: PrivacyBackend):
        self.backend = backend

    def _remove_guard_if_proven_safe(self) -> bool:
        b = self.backend
        if not b.guard_exists():
            return True
        if b.interface_is_up() or not b.guard_is_owned_and_expected():
            return False
        b.remove_owned_guard()
        return not b.guard_exists()

    def enable(self) -> SessionResult:
        b = self.backend
        try:
            if b.guard_exists():
                return SessionResult(
                    SessionState.GUARDED_RECOVERY, False,
                    "Tabel guard sudah ada; menolak menimpa state yang tidak dikenal.",
                )
            if b.interface_is_up():
                return SessionResult(
                    SessionState.GUARDED_RECOVERY, False,
                    "Interface WireGuard sudah aktif di luar sesi PPS; tidak mengubahnya.",
                )
            b.install_guard()
            if not b.guard_exists() or not b.guard_is_owned_and_expected():
                return SessionResult(
                    SessionState.GUARDED_RECOVERY, False,
                    "Guard tidak ada atau struktur/kepemilikannya tidak cocok; tidak menjalankan tunnel.",
                )
            b.bring_interface_up()
            if not b.interface_is_up():
                raise RuntimeError("Interface WireGuard tidak aktif.")
            if not b.verify_handshake():
                raise RuntimeError("Handshake WireGuard belum terverifikasi.")
            if not b.verify_full_tunnel_routes():
                raise RuntimeError("Route full-tunnel tidak terverifikasi.")
            if not b.verify_egress():
                raise RuntimeError("Egress melalui VPN tidak terverifikasi.")
            return SessionResult(SessionState.ACTIVE, True, "Sesi privacy aktif dan seluruh pemeriksaan lulus.")
        except Exception as exc:
            # A partially installed guard may exist even if install_guard raises.
            # Remove it only after proving tunnel-down and exact PPS ownership.
            try:
                if b.interface_is_up():
                    b.bring_interface_down()
                if b.interface_is_up():
                    return SessionResult(
                        SessionState.GUARDED_RECOVERY, False,
                        f"Aktivasi gagal ({exc}); interface belum terbukti down, guard dipertahankan.",
                    )
                if not self._remove_guard_if_proven_safe():
                    return SessionResult(
                        SessionState.GUARDED_RECOVERY, False,
                        f"Aktivasi gagal ({exc}); guard tidak dapat dibuktikan milik PPS/aman dihapus.",
                    )
                return SessionResult(
                    SessionState.OFF, False,
                    f"Aktivasi gagal dan rollback terverifikasi: {exc}",
                )
            except Exception as rollback_exc:
                return SessionResult(
                    SessionState.GUARDED_RECOVERY, False,
                    f"Aktivasi gagal ({exc}); rollback gagal ({rollback_exc}); guard dipertahankan.",
                )

    def disable(self) -> SessionResult:
        b = self.backend
        try:
            if not b.guard_exists():
                if b.interface_is_up():
                    return SessionResult(
                        SessionState.GUARDED_RECOVERY, False,
                        "Interface aktif tanpa guard PPS; tidak melakukan perubahan otomatis.",
                    )
                return SessionResult(SessionState.OFF, True, "Sesi sudah nonaktif.")
            if not b.guard_is_owned_and_expected():
                return SessionResult(
                    SessionState.GUARDED_RECOVERY, False,
                    "Guard ditemukan tetapi struktur/kepemilikannya tidak cocok; tidak mengubahnya.",
                )
            if b.interface_is_up():
                b.bring_interface_down()
            if b.interface_is_up():
                return SessionResult(
                    SessionState.GUARDED_RECOVERY, False,
                    "WireGuard belum terbukti down; guard tetap dipertahankan.",
                )
            b.remove_owned_guard()
            if b.guard_exists():
                return SessionResult(
                    SessionState.GUARDED_RECOVERY, False,
                    "Guard masih terdeteksi setelah penghapusan; perlu pemulihan manual.",
                )
            return SessionResult(SessionState.OFF, True, "WireGuard down; guard PPS yang tervalidasi dihapus.")
        except Exception as exc:
            return SessionResult(
                SessionState.GUARDED_RECOVERY, False,
                f"Proses OFF gagal ({exc}); guard tidak boleh dibuka otomatis.",
            )
