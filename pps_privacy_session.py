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


class GuardStatus(str, Enum):
    ABSENT = "absent"
    OWNED = "owned"
    FOREIGN_OR_MODIFIED = "foreign-or-modified"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class SessionResult:
    state: SessionState
    ok: bool
    message: str


class PrivacyBackend(Protocol):
    def inspect_guard(self) -> GuardStatus: ...
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

    The backend must return GuardStatus.UNKNOWN when nft inspection fails or
    output is incomplete. UNKNOWN is never equivalent to ABSENT and never
    authorizes installation, tunnel activation, or guard deletion.
    """

    def __init__(self, backend: PrivacyBackend):
        self.backend = backend

    def _remove_guard_if_proven_safe(self) -> bool:
        b = self.backend
        status = b.inspect_guard()
        if status == GuardStatus.ABSENT:
            return True
        if status != GuardStatus.OWNED or b.interface_is_up():
            return False
        b.remove_owned_guard()
        return b.inspect_guard() == GuardStatus.ABSENT

    def enable(self) -> SessionResult:
        b = self.backend
        try:
            initial_guard = b.inspect_guard()
            if initial_guard != GuardStatus.ABSENT:
                return SessionResult(
                    SessionState.GUARDED_RECOVERY, False,
                    f"Status guard awal {initial_guard.value}; menolak mengubah state yang tidak pasti.",
                )
            if b.interface_is_up():
                return SessionResult(
                    SessionState.GUARDED_RECOVERY, False,
                    "Interface WireGuard sudah aktif di luar sesi PPS; tidak mengubahnya.",
                )
            b.install_guard()
            if b.inspect_guard() != GuardStatus.OWNED:
                return SessionResult(
                    SessionState.GUARDED_RECOVERY, False,
                    "Guard tidak dapat dibuktikan sebagai tabel PPS yang tepat; tunnel tidak dijalankan.",
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
                        f"Aktivasi gagal ({exc}); guard tidak terbukti aman dihapus.",
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
            status = b.inspect_guard()
            if status == GuardStatus.ABSENT:
                if b.interface_is_up():
                    return SessionResult(
                        SessionState.GUARDED_RECOVERY, False,
                        "Interface aktif tanpa guard PPS; tidak melakukan perubahan otomatis.",
                    )
                return SessionResult(SessionState.OFF, True, "Sesi sudah nonaktif.")
            if status != GuardStatus.OWNED:
                return SessionResult(
                    SessionState.GUARDED_RECOVERY, False,
                    f"Guard berstatus {status.value}; tidak melakukan perubahan otomatis.",
                )
            if b.interface_is_up():
                b.bring_interface_down()
            if b.interface_is_up():
                return SessionResult(
                    SessionState.GUARDED_RECOVERY, False,
                    "WireGuard belum terbukti down; guard tetap dipertahankan.",
                )
            b.remove_owned_guard()
            if b.inspect_guard() != GuardStatus.ABSENT:
                return SessionResult(
                    SessionState.GUARDED_RECOVERY, False,
                    "Guard belum terbukti hilang setelah penghapusan; perlu pemulihan manual.",
                )
            return SessionResult(SessionState.OFF, True, "WireGuard down; guard PPS yang tervalidasi dihapus.")
        except Exception as exc:
            return SessionResult(
                SessionState.GUARDED_RECOVERY, False,
                f"Proses OFF gagal ({exc}); guard tidak boleh dibuka otomatis.",
            )
