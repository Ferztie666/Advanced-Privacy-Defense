"""Safe mapping between read-only nft inspection and session guard states.

This adapter does not run commands and intentionally cannot infer ABSENT from
an inspection failure. The current single-table inspector has no positive
absence proof, so it can map only OWNED / FOREIGN_OR_MODIFIED / UNKNOWN.
"""
from __future__ import annotations

from pps_nft_inspect import InspectionResult, InspectionStatus
from pps_privacy_session import GuardStatus


def guard_status_from_inspection(result: InspectionResult) -> GuardStatus:
    """Translate an inspection result without weakening its certainty."""
    if not isinstance(result, InspectionResult):
        return GuardStatus.UNKNOWN
    if result.status == InspectionStatus.OWNED:
        return GuardStatus.OWNED
    if result.status == InspectionStatus.FOREIGN_OR_MODIFIED:
        return GuardStatus.FOREIGN_OR_MODIFIED
    return GuardStatus.UNKNOWN
