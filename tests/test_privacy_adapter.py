import unittest

from pps_nft_inspect import InspectionResult, InspectionStatus
from pps_privacy_session import GuardStatus
from pps_privacy_adapter import guard_status_from_inspection


class PrivacyAdapterTests(unittest.TestCase):
    def test_owned_maps_to_owned(self):
        result = InspectionResult(InspectionStatus.OWNED, "verified")
        self.assertEqual(guard_status_from_inspection(result), GuardStatus.OWNED)

    def test_foreign_maps_to_foreign(self):
        result = InspectionResult(InspectionStatus.FOREIGN_OR_MODIFIED, "mismatch")
        self.assertEqual(
            guard_status_from_inspection(result),
            GuardStatus.FOREIGN_OR_MODIFIED,
        )

    def test_unknown_maps_to_unknown(self):
        result = InspectionResult(InspectionStatus.UNKNOWN, "command failed")
        self.assertEqual(guard_status_from_inspection(result), GuardStatus.UNKNOWN)

    def test_invalid_input_maps_to_unknown(self):
        self.assertEqual(guard_status_from_inspection(None), GuardStatus.UNKNOWN)
        self.assertEqual(guard_status_from_inspection(object()), GuardStatus.UNKNOWN)

    def test_adapter_never_invents_absent(self):
        for status in InspectionStatus:
            result = InspectionResult(status, "fixture")
            self.assertNotEqual(
                guard_status_from_inspection(result),
                GuardStatus.ABSENT,
            )


if __name__ == "__main__":
    unittest.main()
