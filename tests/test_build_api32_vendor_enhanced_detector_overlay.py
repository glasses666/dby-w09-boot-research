import unittest

from scripts.build_api32_vendor_enhanced_detector_overlay import (
    EXPECTED_FUNCTION_PREFIX,
    GET_VENDOR_ENHANCED_INFO_OFFSET,
    RETURN_ODM_ONLY_INFO,
    patch_image,
)


class VendorEnhancedDetectorOverlayTests(unittest.TestCase):
    def test_only_get_vendor_enhanced_info_entry_is_replaced(self) -> None:
        source = bytearray(GET_VENDOR_ENHANCED_INFO_OFFSET + 64)
        source[:6] = b"\x7fELF\x01\x01"
        start = GET_VENDOR_ENHANCED_INFO_OFFSET
        source[start : start + len(EXPECTED_FUNCTION_PREFIX)] = (
            EXPECTED_FUNCTION_PREFIX
        )

        output, report = patch_image(bytes(source), verify_source_hash=False)

        self.assertEqual(len(output), len(source))
        self.assertEqual(output[start : start + 4], RETURN_ODM_ONLY_INFO)
        self.assertEqual(report["changed_offsets"], list(range(start, start + 4)))
        self.assertEqual(report["changed_byte_count"], 4)
        self.assertEqual(output[:start], source[:start])
        self.assertEqual(output[start + 4 :], source[start + 4 :])

    def test_rejects_wrong_function_prefix(self) -> None:
        source = bytearray(GET_VENDOR_ENHANCED_INFO_OFFSET + 64)
        source[:6] = b"\x7fELF\x01\x01"
        with self.assertRaisesRegex(ValueError, "function prefix mismatch"):
            patch_image(bytes(source), verify_source_hash=False)


if __name__ == "__main__":
    unittest.main()
