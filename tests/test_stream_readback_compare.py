from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/stream_readback_compare.py"


def load_compare():
    spec = importlib.util.spec_from_file_location("stream_readback_compare", SCRIPT)
    if spec is None or spec.loader is None:
        raise AssertionError(f"cannot load {SCRIPT}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class StreamReadbackCompareTests(unittest.TestCase):
    def test_exact_stream_passes_without_output_image(self):
        compare = load_compare()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source.img"
            incoming = root / "incoming.bin"
            source.write_bytes(b"bound-partition" * 8192)
            incoming.write_bytes(source.read_bytes())
            result = compare.compare_stream(incoming, source)
            self.assertTrue(result["byte_identical"])
            self.assertEqual(source.stat().st_size, result["stream_bytes"])

    def test_mismatch_and_short_stream_fail_closed(self):
        compare = load_compare()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source.img"
            incoming = root / "incoming.bin"
            source.write_bytes(b"abcdef")
            incoming.write_bytes(b"abcxef")
            result = compare.compare_stream(incoming, source)
            self.assertFalse(result["byte_identical"])
            self.assertEqual(3, result["mismatch_offset"])

            incoming.write_bytes(b"abc")
            result = compare.compare_stream(incoming, source)
            self.assertFalse(result["byte_identical"])
            self.assertTrue(result["source_has_unread_tail"])


if __name__ == "__main__":
    unittest.main()
