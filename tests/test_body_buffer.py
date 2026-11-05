"""Local codec parity and bounded-output regressions (no network/model)."""
import gzip
import sys
import unittest
import zlib
from pathlib import Path
from unittest import mock

import brotli
import zstandard
from mitmproxy.net import encoding

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "engine"))
from body_buffer import BodyDecodeLimit, decode_body


class BodyBufferTests(unittest.TestCase):
    def encodings(self, body):
        return {"gzip": gzip.compress(body), "deflate": zlib.compress(body),
                "deflateraw": zlib.compress(body, wbits=-15),
                "br": brotli.compress(body),
                "zstd": zstandard.ZstdCompressor().compress(body)}

    def test_supported_headers_empty_and_case(self):
        body = b'{"text":"synthetic test data"}'
        for kind, wire in self.encodings(body).items():
            for header in (kind, kind.upper()):
                with self.subTest(header=header):
                    self.assertEqual(decode_body(wire, header, len(body)), body)
                    self.assertEqual(decode_body(b"", header, 0), b"")
        for kind in ("", "identity", "IDENTITY", "none", None):
            self.assertIs(decode_body(body, kind, len(body)), body)
        self.assertEqual(decode_body(zlib.compress(body), "gzip", len(body)), body)

    def test_all_codecs_reject_expansion_over_ceiling(self):
        for kind, wire in self.encodings(b"a" * (2 * 1024 * 1024)).items():
            with self.subTest(kind=kind), mock.patch.object(encoding, "decode", side_effect=AssertionError("unbounded decode")):
                with self.assertRaises(BodyDecodeLimit):
                    decode_body(wire, kind, 64 * 1024)
        with self.assertRaises(BodyDecodeLimit):
            decode_body(b"abc", "", 2)

    def test_malformed_and_unknown_encodings_fail_closed(self):
        for kind in ("gzip", "deflate", "deflateraw", "br", "zstd", "gzip, br", "utf-8"):
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                decode_body(b"not a compressed body", kind, 1024)

    # Case G601 解码语义与 mitmproxy 同源：截断/尾随垃圾/拼接帧的处置必须逐项一致
    def test_first_frame_trailing_and_truncated_semantics_match_mitmproxy(self):
        # These differences between codecs are intentional mitmproxy semantics:
        # gzip is lenient / first-member only; deflate requires EOF; br is strict;
        # zstd accepts truncated input and traverses all frames.
        for kind, wire in self.encodings(b"hello").items():
            for data in (wire, wire[:-1], wire + wire, wire + b"trailing"):
                with self.subTest(kind=kind, data=data):
                    try:
                        expected = encoding.decode(data, kind)
                    except ValueError:
                        with self.assertRaises(ValueError):
                            decode_body(data, kind, 100)
                    else:
                        self.assertEqual(decode_body(data, kind, 100), expected,
                                         "MASK_5041：decode_body 与 mitmproxy 语义分叉")

    def test_zstd_unknown_size_and_concatenated_frames_are_limited(self):
        compressor = zstandard.ZstdCompressor(write_content_size=False)
        wire = compressor.compress(b"a" * 100_000)
        self.assertEqual(decode_body(wire, "zstd", 100_000), b"a" * 100_000)
        with self.assertRaises(BodyDecodeLimit):
            decode_body(wire + wire, "zstd", 100_000)

    def test_brotli_without_bounded_api_never_falls_back(self):
        with mock.patch("body_buffer.brotli.Decompressor", return_value=object()), \
             mock.patch("body_buffer.brotli.decompress", side_effect=AssertionError("unbounded fallback")):
            with self.assertRaises(ValueError):
                decode_body(brotli.compress(b"test"), "br", 100)


if __name__ == "__main__":
    unittest.main()
