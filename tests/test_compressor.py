from __future__ import annotations

import unittest

from script.compressor import compress_rules


class CompressorTest(unittest.TestCase):
    def test_host_deduplication_and_parent_compression_ignore_case(self) -> None:
        output, filtered = compress_rules(
            [
                "Example.com",
                "example.com",
                "Sub.Example.com",
            ],
            include_wildcards=True,
        )

        self.assertEqual(["||Example.com^"], output)
        self.assertEqual(["example.com", "Sub.Example.com"], filtered)

    def test_wildcard_deduplication_ignores_case(self) -> None:
        output, filtered = compress_rules(
            [
                "||Track.*^",
                "||track.*^",
            ],
            include_wildcards=True,
        )

        self.assertEqual(["||Track.*^"], output)
        self.assertEqual(["||track.*^"], filtered)


if __name__ == "__main__":
    unittest.main()
