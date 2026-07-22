import unittest

from server import extract_bearer


class ExtractBearerTests(unittest.TestCase):
    def test_extracts_a_bearer_token_case_insensitively(self) -> None:
        self.assertEqual(
            extract_bearer({"authorization": "bEaReR mcp-token-example"}),
            "mcp-token-example",
        )

    def test_rejects_missing_or_malformed_authorization(self) -> None:
        self.assertIsNone(extract_bearer({}))
        self.assertIsNone(extract_bearer({"authorization": "Basic credentials"}))
        self.assertIsNone(extract_bearer({"authorization": "Bearer"}))


if __name__ == "__main__":
    unittest.main()
