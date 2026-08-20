import unittest

import httpx

from server import MicroAuthClient, Settings, extract_bearer


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


class ResolveSessionTests(unittest.IsolatedAsyncioTestCase):
    async def test_sends_and_verifies_resource_audience(self) -> None:
        requested_resource: str | None = None

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal requested_resource
            requested_resource = request.headers.get("X-MCP-Resource")
            return httpx.Response(
                200,
                json={
                    "active": True,
                    "resource": "https://other.example.com/mcp",
                    "arcgis_token": {"access_token": "arcgis-token"},
                    "portal": {
                        "portal_url": "https://portal.example.com",
                        "api_root": "https://portal.example.com/sharing/rest",
                    },
                },
            )

        client = MicroAuthClient(
            Settings(
                auth_service_url="https://auth.example.com",
                internal_api_key="secret",
                public_base_url="https://mcp.example.com",
            ),
            transport=httpx.MockTransport(handler),
        )

        self.assertIsNone(await client.resolve_session("mcp-token"))
        self.assertEqual(requested_resource, "https://mcp.example.com/mcp")


if __name__ == "__main__":
    unittest.main()
