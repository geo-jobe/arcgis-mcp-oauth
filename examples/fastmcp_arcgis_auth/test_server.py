import unittest

import httpx

from server import (
    ArcGISSession,
    MicroAuthClient,
    Settings,
    extract_bearer,
    has_required_scopes,
    insufficient_scope_challenge,
)


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


class ScopeTests(unittest.TestCase):
    def test_requires_every_scope(self) -> None:
        session = ArcGISSession(
            access_token="arcgis-token",
            portal_url="https://portal.example.com",
            api_root="https://portal.example.com/sharing/rest",
            username=None,
            scopes=frozenset({"profile"}),
        )
        self.assertTrue(has_required_scopes(session, frozenset({"profile"})))
        self.assertFalse(has_required_scopes(session, frozenset({"profile", "email"})))

    def test_insufficient_scope_challenge_identifies_the_missing_grant(self) -> None:
        self.assertEqual(
            insufficient_scope_challenge(
                "https://mcp.example.com/.well-known/oauth-protected-resource/mcp",
                frozenset({"profile"}),
            ),
            'Bearer error="insufficient_scope", scope="profile", '
            'resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource/mcp"',
        )


if __name__ == "__main__":
    unittest.main()
