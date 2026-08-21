"""A minimal FastMCP resource server protected by arcgis-mcp-oauth."""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any

import httpx
import uvicorn
from fastmcp import FastMCP
from fastmcp.dependencies import CurrentRequest
from fastmcp.exceptions import ToolError
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Mount, Route


@dataclass(frozen=True)
class Settings:
    auth_service_url: str
    internal_api_key: str
    public_base_url: str

    @classmethod
    def from_environment(cls) -> Settings:
        internal_api_key = os.environ.get("INTERNAL_API_KEY")
        if not internal_api_key:
            raise RuntimeError("INTERNAL_API_KEY must be set")

        return cls(
            auth_service_url=os.environ.get(
                "AUTH_SERVICE_URL", "http://localhost:3324"
            ).rstrip("/"),
            internal_api_key=internal_api_key,
            public_base_url=os.environ.get(
                "MCP_PUBLIC_BASE_URL", "http://localhost:3325"
            ).rstrip("/"),
        )


@dataclass(frozen=True)
class ArcGISSession:
    access_token: str
    portal_url: str
    api_root: str
    username: str | None
    scopes: frozenset[str]


def extract_bearer(headers: dict[str, str] | Any) -> str | None:
    authorization = headers.get("authorization", "")
    scheme, _, token = authorization.partition(" ")
    return token if scheme.lower() == "bearer" and token else None


class MicroAuthClient:
    """Resolves an MCP bearer token into ArcGIS credentials."""

    def __init__(
        self,
        settings: Settings,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._session_url = f"{settings.auth_service_url}/internal/session"
        self._internal_api_key = settings.internal_api_key
        self._resource_uri = f"{settings.public_base_url}/mcp"
        self._transport = transport

    async def resolve_session(self, mcp_access_token: str) -> ArcGISSession | None:
        try:
            async with httpx.AsyncClient(
                timeout=5.0,
                transport=self._transport,
            ) as client:
                response = await client.get(
                    self._session_url,
                    headers={
                        # This is the resource server's credential, not the user token.
                        "Authorization": f"Bearer {self._internal_api_key}",
                        "X-MCP-Access-Token": mcp_access_token,
                        "X-MCP-Resource": self._resource_uri,
                    },
                )
                response.raise_for_status()
                payload = response.json()
        except (httpx.HTTPError, ValueError):
            return None

        arcgis_token = payload.get("arcgis_token")
        portal = payload.get("portal")
        scopes = payload.get("scopes")
        if (
            not payload.get("active")
            or payload.get("resource") != self._resource_uri
            or not isinstance(arcgis_token, dict)
            or not isinstance(portal, dict)
            or not isinstance(scopes, list)
            or not all(isinstance(scope, str) for scope in scopes)
        ):
            return None

        access_token = arcgis_token.get("access_token")
        portal_url = portal.get("portal_url")
        api_root = portal.get("api_root")
        if not all(isinstance(value, str) and value for value in (access_token, portal_url, api_root)):
            return None

        username = arcgis_token.get("username")
        return ArcGISSession(
            access_token=access_token,
            portal_url=portal_url,
            api_root=api_root,
            username=username if isinstance(username, str) else None,
            scopes=frozenset(scopes),
        )


def has_required_scopes(session: ArcGISSession, required_scopes: frozenset[str]) -> bool:
    return required_scopes.issubset(session.scopes)


def insufficient_scope_challenge(
    resource_metadata_url: str, required_scopes: frozenset[str]
) -> str:
    required = " ".join(sorted(required_scopes))
    return (
        f'Bearer error="insufficient_scope", scope="{required}", '
        f'resource_metadata="{resource_metadata_url}"'
    )


class MCPBearerAuthMiddleware(BaseHTTPMiddleware):
    """Require a valid arcgis-mcp-oauth MCP access token for every /mcp request."""

    def __init__(
        self,
        app: Any,
        auth_client: MicroAuthClient,
        resource_metadata_url: str,
        required_scopes: frozenset[str],
    ) -> None:
        super().__init__(app)
        self._auth_client = auth_client
        self._resource_metadata_url = resource_metadata_url
        self._required_scopes = required_scopes

    def unauthorized(self, error: str | None = None) -> JSONResponse:
        challenge = f'Bearer resource_metadata="{self._resource_metadata_url}"'
        if error:
            challenge = f'Bearer error="{error}", resource_metadata="{self._resource_metadata_url}"'
        return JSONResponse(
            {"detail": "A valid MCP bearer token is required."},
            status_code=401,
            headers={"WWW-Authenticate": challenge},
        )

    def insufficient_scope(self) -> JSONResponse:
        required = " ".join(sorted(self._required_scopes))
        challenge = insufficient_scope_challenge(
            self._resource_metadata_url, self._required_scopes
        )
        return JSONResponse(
            {"detail": f"Required scope: {required}"},
            status_code=403,
            headers={"WWW-Authenticate": challenge},
        )

    async def dispatch(self, request: Request, call_next: Any) -> Response:
        mcp_access_token = extract_bearer(request.headers)
        if not mcp_access_token:
            return self.unauthorized()

        session = await self._auth_client.resolve_session(mcp_access_token)
        if not session:
            return self.unauthorized("invalid_token")
        if not has_required_scopes(session, self._required_scopes):
            return self.insufficient_scope()

        # Cache only for this HTTP request. Do not put bearer tokens in logs.
        request.state.arcgis_session = session
        return await call_next(request)


async def require_arcgis_session(
    request: Request,
    auth_client: MicroAuthClient,
) -> ArcGISSession:
    """Get the session cached by middleware, or resolve it for a direct tool call."""
    session = getattr(request.state, "arcgis_session", None)
    if isinstance(session, ArcGISSession):
        return session

    mcp_access_token = extract_bearer(request.headers)
    if not mcp_access_token:
        raise ToolError("Unauthorized: no Bearer token in request.")

    session = await auth_client.resolve_session(mcp_access_token)
    if not session:
        raise ToolError("Unauthorized: your session has expired or is invalid.")
    return session


def build_app(settings: Settings) -> Starlette:
    auth_client = MicroAuthClient(settings)
    mcp = FastMCP("ArcGIS-protected FastMCP example")

    @mcp.tool
    async def current_arcgis_user(request: Request = CurrentRequest()) -> dict[str, str | None]:
        """Return the authenticated ArcGIS user's public profile information."""
        session = await require_arcgis_session(request, auth_client)

        # The ArcGIS token is sent only to the selected portal and is never returned.
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(
                f"{session.api_root}/community/self",
                params={"f": "json", "token": session.access_token},
            )
            response.raise_for_status()
            profile = response.json()

        return {
            "username": profile.get("username", session.username),
            "full_name": profile.get("fullName"),
            "portal_url": session.portal_url,
        }

    resource_uri = f"{settings.public_base_url}/mcp"

    async def protected_resource_metadata(_: Request) -> JSONResponse:
        return JSONResponse(
            {
                "resource": resource_uri,
                "authorization_servers": [settings.auth_service_url],
                "bearer_methods_supported": ["header"],
                "scopes_supported": ["profile"],
            }
        )

    metadata_url = f"{settings.public_base_url}/.well-known/oauth-protected-resource/mcp"
    mcp_app = mcp.http_app(
        path="/mcp",
        transport="streamable-http",
        middleware=[
            Middleware(
                MCPBearerAuthMiddleware,
                auth_client=auth_client,
                resource_metadata_url=metadata_url,
                required_scopes=frozenset({"profile"}),
            )
        ],
    )

    return Starlette(
        routes=[
            Route(
                "/.well-known/oauth-protected-resource",
                protected_resource_metadata,
            ),
            Route(
                "/.well-known/oauth-protected-resource/mcp",
                protected_resource_metadata,
            ),
            Mount("/", app=mcp_app),
        ],
        lifespan=mcp_app.lifespan,
    )


if __name__ == "__main__":
    uvicorn.run(build_app(Settings.from_environment()), host="127.0.0.1", port=3325)
