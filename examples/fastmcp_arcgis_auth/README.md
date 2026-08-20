# FastMCP + arcgis-mcp-oauth

This example is a small Python MCP resource server that accepts
`mcp-token-*` bearer tokens issued by `arcgis-mcp-oauth`.

It demonstrates:

1. FastMCP's Streamable HTTP transport at `POST /mcp`.
2. Starlette middleware that validates the client bearer token with
   `arcgis-mcp-oauth`.
3. Protected-resource metadata at
   `/.well-known/oauth-protected-resource/mcp`.
4. Reading the resolved ArcGIS access token and portal context in a FastMCP
   tool, then using that token against the ArcGIS REST API.

## Install and run

Start `arcgis-mcp-oauth` first, then install the example dependencies:

```bash
cd examples/fastmcp_arcgis_auth
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

export AUTH_SERVICE_URL=http://localhost:3324
export MCP_PUBLIC_BASE_URL=http://localhost:3325
export INTERNAL_API_KEY=the-same-value-used-by-arcgis-mcp-oauth
python server.py
```

The example listens on `http://localhost:3325`, with MCP served at
`http://localhost:3325/mcp`.

## Token flow

The MCP client sends its token to this resource server:

```http
Authorization: Bearer mcp-token-...
```

The server then calls `arcgis-mcp-oauth`:

```http
GET /internal/session
Authorization: Bearer <INTERNAL_API_KEY>
X-MCP-Access-Token: mcp-token-...
X-MCP-Resource: http://localhost:3325/mcp
```

`INTERNAL_API_KEY` belongs only to the resource server and `arcgis-mcp-oauth`; it
must never be sent to an MCP client. The middleware caches the resolved ArcGIS
session only on the current request. The example's tool uses the ArcGIS access
token to request `/community/self` and deliberately does not return it.

## Protected-resource metadata

An unauthenticated `/mcp` request receives a `401` with a
`WWW-Authenticate` header pointing to:

```text
http://localhost:3325/.well-known/oauth-protected-resource/mcp
```

That metadata identifies `arcgis-mcp-oauth` as the authorization server, allowing an
MCP client to begin the OAuth flow.

The authorization and token requests must use `http://localhost:3325/mcp` as their
`resource`. The example sends the same value during session resolution and rejects a
response whose `resource` does not match exactly.

## Check

With the virtual environment active:

```bash
python -m unittest test_server.py
```
