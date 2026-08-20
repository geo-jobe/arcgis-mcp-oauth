# TypeScript MCP + arcgis-mcp-oauth

This is a minimal TypeScript MCP resource server that accepts `mcp-token-*`
bearer tokens issued by `arcgis-mcp-oauth`.

It demonstrates:

1. The TypeScript MCP SDK's Streamable HTTP transport at `POST /mcp`.
2. Validating the client bearer token through `arcgis-mcp-oauth`.
3. Protected-resource metadata at `/.well-known/oauth-protected-resource/mcp`.
4. Using the resolved ArcGIS token in a `current_arcgis_user` tool without
   returning or logging it.

## Install and run

Start `arcgis-mcp-oauth` first, then install and start this example:

```bash
cd examples/typescript_mcp_auth
npm install
cp .env.example .env

# Set INTERNAL_API_KEY in .env to the same value used by arcgis-mcp-oauth.
npm start
```

The example listens on `http://localhost:3325`, with MCP served at
`http://localhost:3325/mcp`.

## Token flow

The MCP client sends its token to this resource server:

```http
Authorization: Bearer mcp-token-...
```

The server resolves it with `arcgis-mcp-oauth`:

```http
GET /internal/session
Authorization: Bearer <INTERNAL_API_KEY>
X-MCP-Access-Token: mcp-token-...
X-MCP-Resource: http://localhost:3325/mcp
```

`INTERNAL_API_KEY` belongs only to the resource server and
`arcgis-mcp-oauth`; never send it to an MCP client. The resolved ArcGIS session
is held only in the server's in-memory MCP session. It is refreshed when the
client makes a request. The `current_arcgis_user` tool uses it to call
`/community/self` and returns only public profile information.

Unauthenticated requests receive a `401` with a `WWW-Authenticate` header
pointing to `/.well-known/oauth-protected-resource/mcp`, which identifies
`arcgis-mcp-oauth` as the authorization server.

The authorization and token requests must use `http://localhost:3325/mcp` as their
`resource`. The example sends the same value during session resolution and rejects a
response whose `resource` does not match exactly.

## Check

```bash
npm run typecheck
npm test
```
