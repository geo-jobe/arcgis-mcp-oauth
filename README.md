<p align="center">
  <a href="https://geo-jobe.com/">
    <img src="https://github.com/geo-jobe.png" alt="GEO Jobe" width="80">
  </a>
</p>

<h1 align="center">arcgis-mcp-oauth</h1>

<p align="center">
  OAuth 2.0 authorization server that brokers ArcGIS logins for MCP servers.
</p>

<p align="center">
  <a href="https://github.com/geo-jobe/arcgis-mcp-oauth/actions/workflows/ci.yml"><img src="https://github.com/geo-jobe/arcgis-mcp-oauth/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="#license"><img src="https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg" alt="License"></a>
  <a href="https://geo-jobe.com/"><img src="https://img.shields.io/badge/maintained%20by-GEO%20Jobe-0b6e4f.svg" alt="Maintained by GEO Jobe"></a>
</p>

---

## What is it?

`arcgis-mcp-oauth` is a small authorization server purpose-built for ArcGIS MCP integrations. Its one job is to broker the OAuth handshake between an MCP client (Cursor, Claude Desktop, etc.) and ArcGIS, then hand back a bearer token the MCP server can use.

## Why it exists

Many ArcGIS MCP integrations rely on hard-coded API keys or shared service accounts. That restricts what the integration can do and adds unnecessary security risk. `arcgis-mcp-oauth` replaces that with a real, user-scoped OAuth flow, so every MCP session acts as the person who's actually logged in.

## How it works

You point your MCP server at `arcgis-mcp-oauth`. When a user connects through their MCP client, `arcgis-mcp-oauth` handles the login: the user authenticates through a normal browser-based ArcGIS OAuth flow. From that point on, your MCP server just calls a single internal endpoint to get a live, user-scoped ArcGIS token whenever it needs one.

See the [MCP authorization spec](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/authorization#the-authorization-flow-step-by-step) for background on this pattern.

Example authorization middleware:

```rust
fn auth_middleware() {
    let mcp_token = request.headers().get("Authorization");

    if validate_token(mcp_token).await {
        "MCP token validated successfully"
    } else {
        "Auth validation failed for token"
    }
}
```

## Local development

### 1. Configure environment

```bash
cp .env.example .env
cp config/local.example.toml config/local.toml
```

Set `INTERNAL_API_KEY` to a shared secret (used by your MCP server).

`PUBLIC_BASE_URL` is also the OAuth authorization server's canonical issuer. Configure it to the
externally reachable base URL without a trailing slash. The exact value is published as `issuer` in
authorization-server metadata.

### 2. Configure an ArcGIS portal

Replace the placeholder portal in `config/local.toml` with the details for your ArcGIS OAuth application. Its redirect URI must be:

```
http://localhost:3324/arcgis/callback
```

### 3. Start arcgis-mcp-oauth

```bash
cd arcgis-mcp-oauth
INTERNAL_API_KEY=dev-secret cargo run
```

Listens on `http://localhost:3324` by default (`config/local.toml`).

### 4. Connect your MCP server

Point your MCP server at `AUTH_SERVICE_URL=http://localhost:3324` and use the same `INTERNAL_API_KEY`. See your MCP server project for its run command.

### 5. Walk the OAuth flow

| Step | Request |
|------|---------|
| 1. Discover the authorization server | `GET http://localhost:3325/.well-known/oauth-protected-resource` |
| 2. Identify the client | Use an HTTPS Client ID Metadata Document, or fall back to `POST http://localhost:3324/oauth/register` |
| 3. Authorize | Open the authorize URL in a browser (explicit consent and portal selection, then ArcGIS login) |
| 4. Exchange the code for a token | `POST http://localhost:3324/oauth/token` |
| 5. Call the MCP server | `Authorization: Bearer mcp-token-...` on `http://localhost:3325/mcp` |

## Endpoints

| Route | Description |
|-------|-------------|
| `GET /.well-known/oauth-authorization-server` | OAuth AS metadata |
| `POST /oauth/register` | Dynamic client registration |
| `GET /oauth/authorize` | Review client, resource, scopes, and portal |
| `POST /oauth/authorize/continue` | Submit consent decision |
| `POST /oauth/token` | Token exchange |
| `GET /arcgis/callback` | ArcGIS OAuth callback |
| `GET /internal/session` | Session introspection |
| `GET /health` | Health check |

## Client registration

The authorization server prefers Client ID Metadata Documents (CIMD) for URL-shaped client IDs and
retains Dynamic Client Registration (DCR) for compatibility. Discovery advertises both
`client_id_metadata_document_supported: true` and the DCR `registration_endpoint`. Resolution is
deterministic: HTTP(S) URL client IDs are resolved as CIMD documents; opaque IDs are looked up in the
DCR registry.

A CIMD client ID must be an HTTPS URL with a path. The JSON document must identify that URL exactly,
provide a non-empty client name and redirect URI list, and describe this public authorization-code
flow with `response_types: ["code"]` and `token_endpoint_auth_method: "none"`. Grant types may be
`authorization_code` and `refresh_token`. Requested redirect URIs are compared exactly against the
document. Registered redirects must use HTTPS, except for HTTP loopback redirects used by native
clients.

CIMD fetches use a 2-second connection timeout, a 5-second total timeout, a 5 KiB response limit,
and at most three redirects. Every target and redirect is resolved and checked before connecting;
production blocks loopback, private, link-local, reserved, and other non-public addresses. Successful
documents are cached according to HTTP cache headers, with a 5-minute default TTL and `max-age`
clamped to 1 minute through 1 hour. `ETag` and `Last-Modified` validators are used for revalidation.
Failures and invalid documents are never cached, and an expired document fails closed if it cannot
be refreshed.

For local development only, set `CIMD_ALLOW_PRIVATE_ADDRESSES=true` (or
`cimd_allow_private_addresses = true` in local TOML) to permit private targets and HTTP metadata on
private targets. Production configuration rejects this setting at startup.

## Resource audiences

OAuth requests use RFC 8707 resource indicators. The authorization request and
authorization-code token request must both include the same absolute resource URI, for example
`resource=http%3A%2F%2Flocalhost%3A3325%2Fmcp`. Refresh requests must include that resource again.
The server canonicalizes HTTP(S) URIs, rejects malformed targets with `invalid_target`, and binds
the canonical value to authorization codes, access tokens, and refresh tokens. Existing tokens
created before resource binding require reauthorization.

Resource servers must identify their audience when resolving a session and verify the returned
`resource` exactly:

```http
GET /internal/session
Authorization: Bearer <INTERNAL_API_KEY>
X-MCP-Access-Token: mcp-token-...
X-MCP-Resource: http://localhost:3325/mcp
```

## OAuth scopes

Scopes issued by this service authorize MCP operations; they are not ArcGIS OAuth scopes and are
not sent to an ArcGIS portal. ArcGIS continues to constrain the upstream token through the signed-in
user's privileges and content access. The resource server must separately enforce the MCP scopes
returned by `/internal/session` before using that ArcGIS token.

The examples currently implement the `profile` scope. An omitted scope on an authorization request
defaults to `profile`; unsupported scopes are rejected with `invalid_scope` before ArcGIS login.
Token responses contain the normalized space-delimited `scope`, while `/internal/session` returns
the same grant as a `scopes` array. A refresh request without `scope` preserves its grant. A refresh
request may request a subset of the original grant but can never expand it.

Tokens issued before scope persistence was introduced are invalidated by the database migration and
must be reauthorized.

## Authorization response issuer

Authorization success and redirect-based error responses include the RFC 9207 `iss` query
parameter. OAuth clients must compare it exactly with the `issuer` value from
`/.well-known/oauth-authorization-server` and reject the response if the values differ. The server
preserves registered callback query parameters and the client's `state` while adding `iss`.

## Authorization consent

Every authorization request requires an explicit allow or deny decision before any ArcGIS redirect.
Validated request parameters are kept in short-lived, one-time server-side state and the consent form
is protected by a CSRF token. Denial returns `access_denied` to the previously validated client
redirect URI and preserves client `state`. Grants are not remembered; users review every request.

## Examples

The [`examples/`](./examples) directory contains sample MCP servers wired up to `arcgis-mcp-oauth`:

- [`fastmcp_arcgis_auth`](./examples/fastmcp_arcgis_auth) - Python (FastMCP)
- [`typescript_mcp_auth`](./examples/typescript_mcp_auth) - TypeScript

## License

Licensed under either of [Apache License, Version 2.0](./LICENSE-APACHE) or [MIT license](./LICENSE-MIT) at your option.

---

<p align="center">
  Made with ❤️ by <a href="https://geo-jobe.com/">GEO Jobe</a> — GIS software and services for the Esri ArcGIS System.
</p>
