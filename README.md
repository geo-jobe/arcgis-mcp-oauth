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
| 2. Register a client | `POST http://localhost:3324/oauth/register` |
| 3. Authorize | Open the authorize URL in a browser (portal picker → ArcGIS login) |
| 4. Exchange the code for a token | `POST http://localhost:3324/oauth/token` |
| 5. Call the MCP server | `Authorization: Bearer mcp-token-...` on `http://localhost:3325/mcp` |

## Endpoints

| Route | Description |
|-------|-------------|
| `GET /.well-known/oauth-authorization-server` | OAuth AS metadata |
| `POST /oauth/register` | Dynamic client registration |
| `GET /oauth/authorize` | Portal picker |
| `GET /oauth/authorize/continue` | Redirect to ArcGIS |
| `POST /oauth/token` | Token exchange |
| `GET /arcgis/callback` | ArcGIS OAuth callback |
| `GET /internal/session` | Session introspection |
| `GET /health` | Health check |

## Examples

The [`examples/`](./examples) directory contains sample MCP servers wired up to `arcgis-mcp-oauth`:

- [`fastmcp_arcgis_auth`](./examples/fastmcp_arcgis_auth) — Python (FastMCP)
- [`typescript_mcp_auth`](./examples/typescript_mcp_auth) — TypeScript

## License

Licensed under either of [Apache License, Version 2.0](./LICENSE-APACHE) or [MIT license](./LICENSE-MIT) at your option.

---

<p align="center">
  Made with ❤️ by <a href="https://geo-jobe.com/">GEO Jobe</a> — GIS software and services for the Esri ArcGIS System.
</p>
