<p align="center">
  <a href="https://geo-jobe.com/">
    <img src="https://github.com/geo-jobe.png" alt="GEO Jobe" width="80">
  </a>
</p>

<h1 align="center">arcgis-mcp-oauth</h1>

<p align="center">
  Built and maintained by <a href="https://geo-jobe.com/">GEO Jobe</a>, an Esri Platinum business partner.
</p>

OAuth 2.0 authorization server for the ArcGIS MCP stack. Brokers a double-PKCE flow against ArcGIS Online/Enterprise and issues opaque `mcp-token-*` bearer tokens.

**What is it?**
'arcgis-mcp-oauth' is a small authorization server we built specifically for ArcGIS MCP integrations. Its one job is to broker the OAuth handshake between an MCP client (Cursor, Claude Desktop, etc.) and ArcGIS, then hand back a bearer token the MCP server can actually use.

**Why it exists**
We noticed lots of people in this space struggling to integrate MCP effectively with ArcGIS. The most common example is hard-coded API key's or service accounts, which restricts the service and adds potential security risks. This solves that by issue for you.

**How it works**
You point your MCP server at arcgis-mcp-oauth. When a user connects through their MCP client, arcgis-mcp-oauth handles the ArcGIS login, they authenticate through a normal browser-based ArcGIS OAuth flow. From that point on, your MCP server just calls a single internal endpoint to get a live, user-scoped ArcGIS token whenever it needs one.

[PRM Document Example](https://modelcontextprotocol.io/docs/tutorials/security/autho)

Example authorization middleware
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

Set `INTERNAL_API_KEY` to a shared secret (used by your mcp).

### 2. Configure an ArcGIS portal

Replace the placeholder portal in `config/local.toml` with the details for
your ArcGIS OAuth application. Its redirect URI must be:

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

Point your MCP server at `AUTH_SERVICE_URL=http://localhost:3324` and use the
same `INTERNAL_API_KEY`. See your MCP server project for its run command.

### 5. OAuth flow

1. Discover AS: `GET http://localhost:3325/.well-known/oauth-protected-resource`
2. Register client: `POST http://localhost:3324/oauth/register`
3. Open authorize URL in browser (portal picker → ArcGIS login)
4. Exchange code: `POST http://localhost:3324/oauth/token`
5. Call MCP with `Authorization: Bearer mcp-token-...` on `http://localhost:3325/mcp`

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

---

<p align="center">
  Made with ❤️ by <a href="https://geo-jobe.com/">GEO Jobe</a> — GIS software and services for the Esri ArcGIS System.
</p>
