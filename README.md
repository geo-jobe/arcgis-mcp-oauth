# micro-auth

OAuth 2.0 authorization server for the ArcGIS MCP stack. Brokers a double-PKCE flow against ArcGIS Online/Enterprise and issues opaque `mcp-token-*` bearer tokens.

The sibling [arcgis-mcp-rs](../arcgis-mcp-rs/) project is the MCP resource server — it validates tokens via this service's `/internal/session` endpoint.

## Local development

### 1. Configure environment

```bash
cp .env.example .env
```

Set `INTERNAL_API_KEY` to a shared secret (must match mcp-rs).

### 2. Start micro-auth

```bash
cd micro-auth
INTERNAL_API_KEY=dev-secret cargo run
```

Listens on `http://localhost:3324` by default (`config/local.toml`).

### 3. Start mcp-rs

```bash
cd ../arcgis-mcp-rs
AUTH_SERVICE_URL=http://localhost:3324 \
INTERNAL_API_KEY=dev-secret \
cargo run
```

Listens on `http://localhost:3325`.

### 4. OAuth flow

1. Discover AS: `GET http://localhost:3325/.well-known/oauth-protected-resource`
2. Register client: `POST http://localhost:3324/oauth/register`
3. Open authorize URL in browser (portal picker → ArcGIS login)
4. Exchange code: `POST http://localhost:3324/oauth/token`
5. Call MCP with `Authorization: Bearer mcp-token-...` on `http://localhost:3325/mcp`

### ArcGIS portal setup

Each portal in `config/local.toml` needs an OAuth application with redirect URI:

```
http://localhost:3324/arcgis/callback
```

## Endpoints

| Route | Description |
|-------|-------------|
| `GET /.well-known/oauth-authorization-server` | OAuth AS metadata |
| `POST /oauth/register` | Dynamic client registration |
| `GET /oauth/authorize` | Portal picker |
| `GET /oauth/authorize/continue` | Redirect to ArcGIS |
| `POST /oauth/token` | Token exchange |
| `GET /arcgis/callback` | ArcGIS OAuth callback |
| `GET /internal/session` | Session introspection (mcp-rs only) |
| `GET /health` | Health check |
