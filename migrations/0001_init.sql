CREATE TABLE IF NOT EXISTS tokens (
    mcp_access_token    TEXT PRIMARY KEY NOT NULL,
    arcgis_token        TEXT NOT NULL,
    expires_at          INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS refresh_tokens (
    mcp_refresh_token   TEXT PRIMARY KEY NOT NULL,
    mcp_access_token    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS registered_clients (
    client_id           TEXT PRIMARY KEY NOT NULL,
    redirect_uris       TEXT NOT NULL,
    client_name         TEXT
);
