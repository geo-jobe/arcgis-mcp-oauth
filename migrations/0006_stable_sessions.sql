DROP TABLE refresh_tokens;
DROP TABLE tokens;

CREATE TABLE sessions (
    session_id                  TEXT PRIMARY KEY NOT NULL,
    client_id                   TEXT NOT NULL,
    resource_uri                TEXT NOT NULL,
    scope                       TEXT NOT NULL,
    portal_key                  TEXT NOT NULL,
    portal_url                  TEXT NOT NULL,
    portal_api_root             TEXT NOT NULL,
    portal_apps                 TEXT NOT NULL,
    portal_stories_root         TEXT NOT NULL,
    arcgis_access_token         TEXT NOT NULL,
    arcgis_access_expires_at    INTEGER NOT NULL,
    arcgis_refresh_token        TEXT NOT NULL,
    arcgis_refresh_expires_at   INTEGER NOT NULL,
    arcgis_username             TEXT,
    arcgis_ssl                  INTEGER,
    arcgis_credential_generation INTEGER NOT NULL DEFAULT 0,
    last_forced_refresh_at      INTEGER,
    created_at                  INTEGER NOT NULL,
    last_activity_at            INTEGER NOT NULL,
    absolute_expires_at         INTEGER NOT NULL,
    status                      TEXT NOT NULL CHECK (status IN ('active', 'revoked'))
);

CREATE TABLE mcp_access_tokens (
    mcp_access_token    TEXT PRIMARY KEY NOT NULL,
    session_id          TEXT NOT NULL REFERENCES sessions(session_id) ON DELETE CASCADE,
    expires_at          INTEGER NOT NULL
);

CREATE INDEX mcp_access_tokens_session_id ON mcp_access_tokens(session_id);

CREATE TABLE mcp_refresh_tokens (
    mcp_refresh_token           TEXT PRIMARY KEY NOT NULL,
    session_id                  TEXT NOT NULL REFERENCES sessions(session_id) ON DELETE CASCADE,
    state                       TEXT NOT NULL CHECK (state IN ('active', 'consumed')),
    consumed_at                 INTEGER,
    successor_access_token      TEXT,
    successor_refresh_token     TEXT
);

CREATE INDEX mcp_refresh_tokens_session_id ON mcp_refresh_tokens(session_id);
