# arcgis-mcp-oauth — Production OSS Release TODO

Findings from a read-only review of the codebase (Rust OAuth 2.0 authorization
server, Axum + SQLite, ~1.5k LOC) for production open-source release.

**Already good:** `.env` never committed, PKCE enforced and fails closed,
SQL is parameterized (no injection), refresh tokens rotate, internal API key
uses constant-time comparison.

---

## Critical — fix before any public release

- [x] **Token credentials logged in plaintext.** `TokenRequest` uses a redacted
  `Debug` impl; token parsing logs at `trace!` only (no raw body at `INFO`).

- [x] **Default log level is `debug` in production.** `src/main.rs` defaults to
  `info`; Dockerfile and compose set `RUST_LOG=info`.

- [x] **Path dependency breaks external builds.** `arcgis-sharing-rs` is a git
  dependency pinned to a rev in `Cargo.toml`.

- [x] **Auth codes / pending sessions never expire (security + DoS).**
  `pending_oauth_sessions` and `pending_auth_codes` in `src/arcgis_auth.rs` now
  carry 10-minute TTLs, enforce expiry on consume, sweep every 60s, and cap map
  size at 1000. DCR (`/oauth/register`) is capped at 1000 clients and rate-limited
  to 10 registrations per minute per process.

## High — should fix

- [x] **DB errors panic request handlers.** `store_token`, `store_refresh_token`
  (`src/arcgis_auth.rs`) and `register_client` (`src/oauth/store.rs`) call
  `.expect(...)` on sqlx queries. A DB hiccup panics mid-request; `store_token`
  runs *after* the auth code is consumed, so a failure burns the code with no
  token issued (user stuck). Return proper `500`s; consider a `CatchPanicLayer`.

- [x] **`redirect_uri` not verified at token exchange.** `/oauth/token` now
  compares `token_req.redirect_uri` against stored `pending.mcp_redirect_uri`
  (RFC 6749 §4.1.3).

- [ ] **Unbounded request body.** `axum::body::to_bytes(request.into_body(), usize::MAX)`
  in `oauth_token` lets a client stream an arbitrarily large body into memory.
  Cap it (a few KB is enough for a token request).

## Medium — OSS hygiene / correctness

- [x] **No LICENSE.** Added dual MIT OR Apache-2.0 licensing plus Cargo package
  `description` and `license` metadata. Add `repository` once the public URL exists.
- [x] **Org-specific data committed.** Tracked portal configuration and deployment
  defaults now use generic placeholders; deployment-specific TOML is ignored.
  (ArcGIS client IDs are public-by-design, not a leaked secret, but can be
  org-identifying.)
- [ ] **No tests, no CI.** Highest-leverage gap after security. At minimum: unit
  tests for `pkce_challenge_from_verifier`, `constant_time_eq`, and a token
  exchange happy/refresh path; a GitHub Actions workflow (`fmt`, `clippy -D warnings`,
  `test`).
- [ ] **CORS `Any`** on all routes including `/oauth/token`. Acceptable for bearer
  endpoints (no cookies), but tighten `allow_methods`/`allow_headers` and document.
- [ ] **ArcGIS tokens stored as plaintext JSON at rest** in SQLite. Document it;
  consider at-rest encryption; ensure `data/` is `chmod 700`.
- [ ] **No graceful shutdown.** `tokio` `signal` feature is enabled but unused;
  `axum::serve` has no `.with_graceful_shutdown`, so `docker stop` drops in-flight
  requests.
- [ ] **Missing governance/config files:** `CONTRIBUTING.md`, `SECURITY.md`,
  `CHANGELOG.md`, `CODE_OF_CONDUCT.md`, `rustfmt.toml`, `rust-toolchain.toml`.

## Suggested order of attack

1. Redaction + log level (Critical #1, #2) — quick, stops active credential leakage.
2. Fix build for external users: publish/git-pin `arcgis-sharing-rs` (Critical #3).
3. Auth code TTL + cleanup, DCR rate limiting (Critical #4).
4. Replace `.expect` with error responses (High #1), body cap (High #3),
   redirect_uri check (High #2).
5. LICENSE + Cargo metadata, example configs, one test file + CI.
