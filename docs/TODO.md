# micro-auth — Production OSS Release TODO

Findings from a read-only review of the codebase (Rust OAuth 2.0 authorization
server, Axum + SQLite, ~1.5k LOC) for production open-source release.

**Already good:** `.env` never committed, PKCE enforced and fails closed,
SQL is parameterized (no injection), refresh tokens rotate, internal API key
uses constant-time comparison.

---

## Critical — fix before any public release

- [ ] **Token credentials logged in plaintext.** `src/oauth/routes.rs` logs the
  raw token request body and the parsed `TokenRequest` (derives `Debug`) at
  `INFO`, leaking `code`, `code_verifier`, and `refresh_token` on every token
  exchange. Drop to `trace!` and redact/remove secret fields.
  - `tracing::info!("request body: {}", body_str);`
  - `tracing::info!("successfully parsed form data: {:?}", form);`

- [ ] **Default log level is `debug` in production.** `src/main.rs` falls back to
  `micro_auth=debug` and the Dockerfile never sets `RUST_LOG`, so prod runs at
  debug (amplifies the leak above). Set a sane per-env default and export
  `RUST_LOG=info` in Docker/compose.

- [ ] **Path dependency breaks external builds.** `Cargo.toml` has
  `arcgis-sharing-rs = { path = "../arcgis-sharing-rs/" }`; `git clone && cargo build`
  fails for everyone. Publish to crates.io or use a git dependency pinned to a rev.

- [ ] **Auth codes / pending sessions never expire (security + DoS).**
  `pending_oauth_sessions` and `pending_auth_codes` in `src/arcgis_auth.rs` are
  in-memory `HashMap`s with no TTL or cleanup. Auth codes must be short-lived
  (≤10 min, OAuth spec). Also unbounded: `/oauth/authorize/continue` and the open
  `/oauth/register` (DCR) let anyone grow the maps and `registered_clients` table
  without limit. Add expiry + periodic sweep; cap/rate-limit registration.

## High — should fix

- [ ] **DB errors panic request handlers.** `store_token`, `store_refresh_token`
  (`src/arcgis_auth.rs`) and `register_client` (`src/oauth/store.rs`) call
  `.expect(...)` on sqlx queries. A DB hiccup panics mid-request; `store_token`
  runs *after* the auth code is consumed, so a failure burns the code with no
  token issued (user stuck). Return proper `500`s; consider a `CatchPanicLayer`.

- [ ] **`redirect_uri` not verified at token exchange.** `/oauth/token` never
  compares `token_req.redirect_uri` against stored `pending.mcp_redirect_uri`
  (RFC 6749 §4.1.3). PKCE mitigates the main attack, but close the gap.

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
