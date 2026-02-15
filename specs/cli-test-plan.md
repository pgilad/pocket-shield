# CLI Test Plan: `pocket-shield` Binary E2E Harness

## Goal
Validate end-to-end authentication behavior by launching the real `pocket-shield` binary with temporary config/secrets and a local OIDC stub that replaces Pocket-ID.

## Scope
- Black-box process-level tests (no in-process handler shortcuts).
- Test full browser-style flow across:
  - `GET /verify`
  - `GET /login`
  - `GET /callback`
- Validate both positive and negative paths.

## Out of Scope
- Real Pocket-ID dependency.
- Persistent storage behavior (RAM-only sessions are expected).
- Caddy integration tests.

## Test Environment
- Rust integration tests in `tests/`.
- Spawned child process: `target/debug/pocket-shield`.
- Temporary files per test:
  - `config.toml`
  - `caddy shared secret`
  - `oidc client secret`
- Local OIDC stub server (Axum) on random localhost port.
- Gateway on random localhost port.

## Pocket-ID Stub Contract

### Endpoints
1. `GET /.well-known/openid-configuration`
2. `GET /jwks`
3. `GET /authorize`
4. `POST /token`

### Behavior
- `/authorize` validates query params and redirects to gateway callback with `code` + `state`.
- `/token` validates client auth and authorization code, then returns signed `id_token`.
- JWKS contains signing public key matching token signer key.
- Stub scenarios are configurable per test (groups, nonce mismatch, audience mismatch).

## Binary Launch
- Start gateway with:
  - `--config <temp-config>`
  - `--insecure` (for self-signed local TLS stub)
- Poll `/healthz` until ready (timeout required).
- Always terminate child process in test teardown.

## Test Cases

## 1. Positive Flow: Authenticated and Authorized
### Setup
- Host policy allows group `paperless-users`.
- Stub issues `id_token.groups=["paperless-users"]`.

### Steps
1. Call `/verify` without session cookie and with valid forwarded headers + shared secret.
2. Expect `302` to `/login?rd=...`.
3. Call `/login`; expect `302` to stub `/authorize`.
4. Follow `/authorize`; expect redirect to `/callback?code=...&state=...`.
5. Call `/callback`; expect `302` to original `rd` and `Set-Cookie`.
6. Call `/verify` again with session cookie.

### Assertions
- Final `/verify` returns `204`.
- Response includes `remote-user`.
- Response includes `remote-email` (if token contains email).
- Response includes `remote-groups`.

## 2. Negative Flow: Authenticated but Not Authorized
### Setup
- Host policy requires `paperless-users`.
- Stub issues `id_token.groups=["other-group"]`.

### Steps
1. Execute successful login flow to create session.
2. Call `/verify` with valid session for protected host.

### Assertions
- `/verify` returns `403`.
- No redirect loop (`302`) on this authorized-check path.

## 3. Negative Flow: Token Validation Failure (Nonce/Audience)
### Setup
- Stub issues token with wrong `nonce` (or wrong `aud`).

### Steps
1. Start login via `/login`.
2. Complete redirect to `/callback` with valid code/state.
3. Gateway performs token exchange and validation.

### Assertions
- `/callback` returns `401` (or configured auth failure status).
- No session cookie is set.
- Subsequent `/verify` remains unauthenticated and redirects to `/login`.

## Required Headers in `/verify` Requests
- `Auth-Gateway-Secret: <test secret>`
- `X-Forwarded-Host: <protected host>`
- `X-Forwarded-Proto: https`
- `X-Forwarded-Uri: /desired/path`

## Reliability Requirements
- Per-step timeout for all HTTP requests.
- Randomized ports to avoid collisions.
- No shared mutable global test state.
- Explicit cleanup for child processes and temp files.

## Acceptance Criteria
- All positive-path tests pass.
- All negative-path tests pass.
- `cargo test` exits successfully only when every required scenario passes.

## Suggested File Layout
- `tests/e2e_auth_flow.rs`:
  - process launcher
  - temp config/secrets helpers
  - flow driver
  - assertions
- `tests/common/oidc_stub.rs`:
  - stub server
  - scenario controls
  - signing + JWKS helpers
