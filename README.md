# pocket-shield

<p align="center">
  <img src="images/mantis-logo.png" alt="pocket-shield logo" width="42%" />
</p>

<p align="center"><strong>Minimal OIDC <code>forward_auth</code> gateway for Caddy and homelab services.</strong></p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-green.svg" alt="License: MIT" /></a>
  <a href="https://www.rust-lang.org/"><img src="https://img.shields.io/badge/rust-1.93%2B-orange.svg" alt="Rust 1.93+" /></a>
</p>

Minimal OIDC gateway for Caddy-backed apps.

<code>pocket-shield</code> sits in front of your services, runs the OIDC login flow with your identity provider (for example Pocket-ID), and returns identity headers (`Remote-User`, `Remote-Email`, `Remote-Groups`) only after successful auth.

## Why use pocket-shield

- Fast verify hot path: `GET /verify` does local checks only, with no outbound network calls.
- Small and simple runtime: in-memory session/state stores, no database, low operational footprint.
- Practical security defaults: shared-secret gate, strict redirect validation, secure cookies, and host/group policy checks.
- Predictable deployment model: one binary, simple config file, and explicit Caddy integration.
- Flexible OIDC client model:
  - `single` mode for one OIDC client across hosts.
  - `multi` mode for host-specific client IDs/secrets.
- Container-friendly operation: built-in `--healthcheck` mode for probes.

## Quick Start

### 1. Build

```bash
cargo build --release
```

### 2. Create config and secrets

```bash
cp config.example.toml config.toml
mkdir -p ./secrets
printf 'replace-with-long-random-string\n' > ./secrets/gateway_auth_secret
printf 'replace-with-oidc-client-secret\n' > ./secrets/oidc_client_secret
```

Set these values in `config.toml`:

- `issuer`
- `gateway.public_base_url`
- `gateway.allowed_redirect_root_domain`
- `gateway.gateway_shared_secret_file`
- `[single_client]` or `[[multi_clients]]` secret file paths

### 3. Run

```bash
./target/release/pocket-shield --config ./config.toml
```

Equivalent env var form:

```bash
POCKET_SHIELD_CONFIG=./config.toml cargo run
```

If `--config` and `POCKET_SHIELD_CONFIG` are both omitted, default path is `config.yaml`.

## Docker

Build:

```bash
docker build -t pocket-shield:local .
```

Run:

```bash
docker run --rm -p 8080:8080 \
  -v "$(pwd)/config.toml:/config.toml:ro" \
  -v "$(pwd)/secrets:/run/secrets:ro" \
  -e POCKET_SHIELD_CONFIG=/config.toml \
  pocket-shield:local
```

## Workflow

1. Caddy calls `GET /verify` with forwarded headers and `Auth-Gateway-Secret`.
2. Missing or expired session returns `302` to `/login?rd=<original-url>`.
3. `/login` validates redirect target, creates OIDC state, and redirects to the IdP authorize endpoint.
4. `/callback` validates `state`, exchanges `code`, validates ID token, and sets session cookie.
5. Next `/verify` returns `204` and identity headers for the upstream app.

## Endpoints

| Endpoint | Method | Purpose |
|---|---|---|
| `/verify` | `GET` | Caddy auth check; returns `204`, `302`, or `403` |
| `/login` | `GET` | Starts OIDC Authorization Code flow |
| `/callback` | `GET` | Completes auth flow and establishes session |
| `/logout` | `GET`, `POST` | Clears session and redirects |
| `/healthz` | `GET` | Liveness endpoint (`200 ok`) |

`/verify` expects:

- `Auth-Gateway-Secret`
- `X-Forwarded-Host`
- `X-Forwarded-Proto`
- `X-Forwarded-Uri`

## Security Model

- Shared secret is required on `/verify`; mismatch returns `403`.
- Redirect targets (`rd`) must be HTTPS and inside `allowed_redirect_root_domain`.
- Redirect URLs containing userinfo are rejected.
- Session cookies are `Secure`, `HttpOnly`, and `SameSite=Lax`.
- Identity headers are injected only after successful authentication and authorization.
- Host-based authorization is enforced via `default_policy` and `host_policies`.
- Login and callback endpoints are rate-limited by source IP.
- OIDC discovery and JWKS are cached in memory; JWKS can refresh on `kid` miss.

## Configuration

Supports YAML, JSON, or TOML. Start from [`config.example.toml`](./config.example.toml).

### Single-client mode

```toml
issuer = "https://auth.example.com"
mode = "single"

[gateway]
public_base_url = "https://auth.example.com"
gateway_shared_secret_file = "/run/secrets/gateway_auth_secret"
cookie_domain = ".example.com"
allowed_redirect_root_domain = ".example.com"

[single_client]
client_id = "oidc-gw"
client_secret_file = "/run/secrets/oidc_gw_secret"
```

### Multi-client mode

```toml
mode = "multi"

[[multi_clients]]
host = "paperless.example.com"
client_id = "paperless"
client_secret_file = "/run/secrets/paperless_secret"

[[multi_clients]]
host = "immich.example.com"
client_id = "immich"
client_secret_file = "/run/secrets/immich_secret"
```

Group authorization:

- `default_policy.allowed_groups` applies when no host override exists.
- `[[host_policies]]` overrides allowed groups per host.
- Empty allowed-groups means "allow any authenticated user" for that host.

## Caddy Integration

Checklist:

- Route gateway endpoints (`/verify`, `/login`, `/callback`, `/logout`, `/healthz`) to `pocket-shield`.
- Send `Auth-Gateway-Secret` on `forward_auth`.
- Copy returned identity headers to upstream request headers.
- Strip client-supplied `Remote-*` headers before auth.

Example:

```caddyfile
{
  # Put this in your environment:
  # AUTH_GATEWAY_SECRET=...
}

auth.home.example.com {
  @gateway path /verify /login /callback /logout /healthz
  reverse_proxy @gateway pocket-shield:8080

  @pocketid path /.well-known/openid-configuration /authorize /token /jwks
  reverse_proxy @pocketid pocket-id:1411
}

paperless.home.example.com {
	header {
		-Remote-User
		-Remote-Email
		-Remote-Name
		-Remote-Groups
	}

	forward_auth pocket-shield:8080 {
		uri /verify
		copy_headers Remote-User Remote-Email Remote-Name Remote-Groups
		header_up Auth-Gateway-Secret {env.AUTH_GATEWAY_SECRET}
	}

	reverse_proxy paperless:8000
}
```

## Healthcheck Mode

Use binary-native health checks in minimal containers:

```bash
./target/release/pocket-shield --config ./config.toml --healthcheck
```

- Exit `0` on success, non-zero on failure.
- For wildcard binds, healthcheck auto-switches to loopback:
  - `0.0.0.0:8080` -> `127.0.0.1:8080`
  - `[::]:8080` -> `[::1]:8080`

## Development

```bash
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings
cargo test
cargo build --release
```

See `specs/cli-test-plan.md` for end-to-end auth flow test scenarios.

## Known Constraints

- Session and login state are in memory only; restart logs users out.
- The service is designed to run behind a trusted reverse proxy (Caddy).
- `/verify` should not be exposed publicly without network controls.

## License

MIT. See `LICENSE`.
