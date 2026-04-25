# Repository Guidelines

## Project Structure & Module Organization
Core code lives in `src/` and is split by responsibility: `main.rs` boots the server, `app.rs` defines routes/handlers, `config.rs` loads runtime config, `oidc.rs` handles discovery/JWKS/token validation, and `store.rs`/`rate_limit.rs` manage in-memory state and limits. Keep new modules small and focused. Design and behavior specs live in `specs/` (`design.md`, `cli-test-plan.md`). Use `config.example.toml` as the safe template for local setup. Build artifacts go to `target/`.

## Build, Test, and Development Commands
- `cargo build --release`: build optimized binary (`target/release/pocket-shield`).
- `POCKET_SHIELD_CONFIG=./config.toml cargo run`: run locally using env-config path.
- `cargo run -- --config ./config.toml`: equivalent explicit CLI flag.
- `cargo run -- --config ./config.toml --healthcheck`: run in probe mode; performs `GET /healthz` against configured `gateway.listen_addr` and exits non-zero on failure.
- `cargo test`: run unit/integration tests.
- `cargo fmt --all`: apply standard Rust formatting.
- `cargo clippy --all-targets --all-features -- -D warnings`: enforce lint cleanliness.
- `cargo deny check`: validate dependency/license policy from `deny.toml`.

## Coding Style & Naming Conventions
Use Rust 2024 edition (`Cargo.toml`) with toolchain pinned in `mise.toml` (`rust = "1.95.0"`). Follow `rustfmt` defaults (4-space indentation). Use `snake_case` for files/modules/functions, `UpperCamelCase` for types/traits, and `UPPER_SNAKE_CASE` for constants. Prefer explicit error context (`anyhow::Context`) and avoid outbound I/O on the `/verify` hot path.

## Testing Guidelines
Place integration tests in `tests/` (see `specs/cli-test-plan.md` for expected layout and scenarios). Name tests by behavior, e.g. `verify_redirects_when_session_missing`. Cover both happy and failure paths (authorization failures, token validation failures, rate-limit edges). For auth-flow changes, add at least one end-to-end login/verify assertion and run `cargo test` before opening a PR.

## Commit & Pull Request Guidelines
This repository currently has no commit history; use Conventional Commit style going forward (`feat:`, `fix:`, `docs:`, `chore:`) with imperative, scoped subjects. PRs should include:
- What changed and why.
- Config/security impact (cookies, redirect validation, forwarded headers).
- Validation evidence (commands run, sample `curl` flow, or test output summary).
- Linked issue/spec section when applicable.

## Security & Configuration Tips
Never commit real secrets; keep client and shared secrets in files referenced by config. Require HTTPS issuer/base URLs and keep redirects constrained to the configured root domain. Preserve `Auth-Gateway-Secret` enforcement and header-spoofing protections in Caddy-facing flows.
