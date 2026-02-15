use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use url::Url;

use crate::util::{normalize_host, validate_redirect_url};

#[derive(Clone)]
pub struct RuntimeConfig {
    /// OIDC issuer URL used for discovery and token validation.
    /// Impact: must match the identity provider's issuer claim.
    /// Default: required (no fallback).
    pub issuer: String,
    /// Optional internal OIDC base URL used instead of `issuer` for back-channel calls.
    /// Impact: lets the service reach IdP through private networking.
    /// Default: `None` (use `issuer`).
    pub oidc_internal_base_url: Option<Url>,
    /// Bind address for the HTTP server.
    /// Impact: controls which interface/port accepts inbound traffic.
    /// Default: `"0.0.0.0:8080"`.
    pub listen_addr: String,
    /// Public HTTPS base URL for this gateway.
    /// Impact: used to build externally visible links and callback URL.
    /// Default: required (no fallback).
    pub public_base_url: Url,
    /// OAuth callback URL derived from `public_base_url + /callback`.
    /// Impact: must match redirect URI configured at the IdP.
    /// Default: computed from `public_base_url`.
    pub callback_url: Url,
    /// Shared secret expected from authenticated upstream gateway requests.
    /// Impact: protects gateway endpoints from unauthorized direct access.
    /// Default: required via `gateway.gateway_shared_secret_file`.
    pub gateway_shared_secret: String,
    /// Session cookie name.
    /// Impact: changes cookie key used by clients and proxies.
    /// Default: `"pocket_shield_session"`.
    pub cookie_name: String,
    /// Cookie domain suffix used when setting session cookies.
    /// Impact: controls which hosts receive the session cookie.
    /// Default: `".example.com"`.
    pub cookie_domain: String,
    /// Maximum lifetime of an authenticated session.
    /// Impact: longer values reduce re-login frequency and increase token persistence.
    /// Default: `43_200s` (12 hours).
    pub session_ttl: Duration,
    /// Maximum lifetime of an in-progress login flow.
    /// Impact: limits window for callback completion.
    /// Default: `600s` (10 minutes).
    pub login_ttl: Duration,
    /// Period between cleanup passes for expired login/session state.
    /// Impact: lower values reclaim memory faster, higher values reduce cleanup churn.
    /// Default: `300s` (5 minutes).
    pub cleanup_interval: Duration,
    /// Soft cap on number of active session records retained in memory.
    /// Impact: bounds memory usage and can evict older sessions when pressure increases.
    /// Default: `10_000`.
    pub max_sessions: usize,
    /// Space-delimited OAuth scopes requested during login.
    /// Impact: determines claims/permissions available in returned tokens.
    /// Default: `"openid email profile groups"`.
    pub scopes: String,
    /// Enables PKCE for OAuth authorization code flow.
    /// Impact: adds protection against intercepted authorization codes.
    /// Default: `true`.
    pub enable_pkce: bool,
    /// Root domain suffix allowed for post-login redirect targets.
    /// Impact: blocks open redirect to external domains.
    /// Default: `".example.com"`.
    pub allowed_redirect_root_domain: String,
    /// Optional safe fallback redirect target after login.
    /// Impact: used when requested redirect is absent or invalid.
    /// Default: `None`.
    pub safe_default_rd: Option<Url>,
    /// Redirect URL used after logout.
    /// Impact: controls where users land after session termination.
    /// Default: `safe_default_rd`, else `public_base_url`.
    pub logout_redirect: Url,
    /// Deployment mode controlling client selection behavior.
    /// Impact: `Single` uses one client; `Multi` selects client by host.
    /// Default: required (`single` or `multi` in config).
    pub mode: Mode,
    /// Single OIDC client credentials used when `mode == Single`.
    /// Impact: ignored in multi-tenant mode.
    /// Default: `None` unless mode is `single`.
    pub single_client: Option<ClientConfig>,
    /// OIDC clients keyed by normalized host when `mode == Multi`.
    /// Impact: determines which client ID/secret is used per incoming host.
    /// Default: empty map unless mode is `multi`.
    pub clients_by_host: HashMap<String, ClientConfig>,
    /// Per-host group authorization overrides.
    /// Impact: replaces default group policy for matching hosts.
    /// Default: empty map.
    pub host_allowed_groups: HashMap<String, Vec<String>>,
    /// Default allowed groups when no host-specific policy exists.
    /// Impact: primary authorization gate for hosts without overrides.
    /// Default: empty list.
    pub default_allowed_groups: Vec<String>,
    /// Allowed login attempts per minute per limiter key.
    /// Impact: throttles start of auth flow to reduce abuse.
    /// Default: `60`.
    pub login_rate_limit_per_minute: u32,
    /// Allowed callback requests per minute per limiter key.
    /// Impact: throttles callback endpoint to reduce abuse/noise.
    /// Default: `60`.
    pub callback_rate_limit_per_minute: u32,
}

#[derive(Clone)]
pub enum Mode {
    /// Use a single OIDC client for all hosts.
    Single,
    /// Select OIDC client by normalized request host.
    Multi,
}

#[derive(Clone)]
pub struct ClientConfig {
    /// Stable key used internally to identify this client entry.
    /// Impact: used in logs/state associations.
    /// Default: required; `"single"` in single mode, or host key in multi mode.
    pub key: String,
    /// OIDC client ID sent to the identity provider.
    /// Impact: identifies the relying party application.
    /// Default: required (no fallback).
    pub client_id: String,
    /// OIDC client secret used for token exchange/authentication.
    /// Impact: sensitive credential; must match IdP client configuration.
    /// Default: required via secret file (no fallback).
    pub client_secret: String,
}

#[derive(Debug, Deserialize)]
struct FileConfig {
    /// OIDC issuer URL from config file.
    /// Impact: defines discovery, JWKS, and issuer validation target.
    /// Default: required.
    issuer: String,
    /// Gateway-level settings for listener/cookies/redirect behavior.
    /// Impact: drives most runtime network and session behavior.
    /// Default: required.
    gateway: GatewayConfig,
    /// Operating mode string (`single` or `multi`).
    /// Impact: controls whether host-based client routing is enabled.
    /// Default: required.
    mode: String,
    /// Credentials for single-client mode.
    /// Impact: required only when `mode=single`.
    /// Default: `None`.
    single_client: Option<SingleClientConfig>,
    /// Host-scoped clients for multi-client mode.
    /// Impact: required and must be non-empty when `mode=multi`.
    /// Default: `None`.
    multi_clients: Option<Vec<MultiClientConfig>>,
    /// Global authorization fallback policy.
    /// Impact: provides default allowed groups for hosts without overrides.
    /// Default: `None` (empty allowed group list).
    default_policy: Option<PolicyConfig>,
    /// Host-specific authorization policy overrides.
    /// Impact: overrides global allowed groups per host.
    /// Default: `None`.
    host_policies: Option<Vec<HostPolicyConfig>>,
    /// Per-endpoint rate-limit configuration.
    /// Impact: protects login/callback endpoints from abuse.
    /// Default: `None` (both limits fall back to 60/minute).
    rate_limit: Option<RateLimitConfig>,
}

#[derive(Debug, Deserialize)]
struct GatewayConfig {
    /// Public HTTPS base URL for this service.
    /// Impact: used to build callback URL and fallback redirects.
    /// Default: required.
    public_base_url: String,
    /// Optional internal OIDC URL for back-channel traffic.
    /// Impact: decouples user-facing issuer from server-to-server routing.
    /// Default: `None`.
    oidc_internal_base_url: Option<String>,
    /// Path to file containing the shared secret expected from the upstream gateway.
    /// Impact: requests without matching secret are rejected.
    /// Default: required.
    gateway_shared_secret_file: String,
    /// Listener bind address.
    /// Impact: controls where HTTP server accepts traffic.
    /// Default: `"0.0.0.0:8080"`.
    listen_addr: Option<String>,
    /// Session TTL in seconds.
    /// Impact: controls login persistence duration.
    /// Default: `43_200`.
    session_ttl_seconds: Option<u64>,
    /// Login transaction TTL in seconds.
    /// Impact: limits how long auth callback state remains valid.
    /// Default: `600`.
    login_ttl_seconds: Option<u64>,
    /// Cleanup cadence in seconds.
    /// Impact: affects how quickly expired state is purged.
    /// Default: `300`.
    cleanup_interval_seconds: Option<u64>,
    /// Maximum active sessions retained.
    /// Impact: bounds in-memory session storage.
    /// Default: `10_000`.
    max_sessions: Option<usize>,
    /// Cookie domain suffix.
    /// Impact: defines host scope for session cookie delivery.
    /// Default: `".example.com"`.
    cookie_domain: Option<String>,
    /// Session cookie name.
    /// Impact: changes cookie key used by browsers and intermediaries.
    /// Default: `"pocket_shield_session"`.
    cookie_name: Option<String>,
    /// OAuth scope list requested at authorization time.
    /// Impact: controls claims and permissions requested from IdP.
    /// Default: `["openid", "email", "profile", "groups"]`.
    scopes: Option<Vec<String>>,
    /// Enable PKCE in auth code flow.
    /// Impact: hardens code exchange against interception.
    /// Default: `true`.
    enable_pkce: Option<bool>,
    /// Optional known-safe default redirect URL.
    /// Impact: fallback target when no valid `rd` is supplied.
    /// Default: `None`.
    safe_default_rd: Option<String>,
    /// Post-logout redirect URL.
    /// Impact: determines destination after logout.
    /// Default: `safe_default_rd`, else `public_base_url`.
    logout_redirect: Option<String>,
    /// Allowed redirect domain suffix.
    /// Impact: restricts redirects to trusted domains.
    /// Default: `".example.com"`.
    allowed_redirect_root_domain: Option<String>,
}

#[derive(Debug, Deserialize)]
struct SingleClientConfig {
    /// OIDC client ID for single mode.
    /// Impact: identifies this relying party at the IdP.
    /// Default: required.
    client_id: String,
    /// Path to file containing client secret for single mode.
    /// Impact: used to authenticate token exchange.
    /// Default: required.
    client_secret_file: String,
}

#[derive(Debug, Deserialize)]
struct MultiClientConfig {
    /// Hostname this client configuration applies to.
    /// Impact: selects client credentials by incoming host.
    /// Default: required.
    host: String,
    /// OIDC client ID for this host.
    /// Impact: identifies host-specific relying party at the IdP.
    /// Default: required.
    client_id: String,
    /// Path to file containing client secret for this host.
    /// Impact: used for host-specific token exchange authentication.
    /// Default: required.
    client_secret_file: String,
    /// Optional allowed-groups override for this host.
    /// Impact: overrides `default_policy.allowed_groups` for matching host.
    /// Default: `None`.
    allowed_groups: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct HostPolicyConfig {
    /// Hostname this policy applies to.
    /// Impact: routes authorization checks to host-specific group list.
    /// Default: required.
    host: String,
    /// Allowed groups for the specified host.
    /// Impact: replaces default allowed-groups policy for this host.
    /// Default: required.
    allowed_groups: Vec<String>,
}

#[derive(Debug, Deserialize, Default)]
struct PolicyConfig {
    /// Default allowed groups for hosts without explicit policy.
    /// Impact: global authorization fallback.
    /// Default: `None` (treated as empty list).
    allowed_groups: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, Default)]
struct RateLimitConfig {
    /// Login endpoint request budget per minute.
    /// Impact: throttles authorization-start traffic.
    /// Default: `None` (falls back to `60`).
    login_per_minute: Option<u32>,
    /// Callback endpoint request budget per minute.
    /// Impact: throttles callback processing traffic.
    /// Default: `None` (falls back to `60`).
    callback_per_minute: Option<u32>,
}

impl RuntimeConfig {
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let raw = fs::read_to_string(path)
            .with_context(|| format!("failed to read config file {}", path.display()))?;

        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| e.to_ascii_lowercase());

        let parsed: FileConfig = match ext.as_deref() {
            Some("json") => serde_json::from_str(&raw).context("invalid JSON config")?,
            Some("toml") => toml::from_str(&raw).context("invalid TOML config")?,
            Some("yaml") | Some("yml") => {
                serde_yaml::from_str(&raw).context("invalid YAML config")?
            }
            _ => serde_yaml::from_str(&raw)
                .or_else(|_| serde_json::from_str(&raw))
                .or_else(|_| toml::from_str(&raw))
                .context("invalid YAML/JSON/TOML config")?,
        };

        let mode = match parsed.mode.trim().to_ascii_lowercase().as_str() {
            "single" => Mode::Single,
            "multi" => Mode::Multi,
            value => bail!("unsupported mode: {value}"),
        };

        let issuer = normalize_issuer(&parsed.issuer)?;
        let oidc_internal_base_url = parsed
            .gateway
            .oidc_internal_base_url
            .as_deref()
            .map(normalize_oidc_internal_base_url)
            .transpose()?;

        let public_base_url = Url::parse(&parsed.gateway.public_base_url)
            .context("gateway.public_base_url must be a valid URL")?;
        if public_base_url.scheme() != "https" {
            bail!("gateway.public_base_url must use https");
        }

        let callback_url = public_base_url
            .join("/callback")
            .context("failed to build callback URL")?;

        let allowed_redirect_root_domain = parsed
            .gateway
            .allowed_redirect_root_domain
            .unwrap_or_else(|| ".example.com".to_string());

        let safe_default_rd = match parsed.gateway.safe_default_rd {
            Some(rd) => {
                let url = validate_redirect_url(&rd, &allowed_redirect_root_domain).context(
                    "gateway.safe_default_rd is invalid: must be https and under allowed domain",
                )?;
                Some(url)
            }
            None => None,
        };

        let logout_redirect = match parsed.gateway.logout_redirect {
            Some(url) => validate_redirect_url(&url, &allowed_redirect_root_domain)
                .context("gateway.logout_redirect is invalid")?,
            None => safe_default_rd
                .clone()
                .unwrap_or_else(|| public_base_url.clone()),
        };

        let shared_secret = read_secret_file(&parsed.gateway.gateway_shared_secret_file)
            .context("failed reading gateway.gateway_shared_secret_file")?;

        let default_allowed_groups = parsed
            .default_policy
            .unwrap_or_default()
            .allowed_groups
            .unwrap_or_default();

        let mut host_allowed_groups = HashMap::new();
        if let Some(host_policies) = parsed.host_policies {
            for policy in host_policies {
                let host = normalize_host(&policy.host);
                host_allowed_groups.insert(host, policy.allowed_groups);
            }
        }

        let mut clients_by_host = HashMap::new();
        let mut single_client = None;

        match mode {
            Mode::Single => {
                let single = parsed
                    .single_client
                    .context("single_client is required in mode=single")?;
                let secret = read_secret_file(&single.client_secret_file)
                    .context("failed reading single_client.client_secret_file")?;
                single_client = Some(ClientConfig {
                    key: "single".to_string(),
                    client_id: single.client_id,
                    client_secret: secret,
                });
            }
            Mode::Multi => {
                let multi_clients = parsed
                    .multi_clients
                    .context("multi_clients is required in mode=multi")?;
                if multi_clients.is_empty() {
                    bail!("multi_clients must not be empty");
                }

                for client in multi_clients {
                    let host = normalize_host(&client.host);
                    let secret =
                        read_secret_file(&client.client_secret_file).with_context(|| {
                            format!(
                                "failed reading client secret for host {} from {}",
                                host, client.client_secret_file
                            )
                        })?;

                    if let Some(allowed_groups) = client.allowed_groups {
                        host_allowed_groups.insert(host.clone(), allowed_groups);
                    }

                    clients_by_host.insert(
                        host.clone(),
                        ClientConfig {
                            key: host,
                            client_id: client.client_id,
                            client_secret: secret,
                        },
                    );
                }
            }
        }

        let scopes = parsed
            .gateway
            .scopes
            .unwrap_or_else(|| {
                vec![
                    "openid".to_string(),
                    "email".to_string(),
                    "profile".to_string(),
                    "groups".to_string(),
                ]
            })
            .join(" ");

        let rate_limit = parsed.rate_limit.unwrap_or_default();

        Ok(Self {
            issuer,
            oidc_internal_base_url,
            listen_addr: parsed
                .gateway
                .listen_addr
                .unwrap_or_else(|| "0.0.0.0:8080".to_string()),
            public_base_url,
            callback_url,
            gateway_shared_secret: shared_secret,
            cookie_name: parsed
                .gateway
                .cookie_name
                .unwrap_or_else(|| "pocket_shield_session".to_string()),
            cookie_domain: parsed
                .gateway
                .cookie_domain
                .unwrap_or_else(|| ".example.com".to_string()),
            session_ttl: Duration::from_secs(parsed.gateway.session_ttl_seconds.unwrap_or(43_200)),
            login_ttl: Duration::from_secs(parsed.gateway.login_ttl_seconds.unwrap_or(600)),
            cleanup_interval: Duration::from_secs(
                parsed.gateway.cleanup_interval_seconds.unwrap_or(300),
            ),
            max_sessions: parsed.gateway.max_sessions.unwrap_or(10_000),
            scopes,
            enable_pkce: parsed.gateway.enable_pkce.unwrap_or(true),
            allowed_redirect_root_domain,
            safe_default_rd,
            logout_redirect,
            mode,
            single_client,
            clients_by_host,
            host_allowed_groups,
            default_allowed_groups,
            login_rate_limit_per_minute: rate_limit.login_per_minute.unwrap_or(60),
            callback_rate_limit_per_minute: rate_limit.callback_per_minute.unwrap_or(60),
        })
    }

    pub fn client_for_host(&self, host: &str) -> Option<&ClientConfig> {
        let normalized = normalize_host(host);
        match self.mode {
            Mode::Single => self.single_client.as_ref(),
            Mode::Multi => self.clients_by_host.get(&normalized),
        }
    }

    pub fn allowed_groups_for_host(&self, host: &str) -> &[String] {
        let normalized = normalize_host(host);
        if let Some(groups) = self.host_allowed_groups.get(&normalized) {
            groups
        } else {
            &self.default_allowed_groups
        }
    }
}

fn read_secret_file(path: &str) -> Result<String> {
    let secret = fs::read_to_string(path)
        .with_context(|| format!("failed to read secret file at {path}"))?
        .trim()
        .to_string();

    if secret.is_empty() {
        bail!("secret file {path} is empty");
    }

    Ok(secret)
}

fn normalize_issuer(issuer: &str) -> Result<String> {
    let mut url = Url::parse(issuer).context("issuer must be a valid URL")?;
    if url.scheme() != "https" {
        bail!("issuer must use https");
    }

    let path = url.path().trim_end_matches('/').to_string();
    if path.is_empty() {
        url.set_path("/");
    } else {
        url.set_path(&path);
    }

    Ok(url.to_string().trim_end_matches('/').to_string())
}

fn normalize_oidc_internal_base_url(raw: &str) -> Result<Url> {
    let mut url = Url::parse(raw).context("gateway.oidc_internal_base_url must be a valid URL")?;
    match url.scheme() {
        "http" | "https" => {}
        _ => bail!("gateway.oidc_internal_base_url must use http or https"),
    }

    if url.host_str().is_none() {
        bail!("gateway.oidc_internal_base_url must include a host");
    }
    if !url.username().is_empty() || url.password().is_some() {
        bail!("gateway.oidc_internal_base_url userinfo is not allowed");
    }
    if url.path() != "/" && !url.path().is_empty() {
        bail!("gateway.oidc_internal_base_url must not include a path");
    }

    url.set_path("/");
    url.set_query(None);
    url.set_fragment(None);

    Ok(url)
}
