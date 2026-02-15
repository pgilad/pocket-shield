mod app;
mod config;
mod models;
mod oidc;
mod rate_limit;
mod store;
mod util;

use std::net::SocketAddr;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::bail;
use anyhow::{Context, Result};
use app::{AppState, build_router};
use clap::Parser;
use config::RuntimeConfig;
use oidc::OidcManager;
use rate_limit::FixedWindowRateLimiter;
use store::{LoginStateStore, SessionStore};
use tokio::net::TcpListener;
use tracing::info;
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(name = "pocket-shield")]
struct Cli {
    #[arg(long, env = "POCKET_SHIELD_CONFIG", default_value = "config.yaml")]
    config: String,
    #[arg(long)]
    healthcheck: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();

    let cli = Cli::parse();

    if cli.healthcheck {
        return run_healthcheck(&cli.config).await;
    }

    ensure_jwt_crypto_provider().context("failed to initialize jsonwebtoken crypto provider")?;

    let config = Arc::new(RuntimeConfig::load(&cli.config)?);

    let http = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(15))
        .build()
        .context("failed to build HTTP client")?;

    let oidc = OidcManager::new(
        config.issuer.clone(),
        config.oidc_internal_base_url.clone(),
        http,
    );
    oidc.initialize().await.context(
        "failed OIDC startup checks (discovery/JWKS); verify issuer DNS/TLS and connectivity",
    )?;

    let sessions = Arc::new(SessionStore::new(config.session_ttl, config.max_sessions));
    let login_states = Arc::new(LoginStateStore::new());
    let login_rate_limiter = Arc::new(FixedWindowRateLimiter::new(
        config.login_rate_limit_per_minute as usize,
        Duration::from_secs(60),
    ));
    let callback_rate_limiter = Arc::new(FixedWindowRateLimiter::new(
        config.callback_rate_limit_per_minute as usize,
        Duration::from_secs(60),
    ));

    spawn_cleanup_task(
        config.cleanup_interval,
        sessions.clone(),
        login_states.clone(),
        login_rate_limiter.clone(),
        callback_rate_limiter.clone(),
    );

    let state = AppState {
        config: config.clone(),
        sessions,
        login_states,
        oidc,
        login_rate_limiter,
        callback_rate_limiter,
    };

    let app = build_router(state);
    let listener = TcpListener::bind(&config.listen_addr)
        .await
        .with_context(|| format!("failed to bind {}", config.listen_addr))?;

    info!(addr = %config.listen_addr, "pocket-shield listening");

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await
    .context("server error")?;

    Ok(())
}

fn ensure_jwt_crypto_provider() -> Result<()> {
    let provider = &jsonwebtoken::crypto::aws_lc::DEFAULT_PROVIDER;
    match provider.install_default() {
        Ok(()) => Ok(()),
        Err(existing) if std::ptr::eq(existing, provider) => Ok(()),
        Err(_) => {
            bail!("jsonwebtoken crypto provider was already initialized to a different backend")
        }
    }
}

async fn run_healthcheck(config_path: &str) -> Result<()> {
    let config = RuntimeConfig::load(config_path)
        .with_context(|| format!("failed to load config for healthcheck from {config_path}"))?;
    let healthcheck_url = build_healthcheck_url(&config.listen_addr)?;

    let client = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(2))
        .timeout(Duration::from_secs(5))
        .build()
        .context("failed to build healthcheck HTTP client")?;

    let response = client
        .get(healthcheck_url.as_str())
        .send()
        .await
        .with_context(|| format!("healthcheck request failed for {healthcheck_url}"))?;

    if !response.status().is_success() {
        bail!(
            "healthcheck failed for {healthcheck_url}: status {}",
            response.status()
        );
    }

    Ok(())
}

fn build_healthcheck_url(listen_addr: &str) -> Result<String> {
    let socket_addr: SocketAddr = listen_addr
        .parse()
        .with_context(|| format!("invalid listen_addr for healthcheck: {listen_addr}"))?;

    let host = match socket_addr.ip() {
        IpAddr::V4(ip) if ip.is_unspecified() => IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(ip) if ip.is_unspecified() => IpAddr::V6(Ipv6Addr::LOCALHOST),
        ip => ip,
    };

    Ok(format!(
        "http://{}/healthz",
        SocketAddr::new(host, socket_addr.port())
    ))
}

fn init_tracing() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_target(false)
        .compact()
        .init();
}

fn spawn_cleanup_task(
    interval: Duration,
    sessions: Arc<SessionStore>,
    login_states: Arc<LoginStateStore>,
    login_rate_limiter: Arc<FixedWindowRateLimiter>,
    callback_rate_limiter: Arc<FixedWindowRateLimiter>,
) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        loop {
            ticker.tick().await;
            sessions.sweep_expired().await;
            login_states.sweep_expired().await;
            login_rate_limiter.sweep().await;
            callback_rate_limiter.sweep().await;
        }
    });
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let terminate = async {
        use tokio::signal::unix::{SignalKind, signal};
        if let Ok(mut signal) = signal(SignalKind::terminate()) {
            signal.recv().await;
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    info!("shutdown signal received");
}

#[cfg(test)]
mod tests {
    use super::{build_healthcheck_url, ensure_jwt_crypto_provider};

    #[test]
    fn jwt_crypto_provider_is_initialized() {
        ensure_jwt_crypto_provider().expect("expected jsonwebtoken crypto provider to initialize");
    }

    #[test]
    fn healthcheck_uses_loopback_for_unspecified_ipv4_bind() {
        let url = build_healthcheck_url("0.0.0.0:8080").expect("expected healthcheck URL");
        assert_eq!(url, "http://127.0.0.1:8080/healthz");
    }

    #[test]
    fn healthcheck_uses_loopback_for_unspecified_ipv6_bind() {
        let url = build_healthcheck_url("[::]:9090").expect("expected healthcheck URL");
        assert_eq!(url, "http://[::1]:9090/healthz");
    }

    #[test]
    fn healthcheck_preserves_specific_bind_ip() {
        let url = build_healthcheck_url("10.1.2.3:7070").expect("expected healthcheck URL");
        assert_eq!(url, "http://10.1.2.3:7070/healthz");
    }

    #[test]
    fn healthcheck_rejects_invalid_listen_addr() {
        assert!(build_healthcheck_url("localhost").is_err());
    }
}
