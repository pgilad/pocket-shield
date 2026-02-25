use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use axum::Router;
use axum::extract::{ConnectInfo, Query, State};
use axum::http::header::{COOKIE, LOCATION, SET_COOKIE};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use cookie::time::Duration as CookieDuration;
use cookie::{Cookie, SameSite};
use serde::Deserialize;
use subtle::ConstantTimeEq;
use tower_http::trace::TraceLayer;
use tracing::{debug, error, info, warn};
use url::Url;

use crate::config::{Mode, RuntimeConfig, VerifyAllowLogLevel};
use crate::models::{IdentityClaims, LoginTransaction};
use crate::oidc::{OidcError, OidcManager};
use crate::rate_limit::FixedWindowRateLimiter;
use crate::store::{LoginStateStore, SessionStore};
use crate::util::{
    build_pkce_challenge, normalize_host, parse_x_forwarded_for, random_token,
    validate_redirect_url,
};

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<RuntimeConfig>,
    pub sessions: Arc<SessionStore>,
    pub login_states: Arc<LoginStateStore>,
    pub oidc: OidcManager,
    pub login_rate_limiter: Arc<FixedWindowRateLimiter>,
    pub callback_rate_limiter: Arc<FixedWindowRateLimiter>,
}

#[derive(Deserialize)]
struct LoginQuery {
    rd: Option<String>,
}

#[derive(Deserialize)]
struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
}

pub fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/verify", get(verify_handler))
        .route("/login", get(login_handler))
        .route("/callback", get(callback_handler))
        .route("/logout", get(logout_handler).post(logout_handler))
        .route("/healthz", get(healthz_handler))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

async fn verify_handler(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let request_id = request_id(&headers);
    let shared_secret = header_str(&headers, "auth-gateway-secret").unwrap_or_default();
    if !secrets_match(shared_secret, &state.config.gateway_shared_secret) {
        warn!(request_id = %request_id, outcome = "deny", reason = "shared_secret");
        return (StatusCode::FORBIDDEN, "forbidden").into_response();
    }

    let host = match header_str(&headers, "x-forwarded-host") {
        Some(value) if !value.is_empty() => normalize_host(value),
        _ => {
            warn!(request_id = %request_id, outcome = "deny", reason = "missing_host");
            return (StatusCode::BAD_REQUEST, "missing x-forwarded-host").into_response();
        }
    };

    let proto = header_str(&headers, "x-forwarded-proto").unwrap_or("https");
    let uri = header_str(&headers, "x-forwarded-uri").unwrap_or("/");
    let rd = format!("{proto}://{host}{uri}");

    let session_id = cookie_value(&headers, &state.config.cookie_name);

    let Some(session_id) = session_id else {
        info!(request_id = %request_id, host = %host, outcome = "redirect_login");
        return redirect_to_login(&state.config.public_base_url, &rd);
    };

    let Some(claims) = state.sessions.get_valid(&session_id).await else {
        info!(request_id = %request_id, host = %host, outcome = "redirect_login", reason = "expired_or_missing_session");
        return redirect_to_login(&state.config.public_base_url, &rd);
    };

    if !is_authorized(&state.config, &host, &claims) {
        info!(request_id = %request_id, host = %host, user = %claims.sub, outcome = "deny_not_authorized");
        return (StatusCode::FORBIDDEN, "forbidden").into_response();
    }

    let mut response = StatusCode::NO_CONTENT.into_response();
    inject_identity_headers(response.headers_mut(), &claims);
    log_verify_allow(&state.config, &request_id, &host, &claims.sub);
    response
}

async fn login_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Query(query): Query<LoginQuery>,
) -> Response {
    let request_id = request_id(&headers);
    let ip = source_ip(&headers, addr);
    if !state.login_rate_limiter.allow(format!("login:{ip}")).await {
        warn!(request_id = %request_id, ip = %ip, outcome = "rate_limited", endpoint = "/login");
        return (StatusCode::TOO_MANY_REQUESTS, "too many requests").into_response();
    }

    let rd_url = match query.rd {
        Some(rd) => match validate_redirect_url(&rd, &state.config.allowed_redirect_root_domain) {
            Ok(url) => url,
            Err(_) => {
                if let Some(fallback) = &state.config.safe_default_rd {
                    fallback.clone()
                } else {
                    return (StatusCode::BAD_REQUEST, "invalid rd").into_response();
                }
            }
        },
        None => match &state.config.safe_default_rd {
            Some(fallback) => fallback.clone(),
            None => return (StatusCode::BAD_REQUEST, "missing rd").into_response(),
        },
    };

    let host = normalize_host(rd_url.host_str().unwrap_or_default());
    let client = match state.config.client_for_host(&host) {
        Some(client) => client,
        None => {
            warn!(request_id = %request_id, host = %host, outcome = "deny_no_client");
            return (StatusCode::FORBIDDEN, "no configured OIDC client for host").into_response();
        }
    };

    let state_token = random_token(32);
    let nonce = random_token(32);

    let (pkce_verifier, pkce_challenge) = if state.config.enable_pkce {
        let verifier = random_token(32);
        let challenge = build_pkce_challenge(&verifier);
        (Some(verifier), Some(challenge))
    } else {
        (None, None)
    };

    state
        .login_states
        .insert(
            state_token.clone(),
            LoginTransaction {
                nonce: nonce.clone(),
                pkce_verifier,
                rd: rd_url.to_string(),
                client_key: client.key.clone(),
                expires_at: Instant::now() + state.config.login_ttl,
            },
        )
        .await;

    let discovery = match state.oidc.discovery().await {
        Ok(discovery) => discovery,
        Err(error) => {
            warn!(request_id = %request_id, outcome = "oidc_discovery_failed", error = %error);
            return (
                StatusCode::BAD_GATEWAY,
                "failed to initialize OIDC provider",
            )
                .into_response();
        }
    };

    let mut authorize_url = match Url::parse(&discovery.authorization_endpoint) {
        Ok(url) => url,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "invalid authorization endpoint",
            )
                .into_response();
        }
    };

    {
        let mut query_pairs = authorize_url.query_pairs_mut();
        query_pairs.append_pair("response_type", "code");
        query_pairs.append_pair("scope", &state.config.scopes);
        query_pairs.append_pair("client_id", &client.client_id);
        query_pairs.append_pair("redirect_uri", state.config.callback_url.as_ref());
        query_pairs.append_pair("state", &state_token);
        query_pairs.append_pair("nonce", &nonce);
        if let Some(challenge) = pkce_challenge {
            query_pairs.append_pair("code_challenge", &challenge);
            query_pairs.append_pair("code_challenge_method", "S256");
        }
    }

    info!(request_id = %request_id, host = %host, outcome = "redirect_oidc");
    redirect(authorize_url.as_ref())
}

async fn callback_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Query(query): Query<CallbackQuery>,
) -> Response {
    let request_id = request_id(&headers);
    let ip = source_ip(&headers, addr);
    if !state
        .callback_rate_limiter
        .allow(format!("callback:{ip}"))
        .await
    {
        warn!(request_id = %request_id, ip = %ip, endpoint = "/callback", outcome = "rate_limited");
        return (StatusCode::TOO_MANY_REQUESTS, "too many requests").into_response();
    }

    let state_token = match query.state {
        Some(state) => state,
        None => return (StatusCode::BAD_REQUEST, "missing state").into_response(),
    };
    let code = match query.code {
        Some(code) => code,
        None => return (StatusCode::BAD_REQUEST, "missing code").into_response(),
    };

    let login_tx = match state.login_states.take_valid(&state_token).await {
        Some(tx) => tx,
        None => {
            warn!(request_id = %request_id, outcome = "invalid_state");
            return (StatusCode::UNAUTHORIZED, "invalid or expired state").into_response();
        }
    };

    let client = match client_for_key(&state.config, &login_tx.client_key) {
        Some(client) => client,
        None => return (StatusCode::UNAUTHORIZED, "invalid client mapping").into_response(),
    };

    let token_response = match state
        .oidc
        .exchange_code(
            &client.client_id,
            &client.client_secret,
            &code,
            state.config.callback_url.as_ref(),
            login_tx.pkce_verifier.as_deref(),
        )
        .await
    {
        Ok(tokens) => tokens,
        Err(error) => {
            warn!(request_id = %request_id, outcome = "token_exchange_failed", error = %error);
            return (StatusCode::UNAUTHORIZED, "token exchange failed").into_response();
        }
    };

    let id_token = match token_response.id_token {
        Some(token) => token,
        None => return (StatusCode::UNAUTHORIZED, "id_token missing").into_response(),
    };

    let claims = match state
        .oidc
        .validate_id_token_retry_on_kid_miss(&id_token, &client.client_id, &login_tx.nonce)
        .await
    {
        Ok(claims) => claims,
        Err(error) => {
            warn!(request_id = %request_id, outcome = "id_token_invalid", error = %error);
            return oidc_error_response(error);
        }
    };

    let session_id = random_token(32);
    state
        .sessions
        .insert(session_id.clone(), claims.clone())
        .await;

    let mut response = redirect(&login_tx.rd);
    let cookie = build_session_cookie(&state.config, &session_id);
    if let Ok(value) = HeaderValue::from_str(&cookie.to_string()) {
        response.headers_mut().insert(SET_COOKIE, value);
    }

    info!(request_id = %request_id, user = %claims.sub, outcome = "login_success");
    response
}

async fn logout_handler(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Some(session_id) = cookie_value(&headers, &state.config.cookie_name) {
        state.sessions.remove(&session_id).await;
    }

    let mut response = redirect(state.config.logout_redirect.as_ref());
    let cookie = clear_session_cookie(&state.config);
    if let Ok(value) = HeaderValue::from_str(&cookie.to_string()) {
        response.headers_mut().insert(SET_COOKIE, value);
    }
    response
}

async fn healthz_handler() -> impl IntoResponse {
    (StatusCode::OK, "ok")
}

fn oidc_error_response(error: OidcError) -> Response {
    let message = match error {
        OidcError::KidNotFound
        | OidcError::MissingKid
        | OidcError::Jwt(_)
        | OidcError::UnsupportedAlgorithm
        | OidcError::IssuerMismatch
        | OidcError::AudienceMismatch
        | OidcError::MissingNonce
        | OidcError::NonceMismatch => "authentication failed",
    };
    (StatusCode::UNAUTHORIZED, message).into_response()
}

fn log_verify_allow(config: &RuntimeConfig, request_id: &str, host: &str, user: &str) {
    match config.allow_log_level {
        VerifyAllowLogLevel::Debug => {
            debug!(request_id = %request_id, host = %host, user = %user, outcome = "allow");
        }
        VerifyAllowLogLevel::Info => {
            info!(request_id = %request_id, host = %host, user = %user, outcome = "allow");
        }
        VerifyAllowLogLevel::Warn => {
            warn!(request_id = %request_id, host = %host, user = %user, outcome = "allow");
        }
        VerifyAllowLogLevel::Error => {
            error!(request_id = %request_id, host = %host, user = %user, outcome = "allow");
        }
        VerifyAllowLogLevel::Off => {}
    }
}

fn redirect_to_login(public_base: &Url, rd: &str) -> Response {
    let mut login_url = public_base
        .join("/login")
        .unwrap_or_else(|_| public_base.clone());
    {
        let mut pairs = login_url.query_pairs_mut();
        pairs.append_pair("rd", rd);
    }
    redirect(login_url.as_ref())
}

fn redirect(location: &str) -> Response {
    let mut response = StatusCode::FOUND.into_response();
    if let Ok(header_value) = HeaderValue::from_str(location) {
        response.headers_mut().insert(LOCATION, header_value);
    }
    response
}

fn inject_identity_headers(headers: &mut HeaderMap, claims: &IdentityClaims) {
    if let Ok(value) = HeaderValue::from_str(&claims.sub) {
        headers.insert("remote-user", value);
    }

    if let Some(email) = &claims.email
        && let Ok(value) = HeaderValue::from_str(email)
    {
        headers.insert("remote-email", value);
    }

    if let Some(name) = &claims.name
        && let Ok(value) = HeaderValue::from_str(name)
    {
        headers.insert("remote-name", value);
    }

    let groups = claims.groups.join(",");
    if !groups.is_empty()
        && let Ok(value) = HeaderValue::from_str(&groups)
    {
        headers.insert("remote-groups", value);
    }
}

fn is_authorized(config: &RuntimeConfig, host: &str, claims: &IdentityClaims) -> bool {
    let required_groups = config.allowed_groups_for_host(host);
    if required_groups.is_empty() {
        return true;
    }

    claims
        .groups
        .iter()
        .any(|group| required_groups.iter().any(|required| required == group))
}

fn source_ip(headers: &HeaderMap, addr: SocketAddr) -> String {
    if let Some(value) = header_str(headers, "x-forwarded-for")
        && let Some(ip) = parse_x_forwarded_for(value)
    {
        return ip;
    }

    addr.ip().to_string()
}

fn request_id(headers: &HeaderMap) -> String {
    header_str(headers, "x-request-id")
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| random_token(8))
}

fn build_session_cookie(config: &RuntimeConfig, session_id: &str) -> Cookie<'static> {
    Cookie::build((config.cookie_name.clone(), session_id.to_string()))
        .path("/")
        .domain(config.cookie_domain.clone())
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Lax)
        .max_age(CookieDuration::seconds(config.session_ttl.as_secs() as i64))
        .build()
}

fn clear_session_cookie(config: &RuntimeConfig) -> Cookie<'static> {
    Cookie::build((config.cookie_name.clone(), String::new()))
        .path("/")
        .domain(config.cookie_domain.clone())
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Lax)
        .max_age(CookieDuration::seconds(0))
        .build()
}

fn cookie_value(headers: &HeaderMap, cookie_name: &str) -> Option<String> {
    let cookie_header = headers.get(COOKIE)?.to_str().ok()?;

    for kv in cookie_header.split(';') {
        let mut parts = kv.trim().splitn(2, '=');
        let name = parts.next()?.trim();
        let value = parts.next()?.trim();
        if name == cookie_name {
            return Some(value.to_string());
        }
    }

    None
}

fn client_for_key<'a>(
    config: &'a RuntimeConfig,
    key: &str,
) -> Option<&'a crate::config::ClientConfig> {
    match config.mode {
        Mode::Single => config.single_client.as_ref(),
        Mode::Multi => config.clients_by_host.get(key),
    }
}

fn header_str<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name)?.to_str().ok()
}

fn secrets_match(lhs: &str, rhs: &str) -> bool {
    lhs.as_bytes().ct_eq(rhs.as_bytes()).into()
}
