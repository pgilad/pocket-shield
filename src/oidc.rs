use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use jsonwebtoken::jwk::{Jwk, JwkSet};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use serde::Deserialize;
use tokio::sync::RwLock;
use url::Url;

use crate::models::IdentityClaims;

#[derive(Clone)]
pub struct OidcManager {
    issuer: String,
    internal_base_url: Option<Url>,
    http: reqwest::Client,
    cache_ttl: Duration,
    cache: std::sync::Arc<RwLock<OidcCache>>,
}

struct OidcCache {
    discovery: Option<Cached<DiscoveryDocument>>,
    jwks: Option<Cached<JwkSet>>,
}

struct Cached<T> {
    value: T,
    fetched_at: Instant,
}

#[derive(Clone, Deserialize)]
pub struct DiscoveryDocument {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
}

#[derive(Debug, Deserialize)]
pub struct TokenResponse {
    pub id_token: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum OidcError {
    #[error("missing kid in token header")]
    MissingKid,
    #[error("kid not found in JWKS")]
    KidNotFound,
    #[error("unsupported token algorithm")]
    UnsupportedAlgorithm,
    #[error("JWT validation failed: {0}")]
    Jwt(String),
    #[error("issuer mismatch")]
    IssuerMismatch,
    #[error("audience mismatch")]
    AudienceMismatch,
    #[error("missing nonce")]
    MissingNonce,
    #[error("nonce mismatch")]
    NonceMismatch,
}

impl OidcManager {
    pub fn new(issuer: String, internal_base_url: Option<Url>, http: reqwest::Client) -> Self {
        Self {
            issuer,
            internal_base_url,
            http,
            cache_ttl: Duration::from_secs(3600),
            cache: std::sync::Arc::new(RwLock::new(OidcCache {
                discovery: None,
                jwks: None,
            })),
        }
    }

    pub async fn initialize(&self) -> Result<()> {
        let discovery = self.fetch_discovery().await?;
        let jwks = self.fetch_jwks(&discovery.jwks_uri).await?;

        let mut cache = self.cache.write().await;
        cache.discovery = Some(Cached {
            value: discovery,
            fetched_at: Instant::now(),
        });
        cache.jwks = Some(Cached {
            value: jwks,
            fetched_at: Instant::now(),
        });

        Ok(())
    }

    pub async fn discovery(&self) -> Result<DiscoveryDocument> {
        {
            let cache = self.cache.read().await;
            if let Some(discovery) = &cache.discovery
                && discovery.fetched_at.elapsed() < self.cache_ttl
            {
                return Ok(discovery.value.clone());
            }
        }

        let discovery = self.fetch_discovery().await?;
        let mut cache = self.cache.write().await;
        cache.discovery = Some(Cached {
            value: discovery.clone(),
            fetched_at: Instant::now(),
        });
        Ok(discovery)
    }

    pub async fn refresh_jwks(&self) -> Result<JwkSet> {
        let discovery = self.discovery().await?;
        let jwks = self.fetch_jwks(&discovery.jwks_uri).await?;

        let mut cache = self.cache.write().await;
        cache.jwks = Some(Cached {
            value: jwks.clone(),
            fetched_at: Instant::now(),
        });
        Ok(jwks)
    }

    async fn jwks(&self) -> Result<JwkSet> {
        {
            let cache = self.cache.read().await;
            if let Some(jwks) = &cache.jwks
                && jwks.fetched_at.elapsed() < self.cache_ttl
            {
                return Ok(jwks.value.clone());
            }
        }

        self.refresh_jwks().await
    }

    pub async fn exchange_code(
        &self,
        client_id: &str,
        client_secret: &str,
        code: &str,
        redirect_uri: &str,
        code_verifier: Option<&str>,
    ) -> Result<TokenResponse> {
        let discovery = self.discovery().await?;

        let mut form = vec![
            ("grant_type", "authorization_code".to_string()),
            ("code", code.to_string()),
            ("redirect_uri", redirect_uri.to_string()),
        ];

        if let Some(verifier) = code_verifier {
            form.push(("code_verifier", verifier.to_string()));
        }

        let response = self
            .http
            .post(self.endpoint_for_internal_network(&discovery.token_endpoint)?)
            .basic_auth(client_id, Some(client_secret))
            .form(&form)
            .send()
            .await
            .context("token endpoint request failed")?;

        if !response.status().is_success() {
            bail!("token endpoint returned status {}", response.status());
        }

        response
            .json::<TokenResponse>()
            .await
            .context("token endpoint returned invalid JSON")
    }

    pub async fn validate_id_token(
        &self,
        id_token: &str,
        expected_client_id: &str,
        expected_nonce: &str,
    ) -> std::result::Result<IdentityClaims, OidcError> {
        let header = decode_header(id_token).map_err(|err| OidcError::Jwt(err.to_string()))?;
        let alg = normalize_algorithm(header.alg)?;
        let kid = header.kid.ok_or(OidcError::MissingKid)?;

        let jwks = self
            .jwks()
            .await
            .map_err(|err| OidcError::Jwt(err.to_string()))?;
        validate_with_jwks(
            &self.issuer,
            id_token,
            &kid,
            alg,
            &jwks,
            expected_client_id,
            expected_nonce,
        )
    }

    async fn fetch_discovery(&self) -> Result<DiscoveryDocument> {
        let mut base = if let Some(internal_base_url) = &self.internal_base_url {
            internal_base_url.clone()
        } else {
            Url::parse(&self.issuer).context("issuer must be a valid URL")?
        };
        base.set_path("/.well-known/openid-configuration");
        base.set_query(None);
        base.set_fragment(None);

        let response = self
            .http
            .get(base)
            .send()
            .await
            .context("OIDC discovery request failed")?;

        if !response.status().is_success() {
            bail!("OIDC discovery returned status {}", response.status());
        }

        let discovery = response
            .json::<DiscoveryDocument>()
            .await
            .context("invalid OIDC discovery payload")?;

        let expected = self.issuer.trim_end_matches('/');
        let actual = discovery.issuer.trim_end_matches('/');
        if actual != expected {
            bail!("discovery issuer mismatch: expected {expected}, got {actual}");
        }

        Ok(discovery)
    }

    async fn fetch_jwks(&self, jwks_uri: &str) -> Result<JwkSet> {
        let response = self
            .http
            .get(self.endpoint_for_internal_network(jwks_uri)?)
            .send()
            .await
            .context("JWKS request failed")?;

        if !response.status().is_success() {
            bail!("JWKS request returned status {}", response.status());
        }

        response
            .json::<JwkSet>()
            .await
            .context("invalid JWKS payload")
    }

    pub async fn validate_id_token_retry_on_kid_miss(
        &self,
        id_token: &str,
        expected_client_id: &str,
        expected_nonce: &str,
    ) -> std::result::Result<IdentityClaims, OidcError> {
        match self
            .validate_id_token(id_token, expected_client_id, expected_nonce)
            .await
        {
            Err(OidcError::KidNotFound) => {
                let jwks = self
                    .refresh_jwks()
                    .await
                    .map_err(|err| OidcError::Jwt(err.to_string()))?;

                let header =
                    decode_header(id_token).map_err(|err| OidcError::Jwt(err.to_string()))?;
                let kid = header.kid.ok_or(OidcError::MissingKid)?;
                let alg = normalize_algorithm(header.alg)?;

                validate_with_jwks(
                    &self.issuer,
                    id_token,
                    &kid,
                    alg,
                    &jwks,
                    expected_client_id,
                    expected_nonce,
                )
            }
            other => other,
        }
    }

    fn endpoint_for_internal_network(&self, endpoint: &str) -> Result<Url> {
        let mut url = Url::parse(endpoint).context("OIDC endpoint URL is invalid")?;
        if let Some(internal_base) = &self.internal_base_url {
            let scheme = internal_base.scheme();
            url.set_scheme(scheme)
                .map_err(|_| anyhow::anyhow!("failed to set OIDC endpoint scheme"))?;
            url.set_host(internal_base.host_str())
                .map_err(|err| anyhow::anyhow!("failed to set OIDC endpoint host: {err}"))?;
            url.set_port(internal_base.port())
                .map_err(|_| anyhow::anyhow!("failed to set OIDC endpoint port"))?;
        }
        Ok(url)
    }
}

fn validate_with_jwks(
    expected_issuer: &str,
    id_token: &str,
    kid: &str,
    alg: Algorithm,
    jwks: &JwkSet,
    expected_client_id: &str,
    expected_nonce: &str,
) -> std::result::Result<IdentityClaims, OidcError> {
    let jwk = find_jwk_by_kid(jwks, kid)?;
    let decoding_key =
        DecodingKey::from_jwk(jwk).map_err(|err| OidcError::Jwt(format!("invalid JWK: {err}")))?;

    let mut validation = Validation::new(alg);
    validation.validate_aud = false;
    validation.leeway = 60;

    let token_data = decode::<IdTokenClaims>(id_token, &decoding_key, &validation)
        .map_err(|err| OidcError::Jwt(err.to_string()))?;
    let claims = token_data.claims;

    if claims.iss.trim_end_matches('/') != expected_issuer.trim_end_matches('/') {
        return Err(OidcError::IssuerMismatch);
    }

    if !claims.aud.contains(expected_client_id) {
        return Err(OidcError::AudienceMismatch);
    }

    let nonce = claims.nonce.ok_or(OidcError::MissingNonce)?;
    if nonce != expected_nonce {
        return Err(OidcError::NonceMismatch);
    }

    Ok(IdentityClaims {
        sub: claims.sub,
        email: claims.email,
        name: claims.name,
        groups: claims.groups.map(GroupsClaim::into_vec).unwrap_or_default(),
    })
}

fn find_jwk_by_kid<'a>(jwks: &'a JwkSet, kid: &str) -> std::result::Result<&'a Jwk, OidcError> {
    jwks.keys
        .iter()
        .find(|key| key.common.key_id.as_deref() == Some(kid))
        .ok_or(OidcError::KidNotFound)
}

fn normalize_algorithm(alg: Algorithm) -> std::result::Result<Algorithm, OidcError> {
    match alg {
        Algorithm::RS256
        | Algorithm::RS384
        | Algorithm::RS512
        | Algorithm::ES256
        | Algorithm::ES384 => Ok(alg),
        _ => Err(OidcError::UnsupportedAlgorithm),
    }
}

#[derive(Debug, Deserialize)]
struct IdTokenClaims {
    iss: String,
    sub: String,
    aud: AudienceClaim,
    nonce: Option<String>,
    email: Option<String>,
    name: Option<String>,
    groups: Option<GroupsClaim>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum AudienceClaim {
    Single(String),
    Multiple(Vec<String>),
}

impl AudienceClaim {
    fn contains(&self, expected: &str) -> bool {
        match self {
            Self::Single(value) => value == expected,
            Self::Multiple(values) => values.iter().any(|value| value == expected),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum GroupsClaim {
    Single(String),
    Multiple(Vec<String>),
}

impl GroupsClaim {
    fn into_vec(self) -> Vec<String> {
        match self {
            Self::Single(value) => vec![value],
            Self::Multiple(values) => values,
        }
    }
}
