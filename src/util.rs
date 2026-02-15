use anyhow::{Result, bail};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand::RngExt;
use sha2::{Digest, Sha256};
use url::Url;

pub fn normalize_host(host: &str) -> String {
    let host = host.trim().to_ascii_lowercase();

    if let Some(stripped) = host.strip_prefix('[')
        && let Some(end) = stripped.find(']')
    {
        return stripped[..end].to_string();
    }

    host.split(':')
        .next()
        .unwrap_or_default()
        .trim_end_matches('.')
        .to_string()
}

pub fn validate_redirect_url(rd: &str, allowed_root_domain: &str) -> Result<Url> {
    let mut url = Url::parse(rd)?;

    if url.scheme() != "https" {
        bail!("redirect URL must use https");
    }
    if !url.username().is_empty() || url.password().is_some() {
        bail!("redirect URL userinfo is not allowed");
    }

    let host = url
        .host_str()
        .map(normalize_host)
        .ok_or_else(|| anyhow::anyhow!("redirect URL host is missing"))?;

    let allowed = allowed_root_domain
        .trim()
        .trim_start_matches('.')
        .to_ascii_lowercase();

    let allowed_suffix = format!(".{allowed}");
    if host != allowed && !host.ends_with(&allowed_suffix) {
        bail!("redirect URL host is outside allowed domain");
    }

    url.set_fragment(None);

    Ok(url)
}

pub fn random_token(bytes_len: usize) -> String {
    let mut bytes = vec![0_u8; bytes_len];
    rand::rng().fill(&mut bytes[..]);
    URL_SAFE_NO_PAD.encode(bytes)
}

pub fn build_pkce_challenge(verifier: &str) -> String {
    let digest = Sha256::digest(verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(digest)
}

pub fn parse_x_forwarded_for(value: &str) -> Option<String> {
    let first = value.split(',').next()?.trim();
    if first.is_empty() {
        None
    } else {
        Some(first.to_string())
    }
}
