use std::time::Instant;

#[derive(Clone, Debug)]
pub struct IdentityClaims {
    pub sub: String,
    pub email: Option<String>,
    pub name: Option<String>,
    pub groups: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct SessionEntry {
    pub claims: IdentityClaims,
    pub created_at: Instant,
    pub expires_at: Instant,
}

#[derive(Clone, Debug)]
pub struct LoginTransaction {
    pub nonce: String,
    pub pkce_verifier: Option<String>,
    pub rd: String,
    pub client_key: String,
    pub expires_at: Instant,
}
