use std::collections::HashMap;
use std::time::{Duration, Instant};

use tokio::sync::RwLock;

use crate::models::{IdentityClaims, LoginTransaction, SessionEntry};

pub struct SessionStore {
    inner: RwLock<HashMap<String, SessionEntry>>,
    ttl: Duration,
    max_sessions: usize,
}

impl SessionStore {
    pub fn new(ttl: Duration, max_sessions: usize) -> Self {
        Self {
            inner: RwLock::new(HashMap::new()),
            ttl,
            max_sessions,
        }
    }

    pub async fn insert(&self, session_id: String, claims: IdentityClaims) {
        let now = Instant::now();
        let entry = SessionEntry {
            claims,
            created_at: now,
            expires_at: now + self.ttl,
        };

        let mut guard = self.inner.write().await;

        if guard.len() >= self.max_sessions
            && let Some(oldest_key) = guard
                .iter()
                .min_by_key(|(_, session)| session.created_at)
                .map(|(key, _)| key.clone())
        {
            guard.remove(&oldest_key);
        }

        guard.insert(session_id, entry);
    }

    pub async fn get_valid(&self, session_id: &str) -> Option<IdentityClaims> {
        let now = Instant::now();
        let guard = self.inner.read().await;
        let session = guard.get(session_id)?;

        if session.expires_at <= now {
            return None;
        }

        Some(session.claims.clone())
    }

    pub async fn remove(&self, session_id: &str) {
        let mut guard = self.inner.write().await;
        guard.remove(session_id);
    }

    pub async fn sweep_expired(&self) {
        let now = Instant::now();
        let mut guard = self.inner.write().await;
        guard.retain(|_, session| session.expires_at > now);
    }
}

pub struct LoginStateStore {
    inner: RwLock<HashMap<String, LoginTransaction>>,
}

impl LoginStateStore {
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(HashMap::new()),
        }
    }

    pub async fn insert(&self, state: String, tx: LoginTransaction) {
        self.inner.write().await.insert(state, tx);
    }

    pub async fn take_valid(&self, state: &str) -> Option<LoginTransaction> {
        let now = Instant::now();
        let mut guard = self.inner.write().await;
        let tx = guard.remove(state)?;
        if tx.expires_at <= now {
            return None;
        }
        Some(tx)
    }

    pub async fn sweep_expired(&self) {
        let now = Instant::now();
        let mut guard = self.inner.write().await;
        guard.retain(|_, tx| tx.expires_at > now);
    }
}
