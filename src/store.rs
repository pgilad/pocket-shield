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
    max_states: usize,
}

impl LoginStateStore {
    pub fn new(max_states: usize) -> Self {
        Self {
            inner: RwLock::new(HashMap::new()),
            max_states,
        }
    }

    pub async fn insert(&self, state: String, tx: LoginTransaction) {
        let mut guard = self.inner.write().await;

        if guard.len() >= self.max_states {
            sweep_expired_login_states(&mut guard);
        }

        if guard.len() >= self.max_states
            && let Some(oldest_key) = guard
                .iter()
                .min_by_key(|(_, tx)| tx.expires_at)
                .map(|(key, _)| key.clone())
        {
            guard.remove(&oldest_key);
        }

        if guard.len() < self.max_states {
            guard.insert(state, tx);
        }
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
        let mut guard = self.inner.write().await;
        sweep_expired_login_states(&mut guard);
    }
}

fn sweep_expired_login_states(states: &mut HashMap<String, LoginTransaction>) {
    let now = Instant::now();
    states.retain(|_, tx| tx.expires_at > now);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn login_tx(expires_at: Instant) -> LoginTransaction {
        LoginTransaction {
            nonce: "nonce".to_string(),
            pkce_verifier: None,
            rd: "https://app.example.com/".to_string(),
            client_key: "single".to_string(),
            expires_at,
        }
    }

    #[tokio::test]
    async fn login_state_store_evicts_oldest_when_full() {
        let store = LoginStateStore::new(2);
        let now = Instant::now();

        store
            .insert("old".to_string(), login_tx(now + Duration::from_secs(10)))
            .await;
        store
            .insert("new".to_string(), login_tx(now + Duration::from_secs(20)))
            .await;
        store
            .insert("newer".to_string(), login_tx(now + Duration::from_secs(30)))
            .await;

        assert!(store.take_valid("old").await.is_none());
        assert!(store.take_valid("new").await.is_some());
        assert!(store.take_valid("newer").await.is_some());
    }

    #[tokio::test]
    async fn login_state_store_sweeps_expired_before_evicting() {
        let store = LoginStateStore::new(2);
        let now = Instant::now();

        store
            .insert(
                "expired".to_string(),
                login_tx(now - Duration::from_secs(1)),
            )
            .await;
        store
            .insert("valid".to_string(), login_tx(now + Duration::from_secs(20)))
            .await;
        store
            .insert("new".to_string(), login_tx(now + Duration::from_secs(30)))
            .await;

        assert!(store.take_valid("expired").await.is_none());
        assert!(store.take_valid("valid").await.is_some());
        assert!(store.take_valid("new").await.is_some());
    }
}
