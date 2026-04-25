use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use tokio::sync::Mutex;

pub struct FixedWindowRateLimiter {
    limit: usize,
    window: Duration,
    max_keys: usize,
    buckets: Mutex<HashMap<String, VecDeque<Instant>>>,
}

impl FixedWindowRateLimiter {
    pub fn new(limit: usize, window: Duration, max_keys: usize) -> Self {
        Self {
            limit,
            window,
            max_keys,
            buckets: Mutex::new(HashMap::new()),
        }
    }

    pub async fn allow(&self, key: String) -> bool {
        if self.limit == 0 || self.max_keys == 0 {
            return false;
        }

        let now = Instant::now();
        let mut guard = self.buckets.lock().await;

        if !guard.contains_key(&key) {
            ensure_capacity(&mut guard, self.max_keys, self.window, now);
            if guard.len() >= self.max_keys {
                return false;
            }
        }

        let bucket = guard.entry(key).or_insert_with(VecDeque::new);
        prune_bucket(bucket, self.window, now);

        if bucket.len() >= self.limit {
            return false;
        }

        bucket.push_back(now);
        true
    }

    pub async fn sweep(&self) {
        let now = Instant::now();
        let mut guard = self.buckets.lock().await;
        sweep_buckets(&mut guard, self.window, now);
    }
}

fn ensure_capacity(
    buckets: &mut HashMap<String, VecDeque<Instant>>,
    max_keys: usize,
    window: Duration,
    now: Instant,
) {
    if buckets.len() < max_keys {
        return;
    }

    sweep_buckets(buckets, window, now);

    if buckets.len() >= max_keys
        && let Some(oldest_key) = buckets
            .iter()
            .min_by_key(|(_, bucket)| bucket.back().copied().unwrap_or(now))
            .map(|(key, _)| key.clone())
    {
        buckets.remove(&oldest_key);
    }
}

fn sweep_buckets(buckets: &mut HashMap<String, VecDeque<Instant>>, window: Duration, now: Instant) {
    buckets.retain(|_, bucket| {
        prune_bucket(bucket, window, now);
        !bucket.is_empty()
    });
}

fn prune_bucket(bucket: &mut VecDeque<Instant>, window: Duration, now: Instant) {
    while let Some(front) = bucket.front() {
        if now.duration_since(*front) > window {
            bucket.pop_front();
        } else {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn rate_limiter_caps_tracked_keys() {
        let limiter = FixedWindowRateLimiter::new(10, Duration::from_secs(60), 2);

        assert!(limiter.allow("old".to_string()).await);
        tokio::time::sleep(Duration::from_millis(1)).await;
        assert!(limiter.allow("new".to_string()).await);
        tokio::time::sleep(Duration::from_millis(1)).await;
        assert!(limiter.allow("newer".to_string()).await);

        let guard = limiter.buckets.lock().await;
        assert_eq!(guard.len(), 2);
        assert!(!guard.contains_key("old"));
        assert!(guard.contains_key("new"));
        assert!(guard.contains_key("newer"));
    }

    #[tokio::test]
    async fn rate_limiter_sweeps_expired_keys_before_evicting() {
        let limiter = FixedWindowRateLimiter::new(10, Duration::from_millis(1), 2);

        assert!(limiter.allow("expired".to_string()).await);
        tokio::time::sleep(Duration::from_millis(2)).await;
        assert!(limiter.allow("valid".to_string()).await);
        assert!(limiter.allow("new".to_string()).await);

        let guard = limiter.buckets.lock().await;
        assert_eq!(guard.len(), 2);
        assert!(!guard.contains_key("expired"));
        assert!(guard.contains_key("valid"));
        assert!(guard.contains_key("new"));
    }
}
