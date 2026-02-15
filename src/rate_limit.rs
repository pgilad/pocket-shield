use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use tokio::sync::Mutex;

pub struct FixedWindowRateLimiter {
    limit: usize,
    window: Duration,
    buckets: Mutex<HashMap<String, VecDeque<Instant>>>,
}

impl FixedWindowRateLimiter {
    pub fn new(limit: usize, window: Duration) -> Self {
        Self {
            limit,
            window,
            buckets: Mutex::new(HashMap::new()),
        }
    }

    pub async fn allow(&self, key: String) -> bool {
        let now = Instant::now();
        let mut guard = self.buckets.lock().await;
        let bucket = guard.entry(key).or_insert_with(VecDeque::new);

        while let Some(front) = bucket.front() {
            if now.duration_since(*front) > self.window {
                bucket.pop_front();
            } else {
                break;
            }
        }

        if bucket.len() >= self.limit {
            return false;
        }

        bucket.push_back(now);
        true
    }

    pub async fn sweep(&self) {
        let now = Instant::now();
        let mut guard = self.buckets.lock().await;
        guard.retain(|_, bucket| {
            while let Some(front) = bucket.front() {
                if now.duration_since(*front) > self.window {
                    bucket.pop_front();
                } else {
                    break;
                }
            }
            !bucket.is_empty()
        });
    }
}
