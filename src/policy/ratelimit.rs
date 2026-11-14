use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::config::RateLimitPolicy;
use crate::error::{GuardError, Result};

/// Enforces per-minute rate limits and detects repeated identical tool-call loops.
#[derive(Debug)]
pub struct RateLimiter {
    policy: RateLimitPolicy,
    state: Mutex<RateState>,
}

#[derive(Debug, Default)]
struct RateState {
    recent_calls: VecDeque<Instant>,
    loop_buckets: HashMap<[u8; 32], VecDeque<Instant>>,
}

impl RateLimiter {
    /// Create a new `RateLimiter` from `RateLimitPolicy`.
    pub fn new(policy: RateLimitPolicy) -> Self {
        Self {
            policy,
            state: Mutex::new(RateState::default()),
        }
    }

    /// Record a tool call and return `Err(GuardError::PolicyDenied)` if rate limit or loop breaker trips.
    pub fn check_and_record(&self, tool: &str, args: Option<&Value>) -> Result<()> {
        let now = Instant::now();
        let mut guard = self.state.lock().expect("rate limiter mutex poisoned");

        // 1. Sliding 60-second global rate limit
        if self.policy.max_calls_per_minute > 0 {
            let minute_ago = now - Duration::from_secs(60);
            while guard.recent_calls.front().is_some_and(|&t| t < minute_ago) {
                guard.recent_calls.pop_front();
            }
            if guard.recent_calls.len() >= self.policy.max_calls_per_minute as usize {
                return Err(GuardError::PolicyDenied(format!(
                    "rate limit exceeded ({} calls/min)",
                    self.policy.max_calls_per_minute
                )));
            }
            guard.recent_calls.push_back(now);
        }

        // 2. Loop breaker on identical (tool, arguments)
        if self.policy.loop_breaker_threshold > 0 {
            let window = Duration::from_secs(self.policy.loop_window_secs.max(1));
            let cutoff = now - window;
            let key = fingerprint_call(tool, args);
            let bucket = guard.loop_buckets.entry(key).or_default();
            while bucket.front().is_some_and(|&t| t < cutoff) {
                bucket.pop_front();
            }
            if bucket.len() >= self.policy.loop_breaker_threshold as usize {
                return Err(GuardError::PolicyDenied(format!(
                    "loop breaker triggered: tool '{tool}' called {} times with identical arguments within {}s",
                    self.policy.loop_breaker_threshold, self.policy.loop_window_secs
                )));
            }
            bucket.push_back(now);
        }

        Ok(())
    }
}

fn fingerprint_call(tool: &str, args: Option<&Value>) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(tool.as_bytes());
    hasher.update(b"\0");
    if let Some(v) = args {
        let serialized = serde_json::to_string(v).unwrap_or_default();
        hasher.update(serialized.as_bytes());
    }
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loop_breaker_trips_on_identical_calls() {
        let limiter = RateLimiter::new(RateLimitPolicy {
            max_calls_per_minute: 100,
            loop_breaker_threshold: 3,
            loop_window_secs: 60,
        });

        let args = serde_json::json!({ "path": "/workspace/a.txt" });
        assert!(limiter.check_and_record("read_file", Some(&args)).is_ok());
        assert!(limiter.check_and_record("read_file", Some(&args)).is_ok());
        assert!(limiter.check_and_record("read_file", Some(&args)).is_ok());
        let err = limiter
            .check_and_record("read_file", Some(&args))
            .unwrap_err();
        assert!(err.to_string().contains("loop breaker"));

        // Different arguments should still succeed
        let other = serde_json::json!({ "path": "/workspace/b.txt" });
        assert!(limiter.check_and_record("read_file", Some(&other)).is_ok());
    }
}
