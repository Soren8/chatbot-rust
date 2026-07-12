//! In-process sliding-window rate limiter (per-key + global).

use once_cell::sync::Lazy;
use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, Instant};

const WINDOW: Duration = Duration::from_secs(60);

static LIMITER: Lazy<Mutex<RateLimiter>> = Lazy::new(|| Mutex::new(RateLimiter::new()));

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RateLimitExceeded {
    pub retry_after_secs: u64,
    pub scope: RateLimitScope,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateLimitScope {
    PerUser,
    Global,
}

#[derive(Debug, Default)]
struct RateLimiter {
    per_key: HashMap<String, VecDeque<Instant>>,
    global: VecDeque<Instant>,
}

impl RateLimiter {
    fn new() -> Self {
        Self::default()
    }

    fn prune(queue: &mut VecDeque<Instant>, now: Instant) {
        while queue
            .front()
            .is_some_and(|t| now.duration_since(*t) >= WINDOW)
        {
            queue.pop_front();
        }
    }

    fn retry_after(queue: &VecDeque<Instant>, now: Instant) -> u64 {
        queue
            .front()
            .map(|oldest| {
                WINDOW
                    .checked_sub(now.duration_since(*oldest))
                    .unwrap_or(Duration::from_secs(1))
                    .as_secs()
                    .max(1)
            })
            .unwrap_or(1)
    }

    /// Record a request for `key` if under limits. `0` disables that dimension.
    fn check(
        &mut self,
        key: &str,
        per_user_limit: u32,
        global_limit: u32,
    ) -> Result<(), RateLimitExceeded> {
        if per_user_limit == 0 && global_limit == 0 {
            return Ok(());
        }

        let now = Instant::now();

        if global_limit > 0 {
            Self::prune(&mut self.global, now);
            if self.global.len() as u32 >= global_limit {
                return Err(RateLimitExceeded {
                    retry_after_secs: Self::retry_after(&self.global, now),
                    scope: RateLimitScope::Global,
                });
            }
        }

        if per_user_limit > 0 {
            let queue = self.per_key.entry(key.to_owned()).or_default();
            Self::prune(queue, now);
            if queue.len() as u32 >= per_user_limit {
                return Err(RateLimitExceeded {
                    retry_after_secs: Self::retry_after(queue, now),
                    scope: RateLimitScope::PerUser,
                });
            }
            queue.push_back(now);
        }

        if global_limit > 0 {
            self.global.push_back(now);
        }

        // Drop empty per-key queues occasionally to bound memory.
        if self.per_key.len() > 10_000 {
            self.per_key.retain(|_, q| {
                Self::prune(q, now);
                !q.is_empty()
            });
        }

        Ok(())
    }

    fn clear(&mut self) {
        self.per_key.clear();
        self.global.clear();
    }
}

/// Check and record against the process-wide limiter.
pub fn check(key: &str, per_user_limit: u32, global_limit: u32) -> Result<(), RateLimitExceeded> {
    LIMITER
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .check(key, per_user_limit, global_limit)
}

/// Clear counters (tests).
pub fn reset() {
    LIMITER
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .clear();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_under_per_user_limit() {
        reset();
        for _ in 0..3 {
            assert!(check("user:a", 3, 0).is_ok());
        }
    }

    #[test]
    fn refuses_over_per_user_limit() {
        reset();
        for _ in 0..2 {
            check("user:b", 2, 0).unwrap();
        }
        let err = check("user:b", 2, 0).expect_err("third should fail");
        assert_eq!(err.scope, RateLimitScope::PerUser);
        assert!(err.retry_after_secs >= 1);
    }

    #[test]
    fn isolates_keys() {
        reset();
        check("user:c", 1, 0).unwrap();
        assert!(check("user:d", 1, 0).is_ok());
        assert!(check("user:c", 1, 0).is_err());
    }

    #[test]
    fn refuses_over_global_limit() {
        reset();
        check("user:e", 0, 2).unwrap();
        check("user:f", 0, 2).unwrap();
        let err = check("user:g", 0, 2).expect_err("global should trip");
        assert_eq!(err.scope, RateLimitScope::Global);
    }

    #[test]
    fn zero_limits_disable() {
        reset();
        for _ in 0..50 {
            assert!(check("user:h", 0, 0).is_ok());
        }
    }
}
