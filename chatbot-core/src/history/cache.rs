//! Optional multi-set cache keyed by `(user_id, set_id)`.
//!
//! Never authoritative — redb via [`super::api::HistoryService`] is source of truth.
//!
//! Entries hold **decrypted** snapshots (and lightweight list summaries) so hot paths
//! like `list_sets`, delete, and reload do not re-AEAD-decrypt and re-JSON-parse
//! multi-megabyte histories on every request. The durable store remains ciphertext;
//! this cache is process-local and discarded on restart / eviction.

use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use tracing::debug;

use super::types::{SetId, SetSnapshot, SetSummary, SetVersion};

const DEFAULT_CAPACITY: usize = 256;
const DEFAULT_TTL: Duration = Duration::from_secs(3600);

#[derive(Clone)]
struct CachedPlain {
    version: SetVersion,
    /// Full decrypted snapshot (shared; clones of history only when a caller needs owned data).
    snapshot: Arc<SetSnapshot>,
    last_used: Instant,
}

/// List-row fields without history — enough for `/get_sets` without touching the blob.
#[derive(Clone)]
struct CachedSummary {
    version: SetVersion,
    display_name: String,
    is_default: bool,
    last_used: Instant,
}

/// Process-local multi-set cache. Safe to share via `Arc`.
#[derive(Clone, Default)]
pub struct SetCache {
    entries: Arc<DashMap<(String, SetId), CachedPlain>>,
    summaries: Arc<DashMap<(String, SetId), CachedSummary>>,
    capacity: usize,
    ttl: Duration,
}

impl SetCache {
    pub fn new() -> Self {
        Self {
            entries: Arc::new(DashMap::new()),
            summaries: Arc::new(DashMap::new()),
            capacity: DEFAULT_CAPACITY,
            ttl: DEFAULT_TTL,
        }
    }

    pub fn with_limits(capacity: usize, ttl: Duration) -> Self {
        Self {
            entries: Arc::new(DashMap::new()),
            summaries: Arc::new(DashMap::new()),
            capacity: capacity.max(1),
            ttl,
        }
    }

    fn key(user: &str, set_id: SetId) -> (String, SetId) {
        (user.to_owned(), set_id)
    }

    /// Return a full snapshot only when the cached version matches `expected_version`.
    pub fn get_snapshot_if_version(
        &self,
        user: &str,
        set_id: SetId,
        expected_version: SetVersion,
    ) -> Option<SetSnapshot> {
        let map_key = Self::key(user, set_id);
        let entry = self.entries.get(&map_key)?;
        if entry.last_used.elapsed() > self.ttl {
            drop(entry);
            self.entries.remove(&map_key);
            return None;
        }
        if entry.version != expected_version {
            return None;
        }
        let snap = (*entry.snapshot).clone();
        drop(entry);
        if let Some(mut e) = self.entries.get_mut(&map_key) {
            e.last_used = Instant::now();
        }
        Some(snap)
    }

    /// List-sets acceleration: summary when version matches durable meta.
    pub fn get_summary_if_version(
        &self,
        user: &str,
        set_id: SetId,
        expected_version: SetVersion,
        updated_at: u64,
    ) -> Option<SetSummary> {
        let map_key = Self::key(user, set_id);
        // Prefer full-entry summary (always in sync when full snap is cached).
        if let Some(entry) = self.entries.get(&map_key) {
            if entry.last_used.elapsed() <= self.ttl && entry.version == expected_version {
                let summary = SetSummary {
                    set_id,
                    version: entry.version,
                    display_name: entry.snapshot.display_name.clone(),
                    updated_at,
                    is_default: entry.snapshot.is_default,
                };
                drop(entry);
                if let Some(mut e) = self.entries.get_mut(&map_key) {
                    e.last_used = Instant::now();
                }
                return Some(summary);
            }
        }
        let entry = self.summaries.get(&map_key)?;
        if entry.last_used.elapsed() > self.ttl {
            drop(entry);
            self.summaries.remove(&map_key);
            return None;
        }
        if entry.version != expected_version {
            return None;
        }
        let summary = SetSummary {
            set_id,
            version: entry.version,
            display_name: entry.display_name.clone(),
            updated_at,
            is_default: entry.is_default,
        };
        drop(entry);
        if let Some(mut e) = self.summaries.get_mut(&map_key) {
            e.last_used = Instant::now();
        }
        Some(summary)
    }

    /// Insert or replace cache from a durable snapshot (no crypto — plaintext RAM only).
    pub fn put_snapshot(&self, user: &str, snapshot: &SetSnapshot) {
        let map_key = Self::key(user, snapshot.set_id);
        self.entries.insert(
            map_key.clone(),
            CachedPlain {
                version: snapshot.version,
                snapshot: Arc::new(snapshot.clone()),
                last_used: Instant::now(),
            },
        );
        self.summaries.insert(
            map_key,
            CachedSummary {
                version: snapshot.version,
                display_name: snapshot.display_name.clone(),
                is_default: snapshot.is_default,
                last_used: Instant::now(),
            },
        );
        self.evict_if_needed();
    }

    /// Insert only list metadata (e.g. after list decrypt when full snap is not retained).
    pub fn put_summary(&self, user: &str, summary: &SetSummary) {
        self.summaries.insert(
            Self::key(user, summary.set_id),
            CachedSummary {
                version: summary.version,
                display_name: summary.display_name.clone(),
                is_default: summary.is_default,
                last_used: Instant::now(),
            },
        );
        self.evict_if_needed();
    }

    pub fn invalidate(&self, user: &str, set_id: SetId) {
        let map_key = Self::key(user, set_id);
        self.entries.remove(&map_key);
        self.summaries.remove(&map_key);
    }

    pub fn invalidate_user(&self, user: &str) {
        self.entries.retain(|(u, _), _| u != user);
        self.summaries.retain(|(u, _), _| u != user);
    }

    fn evict_if_needed(&self) {
        if self.entries.len() <= self.capacity && self.summaries.len() <= self.capacity * 2 {
            return;
        }
        if self.entries.len() > self.capacity {
            let mut items: Vec<_> = self
                .entries
                .iter()
                .map(|e| (e.key().clone(), e.last_used))
                .collect();
            items.sort_by_key(|(_, t)| *t);
            let drop_n = (self.entries.len() / 10).max(1);
            for (k, _) in items.into_iter().take(drop_n) {
                self.entries.remove(&k);
            }
            debug!(remaining = self.entries.len(), "set_cache_evicted");
        }
        if self.summaries.len() > self.capacity * 2 {
            let mut items: Vec<_> = self
                .summaries
                .iter()
                .map(|e| (e.key().clone(), e.last_used))
                .collect();
            items.sort_by_key(|(_, t)| *t);
            let drop_n = (self.summaries.len() / 10).max(1);
            for (k, _) in items.into_iter().take(drop_n) {
                self.summaries.remove(&k);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::history::types::SetId;

    #[test]
    fn round_trip_cache_entry() {
        let cache = SetCache::new();
        let set_id = SetId::new();
        let snap = SetSnapshot {
            set_id,
            version: SetVersion(3),
            display_name: "work".into(),
            memory: "m".into(),
            system_prompt: "p".into(),
            history: vec![("u".into(), "a".into())],
            is_default: false,
        };
        cache.put_snapshot("alice", &snap);
        let loaded = cache
            .get_snapshot_if_version("alice", set_id, SetVersion(3))
            .unwrap();
        assert_eq!(loaded.version, SetVersion(3));
        assert_eq!(loaded.display_name, "work");
        assert_eq!(loaded.history.len(), 1);
        assert!(cache
            .get_snapshot_if_version("alice", set_id, SetVersion(2))
            .is_none());
        let summary = cache
            .get_summary_if_version("alice", set_id, SetVersion(3), 99)
            .unwrap();
        assert_eq!(summary.display_name, "work");
        assert_eq!(summary.updated_at, 99);
        cache.invalidate("alice", set_id);
        assert!(cache
            .get_snapshot_if_version("alice", set_id, SetVersion(3))
            .is_none());
    }
}
