//! Optional multi-set cache keyed by `(user_id, set_id)`.
//!
//! Never authoritative — redb via [`super::api::HistoryService`] is source of truth.
//!
//! Entries hold **decrypted** snapshots (and lightweight list summaries) so hot
//! paths like delete and reload do not re-AEAD-decrypt multi-megabyte histories.
//! `list_sets` reads the sealed name row, not the history blob; the summary cache
//! is optional. The durable store remains ciphertext; this cache is process-local
//! and discarded on restart / eviction.
//!
//! Snapshots are shared as `Arc`s, so a hit costs a refcount bump, not a copy of
//! the history. Retained plaintext is bounded by an approximate byte budget as
//! well as an entry count, and expired entries are pruned on every insert.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use tracing::debug;

use super::types::{LogicalSnapshot, SetId, SetSummary, SetVersion};
use crate::config::PrivacyLevel;

const DEFAULT_CAPACITY: usize = 256;
const DEFAULT_TTL: Duration = Duration::from_secs(3600);
/// Approximate plaintext held across all cached snapshots. Large enough for
/// dozens of long active chats (a 500-pair chat at ~4 KiB per pair is ~2 MiB),
/// small enough that the decrypted-history cache cannot dominate process RSS
/// however many sets are touched. Sets bigger than the budget are not cached
/// and fall back to the durable store.
const DEFAULT_BYTE_BUDGET: usize = 64 * 1024 * 1024;

type Key = (String, SetId);

#[derive(Clone)]
struct CachedPlain {
    version: SetVersion,
    /// Normalized logical snapshot (shared; callers materialize an owned
    /// `SetSnapshot` DTO only when they need expanded `data:` URLs).
    snapshot: Arc<LogicalSnapshot>,
    /// `approx_bytes(&snapshot)`, fixed at insert for budget accounting.
    bytes: usize,
    last_used: Instant,
}

/// List-row fields without history — enough for `/get_sets` without touching the blob.
#[derive(Clone)]
struct CachedSummary {
    version: SetVersion,
    display_name: String,
    is_default: bool,
    privacy_level: PrivacyLevel,
    last_used: Instant,
}

/// Approximate heap footprint of a snapshot's text.
fn approx_bytes(snapshot: &LogicalSnapshot) -> usize {
    let s = snapshot.as_snapshot();
    let history: usize = s
        .history
        .iter()
        .map(|(u, a)| u.len() + a.len() + std::mem::size_of::<(String, String)>())
        .sum();
    history
        + s.display_name.len()
        + s.memory.len()
        + s.system_prompt.len()
        + std::mem::size_of_val(s.pair_ids.as_slice())
}

/// Process-local multi-set cache. Safe to share via `Arc`.
#[derive(Clone, Default)]
pub struct SetCache {
    entries: Arc<DashMap<Key, CachedPlain>>,
    summaries: Arc<DashMap<Key, CachedSummary>>,
    /// Sum of `CachedPlain::bytes` over `entries`.
    bytes: Arc<AtomicUsize>,
    capacity: usize,
    byte_budget: usize,
    ttl: Duration,
}

impl SetCache {
    pub fn new() -> Self {
        Self::with_limits(DEFAULT_BYTE_BUDGET, DEFAULT_TTL)
    }

    fn with_limits(byte_budget: usize, ttl: Duration) -> Self {
        Self {
            entries: Arc::new(DashMap::new()),
            summaries: Arc::new(DashMap::new()),
            bytes: Arc::new(AtomicUsize::new(0)),
            capacity: DEFAULT_CAPACITY,
            byte_budget,
            ttl,
        }
    }

    fn key(user: &str, set_id: SetId) -> Key {
        (user.to_owned(), set_id)
    }

    fn remove_entry(&self, key: &Key) {
        if let Some((_, old)) = self.entries.remove(key) {
            self.bytes.fetch_sub(old.bytes, Ordering::Relaxed);
        }
    }

    /// Return the normalized logical snapshot only when the cached version
    /// matches `expected_version`. Callers materialize `data:` URLs themselves.
    pub fn get_snapshot_if_version(
        &self,
        user: &str,
        set_id: SetId,
        expected_version: SetVersion,
    ) -> Option<Arc<LogicalSnapshot>> {
        let map_key = Self::key(user, set_id);
        let entry = self.entries.get(&map_key)?;
        if entry.last_used.elapsed() > self.ttl {
            drop(entry);
            self.remove_entry(&map_key);
            return None;
        }
        if entry.version != expected_version {
            return None;
        }
        let snap = Arc::clone(&entry.snapshot);
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
                    display_name: entry.snapshot.as_snapshot().display_name.clone(),
                    updated_at,
                    is_default: entry.snapshot.as_snapshot().is_default,
                    privacy_level: entry.snapshot.as_snapshot().privacy_level,
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
            privacy_level: entry.privacy_level,
        };
        drop(entry);
        if let Some(mut e) = self.summaries.get_mut(&map_key) {
            e.last_used = Instant::now();
        }
        Some(summary)
    }

    /// Insert or replace cache from a durable-normalized logical snapshot (no
    /// crypto — plaintext RAM only). Materialized `data:`-carrying snapshots
    /// must be normalized by the store commit first; they never reach here.
    /// A snapshot larger than the whole byte budget only refreshes the summary.
    pub fn put_snapshot(&self, user: &str, snapshot: impl Into<Arc<LogicalSnapshot>>) {
        let snapshot = snapshot.into();
        let inner = snapshot.as_snapshot();
        let map_key = Self::key(user, inner.set_id);
        self.prune_expired();
        self.summaries.insert(
            map_key.clone(),
            CachedSummary {
                version: inner.version,
                display_name: inner.display_name.clone(),
                is_default: inner.is_default,
                privacy_level: inner.privacy_level,
                last_used: Instant::now(),
            },
        );
        let bytes = approx_bytes(&snapshot);
        if bytes > self.byte_budget {
            self.remove_entry(&map_key);
            debug!(bytes, "set_cache_snapshot_over_budget");
        } else {
            let version = inner.version;
            self.bytes.fetch_add(bytes, Ordering::Relaxed);
            let old = self.entries.insert(
                map_key.clone(),
                CachedPlain {
                    version,
                    snapshot,
                    bytes,
                    last_used: Instant::now(),
                },
            );
            if let Some(old) = old {
                self.bytes.fetch_sub(old.bytes, Ordering::Relaxed);
            }
        }
        self.evict_if_needed(Some(&map_key));
    }

    /// Insert only list metadata (e.g. after list decrypt when full snap is not retained).
    pub fn put_summary(&self, user: &str, summary: &SetSummary) {
        self.prune_expired();
        self.summaries.insert(
            Self::key(user, summary.set_id),
            CachedSummary {
                version: summary.version,
                display_name: summary.display_name.clone(),
                is_default: summary.is_default,
                privacy_level: summary.privacy_level,
                last_used: Instant::now(),
            },
        );
        self.evict_if_needed(None);
    }

    pub fn invalidate(&self, user: &str, set_id: SetId) {
        let map_key = Self::key(user, set_id);
        self.remove_entry(&map_key);
        self.summaries.remove(&map_key);
    }

    /// Drop entries past their TTL so expired plaintext does not linger until read.
    fn prune_expired(&self) {
        let expired: Vec<Key> = self
            .entries
            .iter()
            .filter(|e| e.last_used.elapsed() > self.ttl)
            .map(|e| e.key().clone())
            .collect();
        for k in &expired {
            self.remove_entry(k);
        }
        self.summaries
            .retain(|_, s| s.last_used.elapsed() <= self.ttl);
    }

    /// Evict least-recently-used snapshots while over the entry cap or byte
    /// budget, never evicting `keep` (the entry just inserted).
    fn evict_if_needed(&self, keep: Option<&Key>) {
        if self.entries.len() > self.capacity
            || self.bytes.load(Ordering::Relaxed) > self.byte_budget
        {
            let mut items: Vec<_> = self
                .entries
                .iter()
                .filter(|e| Some(e.key()) != keep)
                .map(|e| (e.key().clone(), e.last_used))
                .collect();
            items.sort_by_key(|(_, t)| *t);
            let count_drop = if self.entries.len() > self.capacity {
                (self.entries.len() / 10).max(1)
            } else {
                0
            };
            for (n, (k, _)) in items.into_iter().enumerate() {
                if n >= count_drop && self.bytes.load(Ordering::Relaxed) <= self.byte_budget {
                    break;
                }
                self.remove_entry(&k);
            }
            debug!(
                remaining = self.entries.len(),
                bytes = self.bytes.load(Ordering::Relaxed),
                "set_cache_evicted"
            );
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
    use crate::history::types::{SetId, SetSnapshot};

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
            pair_ids: Vec::new(),
            is_default: false,
            privacy_level: PrivacyLevel::Private,
        };
        let logical = LogicalSnapshot::from_normalized(snap);
        cache.put_snapshot("alice", logical);
        let loaded = cache
            .get_snapshot_if_version("alice", set_id, SetVersion(3))
            .unwrap();
        let loaded = loaded.as_snapshot();
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

    fn sized_snapshot(bytes: usize) -> LogicalSnapshot {
        LogicalSnapshot::from_normalized(SetSnapshot {
            set_id: SetId::new(),
            version: SetVersion(1),
            display_name: "big".into(),
            memory: String::new(),
            system_prompt: String::new(),
            history: vec![("u".repeat(bytes / 2), "a".repeat(bytes / 2))],
            pair_ids: Vec::new(),
            is_default: false,
            privacy_level: PrivacyLevel::Private,
        })
    }

    #[test]
    fn hits_share_one_snapshot_allocation() {
        let cache = SetCache::new();
        let logical = sized_snapshot(64);
        let set_id = logical.as_snapshot().set_id;
        cache.put_snapshot("alice", logical);
        let first = cache
            .get_snapshot_if_version("alice", set_id, SetVersion(1))
            .unwrap();
        let second = cache
            .get_snapshot_if_version("alice", set_id, SetVersion(1))
            .unwrap();
        assert!(Arc::ptr_eq(&first, &second));
    }

    #[test]
    fn byte_budget_bounds_retained_plaintext() {
        const MIB: usize = 1024 * 1024;
        let budget = 2 * MIB;
        let cache = SetCache::with_limits(budget, DEFAULT_TTL);
        let snaps: Vec<_> = (0..3).map(|_| sized_snapshot(MIB)).collect();
        let ids: Vec<_> = snaps.iter().map(|s| s.as_snapshot().set_id).collect();
        for snap in snaps {
            cache.put_snapshot("alice", snap);
        }
        let retained: usize = cache
            .entries
            .iter()
            .map(|e| approx_bytes(&e.snapshot))
            .sum();
        assert!(retained <= budget, "retained {retained} > budget {budget}");
        assert_eq!(cache.bytes.load(Ordering::Relaxed), retained);
        assert!(cache
            .get_snapshot_if_version("alice", ids[0], SetVersion(1))
            .is_none());
        assert!(cache
            .get_snapshot_if_version("alice", ids[2], SetVersion(1))
            .is_some());
    }

    #[test]
    fn expired_entry_is_dropped_on_next_insert() {
        let cache = SetCache::with_limits(DEFAULT_BYTE_BUDGET, Duration::from_millis(5));
        let stale = sized_snapshot(64);
        let stale_id = stale.as_snapshot().set_id;
        cache.put_snapshot("alice", stale);
        std::thread::sleep(Duration::from_millis(20));
        cache.put_snapshot("alice", sized_snapshot(64));
        let stale_key = SetCache::key("alice", stale_id);
        assert!(!cache.entries.contains_key(&stale_key));
        assert!(!cache.summaries.contains_key(&stale_key));
        assert_eq!(cache.entries.len(), 1);
        assert_eq!(
            cache.bytes.load(Ordering::Relaxed),
            approx_bytes(&cache.entries.iter().next().unwrap().snapshot)
        );
    }
}
