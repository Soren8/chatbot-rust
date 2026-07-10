//! Optional multi-set ciphertext cache keyed by `(user_id, set_id)`.
//!
//! Never authoritative — redb via [`super::api::HistoryService`] is source of truth.
//! Entries hold sealed AEAD/Fernet blobs with version for optimistic hits.

use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use tracing::debug;

use super::types::{SetId, SetSnapshot, SetVersion};
use crate::enc_key::EncryptionKey;
use crate::history::crypto::{self, CryptoError};
use crate::history::types::{BlobFormat, SetPayloadV1};

const DEFAULT_CAPACITY: usize = 256;
const DEFAULT_TTL: Duration = Duration::from_secs(3600);

#[derive(Clone)]
struct CachedCipher {
    version: SetVersion,
    format: BlobFormat,
    blob: Arc<Vec<u8>>,
    last_used: Instant,
}

/// Process-local multi-set cache. Safe to share via `Arc`.
#[derive(Clone, Default)]
pub struct SetCache {
    entries: Arc<DashMap<(String, SetId), CachedCipher>>,
    capacity: usize,
    ttl: Duration,
}

impl SetCache {
    pub fn new() -> Self {
        Self {
            entries: Arc::new(DashMap::new()),
            capacity: DEFAULT_CAPACITY,
            ttl: DEFAULT_TTL,
        }
    }

    pub fn with_limits(capacity: usize, ttl: Duration) -> Self {
        Self {
            entries: Arc::new(DashMap::new()),
            capacity: capacity.max(1),
            ttl,
        }
    }

    fn key(user: &str, set_id: SetId) -> (String, SetId) {
        (user.to_owned(), set_id)
    }

    pub fn get_snapshot(
        &self,
        user: &str,
        set_id: SetId,
        key: &EncryptionKey,
    ) -> Option<SetSnapshot> {
        let map_key = Self::key(user, set_id);
        let entry = self.entries.get(&map_key)?;
        if entry.last_used.elapsed() > self.ttl {
            drop(entry);
            self.entries.remove(&map_key);
            return None;
        }
        let version = entry.version;
        let format = entry.format;
        let blob = Arc::clone(&entry.blob);
        drop(entry);

        let payload = crypto::open_blob(user, set_id, version, format, &blob, key).ok()?;
        // Refresh last_used
        if let Some(mut e) = self.entries.get_mut(&map_key) {
            e.last_used = Instant::now();
        }
        Some(SetSnapshot {
            set_id,
            version,
            display_name: payload.display_name,
            memory: payload.memory,
            system_prompt: payload.system_prompt,
            history: payload.history,
            is_default: false, // flag lives in redb meta; prefer store load when required
        })
    }

    /// Insert or replace cache from a durable snapshot (encrypt with AEAD v1).
    pub fn put_snapshot(
        &self,
        user: &str,
        snapshot: &SetSnapshot,
        key: &EncryptionKey,
    ) -> Result<(), CryptoError> {
        let payload = SetPayloadV1 {
            display_name: snapshot.display_name.clone(),
            memory: snapshot.memory.clone(),
            system_prompt: snapshot.system_prompt.clone(),
            history: snapshot.history.clone(),
        };
        let blob = crypto::seal_blob(
            user,
            snapshot.set_id,
            snapshot.version,
            BlobFormat::AeadV1,
            &payload,
            key,
        )?;
        self.entries.insert(
            Self::key(user, snapshot.set_id),
            CachedCipher {
                version: snapshot.version,
                format: BlobFormat::AeadV1,
                blob: Arc::new(blob),
                last_used: Instant::now(),
            },
        );
        self.evict_if_needed();
        Ok(())
    }

    pub fn invalidate(&self, user: &str, set_id: SetId) {
        self.entries.remove(&Self::key(user, set_id));
    }

    pub fn invalidate_user(&self, user: &str) {
        self.entries.retain(|(u, _), _| u != user);
    }

    fn evict_if_needed(&self) {
        if self.entries.len() <= self.capacity {
            return;
        }
        // Drop oldest ~10%
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::history::types::SetId;

    fn key() -> EncryptionKey {
        EncryptionKey::from_header_value("dGVzdC1rZXktbWF0ZXJpYWwtMTIzNDU2Nzg5MDEyMzQ1Ng==")
            .unwrap()
    }

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
        let k = key();
        cache.put_snapshot("alice", &snap, &k).unwrap();
        let loaded = cache.get_snapshot("alice", set_id, &k).unwrap();
        assert_eq!(loaded.version, SetVersion(3));
        assert_eq!(loaded.display_name, "work");
        assert_eq!(loaded.history.len(), 1);
        cache.invalidate("alice", set_id);
        assert!(cache.get_snapshot("alice", set_id, &k).is_none());
    }
}
