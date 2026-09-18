//! Owned TTS token-session lifecycle.
//!
//! The parent module keeps token minting, access policy, codec conversion,
//! the encoded-size cap and HTTP rendering. This module owns admission,
//! replay/busy/missing arbitration, cancellation and the generation lease
//! that releases the generating flag on success, failure or drop.

use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{Duration, Instant};

const MAX_PENDING_TTS: usize = 128;
const TTS_TOKEN_TTL: Duration = Duration::from_secs(10 * 60);
// Initial transfer plus three retries, matching NativeVoiceTts MAX_CLIP_ATTEMPTS.
const MAX_TTS_REPLAYS: u8 = 3;

/// Final wire bytes for one TTS clip, in whatever codec the config selects.
/// Cached verbatim for replays so synthesis and encoding both happen once.
#[derive(Debug, Clone)]
pub(crate) struct TtsWireAudio {
    pub(crate) bytes: Vec<u8>,
    pub(crate) content_type: String,
    pub(crate) filename: String,
}

struct PendingTts {
    text: String,
    audio: Option<TtsWireAudio>,
    created_at: Instant,
    replay_count: u8,
    generating: bool,
}

/// Arbitration of one GET /tts_stream/{token} against the store.
pub(crate) enum BeginOutcome<'a> {
    /// Cached wire audio; the store already counted this replay.
    Cached(TtsWireAudio),
    /// First generation for this token. The store marked it generating and
    /// hands out a lease that settles the flag after synthesis.
    Begin {
        text: String,
        lease: GenerationLease<'a>,
    },
    /// Another request is already generating this token.
    Busy,
    /// Unknown or expired token.
    Missing,
    /// Replay budget spent; the entry was removed.
    Exhausted,
}

/// Token-session map with the admission/eviction policy. Each method takes
/// the lock only for its own arbitration; no lock is held across synthesis.
pub(crate) struct PendingTtsStore {
    map: RwLock<HashMap<String, PendingTts>>,
}

impl PendingTtsStore {
    pub(crate) fn new() -> Self {
        Self {
            map: RwLock::new(HashMap::new()),
        }
    }

    /// Admit a fresh token. Returns false when full with nothing safe to
    /// evict. Reinserting an existing token overwrites it.
    pub(crate) fn insert(&self, token: String, text: String) -> bool {
        let mut map = self.map.write().expect("tts lock");
        insert_pending_tts(
            &mut map,
            token,
            PendingTts {
                text,
                audio: None,
                created_at: Instant::now(),
                replay_count: 0,
                generating: false,
            },
        )
    }

    /// Arbitrate one stream request: cached audio, first generation with a
    /// lease, busy, missing or exhausted.
    pub(crate) fn begin(&self, token: &str) -> BeginOutcome<'_> {
        let mut map = self.map.write().expect("tts lock");
        prune_pending_tts(&mut map);
        let pending = match map.get_mut(token) {
            Some(pending) => pending,
            None => return BeginOutcome::Missing,
        };
        if let Some(audio) = pending.audio.clone() {
            if pending.replay_count >= MAX_TTS_REPLAYS {
                map.remove(token);
                return BeginOutcome::Exhausted;
            }
            pending.replay_count += 1;
            BeginOutcome::Cached(audio)
        } else if pending.generating {
            BeginOutcome::Busy
        } else {
            pending.generating = true;
            BeginOutcome::Begin {
                text: pending.text.clone(),
                lease: GenerationLease {
                    store: self,
                    token: token.to_string(),
                    active: true,
                },
            }
        }
    }

    /// Drop a token. Missing tokens are harmless; the handler still answers
    /// 204.
    pub(crate) fn cancel(&self, token: &str) {
        let mut map = self.map.write().expect("tts lock");
        map.remove(token);
    }

    fn reset_generating(&self, token: &str) {
        let mut map = self.map.write().expect("tts lock");
        if let Some(pending) = map.get_mut(token) {
            pending.generating = false;
        }
    }
}

/// Releases the generating flag for one in-flight synthesis. Holds only a
/// store reference and the token, never the lock, so it is safe across await.
pub(crate) struct GenerationLease<'a> {
    store: &'a PendingTtsStore,
    token: String,
    active: bool,
}

impl GenerationLease<'_> {
    /// Cache freshly encoded audio and release the flag. A token cancelled
    /// mid-generation stays gone: this never reinserts.
    pub(crate) fn complete(mut self, audio: TtsWireAudio) -> TtsWireAudio {
        self.active = false;
        let mut map = self.store.map.write().expect("tts lock");
        if let Some(pending) = map.get_mut(&self.token) {
            pending.text.clear();
            pending.audio = Some(audio.clone());
            pending.replay_count = 0;
            pending.generating = false;
        }
        audio
    }

    /// Release the flag without caching so the token stays retryable.
    pub(crate) fn fail(mut self) {
        self.active = false;
        self.store.reset_generating(&self.token);
    }
}

impl Drop for GenerationLease<'_> {
    fn drop(&mut self) {
        if self.active {
            // A poisoned lock must not panic in Drop.
            if let Ok(mut map) = self.store.map.write() {
                if let Some(pending) = map.get_mut(&self.token) {
                    pending.generating = false;
                }
            }
        }
    }
}

fn prune_pending_tts(map: &mut HashMap<String, PendingTts>) {
    map.retain(|_, pending| pending.created_at.elapsed() <= TTS_TOKEN_TTL);
}

fn insert_pending_tts(
    map: &mut HashMap<String, PendingTts>,
    token: String,
    pending: PendingTts,
) -> bool {
    prune_pending_tts(map);
    if !map.contains_key(&token) && map.len() >= MAX_PENDING_TTS {
        let oldest_cached = map
            .iter()
            .filter(|(_, pending)| pending.audio.is_some() && !pending.generating)
            .min_by_key(|(_, pending)| pending.created_at)
            .map(|(token, _)| token.clone());
        if let Some(oldest) = oldest_cached {
            map.remove(&oldest);
        } else {
            let stale_ungenerated = map
                .iter()
                .filter(|(_, pending)| {
                    pending.audio.is_none()
                        && !pending.generating
                        && pending.created_at.elapsed() >= Duration::from_secs(60)
                })
                .min_by_key(|(_, pending)| pending.created_at)
                .map(|(token, _)| token.clone());
            if let Some(stale) = stale_ungenerated {
                map.remove(&stale);
            } else {
                return false;
            }
        }
    }
    map.insert(token, pending);
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pending_tts_capacity_does_not_evict_oldest_pending_entry() {
        let mut map = HashMap::new();
        for index in 0..MAX_PENDING_TTS {
            let token = format!("token-{index}");
            map.insert(
                token,
                PendingTts {
                    text: "queued".to_string(),
                    audio: None,
                    created_at: Instant::now(),
                    replay_count: 0,
                    generating: false,
                },
            );
        }
        let oldest = map
            .iter()
            .min_by_key(|(_, pending)| pending.created_at)
            .map(|(token, _)| token.clone())
            .expect("full map has an oldest entry");

        let inserted = insert_pending_tts(
            &mut map,
            "new-token".to_string(),
            PendingTts {
                text: "new".to_string(),
                audio: None,
                created_at: Instant::now(),
                replay_count: 0,
                generating: false,
            },
        );

        assert_eq!(map.len(), MAX_PENDING_TTS);
        assert!(!inserted);
        assert!(
            map.contains_key(&oldest),
            "a queued token must not be silently evicted when the cap is full"
        );
        assert!(
            !map.contains_key("new-token"),
            "a new token must be rejected when no safe cache entry can be evicted"
        );
    }

    #[test]
    fn prune_pending_tts_removes_only_expired_entries() {
        let now = Instant::now();
        let mut map = HashMap::new();
        map.insert(
            "expired".to_string(),
            PendingTts {
                text: "old".to_string(),
                audio: None,
                created_at: now - Duration::from_secs(11 * 60),
                replay_count: 0,
                generating: false,
            },
        );
        map.insert(
            "fresh".to_string(),
            PendingTts {
                text: "fresh".to_string(),
                audio: None,
                created_at: now - Duration::from_secs(9 * 60),
                replay_count: 0,
                generating: false,
            },
        );
        map.insert(
            "recent".to_string(),
            PendingTts {
                text: "recent".to_string(),
                audio: None,
                created_at: now,
                replay_count: 0,
                generating: false,
            },
        );

        prune_pending_tts(&mut map);

        assert!(
            !map.contains_key("expired"),
            "entry older than the 10m TTL must be pruned"
        );
        assert!(
            map.contains_key("fresh"),
            "entry within the 10m TTL must be kept"
        );
        assert!(map.contains_key("recent"), "recent entry must be kept");
        assert_eq!(map.len(), 2);
    }

    #[test]
    fn insert_pending_tts_prunes_expired_to_make_room() {
        let now = Instant::now();
        let mut map = HashMap::new();
        for index in 0..(MAX_PENDING_TTS - 1) {
            map.insert(
                format!("fresh-{index}"),
                PendingTts {
                    text: "queued".to_string(),
                    audio: None,
                    created_at: Instant::now(),
                    replay_count: 0,
                    generating: false,
                },
            );
        }
        map.insert(
            "expired-slot".to_string(),
            PendingTts {
                text: "old".to_string(),
                audio: None,
                created_at: now - Duration::from_secs(11 * 60),
                replay_count: 0,
                generating: false,
            },
        );
        assert_eq!(map.len(), MAX_PENDING_TTS);

        let inserted = insert_pending_tts(
            &mut map,
            "new-token".to_string(),
            PendingTts {
                text: "new".to_string(),
                audio: None,
                created_at: Instant::now(),
                replay_count: 0,
                generating: false,
            },
        );

        assert!(
            inserted,
            "an expired entry must be pruned to admit the new token"
        );
        assert_eq!(map.len(), MAX_PENDING_TTS);
        assert!(!map.contains_key("expired-slot"));
        assert!(map.contains_key("new-token"));
    }

    #[test]
    fn insert_pending_tts_evicts_oldest_cached_before_stale_ungenerated() {
        let now = Instant::now();
        let mut map = HashMap::new();
        for index in 0..(MAX_PENDING_TTS - 3) {
            map.insert(
                format!("fresh-{index}"),
                PendingTts {
                    text: "queued".to_string(),
                    audio: None,
                    created_at: Instant::now(),
                    replay_count: 0,
                    generating: false,
                },
            );
        }
        map.insert(
            "cached-old".to_string(),
            PendingTts {
                text: String::new(),
                audio: Some(TtsWireAudio {
                    bytes: vec![1, 2, 3],
                    content_type: "audio/wav".to_string(),
                    filename: "tts.wav".to_string(),
                }),
                created_at: now - Duration::from_secs(5 * 60),
                replay_count: 0,
                generating: false,
            },
        );
        map.insert(
            "cached-new".to_string(),
            PendingTts {
                text: String::new(),
                audio: Some(TtsWireAudio {
                    bytes: vec![4, 5, 6],
                    content_type: "audio/wav".to_string(),
                    filename: "tts.wav".to_string(),
                }),
                created_at: now - Duration::from_secs(4 * 60),
                replay_count: 0,
                generating: false,
            },
        );
        map.insert(
            "stale-queued".to_string(),
            PendingTts {
                text: "queued".to_string(),
                audio: None,
                created_at: now - Duration::from_secs(2 * 60),
                replay_count: 0,
                generating: false,
            },
        );
        assert_eq!(map.len(), MAX_PENDING_TTS);

        let inserted = insert_pending_tts(
            &mut map,
            "new-token".to_string(),
            PendingTts {
                text: "new".to_string(),
                audio: None,
                created_at: Instant::now(),
                replay_count: 0,
                generating: false,
            },
        );

        assert!(inserted);
        assert!(
            !map.contains_key("cached-old"),
            "oldest cached clip must be evicted first"
        );
        assert!(
            map.contains_key("cached-new"),
            "newer cached clip must be retained"
        );
        assert!(
            map.contains_key("stale-queued"),
            "stale ungenerated entry must be retained when a cached clip is evictable"
        );
        assert!(map.contains_key("new-token"));
        assert_eq!(map.len(), MAX_PENDING_TTS);
    }

    #[test]
    fn insert_pending_tts_evicts_stale_ungenerated_when_no_cached_available() {
        let now = Instant::now();
        let mut map = HashMap::new();
        for index in 0..(MAX_PENDING_TTS - 1) {
            map.insert(
                format!("fresh-{index}"),
                PendingTts {
                    text: "queued".to_string(),
                    audio: None,
                    created_at: Instant::now(),
                    replay_count: 0,
                    generating: false,
                },
            );
        }
        map.insert(
            "stale-queued".to_string(),
            PendingTts {
                text: "queued".to_string(),
                audio: None,
                created_at: now - Duration::from_secs(2 * 60),
                replay_count: 0,
                generating: false,
            },
        );
        assert_eq!(map.len(), MAX_PENDING_TTS);

        let inserted = insert_pending_tts(
            &mut map,
            "new-token".to_string(),
            PendingTts {
                text: "new".to_string(),
                audio: None,
                created_at: Instant::now(),
                replay_count: 0,
                generating: false,
            },
        );

        assert!(
            inserted,
            "stale ungenerated entry must be evicted when no cached clip exists"
        );
        assert!(!map.contains_key("stale-queued"));
        assert!(map.contains_key("new-token"));
        assert_eq!(map.len(), MAX_PENDING_TTS);
    }

    #[test]
    fn insert_pending_tts_never_evicts_generating_entries() {
        let now = Instant::now();
        let mut map = HashMap::new();
        for index in 0..(MAX_PENDING_TTS - 2) {
            map.insert(
                format!("fresh-{index}"),
                PendingTts {
                    text: "queued".to_string(),
                    audio: None,
                    created_at: Instant::now(),
                    replay_count: 0,
                    generating: false,
                },
            );
        }
        map.insert(
            "generating-old".to_string(),
            PendingTts {
                text: "queued".to_string(),
                audio: None,
                created_at: now - Duration::from_secs(5 * 60),
                replay_count: 0,
                generating: true,
            },
        );
        map.insert(
            "generating-cached".to_string(),
            PendingTts {
                text: String::new(),
                audio: Some(TtsWireAudio {
                    bytes: vec![1, 2, 3],
                    content_type: "audio/wav".to_string(),
                    filename: "tts.wav".to_string(),
                }),
                created_at: now - Duration::from_secs(5 * 60),
                replay_count: 0,
                generating: true,
            },
        );
        assert_eq!(map.len(), MAX_PENDING_TTS);

        let inserted = insert_pending_tts(
            &mut map,
            "new-token".to_string(),
            PendingTts {
                text: "new".to_string(),
                audio: None,
                created_at: Instant::now(),
                replay_count: 0,
                generating: false,
            },
        );

        assert!(
            !inserted,
            "generating entries must never be evicted to make room"
        );
        assert_eq!(map.len(), MAX_PENDING_TTS);
        assert!(map.contains_key("generating-old"));
        assert!(map.contains_key("generating-cached"));
        assert!(!map.contains_key("new-token"));
    }

    #[test]
    fn insert_pending_tts_overwrites_existing_token_when_full() {
        let mut map = HashMap::new();
        for index in 0..MAX_PENDING_TTS {
            map.insert(
                format!("token-{index}"),
                PendingTts {
                    text: "queued".to_string(),
                    audio: None,
                    created_at: Instant::now(),
                    replay_count: 0,
                    generating: false,
                },
            );
        }
        assert_eq!(map.len(), MAX_PENDING_TTS);

        let inserted = insert_pending_tts(
            &mut map,
            "token-0".to_string(),
            PendingTts {
                text: "replaced".to_string(),
                audio: None,
                created_at: Instant::now(),
                replay_count: 0,
                generating: false,
            },
        );

        assert!(
            inserted,
            "reinserting an existing token must succeed even when full"
        );
        assert_eq!(map.len(), MAX_PENDING_TTS);
        assert_eq!(
            map.get("token-0").expect("overwritten token present").text,
            "replaced"
        );
    }

    fn insert_text(store: &PendingTtsStore, token: &str, text: &str) {
        assert!(
            store.insert(token.to_string(), text.to_string()),
            "admission must succeed in test setup"
        );
    }

    fn test_audio(bytes: &[u8]) -> TtsWireAudio {
        TtsWireAudio {
            bytes: bytes.to_vec(),
            content_type: "audio/wav".to_string(),
            filename: "tts.wav".to_string(),
        }
    }

    #[test]
    fn second_begin_while_generating_is_busy() {
        let store = PendingTtsStore::new();
        insert_text(&store, "token", "hello");

        let first = store.begin("token");
        assert!(
            matches!(first, BeginOutcome::Begin { .. }),
            "first stream must start generation"
        );

        assert!(
            matches!(store.begin("token"), BeginOutcome::Busy),
            "concurrent stream must be rejected while generation is in flight"
        );
    }

    #[test]
    fn dropped_lease_resets_generating_without_caching() {
        let store = PendingTtsStore::new();
        insert_text(&store, "token", "hello");

        let first = store.begin("token");
        assert!(
            matches!(first, BeginOutcome::Begin { .. }),
            "first stream must start generation"
        );
        drop(first);

        let retry = store.begin("token");
        if let BeginOutcome::Begin { text, .. } = retry {
            assert_eq!(text, "hello", "dropped generation must stay retryable");
        } else {
            panic!("dropped lease must release the token for a new generation");
        }
    }

    #[test]
    fn completed_lease_caches_audio_for_replay() {
        let store = PendingTtsStore::new();
        insert_text(&store, "token", "hello");

        let first = store.begin("token");
        let BeginOutcome::Begin { text, lease } = first else {
            panic!("first stream must start generation");
        };
        assert_eq!(text, "hello");
        let audio = lease.complete(test_audio(&[1, 2, 3]));

        let outcome = store.begin("token");
        if let BeginOutcome::Cached(replayed) = outcome {
            assert_eq!(replayed.bytes, audio.bytes);
            assert_eq!(replayed.content_type, audio.content_type);
            assert_eq!(replayed.filename, audio.filename);
        } else {
            panic!("completed generation must serve cached audio");
        }
    }

    #[test]
    fn cached_clip_replays_three_times_then_expires() {
        let store = PendingTtsStore::new();
        insert_text(&store, "token", "hello");

        let first = store.begin("token");
        let BeginOutcome::Begin { lease, .. } = first else {
            panic!("first stream must start generation");
        };
        lease.complete(test_audio(&[9]));

        for replay in 1..=3 {
            assert!(
                matches!(store.begin("token"), BeginOutcome::Cached(_)),
                "replay {replay} of 3 must serve cached audio"
            );
        }
        assert!(
            matches!(store.begin("token"), BeginOutcome::Exhausted),
            "fourth replay must exhaust the budget"
        );
        assert!(
            matches!(store.begin("token"), BeginOutcome::Missing),
            "exhausted token must be gone"
        );
    }

    #[test]
    fn leases_settled_after_cancel_never_reinsert_the_token() {
        let store = PendingTtsStore::new();
        insert_text(&store, "completed", "hello");
        insert_text(&store, "dropped", "hello");

        let first = store.begin("completed");
        let BeginOutcome::Begin { lease, .. } = first else {
            panic!("first stream must start generation");
        };
        let second = store.begin("dropped");
        assert!(
            matches!(second, BeginOutcome::Begin { .. }),
            "second stream must start generation"
        );

        store.cancel("completed");
        store.cancel("dropped");

        lease.complete(test_audio(&[1]));
        drop(second);

        assert!(
            matches!(store.begin("completed"), BeginOutcome::Missing),
            "completing a cancelled token must not reinsert it"
        );
        assert!(
            matches!(store.begin("dropped"), BeginOutcome::Missing),
            "dropping a cancelled lease must not reinsert it"
        );
        store.cancel("completed");
    }

    #[test]
    fn independent_stores_do_not_share_tokens() {
        let first = PendingTtsStore::new();
        let second = PendingTtsStore::new();
        insert_text(&first, "token", "hello");

        assert!(
            matches!(second.begin("token"), BeginOutcome::Missing),
            "a token admitted elsewhere must be unknown here"
        );
        assert!(
            matches!(first.begin("token"), BeginOutcome::Begin { .. }),
            "admission must stay visible in its own store"
        );
    }
}
