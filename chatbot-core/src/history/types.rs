//! Public domain types for chat history / sets.
//!
//! Display names and message content live only in decrypted snapshots —
//! never in store keys or plain metadata used for indexing.

use serde::{Deserialize, Serialize};
use std::fmt;
use uuid::Uuid;

/// Opaque set identity. Safe to log and store unencrypted.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SetId(Uuid);

impl SetId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    pub fn from_uuid(id: Uuid) -> Self {
        Self(id)
    }

    pub fn as_uuid(&self) -> Uuid {
        self.0
    }

    pub fn as_bytes(&self) -> &[u8; 16] {
        self.0.as_bytes()
    }

    pub fn parse(s: &str) -> Result<Self, uuid::Error> {
        Ok(Self(Uuid::parse_str(s)?))
    }
}

impl Default for SetId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for SetId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl fmt::Debug for SetId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SetId({})", self.0)
    }
}

/// Monotonic CAS version for a set payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct SetVersion(pub u64);

impl SetVersion {
    pub const INITIAL: Self = Self(0);

    pub fn next(self) -> Self {
        Self(self.0.saturating_add(1))
    }

    pub fn get(self) -> u64 {
        self.0
    }
}

impl fmt::Display for SetVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// One user/assistant exchange.
pub type HistoryPair = (String, String);

/// Decrypted whole-set snapshot used by prepare/finalize and pure ops.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SetSnapshot {
    pub set_id: SetId,
    pub version: SetVersion,
    pub display_name: String,
    pub memory: String,
    pub system_prompt: String,
    pub history: Vec<HistoryPair>,
    pub is_default: bool,
}

impl SetSnapshot {
    pub fn empty(
        set_id: SetId,
        display_name: impl Into<String>,
        system_prompt: impl Into<String>,
        is_default: bool,
    ) -> Self {
        Self {
            set_id,
            version: SetVersion::INITIAL,
            display_name: display_name.into(),
            memory: String::new(),
            system_prompt: system_prompt.into(),
            history: Vec::new(),
            is_default,
        }
    }
}

/// List-sets row after decrypt (name only available with a valid key).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SetSummary {
    pub set_id: SetId,
    pub version: SetVersion,
    pub display_name: String,
    pub updated_at: u64,
    pub is_default: bool,
}

/// Immutable prepare-time capture for chat/regenerate finalize.
///
/// Finalize must commit from this capture only — never from live session RAM.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrepareCapture {
    pub set_id: SetId,
    pub version: SetVersion,
    pub history: Vec<HistoryPair>,
    pub memory: String,
    pub system_prompt: String,
    pub display_name: String,
    pub is_default: bool,
    /// Regenerate: index of the pair being replaced; `None` for plain chat append.
    pub insertion_index: Option<usize>,
    /// Regenerate/edit: user message text for the replaced pair.
    pub replace_user_message: Option<String>,
}

impl PrepareCapture {
    pub fn from_snapshot(snapshot: &SetSnapshot) -> Self {
        Self {
            set_id: snapshot.set_id,
            version: snapshot.version,
            history: snapshot.history.clone(),
            memory: snapshot.memory.clone(),
            system_prompt: snapshot.system_prompt.clone(),
            display_name: snapshot.display_name.clone(),
            is_default: snapshot.is_default,
            insertion_index: None,
            replace_user_message: None,
        }
    }

    pub fn with_regenerate(mut self, insertion_index: usize, user_message: impl Into<String>) -> Self {
        self.insertion_index = Some(insertion_index);
        self.replace_user_message = Some(user_message.into());
        self
    }

    /// History prefix sent to the model for regenerate (pairs before insertion index).
    pub fn context_history_for_model(&self) -> Vec<HistoryPair> {
        match self.insertion_index {
            Some(idx) => self.history.iter().take(idx).cloned().collect(),
            None => self.history.clone(),
        }
    }
}

/// Plaintext payload stored inside AEAD (no set_id/version — those bind via AAD/meta).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SetPayloadV1 {
    pub display_name: String,
    pub memory: String,
    pub system_prompt: String,
    pub history: Vec<HistoryPair>,
}

impl SetPayloadV1 {
    pub fn from_snapshot(snapshot: &SetSnapshot) -> Self {
        Self {
            display_name: snapshot.display_name.clone(),
            memory: snapshot.memory.clone(),
            system_prompt: snapshot.system_prompt.clone(),
            history: snapshot.history.clone(),
        }
    }

    pub fn into_snapshot(self, set_id: SetId, version: SetVersion, is_default: bool) -> SetSnapshot {
        SetSnapshot {
            set_id,
            version,
            display_name: self.display_name,
            memory: self.memory,
            system_prompt: self.system_prompt,
            history: self.history,
            is_default,
        }
    }
}

/// Discriminator for AAD / blob format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum BlobFormat {
    /// Legacy Fernet-wrapped JSON payload (migration).
    FernetLegacy = 0,
    /// AES-256-GCM whole-set payload v1.
    AeadV1 = 1,
}

impl BlobFormat {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::FernetLegacy),
            1 => Some(Self::AeadV1),
            _ => None,
        }
    }

    pub fn as_u8(self) -> u8 {
        self as u8
    }

    pub fn aad_kind(self) -> &'static str {
        match self {
            Self::FernetLegacy => "set_payload_fernet",
            Self::AeadV1 => "set_payload_v1",
        }
    }
}
