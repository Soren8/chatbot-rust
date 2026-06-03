use std::fmt;

use zeroize::{Zeroize, ZeroizeOnDrop};

/// Per-request encryption key material; zeroized on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct EncryptionKey {
    bytes: Vec<u8>,
}

impl EncryptionKey {
    pub fn from_header_value(value: &str) -> Option<Self> {
        let trimmed = value.trim();
        if trimmed.is_empty() || trimmed.len() > 256 {
            return None;
        }
        Some(Self {
            bytes: trimmed.as_bytes().to_vec(),
        })
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl fmt::Debug for EncryptionKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EncryptionKey([redacted])")
    }
}
