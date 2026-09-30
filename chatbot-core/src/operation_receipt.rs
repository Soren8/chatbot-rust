//! Storage-independent operation receipts. Durable callers must insert the receipt
//! in the same write transaction as the mutation, never in a subsequent write.
use std::time::{SystemTime, UNIX_EPOCH};

use crate::enc_key::EncryptionKey;
use aes_gcm::aead::{Aead, AeadCore, Generate, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

pub const RECEIPT_TTL_SECS: u64 = 24 * 60 * 60;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct OperationId(String);
impl OperationId {
    pub fn parse(value: &str) -> Result<Self, &'static str> {
        if !(16..=128).contains(&value.len())
            || !value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err("invalid_operation_id");
        }
        Ok(Self(value.to_owned()))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug)]
pub struct OperationRequest {
    pub id: OperationId,
    pub fingerprint: [u8; 32],
}
impl OperationRequest {
    /// Pass the semantic request DTO only: credentials and CSRF are not input.
    pub fn new(id: OperationId, route: &str, semantic_body: &Value) -> Self {
        fn canonical(value: &Value) -> Value {
            match value {
                Value::Object(map) => {
                    let mut keys: Vec<_> = map.keys().collect();
                    keys.sort();
                    let mut output = serde_json::Map::new();
                    for key in keys {
                        output.insert(key.clone(), canonical(&map[key]));
                    }
                    Value::Object(output)
                }
                Value::Array(values) => Value::Array(values.iter().map(canonical).collect()),
                _ => value.clone(),
            }
        }
        let mut hash = Sha256::new();
        hash.update((route.len() as u64).to_le_bytes());
        hash.update(route.as_bytes());
        hash.update(
            serde_json::to_vec(&canonical(semantic_body)).expect("JSON value serialization"),
        );
        Self {
            id,
            fingerprint: hash.finalize().into(),
        }
    }
}

pub trait ReceiptClock: Send + Sync {
    fn now_secs(&self) -> u64;
}
#[derive(Default)]
pub struct SystemReceiptClock;
impl ReceiptClock for SystemReceiptClock {
    fn now_secs(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub enum ReceiptOutcome {
    Applied,
    Rejected,
}

/// This entire value (including fingerprint) must be AEAD sealed for disk storage.
/// Owner scope belongs in the storage key; it must never be supplied by the client.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Receipt {
    pub operation_id: OperationId,
    pub fingerprint: [u8; 32],
    pub outcome: ReceiptOutcome,
    pub status: u16,
    pub body: Vec<u8>,
    pub created_at: u64,
}
impl Receipt {
    pub fn new(
        request: &OperationRequest,
        outcome: ReceiptOutcome,
        status: u16,
        body: Vec<u8>,
        created_at: u64,
    ) -> Self {
        Self {
            operation_id: request.id.clone(),
            fingerprint: request.fingerprint,
            outcome,
            status,
            body,
            created_at,
        }
    }
    pub fn expired(&self, now: u64) -> bool {
        now.saturating_sub(self.created_at) >= RECEIPT_TTL_SECS
    }
    pub fn matches(&self, request: &OperationRequest) -> bool {
        self.operation_id == request.id && self.fingerprint == request.fingerprint
    }
    pub fn seal(&self, owner: &str, key: &EncryptionKey) -> Result<Vec<u8>, &'static str> {
        let mut plain = serde_json::to_vec(self).map_err(|_| "receipt serialization")?;
        let nonce: Nonce<<Aes256Gcm as AeadCore>::NonceSize> = Nonce::generate();
        let result = receipt_cipher(key).encrypt(
            &nonce,
            Payload {
                msg: &plain,
                aad: &receipt_aad(owner, &self.operation_id),
            },
        );
        plain.zeroize();
        let encrypted = result.map_err(|_| "receipt encryption")?;
        let mut output = nonce.to_vec();
        output.extend(encrypted);
        Ok(output)
    }
    pub fn open(
        owner: &str,
        id: &OperationId,
        blob: &[u8],
        key: &EncryptionKey,
    ) -> Result<Self, &'static str> {
        if blob.len() < 28 {
            return Err("receipt framing");
        }
        let nonce: [u8; 12] = blob[..12].try_into().map_err(|_| "receipt framing")?;
        let mut plain = receipt_cipher(key)
            .decrypt(
                &nonce.into(),
                Payload {
                    msg: &blob[12..],
                    aad: &receipt_aad(owner, id),
                },
            )
            .map_err(|_| "receipt decryption")?;
        let receipt = serde_json::from_slice(&plain).map_err(|_| "receipt serialization");
        plain.zeroize();
        receipt
    }
}
fn receipt_aad(owner: &str, id: &OperationId) -> Vec<u8> {
    let mut aad = b"chatbot-operation-receipt-v1\0".to_vec();
    aad.extend((owner.len() as u64).to_le_bytes());
    aad.extend(owner.as_bytes());
    aad.extend(id.as_str().as_bytes());
    aad
}
fn receipt_cipher(key: &EncryptionKey) -> Aes256Gcm {
    let hkdf = Hkdf::<Sha256>::new(None, key.as_bytes());
    let mut derived = [0u8; 32];
    hkdf.expand(b"chatbot-operation-receipt-v1", &mut derived)
        .expect("valid key size");
    let cipher = Aes256Gcm::new_from_slice(&derived).expect("valid key size");
    derived.zeroize();
    cipher
}
