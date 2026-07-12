//! Seal/open set payloads with AEAD + AAD binding.
//!
//! AAD: `user_id || set_id || blob_kind || version` — prevents ciphertext swap across context.

use aes_gcm::aead::{Aead, AeadCore, KeyInit, Payload};
use aes_gcm::Aes256Gcm;
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;
use thiserror::Error;

use super::types::{BlobFormat, SetId, SetPayloadV1, SetVersion};
use crate::enc_key::EncryptionKey;
use crate::persistence::{DataPersistence, EncryptionMode, PersistenceError};

const HKDF_INFO: &[u8] = b"chatbot-set-payload-v1";
const NONCE_LEN: usize = 12;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("encryption failed")]
    Encrypt,
    #[error("decryption failed")]
    Decrypt,
    #[error("invalid payload framing")]
    Framing,
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("legacy fernet error")]
    Fernet(#[from] PersistenceError),
}

/// Build AAD bytes that bind ciphertext to ownership + version.
pub fn build_aad(user_id: &str, set_id: SetId, format: BlobFormat, version: SetVersion) -> Vec<u8> {
    let mut aad = Vec::with_capacity(user_id.len() + 16 + 32 + 8);
    aad.extend_from_slice(user_id.as_bytes());
    aad.push(0xff);
    aad.extend_from_slice(set_id.as_bytes());
    aad.push(0xff);
    aad.extend_from_slice(format.aad_kind().as_bytes());
    aad.push(0xff);
    aad.extend_from_slice(&version.get().to_le_bytes());
    aad
}

fn nonce_array(bytes: [u8; NONCE_LEN]) -> aes_gcm::Nonce<<Aes256Gcm as AeadCore>::NonceSize> {
    bytes.into()
}

fn derive_aes_key(enc_key: &EncryptionKey) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, enc_key.as_bytes());
    let mut out = [0u8; 32];
    // HKDF expand only fails if length is invalid; 32 is fine.
    hk.expand(HKDF_INFO, &mut out)
        .expect("HKDF expand length valid");
    out
}

/// Encrypt payload as: `nonce (12) || ciphertext+tag`.
pub fn seal_payload_v1(
    user_id: &str,
    set_id: SetId,
    version: SetVersion,
    payload: &SetPayloadV1,
    key: &EncryptionKey,
) -> Result<Vec<u8>, CryptoError> {
    let plaintext = serde_json::to_vec(payload)?;
    let aes_key = derive_aes_key(key);
    let cipher = Aes256Gcm::new_from_slice(&aes_key).map_err(|_| CryptoError::Encrypt)?;

    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::rng().fill_bytes(&mut nonce_bytes);
    let nonce = nonce_array(nonce_bytes);

    let aad = build_aad(user_id, set_id, BlobFormat::AeadV1, version);
    let ct = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: &plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| CryptoError::Encrypt)?;

    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Ok(out)
}

pub fn open_payload_v1(
    user_id: &str,
    set_id: SetId,
    version: SetVersion,
    blob: &[u8],
    key: &EncryptionKey,
) -> Result<SetPayloadV1, CryptoError> {
    if blob.len() < NONCE_LEN + 16 {
        return Err(CryptoError::Framing);
    }
    let (nonce_bytes, ct) = blob.split_at(NONCE_LEN);
    let nonce_fixed: [u8; NONCE_LEN] = nonce_bytes
        .try_into()
        .map_err(|_| CryptoError::Framing)?;
    let aes_key = derive_aes_key(key);
    let cipher = Aes256Gcm::new_from_slice(&aes_key).map_err(|_| CryptoError::Decrypt)?;
    let nonce = nonce_array(nonce_fixed);
    let aad = build_aad(user_id, set_id, BlobFormat::AeadV1, version);

    let plaintext = cipher
        .decrypt(
            &nonce,
            Payload {
                msg: ct,
                aad: &aad,
            },
        )
        .map_err(|_| CryptoError::Decrypt)?;

    Ok(serde_json::from_slice(&plaintext)?)
}

/// Seal using legacy Fernet (migration / interim). No AAD — format flagged in meta.
pub fn seal_payload_fernet(
    payload: &SetPayloadV1,
    key: &EncryptionKey,
) -> Result<Vec<u8>, CryptoError> {
    let json = serde_json::to_string(payload)?;
    Ok(DataPersistence::encrypt_bytes(
        json.as_bytes(),
        EncryptionMode::Fernet(key.as_bytes()),
    )?)
}

pub fn open_payload_fernet(
    blob: &[u8],
    key: &EncryptionKey,
) -> Result<SetPayloadV1, CryptoError> {
    let bytes = DataPersistence::decrypt_bytes(blob, EncryptionMode::Fernet(key.as_bytes()))?;
    Ok(serde_json::from_slice(&bytes)?)
}

pub fn open_blob(
    user_id: &str,
    set_id: SetId,
    version: SetVersion,
    format: BlobFormat,
    blob: &[u8],
    key: &EncryptionKey,
) -> Result<SetPayloadV1, CryptoError> {
    match format {
        BlobFormat::AeadV1 => open_payload_v1(user_id, set_id, version, blob, key),
        BlobFormat::FernetLegacy => open_payload_fernet(blob, key),
    }
}

pub fn seal_blob(
    user_id: &str,
    set_id: SetId,
    version: SetVersion,
    format: BlobFormat,
    payload: &SetPayloadV1,
    key: &EncryptionKey,
) -> Result<Vec<u8>, CryptoError> {
    match format {
        BlobFormat::AeadV1 => seal_payload_v1(user_id, set_id, version, payload, key),
        BlobFormat::FernetLegacy => seal_payload_fernet(payload, key),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::history::types::SetPayloadV1;

    fn test_key() -> EncryptionKey {
        // Fernet-shaped URL-safe base64 32-byte key
        EncryptionKey::from_header_value("dGVzdC1rZXktbWF0ZXJpYWwtMTIzNDU2Nzg5MDEyMzQ1Ng==")
            .expect("key")
    }

    #[test]
    fn aead_round_trip() {
        let key = test_key();
        let set_id = SetId::new();
        let version = SetVersion(1);
        let payload = SetPayloadV1 {
            display_name: "secret-name".into(),
            memory: "m".into(),
            system_prompt: "sys".into(),
            history: vec![("u".into(), "a".into())],
        };
        let blob = seal_payload_v1("alice", set_id, version, &payload, &key).unwrap();
        let opened = open_payload_v1("alice", set_id, version, &blob, &key).unwrap();
        assert_eq!(opened, payload);
    }

    #[test]
    fn aead_rejects_wrong_user_or_version() {
        let key = test_key();
        let set_id = SetId::new();
        let payload = SetPayloadV1 {
            display_name: "n".into(),
            memory: String::new(),
            system_prompt: String::new(),
            history: vec![],
        };
        let blob = seal_payload_v1("alice", set_id, SetVersion(2), &payload, &key).unwrap();
        assert!(open_payload_v1("bob", set_id, SetVersion(2), &blob, &key).is_err());
        assert!(open_payload_v1("alice", set_id, SetVersion(3), &blob, &key).is_err());
        assert!(open_payload_v1("alice", SetId::new(), SetVersion(2), &blob, &key).is_err());
    }
}
