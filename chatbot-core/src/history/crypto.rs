//! Seal/open set payloads with AEAD + AAD binding.
//!
//! AAD: `user_id || set_id || blob_kind || version` — prevents ciphertext swap across context.

use aes_gcm::aead::{Aead, AeadCore, KeyInit, Payload};
use aes_gcm::Aes256Gcm;
use hkdf::Hkdf;
use rand::Rng;
use sha2::Sha256;
use thiserror::Error;

use super::types::{
    BlobFormat, HeaderV1, ImageId, ImagePayloadV1, ManifestV1, PairId, PairPayloadV1, SetId,
    SetPayloadV1, SetVersion, ThumbPayloadV1,
};
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

const NAME_AAD_KIND: &[u8] = b"set_name_v1";
const HEADER_AAD_KIND: &[u8] = b"set_header_v1";
const MANIFEST_AAD_KIND: &[u8] = b"set_manifest_v1";
const PAIR_AAD_KIND: &[u8] = b"set_pair_v1";
const IMAGE_AAD_KIND: &[u8] = b"set_image_v1";
const THUMB_AAD_KIND: &[u8] = b"set_thumb_v1";

/// AAD for the sealed display-name value. Not bound to set version: names are
/// independent of history contents (updated only when the name itself changes).
pub fn build_name_aad(user_id: &str, set_id: SetId) -> Vec<u8> {
    let mut aad = Vec::with_capacity(user_id.len() + 16 + NAME_AAD_KIND.len() + 2);
    aad.extend_from_slice(user_id.as_bytes());
    aad.push(0xff);
    aad.extend_from_slice(set_id.as_bytes());
    aad.push(0xff);
    aad.extend_from_slice(NAME_AAD_KIND);
    aad
}

/// user || 0xff || set_id || 0xff || set_header_v1 || 0xff || header_generation:u32 le
pub fn build_header_aad(user_id: &str, set_id: SetId, header_generation: u32) -> Vec<u8> {
    let mut aad = Vec::with_capacity(user_id.len() + 16 + HEADER_AAD_KIND.len() + 8);
    aad.extend_from_slice(user_id.as_bytes());
    aad.push(0xff);
    aad.extend_from_slice(set_id.as_bytes());
    aad.push(0xff);
    aad.extend_from_slice(HEADER_AAD_KIND);
    aad.push(0xff);
    aad.extend_from_slice(&header_generation.to_le_bytes());
    aad
}

/// user || 0xff || set_id || 0xff || set_manifest_v1 || 0xff || version:u64 le
pub fn build_manifest_aad(user_id: &str, set_id: SetId, version: SetVersion) -> Vec<u8> {
    let mut aad = Vec::with_capacity(user_id.len() + 16 + MANIFEST_AAD_KIND.len() + 12);
    aad.extend_from_slice(user_id.as_bytes());
    aad.push(0xff);
    aad.extend_from_slice(set_id.as_bytes());
    aad.push(0xff);
    aad.extend_from_slice(MANIFEST_AAD_KIND);
    aad.push(0xff);
    aad.extend_from_slice(&version.get().to_le_bytes());
    aad
}

/// user || 0xff || set_id || 0xff || set_pair_v1 || 0xff || pair_id || 0xff || generation:u32 le
pub fn build_pair_aad(user_id: &str, set_id: SetId, pair_id: PairId, generation: u32) -> Vec<u8> {
    let mut aad = Vec::with_capacity(user_id.len() + 16 + PAIR_AAD_KIND.len() + 24);
    aad.extend_from_slice(user_id.as_bytes());
    aad.push(0xff);
    aad.extend_from_slice(set_id.as_bytes());
    aad.push(0xff);
    aad.extend_from_slice(PAIR_AAD_KIND);
    aad.push(0xff);
    aad.extend_from_slice(pair_id.as_bytes());
    aad.push(0xff);
    aad.extend_from_slice(&generation.to_le_bytes());
    aad
}

/// user || 0xff || set_id || 0xff || set_image_v1 || 0xff || image_id
pub fn build_image_aad(user_id: &str, set_id: SetId, image_id: ImageId) -> Vec<u8> {
    let mut aad = Vec::with_capacity(user_id.len() + 16 + IMAGE_AAD_KIND.len() + 18);
    aad.extend_from_slice(user_id.as_bytes());
    aad.push(0xff);
    aad.extend_from_slice(set_id.as_bytes());
    aad.push(0xff);
    aad.extend_from_slice(IMAGE_AAD_KIND);
    aad.push(0xff);
    aad.extend_from_slice(image_id.as_bytes());
    aad
}

/// user || 0xff || set_id || 0xff || set_thumb_v1 || 0xff || image_id
pub fn build_thumb_aad(user_id: &str, set_id: SetId, image_id: ImageId) -> Vec<u8> {
    let mut aad = Vec::with_capacity(user_id.len() + 16 + THUMB_AAD_KIND.len() + 18);
    aad.extend_from_slice(user_id.as_bytes());
    aad.push(0xff);
    aad.extend_from_slice(set_id.as_bytes());
    aad.push(0xff);
    aad.extend_from_slice(THUMB_AAD_KIND);
    aad.push(0xff);
    aad.extend_from_slice(image_id.as_bytes());
    aad
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct SetNameV1 {
    display_name: String,
}

fn nonce_array(bytes: [u8; NONCE_LEN]) -> aes_gcm::Nonce<<Aes256Gcm as AeadCore>::NonceSize> {
    bytes.into()
}

fn aead_seal(aad: &[u8], plaintext: &[u8], enc_key: &EncryptionKey) -> Result<Vec<u8>, CryptoError> {
    let aes_key = derive_aes_key(enc_key);
    let cipher = Aes256Gcm::new_from_slice(&aes_key).map_err(|_| CryptoError::Encrypt)?;
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::rng().fill_bytes(&mut nonce_bytes);
    let nonce = nonce_array(nonce_bytes);
    let ct = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| CryptoError::Encrypt)?;
    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Ok(out)
}

fn aead_open(aad: &[u8], blob: &[u8], enc_key: &EncryptionKey) -> Result<Vec<u8>, CryptoError> {
    if blob.len() < NONCE_LEN + 16 {
        return Err(CryptoError::Framing);
    }
    let (nonce_bytes, ct) = blob.split_at(NONCE_LEN);
    let nonce_fixed: [u8; NONCE_LEN] = nonce_bytes.try_into().map_err(|_| CryptoError::Framing)?;
    let aes_key = derive_aes_key(enc_key);
    let cipher = Aes256Gcm::new_from_slice(&aes_key).map_err(|_| CryptoError::Decrypt)?;
    let nonce = nonce_array(nonce_fixed);
    cipher
        .decrypt(
            &nonce,
            Payload {
                msg: ct,
                aad,
            },
        )
        .map_err(|_| CryptoError::Decrypt)
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
    let aad = build_aad(user_id, set_id, BlobFormat::AeadV1, version);
    aead_seal(&aad, &plaintext, key)
}

pub fn open_payload_v1(
    user_id: &str,
    set_id: SetId,
    version: SetVersion,
    blob: &[u8],
    key: &EncryptionKey,
) -> Result<SetPayloadV1, CryptoError> {
    let aad = build_aad(user_id, set_id, BlobFormat::AeadV1, version);
    let plaintext = aead_open(&aad, blob, key)?;
    Ok(serde_json::from_slice(&plaintext)?)
}

pub fn seal_name_v1(
    user_id: &str,
    set_id: SetId,
    display_name: &str,
    key: &EncryptionKey,
) -> Result<Vec<u8>, CryptoError> {
    let payload = SetNameV1 {
        display_name: display_name.to_owned(),
    };
    let plaintext = serde_json::to_vec(&payload)?;
    let aad = build_name_aad(user_id, set_id);
    aead_seal(&aad, &plaintext, key)
}

pub fn open_name_v1(
    user_id: &str,
    set_id: SetId,
    blob: &[u8],
    key: &EncryptionKey,
) -> Result<String, CryptoError> {
    let aad = build_name_aad(user_id, set_id);
    let plaintext = aead_open(&aad, blob, key)?;
    let payload: SetNameV1 = serde_json::from_slice(&plaintext)?;
    Ok(payload.display_name)
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
        BlobFormat::AeadChunkedV2 => Err(CryptoError::Framing),
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
        BlobFormat::AeadChunkedV2 => Err(CryptoError::Framing),
    }
}

pub fn seal_header_v1(
    user_id: &str,
    set_id: SetId,
    header_generation: u32,
    header: &HeaderV1,
    key: &EncryptionKey,
) -> Result<Vec<u8>, CryptoError> {
    let plaintext = serde_json::to_vec(header)?;
    let aad = build_header_aad(user_id, set_id, header_generation);
    aead_seal(&aad, &plaintext, key)
}

pub fn open_header_v1(
    user_id: &str,
    set_id: SetId,
    header_generation: u32,
    blob: &[u8],
    key: &EncryptionKey,
) -> Result<HeaderV1, CryptoError> {
    let aad = build_header_aad(user_id, set_id, header_generation);
    let plaintext = aead_open(&aad, blob, key)?;
    Ok(serde_json::from_slice(&plaintext)?)
}

pub fn seal_manifest_v1(
    user_id: &str,
    set_id: SetId,
    version: SetVersion,
    manifest: &ManifestV1,
    key: &EncryptionKey,
) -> Result<Vec<u8>, CryptoError> {
    let plaintext = serde_json::to_vec(manifest)?;
    let aad = build_manifest_aad(user_id, set_id, version);
    aead_seal(&aad, &plaintext, key)
}

pub fn open_manifest_v1(
    user_id: &str,
    set_id: SetId,
    version: SetVersion,
    blob: &[u8],
    key: &EncryptionKey,
) -> Result<ManifestV1, CryptoError> {
    let aad = build_manifest_aad(user_id, set_id, version);
    let plaintext = aead_open(&aad, blob, key)?;
    Ok(serde_json::from_slice(&plaintext)?)
}

pub fn seal_pair_v1(
    user_id: &str,
    set_id: SetId,
    pair_id: PairId,
    generation: u32,
    payload: &PairPayloadV1,
    key: &EncryptionKey,
) -> Result<Vec<u8>, CryptoError> {
    let plaintext = serde_json::to_vec(payload)?;
    let aad = build_pair_aad(user_id, set_id, pair_id, generation);
    aead_seal(&aad, &plaintext, key)
}

pub fn open_pair_v1(
    user_id: &str,
    set_id: SetId,
    pair_id: PairId,
    generation: u32,
    blob: &[u8],
    key: &EncryptionKey,
) -> Result<PairPayloadV1, CryptoError> {
    let aad = build_pair_aad(user_id, set_id, pair_id, generation);
    let plaintext = aead_open(&aad, blob, key)?;
    Ok(serde_json::from_slice(&plaintext)?)
}

/// Binary plaintext: `mime_len:u16 le || mime utf8 || raw_bytes`.
pub fn encode_media_plaintext(mime: &str, bytes: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let mime_bytes = mime.as_bytes();
    if mime_bytes.len() > u16::MAX as usize {
        return Err(CryptoError::Framing);
    }
    let mut out = Vec::with_capacity(2 + mime_bytes.len() + bytes.len());
    out.extend_from_slice(&(mime_bytes.len() as u16).to_le_bytes());
    out.extend_from_slice(mime_bytes);
    out.extend_from_slice(bytes);
    Ok(out)
}

pub fn decode_media_plaintext(plain: &[u8]) -> Result<(String, Vec<u8>), CryptoError> {
    if plain.len() < 2 {
        return Err(CryptoError::Framing);
    }
    let mime_len = u16::from_le_bytes([plain[0], plain[1]]) as usize;
    if plain.len() < 2 + mime_len {
        return Err(CryptoError::Framing);
    }
    let mime = std::str::from_utf8(&plain[2..2 + mime_len])
        .map_err(|_| CryptoError::Framing)?
        .to_owned();
    Ok((mime, plain[2 + mime_len..].to_vec()))
}

pub fn seal_image_v1(
    user_id: &str,
    set_id: SetId,
    image_id: ImageId,
    payload: &ImagePayloadV1,
    key: &EncryptionKey,
) -> Result<Vec<u8>, CryptoError> {
    let plaintext = encode_media_plaintext(&payload.mime, &payload.bytes)?;
    let aad = build_image_aad(user_id, set_id, image_id);
    aead_seal(&aad, &plaintext, key)
}

pub fn open_image_v1(
    user_id: &str,
    set_id: SetId,
    image_id: ImageId,
    blob: &[u8],
    key: &EncryptionKey,
) -> Result<ImagePayloadV1, CryptoError> {
    let aad = build_image_aad(user_id, set_id, image_id);
    let plaintext = aead_open(&aad, blob, key)?;
    let (mime, bytes) = decode_media_plaintext(&plaintext)?;
    Ok(ImagePayloadV1 { mime, bytes })
}

pub fn seal_thumb_v1(
    user_id: &str,
    set_id: SetId,
    image_id: ImageId,
    payload: &ThumbPayloadV1,
    key: &EncryptionKey,
) -> Result<Vec<u8>, CryptoError> {
    let plaintext = encode_media_plaintext(&payload.mime, &payload.bytes)?;
    let aad = build_thumb_aad(user_id, set_id, image_id);
    aead_seal(&aad, &plaintext, key)
}

pub fn open_thumb_v1(
    user_id: &str,
    set_id: SetId,
    image_id: ImageId,
    blob: &[u8],
    key: &EncryptionKey,
) -> Result<ThumbPayloadV1, CryptoError> {
    let aad = build_thumb_aad(user_id, set_id, image_id);
    let plaintext = aead_open(&aad, blob, key)?;
    let (mime, bytes) = decode_media_plaintext(&plaintext)?;
    Ok(ThumbPayloadV1 { mime, bytes })
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

    #[test]
    fn name_aead_round_trip_and_binding() {
        let key = test_key();
        let set_id = SetId::new();
        let blob = seal_name_v1("alice", set_id, "secret-name", &key).unwrap();
        assert_eq!(open_name_v1("alice", set_id, &blob, &key).unwrap(), "secret-name");
        assert!(open_name_v1("bob", set_id, &blob, &key).is_err());
        assert!(open_name_v1("alice", SetId::new(), &blob, &key).is_err());
        // Name AAD is not the payload AAD — swapping the two ciphertexts must fail.
        assert!(open_payload_v1("alice", set_id, SetVersion(1), &blob, &key).is_err());
    }

    #[test]
    fn manifest_aad_binds_full_u64_version() {
        let key = test_key();
        let set_id = SetId::new();
        let version = SetVersion((1u64 << 32) | 1);
        let manifest = ManifestV1 { pairs: vec![] };
        let blob = seal_manifest_v1("alice", set_id, version, &manifest, &key).unwrap();
        let opened = open_manifest_v1("alice", set_id, version, &blob, &key).unwrap();
        assert_eq!(opened, manifest);
        // Truncated u32 must not open a version that needs the high 32 bits.
        let truncated = SetVersion(1);
        assert!(open_manifest_v1("alice", set_id, truncated, &blob, &key).is_err());
        assert!(open_manifest_v1("bob", set_id, version, &blob, &key).is_err());
    }

    #[test]
    fn image_seal_is_binary_not_json_array() {
        let key = test_key();
        let set_id = SetId::new();
        let image_id = ImageId::new();
        let jpeg = vec![0xff, 0xd8, 0xff, 0xd9, 1, 2, 3, 4];
        let payload = ImagePayloadV1 {
            mime: "image/jpeg".into(),
            bytes: jpeg.clone(),
        };
        let blob = seal_image_v1("alice", set_id, image_id, &payload, &key).unwrap();
        let mime = b"image/jpeg";
        let expected_plain = 2 + mime.len() + jpeg.len();
        // nonce(12) + tag(16) + binary plaintext
        assert_eq!(blob.len(), 12 + 16 + expected_plain);
        let opened = open_image_v1("alice", set_id, image_id, &blob, &key).unwrap();
        assert_eq!(opened, payload);
        // Thumb AAD is a different kind — cannot open an image blob as a thumb.
        assert!(open_thumb_v1("alice", set_id, image_id, &blob, &key).is_err());
        assert!(open_image_v1("bob", set_id, image_id, &blob, &key).is_err());
        assert!(open_image_v1("alice", set_id, ImageId::new(), &blob, &key).is_err());
    }

    #[test]
    fn header_and_pair_round_trip_and_generation_binding() {
        let key = test_key();
        let set_id = SetId::new();
        let header = HeaderV1 {
            memory: "m".into(),
            system_prompt: "p".into(),
        };
        let blob = seal_header_v1("alice", set_id, 3, &header, &key).unwrap();
        assert_eq!(
            open_header_v1("alice", set_id, 3, &blob, &key).unwrap(),
            header
        );
        assert!(open_header_v1("alice", set_id, 4, &blob, &key).is_err());

        let pair_id = PairId::new();
        let pair = PairPayloadV1 {
            user: "[IMAGE:img:550e8400-e29b-41d4-a716-446655440000]".into(),
            assistant: "ok".into(),
        };
        let pblob = seal_pair_v1("alice", set_id, pair_id, 1, &pair, &key).unwrap();
        assert_eq!(
            open_pair_v1("alice", set_id, pair_id, 1, &pblob, &key).unwrap(),
            pair
        );
        assert!(open_pair_v1("alice", set_id, pair_id, 2, &pblob, &key).is_err());
    }
}
