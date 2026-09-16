//! Fernet sealing for session mirrors and legacy history payloads.
//! Accepts URL-safe and standard base64 key forms.

use base64::engine::general_purpose::{STANDARD, URL_SAFE};
use base64::Engine;
use fernet::Fernet;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum FernetError {
    #[error("invalid encryption key")]
    InvalidEncryptionKey,
    #[error("fernet decryption failed")]
    DecryptionFailed,
    #[error("utf8 error: {0}")]
    Utf8(#[from] std::str::Utf8Error),
}

fn build_fernet(key: &[u8]) -> Result<Fernet, FernetError> {
    let key_str = std::str::from_utf8(key)?;
    if let Some(fernet) = Fernet::new(key_str) {
        return Ok(fernet);
    }

    let decoded = STANDARD
        .decode(key_str)
        .map_err(|_| FernetError::InvalidEncryptionKey)?;
    let reencoded = URL_SAFE.encode(decoded);
    Fernet::new(&reencoded).ok_or(FernetError::InvalidEncryptionKey)
}

pub(crate) fn encrypt_bytes(content: &[u8], key: &[u8]) -> Result<Vec<u8>, FernetError> {
    let fernet = build_fernet(key)?;
    Ok(fernet.encrypt(content).into_bytes())
}

pub(crate) fn decrypt_bytes(content: &[u8], key: &[u8]) -> Result<Vec<u8>, FernetError> {
    let fernet = build_fernet(key)?;
    let token = std::str::from_utf8(content)?;
    fernet
        .decrypt(token)
        .map_err(|_| FernetError::DecryptionFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    const URL_SAFE_KEY: &str = "-_v7-_v7-_v7-_v7-_v7-_v7-_v7-_v7-_v7-_v7-_s=";
    const STANDARD_KEY: &str = "+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/s=";
    const OTHER_KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    const FIXED_TOKEN: &str = "gAAAAABlU_EAABEiM0RVZneImaq7zN3u_ylmq4DAbApkoHmUt9MM7tOs8-BmzFd4q7FY1qpgfpSfZWeTER9zijdvxXFY3dmWZXouppIl5rS_rBh-tDamFJc=";

    #[test]
    fn both_key_alphabets_open_the_same_token() {
        let expected = b"live-helper-contract-plaintext";

        assert_eq!(
            decrypt_bytes(FIXED_TOKEN.as_bytes(), URL_SAFE_KEY.as_bytes()).unwrap(),
            expected
        );
        assert_eq!(
            decrypt_bytes(FIXED_TOKEN.as_bytes(), STANDARD_KEY.as_bytes()).unwrap(),
            expected
        );
    }

    #[test]
    fn sealed_bytes_open_via_fernet_crate() {
        let plaintext = b"domain fernet round trip";

        let sealed = encrypt_bytes(plaintext, URL_SAFE_KEY.as_bytes()).unwrap();
        let sealed_str = std::str::from_utf8(&sealed).unwrap();
        let direct = Fernet::new(URL_SAFE_KEY).expect("fixed key valid");

        assert_eq!(direct.decrypt(sealed_str).unwrap(), plaintext);
        assert_eq!(
            decrypt_bytes(direct.encrypt(plaintext).as_bytes(), URL_SAFE_KEY.as_bytes())
                .unwrap(),
            plaintext
        );
    }

    #[test]
    fn wrong_key_malformed_key_and_garbage_token_fail() {
        let sealed = encrypt_bytes(b"secret", URL_SAFE_KEY.as_bytes()).unwrap();

        assert!(matches!(
            decrypt_bytes(&sealed, OTHER_KEY.as_bytes()).unwrap_err(),
            FernetError::DecryptionFailed
        ));
        assert!(matches!(
            encrypt_bytes(b"x", b"short").unwrap_err(),
            FernetError::InvalidEncryptionKey
        ));
        assert!(matches!(
            decrypt_bytes(b"not-a-token", URL_SAFE_KEY.as_bytes()).unwrap_err(),
            FernetError::DecryptionFailed
        ));
    }
}
