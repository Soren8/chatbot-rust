//! Naming policy and Fernet compatibility across live and migration callers.

use chatbot_core::enc_key::EncryptionKey;
use chatbot_core::history::{self, SetNameError, SetPayloadV1};
use chatbot_core::legacy_sets_json::{EncryptionMode, LegacySetsStore, PersistenceError};
use chatbot_core::persistence::DataPersistence;
use chatbot_core::user_store;

#[test]
fn set_name_trims_surrounding_whitespace() {
    let actual = LegacySetsStore::normalise_set_name(Some("  work  ")).unwrap();

    assert_eq!(actual, "work");
}

#[test]
fn set_name_defaults_when_missing_or_blank() {
    let from_none = LegacySetsStore::normalise_set_name(None).unwrap();
    let from_empty = LegacySetsStore::normalise_set_name(Some("")).unwrap();
    let from_spaces = LegacySetsStore::normalise_set_name(Some("   ")).unwrap();

    assert_eq!(from_none, "default");
    assert_eq!(from_empty, "default");
    assert_eq!(from_spaces, "default");
}

#[test]
fn custom_set_name_rejects_default_and_blank() {
    let default_err = LegacySetsStore::normalise_custom_set_name("default").unwrap_err();
    let padded_default_err =
        LegacySetsStore::normalise_custom_set_name("  default  ").unwrap_err();
    let empty_err = LegacySetsStore::normalise_custom_set_name("").unwrap_err();
    let spaces_err = LegacySetsStore::normalise_custom_set_name("   ").unwrap_err();

    assert!(matches!(
        default_err,
        PersistenceError::InvalidSetName
    ));
    assert!(matches!(
        padded_default_err,
        PersistenceError::InvalidSetName
    ));
    assert!(matches!(empty_err, PersistenceError::InvalidSetName));
    assert!(matches!(spaces_err, PersistenceError::InvalidSetName));
}

#[test]
fn set_name_accepts_allowed_characters_and_64_char_limit() {
    let sixty_four = "a".repeat(64);

    assert_eq!(
        LegacySetsStore::normalise_set_name(Some("work")).unwrap(),
        "work"
    );
    assert_eq!(
        LegacySetsStore::normalise_set_name(Some("Work 2")).unwrap(),
        "Work 2"
    );
    assert_eq!(
        LegacySetsStore::normalise_set_name(Some("my-set_name")).unwrap(),
        "my-set_name"
    );
    assert_eq!(
        LegacySetsStore::normalise_set_name(Some(&sixty_four)).unwrap(),
        sixty_four
    );
}

#[test]
fn set_name_rejects_dot_segments_disallowed_chars_and_overlong() {
    let overlong = "a".repeat(65);
    for raw in [".", "..", "a/b", "a\\b", "name!", "a\nb", overlong.as_str()] {
        let err = LegacySetsStore::normalise_set_name(Some(raw)).unwrap_err();

        assert!(
            matches!(err, PersistenceError::InvalidSetName),
            "expected InvalidSetName for {raw:?}, got {err:?}"
        );
    }
}

#[test]
fn history_facade_delegates_set_name_validation() {
    let from_none = history::normalise_set_name(None).unwrap();
    let trimmed = history::normalise_set_name(Some("  work  ")).unwrap();
    let custom_default_err = history::normalise_custom_set_name("default").unwrap_err();

    assert_eq!(from_none, "default");
    assert_eq!(trimmed, "work");
    assert!(matches!(
        custom_default_err,
        SetNameError::Invalid
    ));
}

#[test]
fn legacy_username_trims_and_reports_invalid_username() {
    let actual = LegacySetsStore::normalise_username("  alice-1_2  ").unwrap();

    assert_eq!(actual, "alice-1_2");

    let overlong = "a".repeat(65);
    for raw in ["", "   ", "alice bob", "a/b", "name!", overlong.as_str()] {
        let err = LegacySetsStore::normalise_username(raw).unwrap_err();

        assert!(matches!(err, PersistenceError::InvalidUsername));
        assert_eq!(err.to_string(), "invalid username");
    }
}

#[test]
fn user_store_username_error_text_differs_from_legacy() {
    let valid_legacy = LegacySetsStore::normalise_username("alice-1_2").unwrap();
    let valid_store = user_store::normalise_username("  alice-1_2  ").unwrap();

    assert_eq!(valid_legacy, "alice-1_2");
    assert_eq!(valid_store, "alice-1_2");

    let empty_err = user_store::normalise_username("   ").unwrap_err();
    let invalid_err = user_store::normalise_username("bad name!").unwrap_err();
    let legacy_err = LegacySetsStore::normalise_username("bad name!").unwrap_err();

    assert_eq!(empty_err, "Username and password required.");
    assert_eq!(
        invalid_err,
        "Username may only include letters, numbers, '_' or '-'"
    );
    assert_eq!(legacy_err.to_string(), "invalid username");
    assert_ne!(invalid_err, legacy_err.to_string());
}

// Keys below encode the same 32 bytes (0xfb * 32) in the two supported
// base64 alphabets; the token was generated independently via
// openssl AES-128-CBC + HMAC-SHA256 with fixed IV/timestamp.

const URL_SAFE_KEY_STR: &str = "-_v7-_v7-_v7-_v7-_v7-_v7-_v7-_v7-_v7-_v7-_s=";
const STANDARD_KEY_STR: &str = "+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/s=";
const OTHER_VALID_KEY_STR: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

/// Fixed Fernet token for b"live-helper-contract-plaintext" under the keys
/// above (version 0x80, timestamp 1700000000,
/// IV 00112233445566778899aabbccddeeff).
const FIXED_TOKEN_STR: &str = "gAAAAABlU_EAABEiM0RVZneImaq7zN3u_ylmq4DAbApkoHmUt9MM7tOs8-BmzFd4q7FY1qpgfpSfZWeTER9zijdvxXFY3dmWZXouppIl5rS_rBh-tDamFJc=";

#[test]
fn fernet_url_safe_key_interops_with_fernet_crate() {
    let plaintext = b"hello fernet interop";

    let sealed =
        DataPersistence::encrypt_bytes(plaintext, EncryptionMode::Fernet(URL_SAFE_KEY_STR.as_bytes()))
            .unwrap();
    let sealed_str = std::str::from_utf8(&sealed).unwrap();

    let direct = fernet::Fernet::new(URL_SAFE_KEY_STR).expect("fixed url-safe key valid");
    let opened = direct.decrypt(sealed_str).unwrap();

    assert_eq!(opened.as_slice(), plaintext as &[u8]);

    let fresh_token = direct.encrypt(plaintext);
    let reopened = DataPersistence::decrypt_bytes(
        fresh_token.as_bytes(),
        EncryptionMode::Fernet(URL_SAFE_KEY_STR.as_bytes()),
    )
    .unwrap();

    assert_eq!(reopened.as_slice(), plaintext as &[u8]);
}

#[test]
fn fernet_standard_base64_key_with_plus_slash_matches_url_safe() {
    assert!(STANDARD_KEY_STR.contains('+') && STANDARD_KEY_STR.contains('/'));
    assert!(URL_SAFE_KEY_STR.contains('-') && URL_SAFE_KEY_STR.contains('_'));

    let plaintext = b"alphabet-interop-check";

    let via_standard = DataPersistence::encrypt_bytes(
        plaintext,
        EncryptionMode::Fernet(STANDARD_KEY_STR.as_bytes()),
    )
    .unwrap();
    let via_url_safe = DataPersistence::encrypt_bytes(
        plaintext,
        EncryptionMode::Fernet(URL_SAFE_KEY_STR.as_bytes()),
    )
    .unwrap();

    let cross_standard_to_url = DataPersistence::decrypt_bytes(
        &via_standard,
        EncryptionMode::Fernet(URL_SAFE_KEY_STR.as_bytes()),
    )
    .unwrap();
    let cross_url_to_standard = DataPersistence::decrypt_bytes(
        &via_url_safe,
        EncryptionMode::Fernet(STANDARD_KEY_STR.as_bytes()),
    )
    .unwrap();

    assert_eq!(cross_standard_to_url.as_slice(), plaintext as &[u8]);
    assert_eq!(cross_url_to_standard.as_slice(), plaintext as &[u8]);
}

#[test]
fn fernet_fixed_independently_generated_token_decrypts() {
    let expected = b"live-helper-contract-plaintext";

    let via_url_safe = DataPersistence::decrypt_bytes(
        FIXED_TOKEN_STR.as_bytes(),
        EncryptionMode::Fernet(URL_SAFE_KEY_STR.as_bytes()),
    )
    .unwrap();
    let via_standard = DataPersistence::decrypt_bytes(
        FIXED_TOKEN_STR.as_bytes(),
        EncryptionMode::Fernet(STANDARD_KEY_STR.as_bytes()),
    )
    .unwrap();

    assert_eq!(via_url_safe.as_slice(), expected as &[u8]);
    assert_eq!(via_standard.as_slice(), expected as &[u8]);

    let direct = fernet::Fernet::new(URL_SAFE_KEY_STR).expect("fixed url-safe key valid");
    let via_crate = direct.decrypt(FIXED_TOKEN_STR).unwrap();

    assert_eq!(via_crate.as_slice(), expected as &[u8]);
}

#[test]
fn fernet_wrong_key_fails_decryption() {
    let plaintext = b"wrong-key must not open";

    let sealed =
        DataPersistence::encrypt_bytes(plaintext, EncryptionMode::Fernet(URL_SAFE_KEY_STR.as_bytes()))
            .unwrap();

    let err = DataPersistence::decrypt_bytes(
        &sealed,
        EncryptionMode::Fernet(OTHER_VALID_KEY_STR.as_bytes()),
    )
    .unwrap_err();

    assert!(matches!(err, PersistenceError::DecryptionFailed));
    assert_eq!(err.to_string(), "fernet decryption failed");
}

#[test]
fn fernet_malformed_key_rejected_as_invalid_key() {
    for raw in ["short", "!!!-not-base64-!!!", ""] {
        let err = DataPersistence::encrypt_bytes(b"x", EncryptionMode::Fernet(raw.as_bytes()))
            .unwrap_err();

        assert!(
            matches!(err, PersistenceError::InvalidEncryptionKey),
            "expected InvalidEncryptionKey for {raw:?}, got {err:?}"
        );
        assert_eq!(err.to_string(), "invalid encryption key");
    }
}

#[test]
fn fernet_invalid_token_bytes_fail_decryption() {
    let garbage_err = DataPersistence::decrypt_bytes(
        b"not-a-valid-fernet-token",
        EncryptionMode::Fernet(URL_SAFE_KEY_STR.as_bytes()),
    )
    .unwrap_err();

    assert!(matches!(
        garbage_err,
        PersistenceError::DecryptionFailed
    ));

    let non_utf8_err = DataPersistence::decrypt_bytes(
        &[0xff, 0xfe, 0xfd],
        EncryptionMode::Fernet(URL_SAFE_KEY_STR.as_bytes()),
    )
    .unwrap_err();

    assert!(matches!(non_utf8_err, PersistenceError::Utf8(_)));
}

#[test]
fn plaintext_mode_passes_bytes_through_unchanged() {
    let message = "plain-memory \u{2713}".as_bytes().to_vec();

    let encrypted =
        DataPersistence::encrypt_bytes(&message, EncryptionMode::Plaintext).unwrap();
    let decrypted =
        DataPersistence::decrypt_bytes(&encrypted, EncryptionMode::Plaintext).unwrap();

    assert_eq!(encrypted, message);
    assert_eq!(decrypted, message);

    let fernet_token = DataPersistence::encrypt_bytes(
        b"ciphertext stays opaque in plaintext mode",
        EncryptionMode::Fernet(URL_SAFE_KEY_STR.as_bytes()),
    )
    .unwrap();
    let passthrough =
        DataPersistence::decrypt_bytes(&fernet_token, EncryptionMode::Plaintext).unwrap();

    assert_eq!(passthrough, fernet_token);
}

#[test]
fn history_fernet_payload_json_survives_fernet_seal() {
    let key = EncryptionKey::from_header_value(URL_SAFE_KEY_STR).expect("fixed key header");
    let payload = SetPayloadV1 {
        display_name: "work".to_string(),
        memory: "remember this".to_string(),
        system_prompt: "be helpful".to_string(),
        history: vec![("hi".to_string(), "hello".to_string())],
    };

    let json = serde_json::to_vec(&payload).unwrap();

    let sealed =
        DataPersistence::encrypt_bytes(&json, EncryptionMode::Fernet(key.as_bytes())).unwrap();
    let opened =
        DataPersistence::decrypt_bytes(&sealed, EncryptionMode::Fernet(key.as_bytes())).unwrap();
    let round_tripped: SetPayloadV1 = serde_json::from_slice(&opened).unwrap();

    assert_eq!(round_tripped, payload);

    let wrong = EncryptionKey::from_header_value(OTHER_VALID_KEY_STR).expect("other key header");
    let err =
        DataPersistence::decrypt_bytes(&sealed, EncryptionMode::Fernet(wrong.as_bytes()))
            .unwrap_err();

    assert!(matches!(err, PersistenceError::DecryptionFailed));
}
