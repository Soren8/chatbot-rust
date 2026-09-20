//! Contract for `static/credential-crypto.js`: owned derivation/wrap/PRF
//! algorithms with explicit env dependencies (phase 1, MOD014).
//!
//! The shared unit owns PBKDF2 derivation, AES-GCM wrap-key
//! generation/probe, data-key wrap/unwrap, PRF import/eval bytes plus
//! base64 transforms. Every browser capability arrives via explicit env
//! params; `static/enc-key.js` keeps store lifecycle plus the `EncKey`
//! surface and passes browser globals per call with no inline algorithm
//! copies. Behavioral coverage lives in
//! `fixtures/credential_crypto_test.js` through the stable UMD import
//! against deterministic Node WebCrypto (independent pbkdf2Sync oracle).

use std::path::Path;
use std::process::Command;

fn unit_js() -> &'static str {
    include_str!("../../static/credential-crypto.js")
}

fn enc_js() -> &'static str {
    include_str!("../../static/enc-key.js")
}

#[test]
fn credential_crypto_projects_owned_algorithms() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let run = Command::new("node")
        .arg(root.join("chatbot-server/tests/fixtures/credential_crypto_test.js"))
        .arg(root.join("static/credential-crypto.js"))
        .output()
        .expect("test image must provide the JS behavior-test runtime");
    assert!(
        run.status.success(),
        "JS credential-crypto behavior: {}",
        String::from_utf8_lossy(&run.stderr)
    );
}

#[test]
fn credential_crypto_js_parses() {
    let source = unit_js();
    let allocator = oxc_allocator::Allocator::default();
    let source_type = oxc_span::SourceType::default()
        .with_module(false)
        .with_jsx(false);
    let ret = oxc_parser::Parser::new(&allocator, source, source_type).parse();
    let errors: Vec<String> = ret.diagnostics.errors().map(ToString::to_string).collect();
    assert!(
        errors.is_empty(),
        "static/credential-crypto.js failed to parse ({} error(s)):\n{}",
        errors.len(),
        errors.join("\n")
    );
}

/// Shared UMD shape owning real algorithms with explicit env deps and no
/// ambient store, DOM, or key-flow reach.
#[test]
fn credential_crypto_is_shared_umd_with_explicit_deps() {
    let unit = unit_js();
    assert!(
        unit.contains("module.exports") && unit.contains("ChatCredentialCrypto"),
        "unit must share the UMD shape (require + browser global)"
    );
    for marker in [
        "deriveKeyFromPassword",
        "generateWrapKey",
        "wrapKeyCanEncrypt",
        "wrapDataKey",
        "unwrapDataKey",
        "importPrfKey",
        "prfEvalBytes",
        "supportsWebAuthnPrf",
        "prfWrapLabel",
        "chatbot-enc-key-wrap-v1",
    ] {
        assert!(
            unit.contains(marker),
            "crypto owner must project {marker}"
        );
    }
    assert!(
        unit.contains("100000") && unit.contains("SHA-256") && unit.contains("AES-GCM"),
        "PBKDF2/AES shapes must stay literal in the owner"
    );
    for forbidden in [
        "crypto.subtle",
        "crypto.getRandomValues",
        "window.",
        "document.",
        "indexedDB",
        "idbGet",
        "navigator",
        "X-Enc-Key",
        "getKeyForRequest",
        "NativeSecureKey",
    ] {
        assert!(
            !unit.contains(forbidden),
            "crypto algorithms must take explicit env instead of reaching {forbidden}"
        );
    }
}

/// enc-key.js wires the crypto owner with explicit browser env and keeps no
/// inline algorithm copies.
#[test]
fn enc_key_wires_crypto_owner_without_inline_copies() {
    let src = enc_js();
    for marker in [
        "ChatCredentialCrypto",
        "cryptoEnv()",
        "deriveKeyFromPassword(password, saltB64, cryptoEnv())",
        "wrapDataKey(rawKeyB64, aesKey, cryptoEnv())",
        "unwrapDataKey(record, aesKey, cryptoEnv())",
        "importPrfKey(prfResults.first, { subtle: crypto.subtle })",
        "prfEvalBytes({ TextEncoderImpl: TextEncoder })",
        "supportsWebAuthnPrf({ credentialCtor: global.PublicKeyCredential })",
    ] {
        assert!(
            src.contains(marker),
            "enc-key.js must wire the crypto owner with explicit env; missing: {marker}"
        );
    }
    for duplicate in [
        "100000",
        "SHA-256",
        "chatbot-enc-key-wrap-v1",
        "AES-GCM",
        "fromCharCode",
        "charCodeAt",
        "deriveBits",
        "importKey",
        "generateKey",
        "0-9a-f",
    ] {
        assert!(
            !src.contains(duplicate),
            "single ownership lives in the crypto/metadata units; enc-key.js must not keep {duplicate}"
        );
    }
    assert!(
        !src.contains("'acct:'") && !src.contains("\"acct:\""),
        "slot prefix lives in the metadata unit"
    );
}
