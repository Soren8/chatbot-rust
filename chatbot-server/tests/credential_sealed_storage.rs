//! Contract for sealed-cookie storage helpers (phase 1, MOD014):
//! `CredentialCookies` (pure cookie names / header parsing / jar value
//! builders) and `SealedCredentialPayload` (exact legacy `org.json` payload
//! codec) in the same `com.chatbot.app` package as
//! `NativeSecureKeyPlugin`.
//!
//! `CredentialCookies` stays dependency-free (`java.*` only) so it runs
//! under plain `javac` behavior tests. `SealedCredentialPayload` owns the
//! exact legacy `JSONObject` behavior (puts in account, remember, enc_key
//! order; absent values via `optString` to `""`) and is verified via source
//! pins, since plain `javac` lacks the Android `org.json` class. The plugin
//! keeps the platform boundary (jar access, keystore wrap/unwrap,
//! biometric prompts), the legacy `storeKey` / `getKey` / `unlockedKeys`
//! API, PBKDF2 derivation, keystore migration and origin resolution
//! unchanged. No custom JSON anywhere.

use std::path::Path;
use std::process::Command;

fn plugin_src() -> &'static str {
    include_str!(
        "../../android/app/src/main/java/com/chatbot/app/NativeSecureKey/NativeSecureKeyPlugin.java"
    )
}

fn cookies_src() -> &'static str {
    include_str!(
        "../../android/app/src/main/java/com/chatbot/app/NativeSecureKey/CredentialCookies.java"
    )
}

fn payload_src() -> &'static str {
    include_str!(
        "../../android/app/src/main/java/com/chatbot/app/NativeSecureKey/SealedCredentialPayload.java"
    )
}

#[test]
fn sealed_storage_pure_subset_projects_owned_policy() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let output_dir = tempfile::tempdir().unwrap();
    let compile = Command::new("javac")
        .arg("-d")
        .arg(output_dir.path())
        .arg(root.join("android/app/src/main/java/com/chatbot/app/NativeSecureKey/CredentialCookies.java"))
        .arg(root.join("chatbot-server/tests/fixtures/CredentialSealedStorageTest.java"))
        .output()
        .expect("test image must provide javac");
    assert!(
        compile.status.success(),
        "Java compilation: {}",
        String::from_utf8_lossy(&compile.stderr)
    );
    let run = Command::new("java")
        .arg("-cp")
        .arg(output_dir.path())
        .arg("CredentialSealedStorageTest")
        .output()
        .expect("run native sealed-storage behavior tests");
    assert!(
        run.status.success(),
        "native sealed-storage behavior: {}",
        String::from_utf8_lossy(&run.stderr)
    );
}

/// The pure cookie helper stays platform-independent; the payload owner is
/// the single place allowed to reach `org.json`.
#[test]
fn sealed_storage_helpers_own_exact_boundaries() {
    assert!(
        cookies_src().contains("package com.chatbot.app;"),
        "CredentialCookies must stay in the plugin package"
    );
    for forbidden in [
        "android.",
        "CookieManager",
        "Biometric",
        "Capacitor",
        "KeyStore",
        "Cipher",
        "GCMParameterSpec",
        "org.json",
        "JSONObject",
        "resolveServerUrl",
        "getServerUrl",
    ] {
        assert!(
            !cookies_src().contains(forbidden),
            "CredentialCookies must not reach {forbidden}"
        );
    }
    for marker in [
        "parseSealedCookieHeader",
        "injectCookieValue",
        "expiredCookieValue",
        "isCredentialCookie",
    ] {
        assert!(
            cookies_src().contains(marker),
            "CredentialCookies must own {marker}"
        );
    }
    assert!(
        payload_src().contains("package com.chatbot.app;"),
        "SealedCredentialPayload must stay in the plugin package"
    );
    for marker in [
        "import org.json.JSONObject",
        "new JSONObject()",
        "new JSONObject(json)",
        "optString",
        "FIELD_ACCOUNT",
        "FIELD_REMEMBER",
        "FIELD_ENC_KEY",
    ] {
        assert!(
            payload_src().contains(marker),
            "payload owner must keep exact legacy org.json behavior; missing: {marker}"
        );
    }
    for reinvented in ["escape(", "unescape(", "fieldValue(", "String.format"] {
        assert!(
            !payload_src().contains(reinvented),
            "no custom JSON reinvention; payload must not contain {reinvented}"
        );
    }
    for forbidden in [
        "CookieManager",
        "Biometric",
        "Capacitor",
        "KeyStore",
        "Cipher",
        "resolveServerUrl",
    ] {
        assert!(
            !payload_src().contains(forbidden),
            "payload codec must not reach {forbidden}"
        );
    }
}

/// The plugin delegates sealed storage to the helpers while keeping the
/// legacy key API, keystore migration, PBKDF2, biometric boundary and
/// origin resolution in place.
#[test]
fn plugin_delegates_sealed_storage_keeping_legacy_api() {
    let src = plugin_src();
    for marker in ["CredentialCookies", "SealedCredentialPayload"] {
        assert!(
            src.contains(marker),
            "plugin must delegate sealed storage to {marker}"
        );
    }
    for marker in [
        "parseSealedCookieHeader",
        "injectCookieValue",
        "expiredCookieValue",
        "SealedCredentialPayload.encode",
        "SealedCredentialPayload.decode",
    ] {
        assert!(
            src.contains(marker),
            "plugin must call sealed-storage helper {marker}"
        );
    }
    assert!(
        !src.contains("new JSONObject"),
        "single JSON ownership lives in the payload helper, not the plugin"
    );
    for legacy in [
        "unlockedKeys",
        "storeKey",
        "getKey",
        "deriveKeyFromPassword",
        "PBKDF2_ITERATIONS",
        "removeLegacyKeyIfPresent",
        "migrateFromV2IfNeeded",
        "getOrCreateKey",
    ] {
        assert!(
            src.contains(legacy),
            "legacy key API / migration / derivation must stay in the plugin; missing: {legacy}"
        );
    }
    for boundary in [
        "promptForUnlock",
        "canPromptForBiometric",
        "BiometricPrompt",
        "resolveServerUrl",
    ] {
        assert!(
            src.contains(boundary),
            "platform boundary must stay in the plugin; missing: {boundary}"
        );
    }
    assert!(
        !src.contains("k.equals(\"remember\")"),
        "seal must not fall back to the generic remember cookie"
    );
    assert!(
        !src.contains("k.equals(\"enc_key\")"),
        "seal must not fall back to the generic enc_key cookie"
    );
}
