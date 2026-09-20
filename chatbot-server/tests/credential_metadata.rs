//! Contract for `static/credential-metadata.js`: owned per-account cached
//! login slot-metadata policy (phase 1, MOD014).
//!
//! The shared unit owns slot naming, hashed-slot detection, remembered /
//! age visibility, recency sorting, the pure last-used bump and purge
//! candidates with explicit inputs. `static/enc-key.js` keeps IndexedDB
//! lifecycle plus the `EncKey` surface and wires the unit with no inline
//! policy copies. Behavioral coverage lives in
//! `fixtures/credential_metadata_test.js` through the stable UMD import.

use std::path::Path;
use std::process::Command;

fn unit_js() -> &'static str {
    include_str!("../../static/credential-metadata.js")
}

fn enc_js() -> &'static str {
    include_str!("../../static/enc-key.js")
}

#[test]
fn credential_metadata_projects_owned_policy() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let run = Command::new("node")
        .arg(root.join("chatbot-server/tests/fixtures/credential_metadata_test.js"))
        .arg(root.join("static/credential-metadata.js"))
        .output()
        .expect("test image must provide the JS behavior-test runtime");
    assert!(
        run.status.success(),
        "JS credential-metadata behavior: {}",
        String::from_utf8_lossy(&run.stderr)
    );
}

#[test]
fn credential_metadata_js_parses() {
    let source = unit_js();
    let allocator = oxc_allocator::Allocator::default();
    let source_type = oxc_span::SourceType::default()
        .with_module(false)
        .with_jsx(false);
    let ret = oxc_parser::Parser::new(&allocator, source, source_type).parse();
    let errors: Vec<String> = ret.diagnostics.errors().map(ToString::to_string).collect();
    assert!(
        errors.is_empty(),
        "static/credential-metadata.js failed to parse ({} error(s)):\n{}",
        errors.len(),
        errors.join("\n")
    );
}

/// Shared UMD shape: stable `require` import plus a browser global, with no
/// storage, DOM, crypto, or key-flow dependencies.
#[test]
fn credential_metadata_is_shared_umd_without_side_channels() {
    let unit = unit_js();
    assert!(
        unit.contains("module.exports") && unit.contains("ChatCredentialMetadata"),
        "unit must share the UMD shape (require + browser global); got head: {}",
        &unit[..unit.len().min(400)]
    );
    for marker in [
        "slotKeyFor",
        "filterCachedAccounts",
        "touchSlotRecord",
        "purgeableSlotUsernames",
        "isHashedSlotUsername",
        "isSlotEntryVisible",
    ] {
        assert!(
            unit.contains(marker),
            "metadata owner must project {marker}"
        );
    }
    for forbidden in [
        "indexedDB",
        "idbGet",
        "window.",
        "document.",
        "crypto.subtle",
        "deriveBits",
        "X-Enc-Key",
        "getKeyForRequest",
        "getKeyForUsername",
        "NativeSecureKey",
    ] {
        assert!(
            !unit.contains(forbidden),
            "metadata policy must not reach {forbidden}"
        );
    }
}

/// enc-key.js wires the metadata owner with no inline policy copies while
/// keeping store lifecycle and the unchanged EncKey surface.
#[test]
fn enc_key_wires_metadata_owner_without_inline_copies() {
    let src = enc_js();
    for marker in [
        "ChatCredentialMetadata",
        "slotKeyFor(username, currentUsername())",
        "filterCachedAccounts(entries, Date.now())",
        "touchSlotRecord(record, Date.now())",
        "purgeableSlotUsernames(entries)",
        "isAccountSlotKey(key)",
        "SLOT_PREFIX + String(hash",
    ] {
        assert!(
            src.contains(marker),
            "enc-key.js must wire the metadata owner; missing: {marker}"
        );
    }
    for surface in [
        "storeFromLogin",
        "listCachedAccounts",
        "touchSlot",
        "removeSlot",
        "purgeNonRememberedSlots",
    ] {
        assert!(
            src.contains(surface),
            "EncKey public surface must stay unchanged; missing: {surface}"
        );
    }
    assert!(
        src.contains("entry.value.mode === 'webauthn-prf'"),
        "scrubWrappedKeys must stay inline preserving webauthn-prf entries"
    );
    for duplicate in ["0-9a-f", "MAX_CACHED_ACCOUNT_AGE_MS"] {
        assert!(
            !src.contains(duplicate),
            "single policy lives in the metadata unit; enc-key.js must not keep {duplicate}"
        );
    }
    assert!(
        !src.contains("'acct:'") && !src.contains("\"acct:\""),
        "slot prefix lives in the metadata unit"
    );
}

/// No new JS key flows: slot lookups still resolve to null without unwrapping
/// or touching native storage.
#[test]
fn enc_key_slot_lookups_still_resolve_null() {
    let src = enc_js();
    for marker in ["async function getKeyForUsername", "async function getKeyForRequest"] {
        assert!(
            src.contains(marker),
            "legacy null-returning lookup must remain; missing: {marker}"
        );
    }
    let start = src
        .find("async function getKeyForUsername")
        .expect("getKeyForUsername");
    let next = src[start + 1..]
        .find("async function ")
        .map(|i| start + 1 + i)
        .unwrap_or(src.len());
    let body = &src[start..next];
    assert!(
        body.contains("return null"),
        "getKeyForUsername must still resolve null"
    );
    assert!(
        !body.contains("unwrapDataKey") && !body.contains("NativeSecureKey"),
        "getKeyForUsername must not unwrap or call native storage"
    );
}
