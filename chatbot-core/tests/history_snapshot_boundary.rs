//! MOD005 boundary: logical (`[IMAGE:img:…]` refs) vs materialized
//! (`[IMAGE:data:…]` URLs) snapshot shapes across cold/warm cache states.
//!
//! Consumer boundary is the public `HistoryService` API (`load` vs
//! `load_logical`). The process cache holds normalized logical snapshots only;
//! `load` materializes an owned copy for compat readers. These tests pin the
//! contract that warm (cache-hit) and cold (reopened) `load_logical` agree
//! exactly — same version, same pair ids, same ref text — across direct
//! append, prepare-capture append, regenerate/edit, and fork, plus
//! materialized fidelity (decoded image bytes and pixels, assistant text) and
//! fork prefix/source separation with fresh fork pair ids.

use chatbot_core::chat_images::fixture_jpeg_data_url;
use chatbot_core::enc_key::EncryptionKey;
use chatbot_core::history::{HistoryService, PrepareCapture};

fn test_key() -> EncryptionKey {
    EncryptionKey::from_header_value("dGVzdC1rZXktbWF0ZXJpYWwtMTIzNDU2Nzg5MDEyMzQ1Ng==")
        .expect("fixed test key header")
}

fn has_data_url(text: &str) -> bool {
    text.contains("[IMAGE:data:")
}

fn has_img_ref(text: &str) -> bool {
    text.contains("[IMAGE:img:")
}

fn image_user_msg(caption: &str) -> String {
    format!("{caption}\n[IMAGE:{}]", fixture_jpeg_data_url(32, 32))
}

fn decoded_first_image_bytes(materialized_user_text: &str) -> (String, Vec<u8>) {
    let url = chatbot_core::chat_images::nth_image_data_url(materialized_user_text, 0)
        .expect("materialized text holds one image data URL");
    chatbot_core::chat_images::decode_image_data_url(&url).expect("image data URL decodes")
}

fn assert_fixture_pixels(bytes: &[u8]) {
    use image::GenericImageView as _;
    let img = image::load_from_memory(bytes).expect("stored image bytes decode to pixels");
    assert_eq!(img.dimensions(), (32, 32));
}

#[test]
fn direct_image_append_warm_and_cold_logical_match() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("h.redb");
    let svc = HistoryService::open_ephemeral(&path).unwrap();
    let key = test_key();

    let created = svc.create_set("snap-user", "photos", &key).unwrap();
    let user_msg = image_user_msg("look");

    // One version bump per successful commit.
    let v2 = svc
        .append_pair("snap-user", created.set_id, created.version, &user_msg, "nice", &key)
        .unwrap();
    assert_eq!(v2.get(), created.version.get() + 1);

    // Warm reads come from the version-checked cache; capture them before
    // reopening (one redb handle per file).
    let warm_logical = svc.load_logical("snap-user", created.set_id, &key).unwrap();
    assert_eq!(warm_logical.version, v2);
    assert_eq!(warm_logical.history.len(), 1);
    assert_eq!(warm_logical.pair_ids.len(), 1);
    let warm_full = svc.load("snap-user", created.set_id, &key).unwrap();

    // Normalized cache shape: refs, no pixel bytes.
    assert!(has_img_ref(&warm_logical.history[0].0));
    assert!(!has_data_url(&warm_logical.history[0].0));

    // Cold: fresh process cache, durable truth from redb chunks.
    drop(svc);
    let cold_svc = HistoryService::open_ephemeral(&path).unwrap();
    let cold_logical = cold_svc
        .load_logical("snap-user", created.set_id, &key)
        .unwrap();
    assert_eq!(cold_logical.version, v2);
    assert_eq!(cold_logical.history.len(), 1);
    assert_eq!(cold_logical.pair_ids.len(), 1);

    // Warm and cold agree exactly: same version, ids, and normalized text.
    assert_eq!(warm_logical.pair_ids, cold_logical.pair_ids);
    assert_eq!(warm_logical.history, cold_logical.history);
    assert!(has_img_ref(&cold_logical.history[0].0));
    assert!(!has_data_url(&cold_logical.history[0].0));

    // Materialized fidelity: same decoded bytes and pixels, assistant exact.
    let cold_full = cold_svc.load("snap-user", created.set_id, &key).unwrap();
    assert!(has_data_url(&warm_full.history[0].0));
    assert!(has_data_url(&cold_full.history[0].0));
    let (_, warm_bytes) = decoded_first_image_bytes(&warm_full.history[0].0);
    let (_, cold_bytes) = decoded_first_image_bytes(&cold_full.history[0].0);
    assert_eq!(warm_bytes, cold_bytes);
    assert_fixture_pixels(&cold_bytes);
    assert_eq!(warm_full.history[0].1, "nice");
    assert_eq!(cold_full.history[0].1, "nice");
}

#[test]
fn chat_capture_append_with_image_warm_vs_cold_shapes() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("h.redb");
    let svc = HistoryService::open_ephemeral(&path).unwrap();
    let key = test_key();

    let created = svc.create_set("snap-user", "chat", &key).unwrap();
    // Session prepare path builds its capture from the materialized `load`.
    let snap = svc.load("snap-user", created.set_id, &key).unwrap();
    let capture = PrepareCapture::from_snapshot(&snap);

    let user_msg = image_user_msg("describe");
    let v2 = svc
        .commit_chat_append("snap-user", &capture, &user_msg, "a cat", &key)
        .unwrap();
    assert_eq!(v2.get(), created.version.get() + 1);

    let warm_logical = svc.load_logical("snap-user", created.set_id, &key).unwrap();
    assert_eq!(warm_logical.version, v2);
    assert_eq!(warm_logical.history.len(), 1);
    assert_eq!(warm_logical.pair_ids.len(), 1);
    let warm_full = svc.load("snap-user", created.set_id, &key).unwrap();

    // The committed cache entry is logical even though the capture carried
    // `data:` URLs: refs, no pixel bytes.
    assert!(has_img_ref(&warm_logical.history[0].0));
    assert!(!has_data_url(&warm_logical.history[0].0));

    drop(svc);
    let cold_svc = HistoryService::open_ephemeral(&path).unwrap();
    let cold_logical = cold_svc
        .load_logical("snap-user", created.set_id, &key)
        .unwrap();
    assert_eq!(cold_logical.version, v2);
    assert_eq!(cold_logical.pair_ids, warm_logical.pair_ids);
    assert_eq!(cold_logical.history, warm_logical.history);

    // Durable logical shape is ref-only.
    assert!(has_img_ref(&cold_logical.history[0].0));
    assert!(!has_data_url(&cold_logical.history[0].0));

    // Materialized fidelity: caption prefix, decoded bytes/pixels, answer exact.
    let cold_full = cold_svc.load("snap-user", created.set_id, &key).unwrap();
    assert_eq!(cold_full.history[0].1, "a cat");
    assert!(cold_full.history[0].0.starts_with("describe\n[IMAGE:data:"));
    let (_, warm_bytes) = decoded_first_image_bytes(&warm_full.history[0].0);
    let (_, cold_bytes) = decoded_first_image_bytes(&cold_full.history[0].0);
    assert_eq!(warm_bytes, cold_bytes);
    assert_fixture_pixels(&cold_bytes);
}

#[test]
fn regenerate_edit_preserves_image_fidelity_warm_vs_cold() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("h.redb");
    let svc = HistoryService::open_ephemeral(&path).unwrap();
    let key = test_key();

    let created = svc.create_set("snap-user", "edit", &key).unwrap();
    let first = image_user_msg("caption");
    let v2 = svc
        .append_pair("snap-user", created.set_id, created.version, &first, "a1", &key)
        .unwrap();

    // Regenerate path: capture holds the stored pair, edit replaces the answer.
    let snap = svc.load("snap-user", created.set_id, &key).unwrap();
    assert_eq!(snap.version, v2);
    let stored_user = snap.history[0].0.clone();
    let capture = PrepareCapture::from_snapshot(&snap).with_regenerate(0, stored_user);

    let v3 = svc
        .commit_regenerate("snap-user", &capture, "a1-edited", &key)
        .unwrap();
    assert_eq!(v3.get(), v2.get() + 1);

    let warm_logical = svc.load_logical("snap-user", created.set_id, &key).unwrap();
    assert_eq!(warm_logical.version, v3);
    assert_eq!(warm_logical.history[0].1, "a1-edited");
    let warm_full = svc.load("snap-user", created.set_id, &key).unwrap();

    // Warm cache entry is logical: refs, no pixel bytes.
    assert!(has_img_ref(&warm_logical.history[0].0));
    assert!(!has_data_url(&warm_logical.history[0].0));

    drop(svc);
    let cold_svc = HistoryService::open_ephemeral(&path).unwrap();
    let cold_logical = cold_svc
        .load_logical("snap-user", created.set_id, &key)
        .unwrap();
    assert_eq!(cold_logical.version, v3);
    assert_eq!(cold_logical.history[0].1, "a1-edited");
    assert_eq!(cold_logical.pair_ids, warm_logical.pair_ids);
    assert_eq!(cold_logical.history, warm_logical.history);

    // Durable logical shape is ref-only; assistant edit applied in place.
    assert!(has_img_ref(&cold_logical.history[0].0));
    assert!(!has_data_url(&cold_logical.history[0].0));

    // Materialized reads keep identical decoded bytes/pixels and the edit.
    let cold_full = cold_svc.load("snap-user", created.set_id, &key).unwrap();
    assert!(has_data_url(&warm_full.history[0].0));
    assert!(has_data_url(&cold_full.history[0].0));
    let (_, warm_bytes) = decoded_first_image_bytes(&warm_full.history[0].0);
    let (_, cold_bytes) = decoded_first_image_bytes(&cold_full.history[0].0);
    assert_eq!(warm_bytes, cold_bytes);
    assert_fixture_pixels(&cold_bytes);
    assert_eq!(cold_full.history[0].1, "a1-edited");
}

#[test]
fn fork_with_image_preserves_prefix_and_source() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("h.redb");
    let svc = HistoryService::open_ephemeral(&path).unwrap();
    let key = test_key();

    let created = svc.create_set("snap-user", "trip", &key).unwrap();
    let mut v = created.version;
    let first = image_user_msg("beach");
    v = svc
        .append_pair("snap-user", created.set_id, v, &first, "a1", &key)
        .unwrap();
    v = svc
        .append_pair("snap-user", created.set_id, v, "second", "a2", &key)
        .unwrap();

    let forked = svc
        .fork_set("snap-user", created.set_id, Some(v), 0, None, &key)
        .unwrap();
    assert_eq!(forked.display_name, "trip - branch");

    // Fork prefix is the inclusive first pair; source keeps both pairs.
    let fork_full = svc.load("snap-user", forked.set_id, &key).unwrap();
    assert_eq!(fork_full.history.len(), 1);
    assert_eq!(fork_full.history[0].1, "a1");
    assert!(has_data_url(&fork_full.history[0].0));

    let source_full = svc.load("snap-user", created.set_id, &key).unwrap();
    assert_eq!(source_full.history.len(), 2);
    assert_eq!(source_full.version, v);

    drop(svc);
    let cold_svc = HistoryService::open_ephemeral(&path).unwrap();
    let fork_cold = cold_svc.load("snap-user", forked.set_id, &key).unwrap();
    assert_eq!(fork_cold.history.len(), 1);
    assert_eq!(fork_cold.history[0].1, "a1");
    assert!(has_data_url(&fork_cold.history[0].0));

    let source_cold = cold_svc.load("snap-user", created.set_id, &key).unwrap();
    assert_eq!(source_cold.history.len(), 2);

    // Fork image bytes equal the source prefix bytes; fork pair id is fresh
    // (bound to the new set, absent from the source id list).
    let (_, fork_bytes) = decoded_first_image_bytes(&fork_cold.history[0].0);
    let (_, source_bytes) = decoded_first_image_bytes(&source_cold.history[0].0);
    assert_eq!(fork_bytes, source_bytes);
    assert_fixture_pixels(&fork_bytes);

    let fork_logical_cold = cold_svc
        .load_logical("snap-user", forked.set_id, &key)
        .unwrap();
    assert_eq!(fork_logical_cold.history.len(), 1);
    assert_eq!(fork_logical_cold.pair_ids.len(), 1);
    let source_logical_cold = cold_svc
        .load_logical("snap-user", created.set_id, &key)
        .unwrap();
    assert_eq!(source_logical_cold.pair_ids.len(), 2);
    assert!(!source_logical_cold
        .pair_ids
        .contains(&fork_logical_cold.pair_ids[0]));
}

/// Undecodable `[IMAGE:...]` sequences are opaque text by design: the commit
/// normalizer leaves them literally (no new blob, no rejection) and warm/cold
/// logical reads must agree exactly. Guards the cache invariant against
/// content-based checks that would panic on accepted input.
#[test]
fn malformed_data_marker_round_trips_identical_warm_and_cold() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("h.redb");
    let svc = HistoryService::open_ephemeral(&path).unwrap();
    let key = test_key();

    let created = svc.create_set("equiv-user", "field-notes", &key).unwrap();
    // Invalid base64: undecodable, so it stays literal through normalization.
    let user_msg = "field notes\n[IMAGE:data:image/jpeg;base64,!!!not-base64!!!]".to_owned();
    let v2 = svc
        .append_pair(
            "equiv-user",
            created.set_id,
            created.version,
            &user_msg,
            "noted",
            &key,
        )
        .unwrap();
    assert_eq!(v2.get(), created.version.get() + 1);

    let warm_logical = svc.load_logical("equiv-user", created.set_id, &key).unwrap();
    assert_eq!(warm_logical.history[0].0, user_msg);
    let warm_full = svc.load("equiv-user", created.set_id, &key).unwrap();
    drop(svc);

    let cold_svc = HistoryService::open_ephemeral(&path).unwrap();
    let cold_logical = cold_svc
        .load_logical("equiv-user", created.set_id, &key)
        .unwrap();
    let cold_full = cold_svc.load("equiv-user", created.set_id, &key).unwrap();

    assert_eq!(warm_logical.version, v2);
    assert_eq!(cold_logical.version, v2);
    assert_eq!(warm_logical.pair_ids, cold_logical.pair_ids);
    assert_eq!(warm_logical.history, cold_logical.history);
    assert_eq!(cold_logical.history[0].0, user_msg);
    assert_eq!(warm_full.history[0].0, user_msg);
    assert_eq!(cold_full.history[0].0, user_msg);
    assert_eq!(cold_full.history[0].1, "noted");
}

/// Desired MOD005 contract: the version-checked cache holds the normalized
/// logical shape, so warm and cold `load_logical` agree exactly (ref text,
/// same pair ids, same version). Fails against the pre-normalization cache
/// which still carries the incoming `data:` URL while cold reads `img:` refs.
#[test]
fn warm_and_cold_logical_match_after_direct_image_append() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("h.redb");
    let svc = HistoryService::open_ephemeral(&path).unwrap();
    let key = test_key();

    let created = svc.create_set("equiv-user", "photos", &key).unwrap();
    let v2 = svc
        .append_pair(
            "equiv-user",
            created.set_id,
            created.version,
            &image_user_msg("look"),
            "nice",
            &key,
        )
        .unwrap();

    let warm_logical = svc.load_logical("equiv-user", created.set_id, &key).unwrap();
    let warm_full = svc.load("equiv-user", created.set_id, &key).unwrap();
    drop(svc);

    let cold_svc = HistoryService::open_ephemeral(&path).unwrap();
    let cold_logical = cold_svc
        .load_logical("equiv-user", created.set_id, &key)
        .unwrap();
    let cold_full = cold_svc.load("equiv-user", created.set_id, &key).unwrap();

    assert_eq!(warm_logical.version, v2);
    assert_eq!(cold_logical.version, v2);
    assert_eq!(warm_logical.pair_ids, cold_logical.pair_ids);
    assert_eq!(warm_logical.history, cold_logical.history);
    assert!(has_img_ref(&warm_logical.history[0].0));
    assert!(!has_data_url(&warm_logical.history[0].0));

    let (_, warm_bytes) = decoded_first_image_bytes(&warm_full.history[0].0);
    let (_, cold_bytes) = decoded_first_image_bytes(&cold_full.history[0].0);
    assert_eq!(warm_bytes, cold_bytes);
    assert_fixture_pixels(&cold_bytes);
    assert_eq!(warm_full.history[0].1, "nice");
    assert_eq!(cold_full.history[0].1, "nice");
}

/// Same contract through the session prepare path: the capture is built from
/// materialized `load`, but the committed cache entry must still be logical.
#[test]
fn warm_and_cold_logical_match_after_chat_capture_append() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("h.redb");
    let svc = HistoryService::open_ephemeral(&path).unwrap();
    let key = test_key();

    let created = svc.create_set("equiv-user", "chat", &key).unwrap();
    let snap = svc.load("equiv-user", created.set_id, &key).unwrap();
    let capture = PrepareCapture::from_snapshot(&snap);

    let v2 = svc
        .commit_chat_append(
            "equiv-user",
            &capture,
            &image_user_msg("describe"),
            "a cat",
            &key,
        )
        .unwrap();

    let warm_logical = svc.load_logical("equiv-user", created.set_id, &key).unwrap();
    let warm_full = svc.load("equiv-user", created.set_id, &key).unwrap();
    drop(svc);

    let cold_svc = HistoryService::open_ephemeral(&path).unwrap();
    let cold_logical = cold_svc
        .load_logical("equiv-user", created.set_id, &key)
        .unwrap();
    let cold_full = cold_svc.load("equiv-user", created.set_id, &key).unwrap();

    assert_eq!(warm_logical.version, v2);
    assert_eq!(cold_logical.version, v2);
    assert_eq!(warm_logical.pair_ids, cold_logical.pair_ids);
    assert_eq!(warm_logical.history, cold_logical.history);
    assert!(has_img_ref(&warm_logical.history[0].0));
    assert!(!has_data_url(&warm_logical.history[0].0));

    let (_, warm_bytes) = decoded_first_image_bytes(&warm_full.history[0].0);
    let (_, cold_bytes) = decoded_first_image_bytes(&cold_full.history[0].0);
    assert_eq!(warm_bytes, cold_bytes);
    assert_fixture_pixels(&cold_bytes);
    assert_eq!(warm_full.history[0].1, "a cat");
    assert_eq!(cold_full.history[0].1, "a cat");
}
