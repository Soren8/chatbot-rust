use std::io::Cursor;

use base64::Engine;
use image::{DynamicImage, ImageBuffer, ImageFormat, Rgb};
use serde_json::{json, Value};

use chatbot_core::{
    enc_key::EncryptionKey,
    history::{HistoryError, HistoryService, SetId},
    operation_receipt::{OperationId, OperationRequest},
};

fn png_data_url() -> String {
    let image = DynamicImage::ImageRgb8(ImageBuffer::from_pixel(1, 1, Rgb([20, 40, 60])));
    let mut bytes = Cursor::new(Vec::new());
    image.write_to(&mut bytes, ImageFormat::Png).unwrap();
    format!(
        "data:image/png;base64,{}",
        base64::engine::general_purpose::STANDARD.encode(bytes.into_inner())
    )
}

#[test]
fn receipt_fork_materializes_images_and_is_immediately_listed() {
    let root = tempfile::tempdir().unwrap();
    let history =
        HistoryService::open_with_data_dir(root.path().join("history"), root.path(), "prompt")
            .unwrap();
    let key = EncryptionKey::from_header_value("data-key").unwrap();
    let source = history.create_set("alice", "Source", &key).unwrap();
    let message = format!("picture [IMAGE:{}]", png_data_url());
    let version = history
        .append_pair(
            "alice",
            source.set_id,
            source.version,
            &message,
            "answer",
            &key,
        )
        .unwrap();
    let request = OperationRequest::new(
        OperationId::parse("image-fork-operation-1234").unwrap(),
        "/fork_set",
        &json!({"pair_index":0}),
    );
    let receipt = history
        .fork_operation(
            "alice",
            source.set_id,
            Some(version),
            0,
            None,
            &key,
            &request,
        )
        .unwrap();
    let body: Value = serde_json::from_slice(&receipt.body).unwrap();
    let id = SetId::parse(body["set_id"].as_str().unwrap()).unwrap();
    assert!(history
        .list_sets("alice", &key)
        .unwrap()
        .iter()
        .any(|s| s.set_id == id));
    let fork = history.load("alice", id, &key).unwrap();
    assert_eq!(fork.history[0].0, message);
    assert_eq!(
        history.load_image("alice", id, 0, 0, &key).unwrap(),
        history
            .load_image("alice", source.set_id, 0, 0, &key)
            .unwrap()
    );
}

#[test]
fn receipt_fork_long_name_matches_legacy_error() {
    let root = tempfile::tempdir().unwrap();
    let history =
        HistoryService::open_with_data_dir(root.path().join("history"), root.path(), "prompt")
            .unwrap();
    let key = EncryptionKey::from_header_value("data-key").unwrap();
    let source = history.create_set("alice", "Source", &key).unwrap();
    let version = history
        .append_pair(
            "alice",
            source.set_id,
            source.version,
            "question",
            "answer",
            &key,
        )
        .unwrap();
    let name = "x".repeat(201);
    assert!(matches!(
        history.fork_set("alice", source.set_id, Some(version), 0, Some(&name), &key),
        Err(HistoryError::InvalidInput("set name too large"))
    ));
    let request = OperationRequest::new(
        OperationId::parse("name-fork-operation-1234").unwrap(),
        "/fork_set",
        &json!({"new_name":name}),
    );
    let receipt = history
        .fork_operation(
            "alice",
            source.set_id,
            Some(version),
            0,
            Some(&name),
            &key,
            &request,
        )
        .unwrap();
    let body: Value = serde_json::from_slice(&receipt.body).unwrap();
    assert_eq!(body["error"], "set name too large");
}
