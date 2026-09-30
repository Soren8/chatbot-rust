use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
    Router,
};
use chatbot_core::{
    history::HistoryService,
    session::{ChatService, ChatSessionStore},
    session_identity::HttpSessionStore,
    user_store::UserStore,
};
use chatbot_server::{
    build_router_with_services, identity::RequestIdentity, resolve_static_root,
    services::AppServices,
};
use serde_json::{json, Value};
use std::sync::Arc;
use tower::ServiceExt;

mod common;

struct Setup {
    _root: tempfile::TempDir,
    app: Router,
    history: Arc<HistoryService>,
    key: chatbot_core::enc_key::EncryptionKey,
    cookie: String,
    csrf: String,
}
fn setup() -> Setup {
    let root = tempfile::tempdir().unwrap();
    let key =
        chatbot_core::enc_key::EncryptionKey::from_header_value("test-resend-user-key").unwrap();
    UserStore::open(root.path())
        .unwrap()
        .ensure_key_verifier_with_secret("alice", key.as_bytes(), b"test-secret")
        .unwrap();
    let history = Arc::new(
        HistoryService::open_with_data_dir(root.path().join("history.redb"), root.path(), "prompt")
            .unwrap(),
    );
    let chat = ChatService::new(
        Arc::new(ChatSessionStore::new(3600, "prompt".into())),
        history.clone(),
        root.path().to_owned(),
        "test-secret".into(),
    );
    let identity = Arc::new(HttpSessionStore::new(3600));
    let login = identity.finalize_login(None, "alice", true).unwrap();
    let cookie = common::extract_cookie(&login.set_cookie);
    let services =
        AppServices::with_owned_stores(RequestIdentity::with_store_and_csrf(identity, true))
            .with_chat_service(chat);
    Setup {
        _root: root,
        app: build_router_with_services(resolve_static_root(), services),
        history,
        key,
        cookie,
        csrf: login.csrf_token,
    }
}
async fn post(setup: &Setup, route: &str, body: &Value, operation: bool) -> (StatusCode, Value) {
    let mut request = Request::builder()
        .method("POST")
        .uri(route)
        .header("content-type", "application/json")
        .header("cookie", &setup.cookie)
        .header("x-csrf-token", &setup.csrf)
        .header("x-enc-key", "test-resend-user-key");
    if operation {
        request = request.header("idempotency-key", "history-operation-1234");
    }
    let response = setup
        .app
        .clone()
        .oneshot(
            request
                .body(Body::from(serde_json::to_vec(body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let body = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    (status, serde_json::from_slice(&body).unwrap())
}

#[tokio::test]
async fn explicit_name_create_resend_does_not_create_another_set() {
    let s = setup();
    let payload = json!({"set_name":"Named chat"});
    let first = post(&s, "/create_set", &payload, false).await;
    assert_eq!(first.1["status"], "success");
    let before = s.history.list_sets("alice", &s.key).unwrap().len();
    assert_eq!(
        post(&s, "/create_set", &payload, false).await.1["status"],
        "error"
    );
    assert_eq!(s.history.list_sets("alice", &s.key).unwrap().len(), before);
}

#[tokio::test]
async fn delete_set_resend_cannot_delete_another_set() {
    let s = setup();
    let set = s.history.create_set("alice", "Named chat", &s.key).unwrap();
    let payload = json!({"set_id":set.set_id.to_string(), "set_name":"Named chat", "expected_version":set.version.get()});
    assert_eq!(
        post(&s, "/delete_set", &payload, false).await.0,
        StatusCode::OK
    );
    let before = s.history.list_sets("alice", &s.key).unwrap().len();
    let second = post(&s, "/delete_set", &payload, false).await;
    assert!(second.0 != StatusCode::OK || second.1["status"] != "success");
    assert_eq!(s.history.list_sets("alice", &s.key).unwrap().len(), before);
}

#[tokio::test]
async fn delete_message_resend_is_fenced_by_version() {
    let s = setup();
    let set = s.history.create_set("alice", "Named chat", &s.key).unwrap();
    let version = s
        .history
        .append_pair("alice", set.set_id, set.version, "first", "answer", &s.key)
        .unwrap();
    let version = s
        .history
        .append_pair("alice", set.set_id, version, "second", "answer", &s.key)
        .unwrap();
    let payload = json!({"set_id":set.set_id.to_string(), "expected_version":version.get(), "pair_index":0,"user_message":"first"});
    assert_eq!(
        post(&s, "/delete_message", &payload, false).await.0,
        StatusCode::OK
    );
    let before = s.history.load("alice", set.set_id, &s.key).unwrap();
    assert_eq!(
        post(&s, "/delete_message", &payload, false).await.0,
        StatusCode::CONFLICT
    );
    let after = s.history.load("alice", set.set_id, &s.key).unwrap();
    assert_eq!(after.version, before.version);
    assert_eq!(after.history, before.history);
}

#[tokio::test]
async fn reset_resend_is_fenced_by_version() {
    let s = setup();
    let set = s.history.create_set("alice", "Named chat", &s.key).unwrap();
    let version = s
        .history
        .append_pair("alice", set.set_id, set.version, "first", "answer", &s.key)
        .unwrap();
    let payload = json!({"set_id":set.set_id.to_string(),"expected_version":version.get()});
    assert_eq!(
        post(&s, "/reset_chat", &payload, false).await.0,
        StatusCode::OK
    );
    let before = s.history.load("alice", set.set_id, &s.key).unwrap();
    assert_eq!(
        post(&s, "/reset_chat", &payload, false).await.0,
        StatusCode::CONFLICT
    );
    let after = s.history.load("alice", set.set_id, &s.key).unwrap();
    assert_eq!(after.version, before.version);
    assert!(after.history.is_empty());
}

#[tokio::test]
async fn fork_with_operation_id_replays_same_fork() {
    let s = setup();
    let set = s.history.create_set("alice", "Named chat", &s.key).unwrap();
    let version = s
        .history
        .append_pair("alice", set.set_id, set.version, "first", "answer", &s.key)
        .unwrap();
    let payload =
        json!({"set_id":set.set_id.to_string(),"expected_version":version.get(),"pair_index":0});
    let first = post(&s, "/fork_set", &payload, true).await;
    assert_eq!(first.0, StatusCode::OK);
    let before = s.history.list_sets("alice", &s.key).unwrap().len();
    let second = post(&s, "/fork_set", &payload, true).await;
    assert_eq!(second, first);
    assert_eq!(s.history.list_sets("alice", &s.key).unwrap().len(), before);
}
