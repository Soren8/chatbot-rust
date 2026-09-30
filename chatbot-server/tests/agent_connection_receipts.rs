use std::sync::{Arc, atomic::{AtomicU64, Ordering}};
use chatbot_core::operation_receipt::{ReceiptClock, RECEIPT_TTL_SECS};
struct Clock(AtomicU64);
impl ReceiptClock for Clock { fn now_secs(&self) -> u64 { self.0.load(Ordering::SeqCst) } }
use axum::{body::{to_bytes, Body}, http::{header, Method, Request, StatusCode}, Router};
use chatbot_core::{account_service::AccountService, agent_connections::ConnectionService, session::{ChatService, ChatSessionStore}, session_identity::HttpSessionStore};
use chatbot_server::{build_router_with_services, identity::RequestIdentity, resolve_static_root, services::AppServices};
use serde_json::{json, Value};
use tower::ServiceExt;
mod common;

struct Fixture { _root: common::TestWorkspace, app: Router, identity: Arc<HttpSessionStore> }
impl Fixture {
    fn new() -> Self { Self::with_clock(Arc::new(Clock(AtomicU64::new(1)))) }
    fn with_clock(clock: Arc<dyn ReceiptClock>) -> Self {
        std::env::set_var("SECRET_KEY", "connection-receipt-fixture-secret");
        let root = common::TestWorkspace::with_config(r#"
llms:
  - provider_name: default
    type: openai
    model_name: fixture
    base_url: https://api.openai.com/v1
    api_key: "${OPENAI_API_KEY}"
external_connections:
  enabled: true
  allowed_users: [alice, bob]
  allow_public_https: true
"#);
        let accounts = AccountService::with_root_and_secret(root.path().join("accounts"), "receipt-fixture-verifier");
        for user in ["alice", "bob"] { accounts.users().unwrap().ensure_key_verifier(user, b"receipt-fixture-key").unwrap(); }
        let connections = ConnectionService::open(root.path(), accounts.clone()).unwrap();
        let identity = Arc::new(HttpSessionStore::new(3600));
        let chat = ChatService::with_storage_and_accounts(Arc::new(ChatSessionStore::new(3600, "helpful".into())), root.path().to_path_buf(), accounts.clone());
        let services = AppServices::with_owned_stores(RequestIdentity::with_store_and_csrf(identity.clone(), true)).with_chat_service(chat).with_account_service(accounts).with_connection_service(connections).with_connection_receipt_clock(clock);
        Self { app: build_router_with_services(resolve_static_root(), services), identity, _root: root }
    }
    fn actor(&self, user: &str) -> (String, String) {
        let login = self.identity.finalize_login(None, user, true).unwrap();
        (common::extract_cookie(&login.set_cookie), login.csrf_token)
    }
    async fn call(&self, actor: &(String, String), method: Method, path: &str, body: Value, operation: Option<&str>, csrf: bool) -> (StatusCode, Vec<u8>) {
        let mut req = Request::builder().method(method).uri(path).header(header::CONTENT_TYPE, "application/json").header(header::COOKIE, &actor.0).header("X-Enc-Key", "receipt-fixture-key");
        if csrf { req = req.header("X-CSRF-Token", &actor.1); }
        if let Some(id) = operation { req = req.header("Idempotency-Key", id); }
        let response = self.app.clone().oneshot(req.body(Body::from(body.to_string())).unwrap()).await.unwrap();
        (response.status(), to_bytes(response.into_body(), 1024*1024).await.unwrap().to_vec())
    }
}
fn input() -> Value { json!({"kind":"opencode","name":"receipt connection","base_url":"https://example.com/agent","username":"opencode","password":"private-password-marker"}) }

#[tokio::test]
async fn receipt_expires_at_twenty_four_hours() {
    let clock = Arc::new(Clock(AtomicU64::new(100)));
    let fixture = Fixture::with_clock(clock.clone()); let alice = fixture.actor("alice");
    let id = Some("receipt-expiry-0001");
    let first = fixture.call(&alice, Method::POST, "/agent_connections", input(), id, true).await;
    clock.0.store(100 + RECEIPT_TTL_SECS - 1, Ordering::SeqCst);
    assert_eq!(fixture.call(&alice, Method::POST, "/agent_connections", input(), id, true).await, first);
    clock.0.store(100 + RECEIPT_TTL_SECS, Ordering::SeqCst);
    let next = fixture.call(&alice, Method::POST, "/agent_connections", input(), id, true).await;
    assert_eq!(next.0, StatusCode::CREATED); assert_ne!(next.1, first.1);
}

#[tokio::test]
async fn receipts_replay_reject_reuse_and_legacy() {
    let fixture = Fixture::new(); let alice = fixture.actor("alice");
    let id = Some("receipt-create-0001");
    let first = fixture.call(&alice, Method::POST, "/agent_connections", input(), id, true).await;
    assert_eq!(first.0, StatusCode::CREATED);
    assert_eq!(fixture.call(&alice, Method::POST, "/agent_connections", input(), id, true).await, first);
    let mut changed = input(); changed["name"] = json!("different");
    assert_eq!(fixture.call(&alice, Method::POST, "/agent_connections", changed, id, true).await.0, StatusCode::CONFLICT);
    assert!(!String::from_utf8_lossy(&first.1).contains("private-password-marker"));
    let list = fixture.call(&alice, Method::GET, "/agent_connections", Value::Null, None, false).await;
    assert_eq!(serde_json::from_slice::<Value>(&list.1).unwrap().as_array().unwrap().len(), 1);
    let mut invalid = input(); invalid["name"] = json!("");
    let rejected = fixture.call(&alice, Method::POST, "/agent_connections", invalid.clone(), Some("receipt-reject-0001"), true).await;
    assert_eq!(rejected.0, StatusCode::BAD_REQUEST);
    assert_eq!(fixture.call(&alice, Method::POST, "/agent_connections", invalid, Some("receipt-reject-0001"), true).await, rejected);
    assert_eq!(fixture.call(&alice, Method::POST, "/agent_connections", input(), Some("receipt-reject-0001"), true).await.0, StatusCode::CONFLICT);
    assert_eq!(fixture.call(&alice, Method::POST, "/agent_connections", input(), None, true).await.0, StatusCode::CREATED);
}

#[tokio::test]
async fn concurrent_duplicate_csrf_and_owner_scope() {
    let fixture = Fixture::new(); let alice = fixture.actor("alice"); let bob = fixture.actor("bob");
    let id = Some("receipt-concurrent-01");
    assert_eq!(fixture.call(&alice, Method::POST, "/agent_connections", input(), id, false).await.0, StatusCode::UNAUTHORIZED);
    let (a,b) = tokio::join!(fixture.call(&alice, Method::POST, "/agent_connections", input(), id, true), fixture.call(&alice, Method::POST, "/agent_connections", input(), id, true));
    assert_eq!(a.0, StatusCode::CREATED); assert_eq!(a,b);
    let other = fixture.call(&bob, Method::POST, "/agent_connections", input(), id, true).await;
    assert_eq!(other.0, StatusCode::CREATED); assert_ne!(a.1,other.1);
    let list = fixture.call(&alice, Method::GET, "/agent_connections", Value::Null, None, false).await;
    assert_eq!(serde_json::from_slice::<Value>(&list.1).unwrap().as_array().unwrap().len(), 1);
}
