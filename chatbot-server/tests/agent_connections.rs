use std::{
    fs,
    io::{Read, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener},
    sync::{Arc, Mutex, OnceLock, atomic::AtomicBool},
    thread,
    time::{Duration, Instant},
};

use axum::{body::{to_bytes, Body}, http::{header, Method, Request, StatusCode}, Router};
use chatbot_core::{
    account_service::AccountService,
    agent_connections::{ConnectionError, ConnectionInput, ConnectionPatch, ConnectionService},
    config::{agent_egress::{self, EgressError, OpenCodeClient, Resolver, Transport}, destination_is_eligible, ExternalConnectionsConfig, ExternalTarget, PrivacyLevel},
    enc_key::EncryptionKey,
    session::{ChatService, ChatSessionStore},
    session_identity::HttpSessionStore,
};
use chatbot_server::{build_router_with_services, identity::RequestIdentity, resolve_static_root, services::AppServices};
use serde_json::{json, Value};
use tower::ServiceExt;

mod common;

const ALICE: &str = "agent_alice";
const BOB: &str = "agent_bob";
const CAROL: &str = "agent_carol_checks";
const KEY_A: &str = "test-fernet-key-alice-not-a-secret";
const KEY_B: &str = "test-fernet-key-bob-not-a-secret";
const KEY_C: &str = "test-fernet-key-carol-not-a-secret";

fn key(value: &str) -> EncryptionKey { EncryptionKey::from_header_value(value).unwrap() }

fn policy() -> ExternalConnectionsConfig {
    ExternalConnectionsConfig {
        enabled: true,
        allowed_users: vec![ALICE.into(), BOB.into()],
        allow_public_https: true,
        targets: vec![ExternalTarget {
            id: "sandbox".into(), base_url: "http://127.0.0.1:14096/agent".into(),
            allowed_users: vec![ALICE.into()], allowed_ips: vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
            allow_tunneled_http: true,
        }],
    }.validate().unwrap()
}

struct Setup {
    _workspace: common::TestWorkspace,
    app: Router,
    identity: Arc<HttpSessionStore>,
}

impl Setup {
    fn new() -> Self {
        std::env::set_var("SECRET_KEY", "agent-integration-test-secret");
        let config = format!(r#"
llms:
  - provider_name: default
    type: openai
    model_name: gpt-test
    base_url: https://api.openai.com/v1
    api_key: "${{OPENAI_API_KEY}}"
external_connections:
  enabled: true
  allowed_users: [{ALICE}, {BOB}, {CAROL}]
  allow_public_https: true
  targets:
    - id: sandbox
      base_url: http://127.0.0.1:14096/agent
      allowed_users: [{ALICE}]
      allowed_ips: [127.0.0.1]
      allow_tunneled_http: true
    - id: check-fixture
      base_url: http://127.0.0.1:14097/agent
      allowed_users: [{CAROL}]
      allowed_ips: [127.0.0.1]
      allow_tunneled_http: true
    - id: other-check-fixture
      base_url: http://127.0.0.1:14098/agent
      allowed_users: [{BOB}]
      allowed_ips: [127.0.0.1]
      allow_tunneled_http: true
"#);
        let workspace = common::TestWorkspace::with_config(&config);
        let accounts = AccountService::with_root_and_secret(workspace.path().join("accounts"), "agent-verifier-secret");
        let users = accounts.users().unwrap();
        for (username, secret) in [(ALICE, KEY_A), (BOB, KEY_B), (CAROL, KEY_C)] {
            users.ensure_key_verifier(username, secret.as_bytes()).unwrap();
        }
        let connections = ConnectionService::open(workspace.path(), accounts.clone()).unwrap();
        let identity = Arc::new(HttpSessionStore::new(3600));
        let chat = ChatService::with_storage_and_accounts(
            Arc::new(ChatSessionStore::new(3600, "You are helpful".into())),
            workspace.path().to_path_buf(), accounts.clone(),
        );
        let services = AppServices::with_owned_stores(RequestIdentity::with_store_and_csrf(identity.clone(), true))
            .with_chat_service(chat).with_account_service(accounts).with_connection_service(connections.clone());
        let app = build_router_with_services(resolve_static_root(), services);
        Self { _workspace: workspace, app, identity }
    }

    fn actor(&self, username: &str, secret: &str) -> Actor {
        let login = self.identity.finalize_login(None, username, true).unwrap();
        Actor { cookie: common::extract_cookie(&login.set_cookie), csrf: login.csrf_token, key: secret.into() }
    }

    async fn call(&self, actor: Option<&Actor>, method: Method, path: &str, body: Value) -> (StatusCode, Value) {
        let mut request = Request::builder().method(method.clone()).uri(path).header(header::CONTENT_TYPE, "application/json");
        if let Some(actor) = actor {
            request = request.header(header::COOKIE, &actor.cookie).header("X-Enc-Key", &actor.key);
            if method != Method::GET { request = request.header("X-CSRF-Token", &actor.csrf); }
        }
        let response = self.app.clone().oneshot(request.body(Body::from(body.to_string())).unwrap()).await.unwrap();
        let status = response.status();
        if response.status().is_success() && method == Method::GET && path.starts_with("/agent_connections") {
            assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        }
        let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
        let payload = if bytes.is_empty() { Value::Null } else { serde_json::from_slice(&bytes).unwrap_or_else(|_| json!({"raw": String::from_utf8_lossy(&bytes)})) };
        (status, payload)
    }

    async fn create(&self, actor: &Actor, url: &str) -> Value {
        let (status, value) = self.call(Some(actor), Method::POST, "/agent_connections", json!({
            "name":"Alice's sandbox", "kind":"opencode", "base_url":url,
            "username":"opencode", "password":"dummy-password"
        })).await;
        assert_eq!(status, StatusCode::CREATED, "{value}");
        value
    }
}

#[derive(Clone)]
struct Actor { cookie: String, csrf: String, key: String }

fn path(id: &Value) -> String { format!("/agent_connections/{}", id["id"].as_str().unwrap()) }
fn assert_error(result: &(StatusCode, Value), status: StatusCode, error: &str) {
    assert_eq!(result.0, status, "{:?}", result.1);
    assert_eq!(result.1["error"], error);
}

fn serial() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(())).lock().unwrap_or_else(|e| e.into_inner())
}

fn change_policy(setup: &Setup, edit: impl FnOnce(String) -> String) {
    let file = setup._workspace.path().join(".config.yml");
    fs::write(&file, edit(fs::read_to_string(&file).unwrap())).unwrap();
    chatbot_core::config::reset();
}

#[tokio::test]
async fn live_target_and_feature_revocation_override_previous_success() {
    let _guard = serial();
    let setup = Setup::new();
    let alice = setup.actor(ALICE, KEY_A);
    let url = "http://127.0.0.1:14096/agent";
    let first = setup.create(&alice, url).await;
    let second = setup.create(&alice, url).await;
    let listener = TcpListener::bind("127.0.0.1:14096").unwrap();
    let server = fake_health(listener, "/agent/global/health", "b3BlbmNvZGU6ZHVtbXktcGFzc3dvcmQ=", 200,
        br#"{"healthy":true,"version":"old-success"}"#.to_vec(), Duration::ZERO, None);
    assert_eq!(setup.call(Some(&alice), Method::POST, &format!("{}/check", path(&first)), json!({"expected_revision":1})).await.0, StatusCode::OK);
    server.join().unwrap();
    change_policy(&setup, |config| config.replacen("allowed_users: [agent_alice]\n      allowed_ips: [127.0.0.1]", "allowed_users: [agent_carol_checks]\n      allowed_ips: [127.0.0.1]", 1));
    let (_, records) = setup.call(Some(&alice), Method::GET, "/agent_connections", Value::Null).await;
    assert_eq!(records.as_array().unwrap().len(), 2);
    assert_eq!(records.as_array().unwrap().iter().find(|v| v["id"] == first["id"]).unwrap()["last_check"]["status"], "blocked_by_policy");
    assert_error(&setup.call(Some(&alice), Method::POST, &format!("{}/check", path(&first)), json!({"expected_revision":1})).await,
        StatusCode::FORBIDDEN, "connection_target_forbidden");
    assert_error(&setup.call(Some(&alice), Method::PATCH, &path(&first), json!({"expected_revision":1,"name":"still blocked"})).await,
        StatusCode::FORBIDDEN, "connection_target_forbidden");
    let (status, edited) = setup.call(Some(&alice), Method::PATCH, &path(&first),
        json!({"expected_revision":1,"base_url":"https://example.com/agent"})).await;
    assert_eq!(status, StatusCode::OK, "{edited}");
    assert_eq!(edited["last_check"], Value::Null);
    assert_eq!(setup.call(Some(&alice), Method::DELETE, &path(&second), json!({"expected_revision":1})).await.0, StatusCode::NO_CONTENT);

    change_policy(&setup, |config| config.replacen("enabled: true", "enabled: false", 1));
    assert_error(&setup.call(Some(&alice), Method::GET, "/agent_connections", Value::Null).await,
        StatusCode::FORBIDDEN, "agent_connections_forbidden");
    assert_error(&setup.call(Some(&alice), Method::POST, &format!("{}/check", path(&first)), json!({"expected_revision":2})).await,
        StatusCode::FORBIDDEN, "agent_connections_forbidden");
}

#[tokio::test]
async fn owned_http_crud_isolation_privacy_and_csrf() {
    let _guard = serial();
    let setup = Setup::new();
    let alice = setup.actor(ALICE, KEY_A);
    let bob = setup.actor(BOB, KEY_B);
    let a = setup.create(&alice, "https://example.com/api").await;
    let b = setup.create(&bob, "https://other.example/api").await;
    assert_ne!(a["id"], b["id"]);
    assert_eq!(a["privacy_level"], "non_private");
    assert_eq!(a["has_password"], true);
    assert_eq!(a["revision"], 1);
    assert!(!a.to_string().contains("dummy-password"));
    assert_eq!(a["last_check"], Value::Null);
    assert!(!destination_is_eligible(PrivacyLevel::Private, PrivacyLevel::NonPrivate));
    assert!(destination_is_eligible(PrivacyLevel::NonPrivate, PrivacyLevel::NonPrivate));

    for (actor, own, foreign) in [(&alice, &a, &b), (&bob, &b, &a)] {
        let (status, list) = setup.call(Some(actor), Method::GET, "/agent_connections", Value::Null).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(list.as_array().unwrap().len(), 1);
        assert_eq!(list[0]["id"], own["id"]);
        assert!(!list.to_string().contains("dummy-password"));
        for (method, suffix, payload) in [
            (Method::PATCH, "", json!({"expected_revision":1,"password":"rotated"})),
            (Method::DELETE, "", json!({"expected_revision":1})),
            (Method::POST, "/check", json!({"expected_revision":1})),
        ] {
            assert_error(&setup.call(Some(actor), method, &format!("{}{suffix}", path(foreign)), payload).await,
                StatusCode::NOT_FOUND, "connection_not_found");
        }
    }
    let guest = setup.call(None, Method::GET, "/agent_connections", Value::Null).await;
    assert_eq!(guest.0, StatusCode::UNAUTHORIZED);
    let mut invalid = setup.actor(ALICE, KEY_B);
    assert_eq!(setup.call(Some(&invalid), Method::GET, "/agent_connections", Value::Null).await.0, StatusCode::UNAUTHORIZED);
    invalid.key = KEY_A.into();
    invalid.csrf = "invalid-csrf".into();
    assert_eq!(setup.call(Some(&invalid), Method::DELETE, &path(&a), json!({"expected_revision":1})).await.0, StatusCode::UNAUTHORIZED);
    assert_eq!(setup.call(Some(&alice), Method::GET, "/", Value::Null).await.0, StatusCode::OK);
}

#[tokio::test]
async fn http_revision_rotation_policy_and_input_boundaries() {
    let _guard = serial();
    let setup = Setup::new();
    let alice = setup.actor(ALICE, KEY_A);
    let a = setup.create(&alice, "https://example.com:443/agent").await;
    assert_eq!(a["base_url"], "https://example.com/agent");
    let p = path(&a);
    let stale = setup.call(Some(&alice), Method::PATCH, &p, json!({"expected_revision":0,"name":"new"})).await;
    assert_error(&stale, StatusCode::CONFLICT, "connection_version_conflict");
    assert_eq!(stale.1["current_revision"], 1);
    let (status, edited) = setup.call(Some(&alice), Method::PATCH, &p, json!({"expected_revision":1,"name":"renamed"})).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(edited["revision"], 2);
    assert_eq!(edited["name"], "renamed");
    let (status, rotated) = setup.call(Some(&alice), Method::PATCH, &p, json!({"expected_revision":2,"username":"different","password":"new-dummy"})).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(rotated["last_check"], Value::Null);
    assert!(!rotated.to_string().contains("new-dummy"));
    let stale = setup.call(Some(&alice), Method::DELETE, &p, json!({"expected_revision":2})).await;
    assert_error(&stale, StatusCode::CONFLICT, "connection_version_conflict");
    let (status, _) = setup.call(Some(&alice), Method::DELETE, &p, json!({"expected_revision":3})).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_error(&setup.call(Some(&alice), Method::POST, &format!("{p}/check"), json!({"expected_revision":3})).await,
        StatusCode::NOT_FOUND, "connection_not_found");
    for bad in ["http://example.com", "https://example.com:444", "https://u:p@example.com", "https://example.com/%2e%2e/", "https://example.com/a%2fb", "https://example.com/?secret=x", "https://example.com/#fragment"] {
        let (status, value) = setup.call(Some(&alice), Method::POST, "/agent_connections", json!({"name":"x","kind":"opencode","base_url":bad,"username":"u","password":"p"})).await;
        assert!(matches!(status, StatusCode::BAD_REQUEST | StatusCode::FORBIDDEN), "{bad}: {value}");
    }
    assert_eq!(setup.call(Some(&alice), Method::POST, "/agent_connections", json!({"name":"x","kind":"opencode","base_url":"https://example.com","username":"u","password":"p","privacy_level":"private"})).await.0, StatusCode::BAD_REQUEST);
    assert_eq!(setup.call(Some(&alice), Method::POST, "/agent_connections", json!({"name":"x","kind":"other","base_url":"https://example.com","username":"u","password":"p"})).await.0, StatusCode::BAD_REQUEST);
    let huge = "x".repeat(17_000);
    assert_eq!(setup.call(Some(&alice), Method::POST, "/agent_connections", json!({"name":huge})).await.0, StatusCode::PAYLOAD_TOO_LARGE);
}

#[derive(Clone)]
struct Answers(Arc<Mutex<Vec<Vec<IpAddr>>>>);
impl Resolver for Answers {
    fn resolve(&self, _: &str, _: u16) -> Result<Vec<IpAddr>, EgressError> {
        Ok(self.0.lock().unwrap().remove(0))
    }
}
struct Capture(Arc<Mutex<Vec<Vec<SocketAddr>>>>);
impl Transport for Capture {
    type Response = String;
    fn get_health(&self, url: &reqwest::Url, pins: &[SocketAddr], user: &str, password: &str) -> Result<String, EgressError> {
        assert!(url.path().ends_with("/global/health"));
        assert_eq!((user, password), ("opencode", "dummy"));
        self.0.lock().unwrap().push(pins.to_vec());
        Ok("fixture-version".into())
    }
}

#[test]
fn injected_resolver_pins_only_authorized_destinations_each_time() {
    let policy = policy();
    let public: IpAddr = "8.8.8.8".parse().unwrap();
    let private: IpAddr = "10.0.0.1".parse().unwrap();
    let loopback: IpAddr = "127.0.0.1".parse().unwrap();
    let pins = Arc::new(Mutex::new(Vec::new()));
    let answers = Answers(Arc::new(Mutex::new(vec![vec![public], vec![public, private], vec![private], vec![loopback], vec![public]])));
    let client = OpenCodeClient::new(answers, Capture(pins.clone()));
    assert_eq!(client.check(&policy, ALICE, "https://public.example/agent", "opencode", "dummy"), Ok("fixture-version".into()));
    assert_eq!(client.check(&policy, ALICE, "https://public.example/agent", "opencode", "dummy"), Err(EgressError::Blocked));
    assert_eq!(client.check(&policy, ALICE, "https://public.example/agent", "opencode", "dummy"), Err(EgressError::Blocked));
    assert_eq!(client.check(&policy, ALICE, "https://public.example/agent", "opencode", "dummy"), Err(EgressError::Blocked));
    assert_eq!(client.check(&policy, ALICE, "https://public.example/agent", "opencode", "dummy"), Ok("fixture-version".into()));
    assert_eq!(pins.lock().unwrap().as_slice(), &[vec![SocketAddr::new(public, 443)], vec![SocketAddr::new(public, 443)]]);
    let check = |url, user, answer| OpenCodeClient::new(Answers(Arc::new(Mutex::new(vec![vec![answer]]))), Capture(Arc::new(Mutex::new(Vec::new()))))
        .check(&policy, user, url, "opencode", "dummy");
    assert_eq!(check("http://127.0.0.1:14096/agent", ALICE, loopback), Ok("fixture-version".into()));
    assert_eq!(check("http://127.0.0.1:14096/agent", BOB, loopback), Err(EgressError::Blocked));
    assert_eq!(check("https://alias.example:14096/agent", ALICE, loopback), Err(EgressError::Blocked));
    assert_eq!(check("https://127.0.0.1/agent", ALICE, loopback), Err(EgressError::Blocked));
    for address in ["::1", "::ffff:127.0.0.1", "fe80::1", "169.254.169.254", "2001:db8::1"] {
        assert_eq!(check("https://public.example", ALICE, address.parse().unwrap()), Err(EgressError::Blocked), "{address}");
    }
}

#[test]
fn storage_reopen_encryption_ownership_and_concurrent_cas() {
    let temp = tempfile::tempdir().unwrap();
    let accounts = AccountService::with_root_and_secret(temp.path().join("accounts"), "storage-verifier");
    let users = accounts.users().unwrap();
    users.ensure_key_verifier(ALICE, KEY_A.as_bytes()).unwrap();
    users.ensure_key_verifier(BOB, KEY_B.as_bytes()).unwrap();
    let store = ConnectionService::open(temp.path(), accounts.clone()).unwrap();
    let a = store.create(ALICE, &key(KEY_A), ConnectionInput {name:"unique-private-label".into(), base_url:"https://secret-url.example".into(), username:"unique-user".into(), password:"unique-password".into()}).unwrap();
    let bytes = fs::read(temp.path().join("connections/redb")).unwrap();
    for marker in ["unique-private-label", "secret-url.example", "unique-user", "unique-password"] {
        assert!(!bytes.windows(marker.len()).any(|w| w == marker.as_bytes()), "plaintext marker {marker}");
    }
    assert!(matches!(store.credentials(BOB, &key(KEY_B), a.id), Err(ConnectionError::NotFound)));
    assert!(matches!(store.list(ALICE, &key(KEY_B)), Err(ConnectionError::InvalidKey)));
    let left = store.clone();
    let right = store.clone();
    let one = thread::spawn(move || left.update(ALICE, &key(KEY_A), a.id, 1, ConnectionPatch {name: Some("first".into()), ..Default::default()}));
    let two = thread::spawn(move || right.update(ALICE, &key(KEY_A), a.id, 1, ConnectionPatch {name: Some("second".into()), ..Default::default()}));
    let results = [one.join().unwrap(), two.join().unwrap()];
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
    assert_eq!(results.iter().filter(|r| matches!(r, Err(ConnectionError::Conflict { current_revision: 2 }))).count(), 1);
    drop(store);
    let reopened = ConnectionService::open(temp.path(), accounts).unwrap();
    assert_eq!(reopened.list(ALICE, &key(KEY_A)).unwrap()[0].revision, 2);
    assert_eq!(reopened.credentials(ALICE, &key(KEY_A), a.id).unwrap().1.password, "unique-password");
}

fn fake_health(listener: TcpListener, expected_path: &'static str, expected_auth: &'static str, status: u16, body: Vec<u8>, pause: Duration, arrived: Option<std::sync::mpsc::Sender<()>>) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let mut input = [0; 4096];
        let mut size = 0;
        while size < input.len() {
            let received = stream.read(&mut input[size..]).unwrap();
            if received == 0 { break; }
            size += received;
            if input[..size].windows(4).any(|slice| slice == b"\r\n\r\n") { break; }
        }
        let request = String::from_utf8_lossy(&input[..size]);
        assert!(request.starts_with(&format!("GET {expected_path} HTTP/1.1")), "{request}");
        assert!(request.to_ascii_lowercase().contains(&format!("authorization: basic {expected_auth}").to_ascii_lowercase()), "missing expected Basic auth");
        for forbidden in ["cookie:", "x-enc-key:", "x-csrf-token:", "proxy-authorization:"] {
            assert!(!request.to_ascii_lowercase().contains(forbidden));
        }
        if let Some(arrived) = arrived { arrived.send(()).unwrap(); }
        thread::sleep(pause);
        let header = format!("HTTP/1.1 {status} Result\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
        let _ = stream.write_all(header.as_bytes());
        let _ = stream.write_all(&body);
    })
}

#[tokio::test]
async fn real_http_check_sends_basic_only_and_never_echoes_password() {
    let _guard = serial();
    let setup = Setup::new();
    let alice = setup.actor(ALICE, KEY_A);
    let connection = setup.create(&alice, "http://127.0.0.1:14096/agent").await;
    let listener = TcpListener::bind("127.0.0.1:14096").unwrap();
    let server = fake_health(listener, "/agent/global/health", "b3BlbmNvZGU6ZHVtbXktcGFzc3dvcmQ=", 200,
        br#"{"healthy":true,"version":"1.2.3"}"#.to_vec(), Duration::ZERO, None);
    let (status, result) = setup.call(Some(&alice), Method::POST, &format!("{}/check", path(&connection)), json!({"expected_revision":1})).await;
    server.join().unwrap();
    assert_eq!(status, StatusCode::OK, "{result}");
    assert_eq!(result["status"], "reachable");
    assert_eq!(result["version"], "1.2.3");
    assert!(result["checked_at"].is_number());
    let (_, list) = setup.call(Some(&alice), Method::GET, "/agent_connections", Value::Null).await;
    assert_eq!(list[0]["last_check"]["status"], "reachable");
    assert!(!list.to_string().contains("dummy-password"));
    let (status, rotated) = setup.call(Some(&alice), Method::PATCH, &path(&connection), json!({"expected_revision":1,"password":"new-password"})).await;
    assert_eq!(status, StatusCode::OK, "{rotated}");
    assert_eq!(rotated["last_check"], Value::Null);
    assert_error(&setup.call(Some(&alice), Method::POST, &format!("{}/check", path(&connection)), json!({"expected_revision":1})).await,
        StatusCode::CONFLICT, "connection_version_conflict");
}

#[tokio::test]
async fn deletion_while_remote_check_runs_cannot_publish_stale_health() {
    let _guard = serial();
    let setup = Setup::new();
    let alice = setup.actor(ALICE, KEY_A);
    let connection = setup.create(&alice, "http://127.0.0.1:14096/agent").await;
    let (tx, rx) = std::sync::mpsc::channel();
    let server = fake_health(TcpListener::bind("127.0.0.1:14096").unwrap(), "/agent/global/health",
        "b3BlbmNvZGU6ZHVtbXktcGFzc3dvcmQ=", 200,
        br#"{"healthy":true,"version":"stale"}"#.to_vec(), Duration::from_millis(250), Some(tx));
    let app = setup.app.clone();
    let cookie = alice.cookie.clone();
    let csrf = alice.csrf.clone();
    let secret = alice.key.clone();
    let check_path = format!("{}/check", path(&connection));
    let check = tokio::spawn(async move {
        let response = app.oneshot(Request::builder().method(Method::POST).uri(check_path)
            .header(header::COOKIE, cookie).header("X-CSRF-Token", csrf).header("X-Enc-Key", secret)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(json!({"expected_revision":1}).to_string())).unwrap()).await.unwrap();
        response.status()
    });
    tokio::task::spawn_blocking(move || rx.recv_timeout(Duration::from_secs(3)).unwrap()).await.unwrap();
    assert_eq!(setup.call(Some(&alice), Method::DELETE, &path(&connection), json!({"expected_revision":1})).await.0, StatusCode::NO_CONTENT);
    assert_eq!(check.await.unwrap(), StatusCode::NOT_FOUND);
    server.join().unwrap();
    assert_eq!(setup.call(Some(&alice), Method::GET, "/agent_connections", Value::Null).await.1, json!([]));
}

#[tokio::test]
async fn offline_check_is_bounded_and_home_still_works() {
    let _guard = serial();
    let setup = Setup::new();
    let alice = setup.actor(ALICE, KEY_A);
    let connection = setup.create(&alice, "http://127.0.0.1:14096/agent").await;
    let unused = TcpListener::bind("127.0.0.1:14096").unwrap();
    drop(unused);
    let result = setup.call(Some(&alice), Method::POST, &format!("{}/check", path(&connection)), json!({"expected_revision":1})).await;
    assert_error(&result, StatusCode::BAD_GATEWAY, "agent_unavailable");
    let (status, list) = setup.call(Some(&alice), Method::GET, "/agent_connections", Value::Null).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(list[0]["last_check"], Value::Null);
    assert_eq!(setup.call(Some(&alice), Method::GET, "/", Value::Null).await.0, StatusCode::OK);
}

#[test]
fn real_transport_rejects_unhealthy_malformed_and_oversized_bodies() {
    use agent_egress::{HealthTransport, Transport};
    for (status, body, expected) in [
        (401, br#"{"secret":"upstream-secret"}"#.to_vec(), EgressError::Authentication),
        (403, b"denied".to_vec(), EgressError::Authentication),
        (302, b"redirect".to_vec(), EgressError::Unhealthy),
        (200, b"not-json".to_vec(), EgressError::InvalidHealth),
        (200, br#"{"healthy":true}"#.to_vec(), EgressError::InvalidHealth),
        (200, br#"{"healthy":false,"version":"1"}"#.to_vec(), EgressError::Unhealthy),
        (200, vec![b'x'; 65_537], EgressError::InvalidHealth),
    ] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = fake_health(listener, "/global/health", "b3BlbmNvZGU6ZHVtbXk=", status, body, Duration::ZERO, None);
        let url = format!("http://127.0.0.1:{}/global/health", addr.port()).parse().unwrap();
        let transport = HealthTransport::new(Instant::now() + Duration::from_secs(2), Arc::new(std::sync::atomic::AtomicBool::new(false)));
        assert_eq!(transport.get_health(&url, &[addr], "opencode", "dummy"), Err(expected));
        server.join().unwrap();
    }
}

#[test]
fn expired_dns_deadline_and_stalled_body_are_bounded_and_sanitized() {
    use agent_egress::{DeadlineResolver, HealthTransport};
    let cancelled = Arc::new(AtomicBool::new(false));
    let resolver = DeadlineResolver::new(Instant::now() - Duration::from_secs(1), cancelled.clone());
    assert_eq!(resolver.resolve("127.0.0.1", 443), Err(EgressError::Timeout));

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let (arrived, request_seen) = std::sync::mpsc::channel();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let mut request = [0; 4096];
        let len = stream.read(&mut request).unwrap();
        assert!(String::from_utf8_lossy(&request[..len]).starts_with("GET /global/health HTTP/1.1"));
        stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\nConnection: close\r\n\r\n").unwrap();
        arrived.send(()).unwrap();
        // The response body never arrives; the client deadline must close the socket.
        let mut byte = [0];
        let _ = stream.read(&mut byte);
    });
    let url = format!("http://127.0.0.1:{}/global/health", addr.port()).parse().unwrap();
    let transport = HealthTransport::new(Instant::now() + Duration::from_millis(350), cancelled);
    assert_eq!(transport.get_health(&url, &[addr], "opencode", "not-for-logs"), Err(EgressError::Timeout));
    request_seen.recv_timeout(Duration::from_secs(2)).unwrap();
    server.join().unwrap();
}

#[test]
fn invalid_tls_peer_does_not_downgrade_or_reveal_credentials() {
    use agent_egress::{HealthTransport, Transport};
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let mut hello = [0; 4096];
        let n = stream.read(&mut hello).unwrap();
        assert_eq!(hello[0], 22, "must negotiate TLS, never send plaintext Basic auth");
        assert!(!hello[..n].windows(14).any(|bytes| bytes == b"tls-secret-pass"));
        stream.write_all(b"HTTP/1.1 200 OK\r\n\r\n").unwrap();
    });
    let transport = HealthTransport::new(Instant::now() + Duration::from_secs(2), Arc::new(AtomicBool::new(false)));
    let url = "https://localhost/global/health".parse().unwrap();
    assert_eq!(transport.get_health(&url, &[addr], "opencode", "tls-secret-pass"), Err(EgressError::Transport));
    server.join().unwrap();
}

#[test]
fn ambient_proxy_is_ignored_for_pinned_health_connection() {
    use agent_egress::{HealthTransport, Transport};
    let _guard = serial();
    struct Restore(Vec<(&'static str, Option<String>)>);
    impl Drop for Restore {
        fn drop(&mut self) {
            for (name, previous) in &self.0 {
                match previous { Some(value) => std::env::set_var(name, value), None => std::env::remove_var(name) }
            }
        }
    }
    let saved = Restore(["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy", "NO_PROXY", "no_proxy"]
        .into_iter().map(|name| (name, std::env::var(name).ok())).collect());
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let server = fake_health(listener, "/global/health", "b3BlbmNvZGU6ZHVtbXk=", 200,
        br#"{"healthy":true,"version":"direct"}"#.to_vec(), Duration::ZERO, None);
    for name in ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"] {
        std::env::set_var(name, "http://127.0.0.1:1");
    }
    std::env::remove_var("NO_PROXY");
    std::env::remove_var("no_proxy");
    let transport = HealthTransport::new(Instant::now() + Duration::from_secs(2), Arc::new(AtomicBool::new(false)));
    let url = "http://service.invalid/global/health".parse().unwrap();
    assert_eq!(transport.get_health(&url, &[addr], "opencode", "dummy"), Ok("direct".into()));
    server.join().unwrap();
    drop(saved);
}

#[tokio::test]
async fn check_slots_and_six_per_minute_are_per_account() {
    let _guard = serial();
    let setup = Setup::new();
    let carol = setup.actor(CAROL, KEY_C);
    let connection = setup.create(&carol, "http://127.0.0.1:14097/agent").await;
    let listener = TcpListener::bind("127.0.0.1:14097").unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let server = thread::spawn(move || {
        let mut streams = Vec::new();
        for _ in 0..2 {
            let (mut stream, _) = listener.accept().unwrap();
            stream.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            let mut buf = [0; 4096];
            let len = stream.read(&mut buf).unwrap();
            assert!(String::from_utf8_lossy(&buf[..len]).starts_with("GET /agent/global/health HTTP/1.1"));
            streams.push(stream);
            tx.send(()).unwrap();
        }
        release_rx.recv_timeout(Duration::from_secs(3)).unwrap();
        for mut stream in streams {
            let response = b"HTTP/1.1 200 OK\r\nContent-Length: 34\r\nConnection: close\r\n\r\n{\"healthy\":true,\"version\":\"slots\"}";
            stream.write_all(response).unwrap();
        }
    });
    let check_path = format!("{}/check", path(&connection));
    let mut running = Vec::new();
    for _ in 0..2 {
        let app = setup.app.clone();
        let actor = carol.clone();
        let path = check_path.clone();
        running.push(tokio::spawn(async move {
            app.oneshot(Request::builder().method(Method::POST).uri(path)
                .header(header::COOKIE, actor.cookie).header("X-CSRF-Token", actor.csrf)
                .header("X-Enc-Key", actor.key).header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(json!({"expected_revision":1}).to_string())).unwrap()).await.unwrap().status()
        }));
    }
    tokio::task::spawn_blocking(move || {
        for _ in 0..2 { rx.recv_timeout(Duration::from_secs(3)).unwrap(); }
    }).await.unwrap();
    assert_error(&setup.call(Some(&carol), Method::POST, &check_path, json!({"expected_revision":1})).await,
        StatusCode::TOO_MANY_REQUESTS, "agent_check_busy");
    release_tx.send(()).unwrap();
    for check in running { assert_eq!(check.await.unwrap(), StatusCode::OK); }
    server.join().unwrap();
    // Failed offline checks count as attempts; a rejected busy check does not.
    for _ in 0..4 {
        assert_error(&setup.call(Some(&carol), Method::POST, &check_path, json!({"expected_revision":1})).await,
            StatusCode::BAD_GATEWAY, "agent_unavailable");
    }
    assert_error(&setup.call(Some(&carol), Method::POST, &check_path, json!({"expected_revision":1})).await,
        StatusCode::TOO_MANY_REQUESTS, "agent_check_rate_limited");
    let bob = setup.actor(BOB, KEY_B);
    let other = setup.create(&bob, "http://127.0.0.1:14098/agent").await;
    assert_error(&setup.call(Some(&bob), Method::POST, &format!("{}/check", path(&other)), json!({"expected_revision":1})).await,
        StatusCode::BAD_GATEWAY, "agent_unavailable");
}
