//! Server-owned generations: HTTP views never own inference or settlement.
mod common;

use std::{
    collections::HashMap,
    sync::{Arc, Mutex, OnceLock},
    time::Duration,
};

use axum::{
    body::{to_bytes, Body},
    http::{header, Request, Response, StatusCode},
    Router,
};
use chatbot_core::{
    session::{ChatService, ChatSessionStore},
    session_identity::HttpSessionStore,
};
use chatbot_server::{
    build_router_with_services, generation_deps::GenerationDeps, generations::GenerationTiming,
    identity::RequestIdentity, resolve_static_root, services::AppServices,
};
use futures_util::StreamExt;
use serde_json::{json, Value};
use tower::ServiceExt;

fn lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

struct Fixture {
    app: Router,
    cookie: String,
    csrf: String,
    chat: ChatService,
    session: String,
}

async fn fixture(delay: u64, deadline: Duration) -> Fixture {
    let identity =
        RequestIdentity::with_store_and_csrf(Arc::new(HttpSessionStore::new(3600)), true);
    let home = identity.prepare_home_context(None).unwrap();
    let cookie = common::extract_cookie(&home.set_cookie);
    let session = home.session_id;
    let root = std::env::current_dir().unwrap();
    let chat = ChatService::with_storage(
        Arc::new(ChatSessionStore::new(3600, "test".into())),
        root.clone(),
        root,
        "test-secret".into(),
    );
    let provider = chatbot_core::config::get_provider_config(None).unwrap();
    let generation = GenerationDeps::new_with_fake(
        HashMap::from([("default".into(), provider)]),
        "default".into(),
        false,
        false,
        None,
        Some(vec!["first".into(), "second".into(), "third".into()]),
        None,
        None,
        delay,
        None,
    );
    let services = AppServices::with_owned_stores(identity)
        .with_chat_service(chat.clone())
        .with_generation_deps(generation)
        .with_generation_timing(GenerationTiming {
            heartbeat: Duration::from_millis(10),
            deadline,
            grace: Duration::from_secs(120),
        });
    Fixture {
        app: build_router_with_services(resolve_static_root(), services),
        cookie,
        csrf: home.csrf_token,
        chat,
        session,
    }
}

fn request(
    f: &Fixture,
    method: &str,
    uri: &str,
    payload: Value,
    key: Option<&str>,
) -> Request<Body> {
    let durable = method == "POST" && (uri == "/chat" || uri == "/regenerate");
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::COOKIE, &f.cookie)
        .header("X-CSRF-Token", &f.csrf)
        .header(header::CONTENT_TYPE, "application/json");
    if durable { builder = builder.header("X-Generation-Mode", "durable"); }
    if let Some(key) = key {
        builder = builder.header("Idempotency-Key", key);
    }
    builder
        .body(if method == "GET" {
            Body::empty()
        } else {
            Body::from(serde_json::to_vec(&payload).unwrap())
        })
        .unwrap()
}

async fn call(
    f: &Fixture,
    method: &str,
    uri: &str,
    payload: Value,
    key: Option<&str>,
) -> Response<Body> {
    f.app
        .clone()
        .oneshot(request(f, method, uri, payload, key))
        .await
        .unwrap()
}
async fn value(response: Response<Body>) -> Value {
    if let Some(id) = response.headers().get("X-Generation-Id") {
        let id = id.to_str().unwrap().to_owned();
        let version = response.headers().get("X-Generation-Base-Version").unwrap().to_str().unwrap().parse::<u64>().unwrap();
        drop(response);
        return json!({"generation_id":id, "state":"running", "base_version":version});
    }
    serde_json::from_slice(&to_bytes(response.into_body(), 1024 * 1024).await.unwrap()).unwrap()
}
fn send() -> Value {
    json!({"kind":"chat", "set_id":"", "expected_version":0, "message":"question"})
}
async fn admit(f: &Fixture) -> String {
    let response = call(f, "POST", "/chat", send(), None).await;
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    value(response).await["generation_id"]
        .as_str()
        .unwrap()
        .to_owned()
}
async fn events(f: &Fixture, id: &str, after: u64) -> Vec<Value> {
    let response = call(
        f,
        "GET",
        &format!("/generations/{id}/events?after={after}"),
        Value::Null,
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    assert_eq!(response.headers()["X-Accel-Buffering"], "no");
    assert!(!response.headers().contains_key(header::CONNECTION));
    let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    std::str::from_utf8(&bytes)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .filter(|v| v["type"] != "heartbeat")
        .collect()
}

#[tokio::test]
async fn header_free_chat_and_regenerate_keep_legacy_disconnect_stop() {
    let _lock = lock();
    let _workspace = common::TestWorkspace::with_openai_provider();
    let f = fixture(100, Duration::from_secs(1800)).await;
    for route in ["/chat", "/regenerate"] {
        let mut payload = send();
        if route == "/regenerate" { payload["pair_index"] = json!(0); }
        let mut req = request(&f, "POST", route, payload, None);
        req.headers_mut().remove("X-Generation-Mode");
        let response = f.app.clone().oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[header::CONTENT_TYPE], "text/plain; charset=utf-8");
        assert!(!response.headers().contains_key("X-Generation-Id"));
        let mut stream = response.into_body().into_data_stream();
        assert_eq!(stream.next().await.unwrap().unwrap(), "first");
        drop(stream);
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(f.chat.session_history(&f.session).last().unwrap().1, "first");
    }
}

#[tokio::test]
async fn disconnect_replay_two_subscribers_and_saved_turn() {
    let _lock = lock();
    let _workspace = common::TestWorkspace::with_openai_provider();
    let f = fixture(30, Duration::from_secs(1800)).await;
    let id = admit(&f).await;
    let response = call(
        &f,
        "GET",
        &format!("/generations/{id}/events"),
        Value::Null,
        None,
    )
    .await;
    let mut view = response.into_body().into_data_stream();
    let first: Value = loop {
        let bytes = view.next().await.unwrap().unwrap();
        let event: Value = serde_json::from_slice(&bytes).unwrap();
        if event["type"] == "delta" {
            break event;
        }
    };
    drop(view);
    let (all, second) = tokio::join!(events(&f, &id, 0), events(&f, &id, 0));
    assert_eq!(all, second);
    let missing = events(&f, &id, first["seq"].as_u64().unwrap()).await;
    assert_eq!(
        missing,
        all.iter()
            .filter(|event| event["seq"].as_u64().unwrap() > first["seq"].as_u64().unwrap())
            .cloned()
            .collect::<Vec<_>>()
    );
    assert!(all.iter().any(|e| e["type"] == "saved"));
    assert_eq!(
        all.iter()
            .filter(|e| e["type"] == "delta")
            .map(|e| e["text"].as_str().unwrap())
            .collect::<String>(),
        "firstsecondthird"
    );
    let status =
        value(call(&f, "GET", &format!("/generations/{id}"), Value::Null, None).await).await;
    assert_eq!(status["state"], "completed");
    let history = f.chat.session_history(&f.session);
    assert_eq!(history.last().unwrap().1, "firstsecondthird");
}

#[tokio::test]
async fn stop_partial_reservation_idempotency_and_ownership() {
    let _lock = lock();
    let _workspace = common::TestWorkspace::with_openai_provider();
    let f = fixture(200, Duration::from_secs(1800)).await;
    let response = call(
        &f,
        "POST",
        "/chat",
        send(),
        Some("generation-operation-001"),
    )
    .await;
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let descriptor = value(response).await;
    let replay = value(
        call(
            &f,
            "POST",
            "/chat",
            send(),
            Some("generation-operation-001"),
        )
        .await,
    )
    .await;
    assert_eq!(descriptor, replay);
    let mut other = send();
    other["message"] = json!("other");
    let conflict = call(&f, "POST", "/chat", other, None).await;
    assert_eq!(conflict.status(), StatusCode::CONFLICT);
    assert_eq!(value(conflict).await["error"], "generation_active");
    let id = descriptor["generation_id"].as_str().unwrap();
    let foreign = fixture(0, Duration::from_secs(1800)).await;
    for uri in [
        format!("/generations/{id}"),
        format!("/generations/{id}/events"),
    ] {
        assert_eq!(
            call(&foreign, "GET", &uri, Value::Null, None)
                .await
                .status(),
            StatusCode::NOT_FOUND
        );
    }
    assert_eq!(
        call(
            &foreign,
            "POST",
            &format!("/generations/{id}/stop"),
            json!({}),
            None
        )
        .await
        .status(),
        StatusCode::NOT_FOUND
    );
    let response = call(
        &f,
        "GET",
        &format!("/generations/{id}/events"),
        Value::Null,
        None,
    )
    .await;
    let mut view = response.into_body().into_data_stream();
    loop {
        let bytes = view.next().await.unwrap().unwrap();
        let event: Value = serde_json::from_slice(&bytes).unwrap();
        if event["type"] == "delta" {
            break;
        }
    }
    let stop = call(
        &f,
        "POST",
        &format!("/generations/{id}/stop"),
        json!({}),
        Some("stop-operation-00001"),
    )
    .await;
    assert_eq!(stop.status(), StatusCode::OK);
    drop(view);
    let output = events(&f, id, 0).await;
    assert!(output
        .iter()
        .any(|e| e["type"] == "ended" && e["text"] == "stopped"));
    assert!(output.iter().any(|e| e["type"] == "saved"));
    assert_eq!(
        f.chat.session_history(&f.session).last().unwrap().1,
        "first"
    );
    let stop_again = value(
        call(
            &f,
            "POST",
            &format!("/generations/{id}/stop"),
            json!({}),
            None,
        )
        .await,
    )
    .await;
    assert_eq!(stop_again["state"], "stopped");
}

#[tokio::test]
async fn stop_before_worker_poll_saves_empty_turn() {
    let _lock = lock();
    let _workspace = common::TestWorkspace::with_openai_provider();
    let f = fixture(1000, Duration::from_secs(1800)).await;
    let id = admit(&f).await;
    let response = call(
        &f,
        "POST",
        &format!("/generations/{id}/stop"),
        json!({}),
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let output = events(&f, &id, 0).await;
    assert!(output.iter().any(|e| e["type"] == "saved"));
    assert_eq!(
        f.chat.session_history(&f.session),
        vec![("question".into(), "".into())]
    );
}

#[tokio::test]
async fn authenticated_privacy_regenerate_and_set_reservation() {
    let _lock = lock();
    let workspace = common::TestWorkspace::with_openai_provider();
    let identity =
        RequestIdentity::with_store_and_csrf(Arc::new(HttpSessionStore::new(3600)), true);
    let home = identity.prepare_home_context(None).unwrap();
    let login = identity
        .finalize_login(Some(&common::extract_cookie(&home.set_cookie)), "alice")
        .unwrap();
    let cookie = common::extract_cookie(&login.set_cookie);
    let session = identity.session_context(Some(&cookie)).unwrap().session_id;
    let root = workspace.path().to_path_buf();
    let key =
        chatbot_core::enc_key::EncryptionKey::from_header_value("test-encryption-key-material")
            .unwrap();
    let mut users = chatbot_core::user_store::UserStore::open(&root).unwrap();
    users.create_user("alice", "unused-hash").unwrap();
    users
        .ensure_key_verifier_with_secret("alice", key.as_bytes(), b"test-secret")
        .unwrap();
    let chat = ChatService::with_storage(
        Arc::new(ChatSessionStore::new(3600, "test".into())),
        root.clone(),
        root,
        "test-secret".into(),
    );
    let snapshot = chat
        .history()
        .unwrap()
        .ensure_default_set("alice", &key)
        .unwrap();
    let coordinator = chatbot_server::set_privacy_coordinator::SetPrivacyCoordinator::default();
    let provider = chatbot_core::config::get_provider_config(None).unwrap();
    let deps = GenerationDeps::new_with_fake(
        HashMap::from([("default".into(), provider)]),
        "default".into(),
        false,
        false,
        None,
        Some(vec!["first".into(), "second".into()]),
        None,
        None,
        100,
        None,
    );
    let services = AppServices::with_owned_stores(identity.clone())
        .with_chat_service(chat.clone())
        .with_generation_deps(deps)
        .with_set_privacy_coordinator(coordinator.clone());
    let f = Fixture {
        app: build_router_with_services(resolve_static_root(), services),
        cookie,
        csrf: login.csrf_token,
        chat,
        session,
    };
    let authenticated = |method: &str, uri: &str, payload: Value| {
        let mut request = request(&f, method, uri, payload, None);
        request
            .headers_mut()
            .insert("X-Enc-Key", "test-encryption-key-material".parse().unwrap());
        request
    };
    let payload = json!({"kind":"chat", "set_id":snapshot.set_id.to_string(), "expected_version":snapshot.version.0, "message":"question"});
    let response = f
        .app
        .clone()
        .oneshot(authenticated("POST", "/chat", payload.clone()))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let id = value(response).await["generation_id"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(coordinator.try_update("alice", snapshot.set_id).is_none());
    // The same account's other HTTP session attaches, but cannot send another
    // generation for the reserved set, even via a differently formatted UUID.
    let other_home = identity.prepare_home_context(None).unwrap();
    let other_login = identity
        .finalize_login(
            Some(&common::extract_cookie(&other_home.set_cookie)),
            "alice",
        )
        .unwrap();
    let mut other = authenticated(
        "POST",
        "/chat",
        json!({"kind":"chat", "set_id":snapshot.set_id.to_string().to_uppercase(), "expected_version":snapshot.version.0, "message":"other"}),
    );
    other.headers_mut().insert(
        header::COOKIE,
        common::extract_cookie(&other_login.set_cookie)
            .parse()
            .unwrap(),
    );
    other
        .headers_mut()
        .insert("X-CSRF-Token", other_login.csrf_token.parse().unwrap());
    let response = f.app.clone().oneshot(other).await.unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_eq!(value(response).await["error"], "generation_active");
    let mut view = authenticated("GET", &format!("/generations/{id}/events"), Value::Null);
    view.headers_mut().insert(
        header::COOKIE,
        common::extract_cookie(&other_login.set_cookie)
            .parse()
            .unwrap(),
    );
    let response = f.app.clone().oneshot(view).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let output = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    assert!(std::str::from_utf8(&output).unwrap().contains("\"saved\""));
    assert!(coordinator.try_update("alice", snapshot.set_id).is_some());
    let saved = f
        .chat
        .history()
        .unwrap()
        .load("alice", snapshot.set_id, &key)
        .unwrap();
    assert_eq!(saved.history.last().unwrap().1, "firstsecond");
    let response = f.app.clone().oneshot(authenticated("POST", "/regenerate", json!({"kind":"regenerate", "set_id":snapshot.set_id.to_string(), "expected_version":saved.version.0, "message":"question", "pair_index":0}))).await.unwrap();
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let id = value(response).await["generation_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let response = f
        .app
        .clone()
        .oneshot(authenticated(
            "GET",
            &format!("/generations/{id}/events"),
            Value::Null,
        ))
        .await
        .unwrap();
    let _ = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    let regenerated = f
        .chat
        .history()
        .unwrap()
        .load("alice", snapshot.set_id, &key)
        .unwrap();
    assert_eq!(regenerated.history.len(), 1);
    assert_eq!(regenerated.history[0].1, "firstsecond");
    assert!(regenerated.version.0 > saved.version.0);
}

#[tokio::test]
async fn invalid_admission_never_saves_legacy_error_turn() {
    let _lock = lock();
    let _workspace = common::TestWorkspace::with_openai_provider();
    let f = fixture(0, Duration::from_secs(1800)).await;
    let mut payload = send();
    payload["model_name"] = json!("missing-provider");
    let response = call(&f, "POST", "/chat", payload, None).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(f.chat.session_history(&f.session).is_empty());
    let mut payload = send();
    payload["expected_version"] = json!(99);
    let response = call(&f, "POST", "/chat", payload, None).await;
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_eq!(value(response).await["error"], "version_conflict");
    assert!(f.chat.session_history(&f.session).is_empty());
}

#[tokio::test]
async fn blocked_provider_connection_is_worker_owned_and_deadline_bounded() {
    let _lock = lock();
    let _workspace = common::TestWorkspace::with_openai_provider();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (started, waiting) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let _ = started.send(());
        std::future::pending::<()>().await;
        drop(socket);
    });
    let identity =
        RequestIdentity::with_store_and_csrf(Arc::new(HttpSessionStore::new(3600)), true);
    let home = identity.prepare_home_context(None).unwrap();
    let root = std::env::current_dir().unwrap();
    let chat = ChatService::with_storage(
        Arc::new(ChatSessionStore::new(3600, "test".into())),
        root.clone(),
        root,
        "test-secret".into(),
    );
    let mut provider = chatbot_core::config::get_provider_config(None).unwrap();
    provider.base_url = format!("http://{address}/v1");
    provider.test_chunks = None;
    let deps = GenerationDeps::new(
        HashMap::from([("default".into(), provider)]),
        "default".into(),
        false,
        false,
        None,
    );
    let services = AppServices::with_owned_stores(identity)
        .with_chat_service(chat.clone())
        .with_generation_deps(deps)
        .with_generation_timing(GenerationTiming {
            heartbeat: Duration::from_millis(10),
            deadline: Duration::from_millis(200),
            grace: Duration::from_secs(120),
        });
    let f = Fixture {
        app: build_router_with_services(resolve_static_root(), services),
        cookie: common::extract_cookie(&home.set_cookie),
        csrf: home.csrf_token,
        session: home.session_id,
        chat,
    };
    let response = tokio::time::timeout(
        Duration::from_millis(100),
        call(&f, "POST", "/chat", send(), None),
    )
    .await
    .expect("admission must not await provider connection");
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let id = value(response).await["generation_id"]
        .as_str()
        .unwrap()
        .to_owned();
    tokio::time::timeout(Duration::from_secs(1), waiting)
        .await
        .unwrap()
        .unwrap();
    let response = call(
        &f,
        "GET",
        &format!("/generations/{id}/events"),
        Value::Null,
        None,
    )
    .await;
    drop(response);
    let output = tokio::time::timeout(Duration::from_secs(1), events(&f, &id, 0))
        .await
        .unwrap();
    assert!(output
        .iter()
        .any(|e| e["type"] == "ended" && e["text"] == "stopped"));
    assert!(output.iter().any(|e| e["type"] == "saved"));
    assert_eq!(
        f.chat.session_history(&f.session),
        vec![("question".into(), "".into())]
    );
    server.abort();
}

#[tokio::test]
async fn thinking_events_are_distinct_from_answer_and_saved_without_thoughts() {
    let _lock = lock();
    let _workspace = common::TestWorkspace::with_openai_provider();
    let identity =
        RequestIdentity::with_store_and_csrf(Arc::new(HttpSessionStore::new(3600)), true);
    let home = identity.prepare_home_context(None).unwrap();
    let root = std::env::current_dir().unwrap();
    let chat = ChatService::with_storage(
        Arc::new(ChatSessionStore::new(3600, "test".into())),
        root.clone(),
        root,
        "test-secret".into(),
    );
    let provider = chatbot_core::config::get_provider_config(None).unwrap();
    let deps = GenerationDeps::new_with_fake(
        HashMap::from([("default".into(), provider)]),
        "default".into(),
        false,
        false,
        None,
        Some(vec![
            "answer<th".into(),
            "ink>reason".into(),
            "</think>end".into(),
        ]),
        None,
        None,
        0,
        None,
    );
    let services = AppServices::with_owned_stores(identity)
        .with_chat_service(chat.clone())
        .with_generation_deps(deps);
    let f = Fixture {
        app: build_router_with_services(resolve_static_root(), services),
        cookie: common::extract_cookie(&home.set_cookie),
        csrf: home.csrf_token,
        session: home.session_id,
        chat,
    };
    let id = admit(&f).await;
    let output = events(&f, &id, 0).await;
    assert_eq!(
        output
            .iter()
            .filter(|e| e["type"] == "thinking")
            .map(|e| e["text"].as_str().unwrap())
            .collect::<String>(),
        "reason"
    );
    assert_eq!(
        output
            .iter()
            .filter(|e| e["type"] == "delta")
            .map(|e| e["text"].as_str().unwrap())
            .collect::<String>(),
        "answerend"
    );
    assert_eq!(
        f.chat.session_history(&f.session).last().unwrap().1,
        "answerend"
    );
}

#[tokio::test]
async fn receipts_replay_stop_and_rejected_admission_without_reexecution() {
    let _lock = lock();
    let _workspace = common::TestWorkspace::with_openai_provider();
    let f = fixture(1000, Duration::from_secs(1800)).await;
    let mut invalid = send();
    invalid["model_name"] = json!("missing-provider");
    let rejected = call(&f, "POST", "/chat", invalid, Some("rejected-operation-0001")).await;
    assert_eq!(rejected.status(), StatusCode::BAD_REQUEST);
    let reused = call(&f, "POST", "/chat", send(), Some("rejected-operation-0001")).await;
    assert_eq!(reused.status(), StatusCode::CONFLICT);
    assert_eq!(value(reused).await["error"], "operation_id_reused");
    let id = admit(&f).await;
    let first = value(call(&f, "POST", &format!("/generations/{id}/stop"), json!({}), Some("stop-receipt-operation-01")).await).await;
    let _ = events(&f, &id, 0).await;
    let replay = value(call(&f, "POST", &format!("/generations/{id}/stop"), json!({}), Some("stop-receipt-operation-01")).await).await;
    assert_eq!(replay, first);
}

#[tokio::test]
async fn activity_and_conflicts_use_canonical_set_identity() {
    let _lock = lock();
    let workspace = common::TestWorkspace::with_openai_provider();
    let identity = RequestIdentity::with_store_and_csrf(Arc::new(HttpSessionStore::new(3600)), true);
    let home = identity.prepare_home_context(None).unwrap();
    let login = identity.finalize_login(Some(&common::extract_cookie(&home.set_cookie)), "alice").unwrap();
    let root = workspace.path().to_path_buf();
    let key = chatbot_core::enc_key::EncryptionKey::from_header_value("test-encryption-key-material").unwrap();
    let mut users = chatbot_core::user_store::UserStore::open(&root).unwrap();
    users.create_user("alice", "unused-hash").unwrap();
    users.ensure_key_verifier_with_secret("alice", key.as_bytes(), b"test-secret").unwrap();
    let chat = ChatService::with_storage(Arc::new(ChatSessionStore::new(3600, "test".into())), root.clone(), root, "test-secret".into());
    let snapshot = chat.history().unwrap().ensure_default_set("alice", &key).unwrap();
    let provider = chatbot_core::config::get_provider_config(None).unwrap();
    let deps = GenerationDeps::new_with_fake(HashMap::from([("default".into(), provider)]), "default".into(), false, false, None, Some(vec!["first".into()]), None, None, 1000, None);
    let services = AppServices::with_owned_stores(identity).with_chat_service(chat.clone()).with_generation_deps(deps);
    let f = Fixture { app: build_router_with_services(resolve_static_root(), services), cookie: common::extract_cookie(&login.set_cookie), csrf: login.csrf_token, chat, session: login.session_id };
    let authenticated = |method: &str, uri: &str, payload: Value| {
        let mut request = request(&f, method, uri, payload, None);
        request.headers_mut().insert("X-Enc-Key", "test-encryption-key-material".parse().unwrap());
        request
    };
    let response = f.app.clone().oneshot(authenticated("POST", "/chat", json!({"kind":"chat", "set_id":snapshot.set_id.to_string(), "expected_version":99, "message":"question"}))).await.unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_eq!(value(response).await, chatbot_core::history::HistoryService::version_conflict_body(snapshot.set_id, snapshot.version));
    let response = f.app.clone().oneshot(authenticated("POST", "/chat", json!({"kind":"chat", "set_id":snapshot.set_id.to_string(), "expected_version":snapshot.version.0, "message":"question"}))).await.unwrap();
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let descriptor = value(response).await;
    let response = f.app.clone().oneshot(authenticated("GET", &format!("/activity?set_id={}", snapshot.set_id.to_string().to_uppercase()), Value::Null)).await.unwrap();
    assert_eq!(value(response).await["generations"], json!([descriptor]));
    let _ = f.app.clone().oneshot(authenticated("POST", &format!("/generations/{}/stop", descriptor["generation_id"].as_str().unwrap()), json!({}))).await.unwrap();
}

#[tokio::test]
async fn idle_heartbeat_and_injected_deadline_settle_without_view() {
    let _lock = lock();
    let _workspace = common::TestWorkspace::with_openai_provider();
    let f = fixture(1000, Duration::from_millis(50)).await;
    let id = admit(&f).await;
    let response = call(
        &f,
        "GET",
        &format!("/generations/{id}/events"),
        Value::Null,
        None,
    )
    .await;
    let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    let output: Vec<Value> = std::str::from_utf8(&bytes)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert!(output
        .iter()
        .any(|e| e["type"] == "heartbeat" && e.get("seq").is_none()));
    assert!(output
        .iter()
        .any(|e| e["type"] == "ended" && e["text"] == "stopped"));
    assert!(output.iter().any(|e| e["type"] == "saved"));
}
