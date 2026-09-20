//! Two-router request-config and fake-provider isolation.
//!
//! Given two fully owned routers (separate identity stores, session mirrors,
//! durable history, account roots/secrets, generation maps and request
//! configs), when ambient fake env is poisoned with decoys
//! (`CHATBOT_TEST_OPENAI_CHUNKS` / `CHATBOT_TEST_OPENAI_TOOL_CALL_QUERY` /
//! `CHATBOT_TEST_BRAVE_RESULTS` / `XAI_API_KEY`), then CSRF policy, cookie
//! `Secure`/`Max-Age`, home prompt/models, voice endpoints and fake
//! stream/search responses stay scoped per router with no decoy leak and no
//! real upstream calls when fakes are present.
//!
//! These tests pin the owned path only. Live-global timing (lazy first-use,
//! per-call reads, no startup snapshot) is pinned by the existing
//! characterization suites. Account/chat durability isolation itself is reused
//! from `router_account_service_isolation` / `router_chat_service_isolation`;
//! here distinct temp roots prove only that sessions do not leak across the
//! two configs under test.

mod common;

use std::{
    collections::HashMap,
    env,
    net::SocketAddr,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex, OnceLock,
    },
};

use axum::{
    body::Body,
    http::{header, Method, Request, StatusCode},
    routing::post,
    Router,
};
use chatbot_core::{
    account_service::AccountService,
    config::ProviderConfig,
    config_source::ConfigSource,
    session::{ChatSessionStore, ChatService},
    session_identity::HttpSessionStore,
};
use chatbot_server::{
    build_router_with_services, generation_deps::GenerationDeps, identity::RequestIdentity,
    resolve_static_root, services::AppServices,
};
use once_cell::sync::Lazy;
use regex::Regex;
use serde_json::{json, Value};
use tower::ServiceExt;

static CSRF_META_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"<meta name=\"csrf-token\" content=\"([^\"]+)\""#).expect("csrf regex")
});

fn test_mutex() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

fn clear_owned_env() {
    for key in [
        "BRAVE_API_KEY",
        "CHATBOT_TEST_OPENAI_CHUNKS",
        "CHATBOT_TEST_OPENAI_CHUNK_DELAY_MS",
        "CHATBOT_TEST_OPENAI_TOOL_CALL_QUERY",
        "CHATBOT_TEST_BRAVE_RESULTS",
        "XAI_API_KEY",
    ] {
        env::remove_var(key);
    }
}

/// Poison ambient fake env with decoys owned routers must ignore. Each test
/// asserts its explicit fakes win and no decoy leaks into either router.
fn poison_fake_env() {
    env::set_var(
        "CHATBOT_TEST_OPENAI_CHUNKS",
        serde_json::to_string(&vec!["env-decoy-chunk".to_string()]).unwrap(),
    );
    env::set_var("CHATBOT_TEST_OPENAI_TOOL_CALL_QUERY", "env-decoy-query");
    env::set_var("CHATBOT_TEST_BRAVE_RESULTS", "env-decoy-results");
    env::set_var("XAI_API_KEY", "env-decoy-xai-key");
}

fn test_provider_with_chunks(name: &str, chunks: &[&str]) -> ProviderConfig {
    ProviderConfig {
        provider_name: name.to_string(),
        provider_type: "openai".to_string(),
        tier: None,
        model_name: format!("{name}-model"),
        context_size: Some(4096),
        base_url: "https://example.test/v1".to_string(),
        api_key: None,
        allowed_providers: vec![],
        request_timeout: Some(5.0),
        rate_limit_retries: Some(0),
        rate_limit_max_wait_secs: Some(0.02),
        test_chunks: Some(chunks.iter().map(|s| s.to_string()).collect()),
        search: false,
        xai_search: true,
        xai_zdr: false,
    }
}

fn deps_from_entries(entries: Vec<ProviderConfig>, default: &str) -> GenerationDeps {
    let mut map = HashMap::new();
    for entry in entries {
        map.insert(entry.provider_name.clone(), entry);
    }
    GenerationDeps::new(map, default.to_owned(), true, false, None)
}

struct OwnedRouter {
    _temp: tempfile::TempDir,
    app: Router,
}

fn owned_router(
    config: ConfigSource,
    generation: GenerationDeps,
    secret: &str,
    timeout_override: Option<u64>,
    prompt_override: Option<String>,
) -> OwnedRouter {
    let temp = tempfile::tempdir().expect("tempdir");
    let timeout = timeout_override.unwrap_or_else(|| config.session_timeout());
    let prompt = prompt_override.unwrap_or_else(|| config.default_system_prompt());
    let account_root = temp.path().join("accounts");
    std::fs::create_dir_all(&account_root).expect("account root");
    let accounts =
        AccountService::with_root_and_secret(account_root, secret.to_owned());
    let sessions = Arc::new(ChatSessionStore::new(timeout, prompt));
    let chat = ChatService::with_storage_and_accounts(
        sessions,
        temp.path().to_path_buf(),
        accounts.clone(),
    );
    let identity = RequestIdentity::with_store_and_config(
        Arc::new(HttpSessionStore::new(config.session_timeout())),
        config.clone(),
    );
    let services = AppServices::with_owned_stores(identity)
        .with_chat_service(chat)
        .with_account_service(accounts)
        .with_generation_deps(generation)
        .with_config_source(config);
    let app = build_router_with_services(resolve_static_root(), services);
    OwnedRouter { _temp: temp, app }
}

async fn get_home(app: &Router) -> (StatusCode, Vec<String>, String) {
    let response = app
        .clone()
        .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
        .await
        .expect("GET /");
    let status = response.status();
    let cookies: Vec<String> = response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok().map(str::to_owned))
        .collect();
    let body = axum::body::to_bytes(response.into_body(), 256 * 1024)
        .await
        .expect("home body");
    (
        status,
        cookies,
        std::str::from_utf8(&body).expect("utf8").to_owned(),
    )
}

fn session_cookie(cookies: &[String]) -> String {
    cookies
        .iter()
        .find_map(|c| {
            let pair = common::extract_cookie(c);
            pair.starts_with("session=").then(|| pair)
        })
        .expect("session cookie")
}

fn csrf_from_home(html: &str) -> String {
    CSRF_META_RE
        .captures(html)
        .and_then(|c| c.get(1).map(|m| m.as_str().to_owned()))
        .expect("csrf token")
}

async fn post_chat(
    app: &Router,
    cookie: &str,
    csrf: &str,
    payload: Value,
) -> (StatusCode, String) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/chat")
                .header(header::CONTENT_TYPE, "application/json")
                .header("X-CSRF-Token", csrf)
                .header(header::COOKIE, cookie)
                .body(Body::from(serde_json::to_vec(&payload).unwrap()))
                .unwrap(),
        )
        .await
        .expect("POST /chat");
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), 512 * 1024)
        .await
        .expect("chat body");
    (
        status,
        std::str::from_utf8(&body).expect("utf8").to_owned(),
    )
}

fn fresh_capture() -> (
    Arc<tokio::sync::Mutex<Vec<Value>>>,
    Arc<AtomicUsize>,
) {
    (
        Arc::new(tokio::sync::Mutex::new(Vec::new())),
        Arc::new(AtomicUsize::new(0)),
    )
}

async fn spawn_openai_mock(
    captured: Arc<tokio::sync::Mutex<Vec<Value>>>,
    hits: Arc<AtomicUsize>,
    delta: &str,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let delta = delta.to_owned();
    let app = Router::new().route(
        "/v1/chat/completions",
        post(move |axum::Json(payload): axum::Json<Value>| {
            let captured = captured.clone();
            let hits = hits.clone();
            let delta = delta.clone();
            async move {
                captured.lock().await.push(payload);
                hits.fetch_add(1, Ordering::SeqCst);
                let body = format!(
                    "data: {{\"choices\":[{{\"delta\":{{\"content\":\"{delta}\"}}}}]}}\n\ndata: [DONE]\n\n"
                );
                (
                    StatusCode::OK,
                    [(header::CONTENT_TYPE, "text/event-stream")],
                    body,
                )
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind openai mock");
    let addr = listener.local_addr().expect("mock addr");
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (addr, handle)
}

async fn spawn_xai_mock(
    captured_auth: Arc<tokio::sync::Mutex<Vec<String>>>,
    hits: Arc<AtomicUsize>,
    delta: &str,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let delta = delta.to_owned();
    let app = Router::new().route(
        "/responses",
        post(move |req: Request<Body>| {
            let captured_auth = captured_auth.clone();
            let hits = hits.clone();
            let delta = delta.clone();
            async move {
                let auth = req
                    .headers()
                    .get(header::AUTHORIZATION)
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("")
                    .to_owned();
                captured_auth.lock().await.push(auth);
                hits.fetch_add(1, Ordering::SeqCst);
                let body = format!(
                    "data: {{\"choices\":[{{\"delta\":{{\"content\":\"{delta}\"}}}}]}}\n\ndata: [DONE]\n\n"
                );
                (
                    StatusCode::OK,
                    [(header::CONTENT_TYPE, "text/event-stream")],
                    body,
                )
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind xai mock");
    let addr = listener.local_addr().expect("mock addr");
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (addr, handle)
}

fn mock_openai_provider(base_url: &str) -> ProviderConfig {
    ProviderConfig {
        provider_name: "default".to_string(),
        provider_type: "openai".to_string(),
        tier: None,
        model_name: "gpt-test".to_string(),
        context_size: Some(4096),
        base_url: base_url.to_owned(),
        api_key: None,
        allowed_providers: vec![],
        request_timeout: Some(5.0),
        rate_limit_retries: Some(0),
        rate_limit_max_wait_secs: Some(0.02),
        test_chunks: None,
        search: false,
        xai_search: true,
        xai_zdr: false,
    }
}

fn mock_xai_provider(base_url: &str) -> ProviderConfig {
    ProviderConfig {
        provider_name: "default".to_string(),
        provider_type: "xai".to_string(),
        tier: None,
        model_name: "grok-test".to_string(),
        context_size: Some(4096),
        base_url: base_url.to_owned(),
        api_key: None,
        allowed_providers: vec![],
        request_timeout: Some(5.0),
        rate_limit_retries: Some(0),
        rate_limit_max_wait_secs: Some(0.02),
        test_chunks: None,
        search: false,
        xai_search: true,
        xai_zdr: false,
    }
}

#[tokio::test]
async fn global_identity_with_owned_config_scopes_bootstrap_and_validation() {
    // Focused global-store case: `RequestIdentity::global().with_config_source`
    // keeps global records and store-first timing, but CSRF-off bootstrap and
    // validation agree (open POST succeeds), while CSRF-on agrees (open POST
    // 401s). Poisoned env must not leak.
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap_or_else(|p| p.into_inner());
    env::set_var("SECRET_KEY", "request_config_isolation_secret");
    let _workspace = common::TestWorkspace::with_openai_provider();
    clear_owned_env();
    env::set_var("RATE_LIMIT_PER_USER_PER_MINUTE", "0");
    env::set_var("RATE_LIMIT_GLOBAL_PER_MINUTE", "0");
    chatbot_core::config::reset();
    chatbot_core::rate_limit::reset();
    poison_fake_env();

    fn global_router(csrf: bool) -> Router {
        let config = ConfigSource::new(
            csrf,
            3600,
            "prompt".to_string(),
            "http://127.0.0.1:1".to_string(),
        );
        let mut map = HashMap::new();
        map.insert(
            "default".to_string(),
            test_provider_with_chunks("default", &["global-fake-marker"]),
        );
        let generation =
            GenerationDeps::new(map, "default".to_string(), true, false, None);
        let identity = RequestIdentity::global().with_config_source(config.clone());
        let services = AppServices::with_identity(identity)
            .with_generation_deps(generation)
            .with_config_source(config);
        build_router_with_services(resolve_static_root(), services)
    }

    let app_off = global_router(false);
    let (_, cookies_off, _) = get_home(&app_off).await;
    let cookie_off = session_cookie(&cookies_off);
    let (status_off, body_off) = post_chat(
        &app_off,
        &cookie_off,
        "",
        json!({"message": "Hello", "set_name": "default"}),
    )
    .await;

    let app_on = global_router(true);
    let (_, cookies_on, _) = get_home(&app_on).await;
    let cookie_on = session_cookie(&cookies_on);
    let (status_on, _) = post_chat(
        &app_on,
        &cookie_on,
        "",
        json!({"message": "Hello", "set_name": "default"}),
    )
    .await;

    clear_owned_env();

    assert_eq!(status_off, StatusCode::OK);
    assert!(
        body_off.contains("global-fake-marker") && !body_off.contains("env-decoy-chunk"),
        "global CSRF-off must bootstrap and validate open, got: {body_off}"
    );
    assert_eq!(status_on, StatusCode::UNAUTHORIZED);
    assert_eq!(chatbot_server::test_instrumentation::take_error_count(), 0);
}

#[tokio::test]
async fn two_routers_isolate_csrf_policy_with_poisoned_env() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap_or_else(|p| p.into_inner());
    env::set_var("SECRET_KEY", "request_config_isolation_secret");
    let _workspace = common::TestWorkspace::with_openai_provider();
    clear_owned_env();
    env::set_var("RATE_LIMIT_PER_USER_PER_MINUTE", "0");
    env::set_var("RATE_LIMIT_GLOBAL_PER_MINUTE", "0");
    chatbot_core::config::reset();
    chatbot_core::rate_limit::reset();
    poison_fake_env();

    let config_a = ConfigSource::new(false, 3600, "prompt-a".to_string(), "http://127.0.0.1:1".to_string());
    let config_b = ConfigSource::new(true, 3600, "prompt-b".to_string(), "http://127.0.0.1:1".to_string());
    let deps_a = deps_from_entries(vec![test_provider_with_chunks("default", &["csrf-a-marker-aaa"])], "default");
    let deps_b = deps_from_entries(vec![test_provider_with_chunks("default", &["csrf-b-marker-bbb"])], "default");
    let router_a = owned_router(config_a, deps_a, "csrf-secret-a", None, None);
    let router_b = owned_router(config_b, deps_b, "csrf-secret-b", None, None);

    let (_, cookies_a, html_a) = get_home(&router_a.app).await;
    let (_, cookies_b, html_b) = get_home(&router_b.app).await;
    let cookie_a = session_cookie(&cookies_a);
    let cookie_b = session_cookie(&cookies_b);
    let csrf_a = csrf_from_home(&html_a);
    let csrf_b = csrf_from_home(&html_b);

    let (status_a_open, body_a_open) = post_chat(
        &router_a.app,
        &cookie_a,
        "",
        json!({"message": "Hello", "set_name": "default"}),
    )
    .await;
    let (status_b_open, _) = post_chat(
        &router_b.app,
        &cookie_b,
        "",
        json!({"message": "Hello", "set_name": "default"}),
    )
    .await;

    let (status_a_shut, body_a_shut) = post_chat(
        &router_a.app,
        &cookie_a,
        &csrf_a,
        json!({"message": "Hello", "set_name": "default"}),
    )
    .await;
    let (status_b_shut, body_b_shut) = post_chat(
        &router_b.app,
        &cookie_b,
        &csrf_b,
        json!({"message": "Hello", "set_name": "default"}),
    )
    .await;

    let (status_cross, _) = post_chat(
        &router_b.app,
        &cookie_b,
        &csrf_a,
        json!({"message": "Hello", "set_name": "default"}),
    )
    .await;

    clear_owned_env();

    assert_eq!(status_a_open, StatusCode::OK);
    assert!(
        body_a_open.contains("csrf-a-marker-aaa"),
        "csrf-off router must accept missing token, got: {body_a_open}"
    );
    assert_eq!(status_b_open, StatusCode::UNAUTHORIZED);
    assert_eq!(status_a_shut, StatusCode::OK);
    assert!(
        body_a_shut.contains("csrf-a-marker-aaa"),
        "csrf-off router must still stream its own fake, got: {body_a_shut}"
    );
    assert_eq!(status_b_shut, StatusCode::OK);
    assert!(
        body_b_shut.contains("csrf-b-marker-bbb"),
        "csrf-on router must stream its own fake with token, got: {body_b_shut}"
    );
    assert_eq!(status_cross, StatusCode::UNAUTHORIZED);
    assert!(
        !body_a_open.contains("env-decoy-chunk")
            && !body_a_shut.contains("env-decoy-chunk")
            && !body_b_shut.contains("env-decoy-chunk"),
        "poisoned chunks must not leak: {body_a_open} / {body_a_shut} / {body_b_shut}"
    );
    assert_eq!(chatbot_server::test_instrumentation::take_error_count(), 0);
}

#[tokio::test]
async fn two_routers_isolate_cookie_secure_and_max_age() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap_or_else(|p| p.into_inner());
    env::set_var("SECRET_KEY", "request_config_isolation_secret");
    let _workspace = common::TestWorkspace::with_openai_provider();
    clear_owned_env();
    env::set_var("RATE_LIMIT_PER_USER_PER_MINUTE", "0");
    env::set_var("RATE_LIMIT_GLOBAL_PER_MINUTE", "0");
    chatbot_core::config::reset();
    chatbot_core::rate_limit::reset();
    poison_fake_env();

    let config_a = ConfigSource::new(true, 3600, "prompt-a".to_string(), "http://127.0.0.1:1".to_string());
    let config_b = ConfigSource::new(false, 7200, "prompt-b".to_string(), "http://127.0.0.1:1".to_string());
    let deps = || {
        deps_from_entries(
            vec![test_provider_with_chunks("default", &["cookie-marker"])],
            "default",
        )
    };
    let router_a = owned_router(config_a, deps(), "cookie-secret-a", None, None);
    let router_b = owned_router(config_b, deps(), "cookie-secret-b", None, None);

    let (_, cookies_a, _) = get_home(&router_a.app).await;
    let (_, cookies_b, _) = get_home(&router_b.app).await;
    let raw_a = cookies_a
        .iter()
        .find(|c| c.starts_with("session="))
        .expect("session a");
    let raw_b = cookies_b
        .iter()
        .find(|c| c.starts_with("session="))
        .expect("session b");

    clear_owned_env();

    assert!(
        raw_a.contains("Max-Age=3600") && raw_a.contains("Secure"),
        "3600/csrf-on router must set Max-Age=3600 plus Secure, got: {raw_a}"
    );
    assert!(
        raw_b.contains("Max-Age=7200") && !raw_b.contains("Secure"),
        "7200/csrf-off router must set Max-Age=7200 without Secure, got: {raw_b}"
    );
    assert_eq!(chatbot_server::test_instrumentation::take_error_count(), 0);
}

#[tokio::test]
async fn two_routers_isolate_home_prompt_and_models() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap_or_else(|p| p.into_inner());
    env::set_var("SECRET_KEY", "request_config_isolation_secret");
    let _workspace = common::TestWorkspace::with_openai_provider();
    clear_owned_env();
    env::set_var("RATE_LIMIT_PER_USER_PER_MINUTE", "0");
    env::set_var("RATE_LIMIT_GLOBAL_PER_MINUTE", "0");
    chatbot_core::config::reset();
    chatbot_core::rate_limit::reset();
    poison_fake_env();

    let config_a = ConfigSource::new(
        true,
        3600,
        "prompt-A-HOME-AAA".to_string(),
        "http://127.0.0.1:1".to_string(),
    );
    let config_b = ConfigSource::new(
        true,
        3600,
        "prompt-B-HOME-BBB".to_string(),
        "http://127.0.0.1:1".to_string(),
    );
    let deps_a = deps_from_entries(vec![test_provider_with_chunks("alpha-only", &["a"])], "alpha-only");
    let deps_b = deps_from_entries(vec![test_provider_with_chunks("beta-only", &["b"])], "beta-only");
    let router_a = owned_router(config_a, deps_a, "home-secret-a", None, None);
    let router_b = owned_router(config_b, deps_b, "home-secret-b", None, None);

    let (_, _, html_a) = get_home(&router_a.app).await;
    let (_, _, html_b) = get_home(&router_b.app).await;

    clear_owned_env();

    assert!(
        html_a.contains("prompt-A-HOME-AAA") && html_a.contains("alpha-only"),
        "router A home must render its own prompt and model"
    );
    assert!(
        html_b.contains("prompt-B-HOME-BBB") && html_b.contains("beta-only"),
        "router B home must render its own prompt and model"
    );
    assert!(
        !html_a.contains("prompt-B-HOME-BBB") && !html_a.contains("beta-only"),
        "router A home must not leak router B inputs"
    );
    assert!(
        !html_b.contains("prompt-A-HOME-AAA") && !html_b.contains("alpha-only"),
        "router B home must not leak router A inputs"
    );
    assert_eq!(chatbot_server::test_instrumentation::take_error_count(), 0);
}

#[tokio::test]
async fn two_routers_isolate_fake_chunks_with_priority_over_config_and_env() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap_or_else(|p| p.into_inner());
    env::set_var("SECRET_KEY", "request_config_isolation_secret");
    let _workspace = common::TestWorkspace::with_openai_provider();
    clear_owned_env();
    env::set_var("RATE_LIMIT_PER_USER_PER_MINUTE", "0");
    env::set_var("RATE_LIMIT_GLOBAL_PER_MINUTE", "0");
    chatbot_core::config::reset();
    chatbot_core::rate_limit::reset();
    poison_fake_env();

    let config = || {
        ConfigSource::new(true, 3600, "prompt".to_string(), "http://127.0.0.1:1".to_string())
    };
    // Router A: explicit fake override wins over its own config chunks.
    let mut map_a = HashMap::new();
    map_a.insert(
        "default".to_string(),
        test_provider_with_chunks("default", &["config-A-ignored"]),
    );
    let deps_a = GenerationDeps::new(map_a, "default".to_string(), true, false, None)
        .with_fake_chunks(vec!["fake-A-override-AAA".to_string()]);
    // Router B: no fake, falls back to its own config chunks (not env).
    let deps_b = deps_from_entries(
        vec![test_provider_with_chunks("default", &["config-B-fallback-BBB"])],
        "default",
    );

    let router_a = owned_router(config(), deps_a, "fake-secret-a", None, None);
    let router_b = owned_router(config(), deps_b, "fake-secret-b", None, None);

    let (_, cookies_a, html_a) = get_home(&router_a.app).await;
    let (_, cookies_b, html_b) = get_home(&router_b.app).await;
    let (cookie_a, csrf_a) = (session_cookie(&cookies_a), csrf_from_home(&html_a));
    let (cookie_b, csrf_b) = (session_cookie(&cookies_b), csrf_from_home(&html_b));

    let (_, body_a) = post_chat(
        &router_a.app,
        &cookie_a,
        &csrf_a,
        json!({"message": "Hello", "set_name": "default"}),
    )
    .await;
    let (_, body_b) = post_chat(
        &router_b.app,
        &cookie_b,
        &csrf_b,
        json!({"message": "Hello", "set_name": "default"}),
    )
    .await;

    clear_owned_env();

    assert!(
        body_a.contains("fake-A-override-AAA") && !body_a.contains("config-A-ignored"),
        "explicit fake must win over config chunks, got: {body_a}"
    );
    assert!(
        body_b.contains("config-B-fallback-BBB"),
        "absent fake must fall back to config chunks, got: {body_b}"
    );
    assert!(
        !body_a.contains("env-decoy-chunk") && !body_b.contains("env-decoy-chunk"),
        "poisoned env chunks must not leak: {body_a} / {body_b}"
    );
    assert_eq!(chatbot_server::test_instrumentation::take_error_count(), 0);
}

#[tokio::test]
async fn two_routers_isolate_fake_search_via_captured_requests() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap_or_else(|p| p.into_inner());
    env::set_var("SECRET_KEY", "request_config_isolation_secret");
    let _workspace = common::TestWorkspace::with_openai_provider();
    clear_owned_env();
    env::set_var("RATE_LIMIT_PER_USER_PER_MINUTE", "0");
    env::set_var("RATE_LIMIT_GLOBAL_PER_MINUTE", "0");
    chatbot_core::config::reset();
    chatbot_core::rate_limit::reset();
    poison_fake_env();

    // Final LLM calls hit mock servers so the injected search results are
    // observable in captured requests (fake-chunk finals would bypass HTTP).
    let (captured_a, hits_a) = fresh_capture();
    let (captured_b, hits_b) = fresh_capture();
    let (addr_a, handle_a) =
        spawn_openai_mock(captured_a.clone(), hits_a.clone(), "mock-answer-a").await;
    let (addr_b, handle_b) =
        spawn_openai_mock(captured_b.clone(), hits_b.clone(), "mock-answer-b").await;

    let config = || {
        ConfigSource::new(true, 3600, "prompt".to_string(), "http://127.0.0.1:1".to_string())
    };
    let mut map_a = HashMap::new();
    map_a.insert(
        "default".to_string(),
        mock_openai_provider(&format!("http://{addr_a}/v1")),
    );
    let deps_a = GenerationDeps::new(
        map_a,
        "default".to_string(),
        true,
        false,
        Some("router-a-brave-key".to_string()),
    )
    .with_fake_tool_query("weather-a-query".to_string())
    .with_fake_brave_results("router-a-brave-RESULT".to_string());
    let mut map_b = HashMap::new();
    map_b.insert(
        "default".to_string(),
        mock_openai_provider(&format!("http://{addr_b}/v1")),
    );
    let deps_b = GenerationDeps::new(map_b, "default".to_string(), true, false, None);

    let router_a = owned_router(config(), deps_a, "fake-secret-a", None, None);
    let router_b = owned_router(config(), deps_b, "fake-secret-b", None, None);

    let (_, cookies_a, html_a) = get_home(&router_a.app).await;
    let (_, cookies_b, html_b) = get_home(&router_b.app).await;
    let (cookie_a, csrf_a) = (session_cookie(&cookies_a), csrf_from_home(&html_a));
    let (cookie_b, csrf_b) = (session_cookie(&cookies_b), csrf_from_home(&html_b));

    let (status_a, body_a) = post_chat(
        &router_a.app,
        &cookie_a,
        &csrf_a,
        json!({"message": "Weather?", "set_name": "default", "web_search": true}),
    )
    .await;
    let (status_b, body_b) = post_chat(
        &router_b.app,
        &cookie_b,
        &csrf_b,
        json!({"message": "Weather?", "set_name": "default", "web_search": true}),
    )
    .await;

    let payloads_a = captured_a.lock().await.clone();
    let payloads_b = captured_b.lock().await.clone();
    handle_a.abort();
    handle_b.abort();
    clear_owned_env();

    assert_eq!(status_a, StatusCode::OK);
    assert_eq!(status_b, StatusCode::OK);
    assert!(
        body_a.contains("<think>Searching for: weather-a-query...</think>")
            && body_a.contains("mock-answer-a"),
        "router A must run explicit search then mock answer, got: {body_a}"
    );
    assert!(
        !body_a.contains("env-decoy-query") && !body_a.contains("env-decoy-results"),
        "poisoned search env must not leak into A: {body_a}"
    );
    let last_a = payloads_a.last().expect("router A final payload");
    let last_a_str = serde_json::to_string(last_a).expect("serialize A");
    assert!(
        last_a_str.contains("router-a-brave-RESULT"),
        "captured final request must carry explicit brave results, got: {last_a_str}"
    );
    assert!(
        !last_a_str.contains("env-decoy-results"),
        "captured request must not carry decoy results: {last_a_str}"
    );
    assert!(
        !body_b.contains("<think>Searching"),
        "keyless router must fall back to direct streaming, got: {body_b}"
    );
    assert!(
        body_b.contains("mock-answer-b"),
        "keyless router must still stream its mock answer, got: {body_b}"
    );
    let last_b = payloads_b.last().expect("router B payload");
    let last_b_str = serde_json::to_string(last_b).expect("serialize B");
    assert!(
        !last_b_str.contains("router-a-brave-RESULT")
            && !last_b_str.contains("env-decoy-results"),
        "router B request must carry no search results: {last_b_str}"
    );
    assert_eq!(chatbot_server::test_instrumentation::take_error_count(), 0);
}

#[tokio::test]
async fn two_routers_isolate_xai_key_via_captured_auth() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap_or_else(|p| p.into_inner());
    env::set_var("SECRET_KEY", "request_config_isolation_secret");
    let _workspace = common::TestWorkspace::with_openai_provider();
    clear_owned_env();
    env::set_var("RATE_LIMIT_PER_USER_PER_MINUTE", "0");
    env::set_var("RATE_LIMIT_GLOBAL_PER_MINUTE", "0");
    chatbot_core::config::reset();
    chatbot_core::rate_limit::reset();
    poison_fake_env();

    let captured_a = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let captured_b = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let (hits_a, hits_b) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
    let (addr_a, handle_a) =
        spawn_xai_mock(captured_a.clone(), hits_a.clone(), "xai-answer-a").await;
    let (addr_b, handle_b) =
        spawn_xai_mock(captured_b.clone(), hits_b.clone(), "xai-answer-b").await;

    let config = || {
        ConfigSource::new(true, 3600, "prompt".to_string(), "http://127.0.0.1:1".to_string())
    };
    let mut map_a = HashMap::new();
    map_a.insert(
        "default".to_string(),
        mock_xai_provider(&format!("http://{addr_a}")),
    );
    let deps_a = GenerationDeps::new(map_a, "default".to_string(), true, false, None)
        .with_fake_xai_key("xai-key-A-explicit".to_string());
    let mut map_b = HashMap::new();
    map_b.insert(
        "default".to_string(),
        mock_xai_provider(&format!("http://{addr_b}")),
    );
    let deps_b = GenerationDeps::new(map_b, "default".to_string(), true, false, None)
        .with_fake_xai_key("xai-key-B-explicit".to_string());

    let router_a = owned_router(config(), deps_a, "xai-secret-a", None, None);
    let router_b = owned_router(config(), deps_b, "xai-secret-b", None, None);

    let (_, cookies_a, html_a) = get_home(&router_a.app).await;
    let (_, cookies_b, html_b) = get_home(&router_b.app).await;
    let (cookie_a, csrf_a) = (session_cookie(&cookies_a), csrf_from_home(&html_a));
    let (cookie_b, csrf_b) = (session_cookie(&cookies_b), csrf_from_home(&html_b));

    let (status_a, body_a) = post_chat(
        &router_a.app,
        &cookie_a,
        &csrf_a,
        json!({"message": "Hello", "set_name": "default"}),
    )
    .await;
    let (status_b, body_b) = post_chat(
        &router_b.app,
        &cookie_b,
        &csrf_b,
        json!({"message": "Hello", "set_name": "default"}),
    )
    .await;

    let auths_a = captured_a.lock().await.clone();
    let auths_b = captured_b.lock().await.clone();
    handle_a.abort();
    handle_b.abort();
    clear_owned_env();

    assert_eq!(status_a, StatusCode::OK);
    assert_eq!(status_b, StatusCode::OK);
    assert!(
        body_a.contains("xai-answer-a") && !body_a.contains("xai-answer-b"),
        "router A must stream its own mock, got: {body_a}"
    );
    assert!(
        body_b.contains("xai-answer-b") && !body_b.contains("xai-answer-a"),
        "router B must stream its own mock, got: {body_b}"
    );
    assert_eq!(
        auths_a.last().map(String::as_str),
        Some("Bearer xai-key-A-explicit")
    );
    assert_eq!(
        auths_b.last().map(String::as_str),
        Some("Bearer xai-key-B-explicit")
    );
    assert!(
        !auths_a.iter().any(|a| a.contains("env-decoy-xai-key"))
            && !auths_b.iter().any(|a| a.contains("env-decoy-xai-key")),
        "poisoned XAI key must not leak: {auths_a:?} / {auths_b:?}"
    );
    assert_eq!(chatbot_server::test_instrumentation::take_error_count(), 0);
}

#[tokio::test]
async fn two_routers_isolate_voice_endpoint_for_deep_health() {
    common::init_tracing();
    let _guard = test_mutex().lock().unwrap_or_else(|p| p.into_inner());
    env::set_var("SECRET_KEY", "request_config_isolation_secret");
    let _workspace = common::TestWorkspace::with_openai_provider();
    clear_owned_env();
    env::set_var("RATE_LIMIT_PER_USER_PER_MINUTE", "0");
    env::set_var("RATE_LIMIT_GLOBAL_PER_MINUTE", "0");
    chatbot_core::config::reset();
    chatbot_core::rate_limit::reset();
    poison_fake_env();

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock voice");
    let addr = listener.local_addr().expect("voice addr");
    let voice_app = axum::Router::new().route(
        "/health",
        axum::routing::get(|| async { (StatusCode::OK, "ok") }),
    );
    let handle = tokio::spawn(async move {
        axum::serve(listener, voice_app).await.expect("serve voice");
    });

    let config_a = ConfigSource::new(
        true,
        3600,
        "prompt".to_string(),
        format!("http://{addr}"),
    );
    let config_b = ConfigSource::new(
        true,
        3600,
        "prompt".to_string(),
        "http://127.0.0.1:1".to_string(),
    );
    let deps = || {
        deps_from_entries(
            vec![test_provider_with_chunks("default", &["voice-marker"])],
            "default",
        )
    };
    let router_a = owned_router(config_a, deps(), "voice-secret-a", None, None);
    let router_b = owned_router(config_b, deps(), "voice-secret-b", None, None);

    async fn deep_health(app: &Router) -> (StatusCode, Value) {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/health?deep=true")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("deep health");
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .expect("health body");
        let json: Value = serde_json::from_slice(&body).expect("health json");
        (status, json)
    }

    let (status_a, body_a) = deep_health(&router_a.app).await;
    let (status_b, body_b) = deep_health(&router_b.app).await;
    handle.abort();
    clear_owned_env();

    assert_eq!(status_a, StatusCode::OK);
    assert_eq!(body_a["status"], json!("healthy"));
    assert_eq!(status_b, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body_b["status"], json!("degraded"));
    assert_eq!(chatbot_server::test_instrumentation::take_error_count(), 0);
}
