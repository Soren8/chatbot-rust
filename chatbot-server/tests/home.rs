use std::{
    env,
    fs::File,
    io::Write,
    sync::{Mutex, OnceLock},
};

use axum::{
    body::{to_bytes, Body},
    http::{header, Method, Request, StatusCode},
};
use bcrypt::{hash, DEFAULT_COST};
use chatbot_server::{build_router, resolve_static_root};
use serde_json::{json, Value};
use tower::ServiceExt;

mod common;

const TEST_CONFIG: &str = r#"llms:
  - provider_name: "free-model"
    type: "openai"
    model_name: "free"
    tier: "free"
  - provider_name: "premium-model"
    type: "openai"
    model_name: "premium"
    tier: "premium"
default_system_prompt: "Test system prompt"
"#;

const MULTI_FREE_MODEL_CONFIG: &str = r#"llms:
  - provider_name: "free-model-a"
    type: "openai"
    model_name: "free-a"
    tier: "free"
  - provider_name: "free-model-b"
    type: "openai"
    model_name: "free-b"
    tier: "free"
default_system_prompt: "Test system prompt"
"#;

fn test_mutex() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

fn setup_workspace() -> common::TestWorkspace {
    env::set_var("SECRET_KEY", "integration_test_secret");
    common::TestWorkspace::with_config(TEST_CONFIG)
}

fn write_users_json(workspace: &common::TestWorkspace, payload: &Value) {
    let path = workspace.path().join("users.json");
    let mut file = File::create(&path).expect("create users.json");
    file.write_all(serde_json::to_vec_pretty(payload).unwrap().as_slice())
        .expect("write users.json");
}

fn build_app() -> axum::Router {
    let static_root = resolve_static_root();
    build_router(static_root)
}

fn assert_settings_has_system_prompt_and_memory(body: &str) {
    for marker in [
        r#"<h6 class="mb-0">System Prompt</h6>"#,
        r#"id="user-system-prompt""#,
        r#"id="save-system-prompt""#,
        r#"<h6 class="mb-0">Memory</h6>"#,
        r#"id="user-memory""#,
        r#"id="save-memory""#,
    ] {
        assert!(
            body.contains(marker),
            "settings panel must render System Prompt and Memory sections, missing: {marker}",
        );
    }
}

fn extract_app_data(body: &str) -> Value {
    const MARKER: &str = "<script id=\"app-data\" type=\"application/json\">";
    let start = body.find(MARKER).expect("app-data marker present");
    let json_start = start + MARKER.len();
    let end = body[json_start..]
        .find("</script>")
        .map(|rel| json_start + rel)
        .expect("closing script tag");
    let payload = body[json_start..end].trim();
    serde_json::from_str(payload).expect("app-data json")
}

#[tokio::test]
async fn home_route_guest_filters_premium_models() {
    let _guard = test_mutex().lock().unwrap();
    let _workspace = setup_workspace();

    let app = build_app();

    let response = app
        .clone()
        .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
        .await
        .expect("GET /");

    assert_eq!(response.status(), StatusCode::OK);
    let set_cookie = response.headers().get(header::SET_COOKIE);
    assert!(set_cookie.is_some(), "guest response sets session cookie");

    let body = to_bytes(response.into_body(), 512 * 1024)
        .await
        .expect("read body");
    let body = std::str::from_utf8(&body).expect("utf8 body");
    assert!(body.contains("data-logged-in=\"false\""));

    let app_data = extract_app_data(body);
    let models = app_data
        .get("availableModels")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    assert!(
        models
            .iter()
            .all(|entry| entry.get("tier").and_then(|v| v.as_str()) != Some("premium")),
        "guest view should not expose premium models",
    );
}

#[tokio::test]
async fn home_route_logged_in_premium_sees_premium_models() {
    let _guard = test_mutex().lock().unwrap();
    let workspace = setup_workspace();

    let password = "Sup3rS3cret!";
    let username = "premium-user";
    let hashed = hash(password, DEFAULT_COST).expect("hash password");
    let payload = json!({
        username: {
            "password": hashed,
            "tier": "premium"
        }
    });
    write_users_json(&workspace, &payload);

    let app = build_app();

    let login_get = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/login")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("GET /login");
    assert_eq!(login_get.status(), StatusCode::OK);
    let (login_parts, login_body) = login_get.into_parts();
    let set_cookie = login_parts
        .headers
        .get(header::SET_COOKIE)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
        .expect("session cookie");
    let body = to_bytes(login_body, 128 * 1024)
        .await
        .expect("read login page");
    let csrf = common::extract_csrf_token(std::str::from_utf8(&body).expect("utf8 body"))
        .expect("csrf token");

    let form = format!(
        "username={}&password={}&csrf_token={}",
        urlencoding::encode(username),
        urlencoding::encode(password),
        urlencoding::encode(&csrf),
    );

    let login_post = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/login")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::COOKIE, common::extract_cookie(&set_cookie))
                .body(Body::from(form))
                .unwrap(),
        )
        .await
        .expect("POST /login");
    assert_eq!(login_post.status(), StatusCode::FOUND);
    let login_cookie = login_post
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
        .expect("set-cookie after login");
    let cookie_header = common::extract_cookie(&login_cookie);

    let home_response = app
        .oneshot(
            Request::builder()
                .uri("/")
                .header(header::COOKIE, &cookie_header)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("GET / with auth");

    assert_eq!(home_response.status(), StatusCode::OK);
    let body = to_bytes(home_response.into_body(), 512 * 1024)
        .await
        .expect("read home body");
    let body = std::str::from_utf8(&body).expect("utf8 body");
    assert!(body.contains("data-logged-in=\"true\""));

    let app_data = extract_app_data(body);
    let models = app_data
        .get("availableModels")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    assert!(
        models
            .iter()
            .any(|entry| entry.get("tier").and_then(|v| v.as_str()) == Some("premium")),
        "premium view should include premium models",
    );
    assert!(
        body.contains(r#"<select id="modelSelect""#),
        "logged-in users should see the model picker",
    );
}

#[tokio::test]
async fn home_route_guest_with_multiple_free_models_shows_model_picker() {
    let _guard = test_mutex().lock().unwrap();
    let _workspace = common::TestWorkspace::with_config(MULTI_FREE_MODEL_CONFIG);

    let app = build_app();

    let response = app
        .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
        .await
        .expect("GET /");

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 512 * 1024)
        .await
        .expect("read body");
    let body = std::str::from_utf8(&body).expect("utf8 body");
    assert!(body.contains("data-logged-in=\"false\""));
    assert!(
        body.contains(r#"<select id="modelSelect""#),
        "guest with more than one free model should see the model picker",
    );
    assert!(body.contains(r#"value="free-model-a""#));
    assert!(body.contains(r#"value="free-model-b""#));
    assert!(
        !body.contains(r#"id="set-selector""#),
        "guest should not see set controls",
    );
}

#[tokio::test]
async fn home_route_guest_with_single_free_model_hides_model_picker() {
    let _guard = test_mutex().lock().unwrap();
    let _workspace = setup_workspace();

    let app = build_app();

    let response = app
        .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
        .await
        .expect("GET /");

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 512 * 1024)
        .await
        .expect("read body");
    let body = std::str::from_utf8(&body).expect("utf8 body");
    assert!(body.contains("data-logged-in=\"false\""));
    assert!(
        !body.contains(r#"id="modelSelect""#),
        "guest with a single free model should not see a model picker",
    );
}

#[tokio::test]
async fn home_route_logged_in_free_user_sees_model_picker_with_single_free_model() {
    let _guard = test_mutex().lock().unwrap();
    let workspace = setup_workspace();

    let password = "Sup3rS3cret!";
    let username = "free-user";
    let hashed = hash(password, DEFAULT_COST).expect("hash password");
    let payload = json!({
        username: {
            "password": hashed,
            "tier": "free"
        }
    });
    write_users_json(&workspace, &payload);

    let app = build_app();

    let login_get = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/login")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("GET /login");
    assert_eq!(login_get.status(), StatusCode::OK);
    let (login_parts, login_body) = login_get.into_parts();
    let set_cookie = login_parts
        .headers
        .get(header::SET_COOKIE)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
        .expect("session cookie");
    let body = to_bytes(login_body, 128 * 1024)
        .await
        .expect("read login page");
    let csrf = common::extract_csrf_token(std::str::from_utf8(&body).expect("utf8 body"))
        .expect("csrf token");

    let form = format!(
        "username={}&password={}&csrf_token={}",
        urlencoding::encode(username),
        urlencoding::encode(password),
        urlencoding::encode(&csrf),
    );

    let login_post = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/login")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::COOKIE, common::extract_cookie(&set_cookie))
                .body(Body::from(form))
                .unwrap(),
        )
        .await
        .expect("POST /login");
    assert_eq!(login_post.status(), StatusCode::FOUND);
    let login_cookie = login_post
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
        .expect("set-cookie after login");

    let home_response = app
        .oneshot(
            Request::builder()
                .uri("/")
                .header(header::COOKIE, common::extract_cookie(&login_cookie))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("GET / with auth");

    assert_eq!(home_response.status(), StatusCode::OK);
    let body = to_bytes(home_response.into_body(), 512 * 1024)
        .await
        .expect("read home body");
    let body = std::str::from_utf8(&body).expect("utf8 body");
    assert!(body.contains("data-logged-in=\"true\""));
    assert!(
        body.contains(r#"<select id="modelSelect""#),
        "logged-in free users should always see the model picker",
    );
    assert!(
        body.contains(r#"value="free-model""#),
        "logged-in free user should see the free model option",
    );
    assert!(
        !body.contains(r#"value="premium-model""#),
        "logged-in free user should not see premium options",
    );
}

#[tokio::test]
async fn home_route_guest_settings_has_system_prompt_and_memory() {
    let _guard = test_mutex().lock().unwrap();
    let _workspace = setup_workspace();
    let app = build_app();

    let response = app
        .clone()
        .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
        .await
        .expect("GET /");

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 512 * 1024)
        .await
        .expect("read body");
    let body = std::str::from_utf8(&body).expect("utf8 body");
    assert!(body.contains("data-logged-in=\"false\""));
    assert_settings_has_system_prompt_and_memory(body);
}

#[tokio::test]
async fn home_route_logged_in_settings_has_system_prompt_memory_and_connections() {
    let _guard = test_mutex().lock().unwrap();
    let workspace = setup_workspace();

    let password = "Sup3rS3cret!";
    let username = "settings-user";
    let hashed = hash(password, DEFAULT_COST).expect("hash password");
    let payload = json!({
        username: {
            "password": hashed,
            "tier": "free"
        }
    });
    write_users_json(&workspace, &payload);

    let app = build_app();

    let login_get = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/login")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("GET /login");
    assert_eq!(login_get.status(), StatusCode::OK);
    let (login_parts, login_body) = login_get.into_parts();
    let set_cookie = login_parts
        .headers
        .get(header::SET_COOKIE)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
        .expect("session cookie");
    let body = to_bytes(login_body, 128 * 1024)
        .await
        .expect("read login page");
    let csrf = common::extract_csrf_token(std::str::from_utf8(&body).expect("utf8 body"))
        .expect("csrf token");

    let form = format!(
        "username={}&password={}&csrf_token={}",
        urlencoding::encode(username),
        urlencoding::encode(password),
        urlencoding::encode(&csrf),
    );

    let login_post = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/login")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::COOKIE, common::extract_cookie(&set_cookie))
                .body(Body::from(form))
                .unwrap(),
        )
        .await
        .expect("POST /login");
    assert_eq!(login_post.status(), StatusCode::FOUND);
    let login_cookie = login_post
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
        .expect("set-cookie after login");

    let home_response = app
        .oneshot(
            Request::builder()
                .uri("/")
                .header(header::COOKIE, common::extract_cookie(&login_cookie))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("GET / with auth");

    assert_eq!(home_response.status(), StatusCode::OK);
    let body = to_bytes(home_response.into_body(), 512 * 1024)
        .await
        .expect("read home body");
    let body = std::str::from_utf8(&body).expect("utf8 body");
    assert!(body.contains("data-logged-in=\"true\""));
    assert_settings_has_system_prompt_and_memory(body);
    assert!(
        !body.contains(r#"id="connections-settings""#),
        "disabled Connections section must not render for logged-in users",
    );
}

/// Extract the declaration block for an exact CSS selector (first occurrence).
/// `selector` must include its opening brace, e.g. `".settings-cards {"`;
/// the returned slice is the declarations up to the closing brace.
fn css_rule_block<'a>(css: &'a str, selector_with_brace: &str) -> &'a str {
    let start = css.find(selector_with_brace).unwrap_or_else(|| {
        panic!("style.css must contain selector `{selector_with_brace}`")
    });
    let body = &css[start + selector_with_brace.len()..];
    let close = body.find('}').unwrap_or_else(|| {
        panic!("selector `{selector_with_brace}` must close its block")
    });
    &body[..close]
}

/// Logged-in desktop regression: the md+ flex rules for `.settings-cards`
/// must not let the System Prompt / Memory cards (or their textareas) shrink
/// to zero height. With the Encryption + Connections siblings present the
/// panel overflows its 100% height, and `flex: 1 1 ...` + `min-height: 0`
/// collapsed both cards to ~14px slivers: present in the DOM, invisible in
/// the UI. The cards keep `flex-grow` for the short-content stretch layout
/// but must never shrink below a usable height.
#[test]
fn settings_cards_cannot_collapse_to_zero_on_desktop() {
    const CSS: &str = include_str!("../../static/style.css");

    let container = css_rule_block(CSS, ".settings-cards {");
    assert!(
        !container.contains("flex: 1 1"),
        "settings-cards container must not shrink (flex-shrink collapses it to 0px when logged in), got: {{{container}}}",
    );

    let card = css_rule_block(CSS, ".settings-cards .card {");
    assert!(
        !card.contains("flex: 1 1"),
        "settings cards must not shrink below their content when the panel overflows, got: {{{card}}}",
    );
    assert!(
        !card.contains("min-height: 0"),
        "settings cards need a usable minimum height so System Prompt / Memory stay visible, got: {{{card}}}",
    );

    let textarea = css_rule_block(CSS, ".settings-cards .card .card-body textarea {");
    assert!(
        !textarea.contains("min-height: 0"),
        "settings textareas need a usable minimum height instead of collapsing to a sliver, got: {{{textarea}}}",
    );
}
