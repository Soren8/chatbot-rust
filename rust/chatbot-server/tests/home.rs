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

fn extract_app_data(body: &str) -> Value {
    const MARKER: &str = "<template id=\"app-data\" type=\"application/json\">";
    let start = body.find(MARKER).expect("app-data marker present");
    let json_start = start + MARKER.len();
    let end = body[json_start..]
        .find("</template>")
        .map(|rel| json_start + rel)
        .expect("closing template tag");
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
}
