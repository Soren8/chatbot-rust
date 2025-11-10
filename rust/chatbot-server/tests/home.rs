use std::{env, fs::File, io::Write, path::PathBuf, sync::OnceLock};

use axum::{
    body::{to_bytes, Body},
    http::{header, Request, StatusCode},
};
use bcrypt::{hash, DEFAULT_COST};
use chatbot_core::{bridge, config};
use chatbot_server::{build_router, resolve_static_root};
use serde_json::{json, Value};
use tower::ServiceExt;

mod common;

struct TestEnv {
    data_dir: tempfile::TempDir,
}

fn ensure_env() -> PathBuf {
    static TEST_ENV: OnceLock<TestEnv> = OnceLock::new();

    let env_state = TEST_ENV.get_or_init(|| {
        common::ensure_pythonpath();
        common::init_tracing();
        env::set_var("SECRET_KEY", "test_secret_key");

        let dir = tempfile::TempDir::new().expect("temp data dir");
        env::set_var("HOST_DATA_DIR", dir.path());

        let config = r#"llms:
  - provider_name: "free-model"
    type: "stub"
    model_name: "free"
    tier: "free"
  - provider_name: "premium-model"
    type: "stub"
    model_name: "premium"
    tier: "premium"
default_system_prompt: "Test system prompt"
"#;
        std::fs::write(dir.path().join(".config.yml"), config).expect("write config");
        env::set_current_dir(dir.path()).expect("chdir test config dir");
        config::reset();

        env::set_var("SECRET_KEY", "test_secret_key");
        common::configure_python_env(dir.path());

        TestEnv { data_dir: dir }
    });

    env_state.data_dir.path().to_path_buf()
}

fn build_app() -> axum::Router {
    ensure_env();
    bridge::initialize_python().expect("python init");
    let static_root = resolve_static_root();
    build_router(static_root)
}

fn extract_app_data(body: &str) -> Value {
    const MARKER: &str = "<template id=\"app-data\" type=\"application/json\">";
    let start = body.find(MARKER).expect("app-data marker present");
    let json_start = start + MARKER.len();
    let end = body[json_start..]
        .find("</template>")
        .map(|relative| json_start + relative)
        .expect("closing template tag");
    let payload = body[json_start..end].trim();
    serde_json::from_str(payload).expect("app-data json")
}

#[tokio::test]
async fn home_route_guest_filters_premium_models() {
    if !common::ensure_flask_available() {
        eprintln!("skipping home_route_guest_filters_premium_models: flask not available");
        return;
    }
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
    if !common::ensure_flask_available() {
        eprintln!("skipping home_route_logged_in_premium_sees_premium_models: flask not available");
        return;
    }
    let data_dir = ensure_env();
    let users_file = data_dir.join("users.json");

    let password = "Sup3rS3cret!";
    let username = "premium-user";
    let hashed = hash(password, DEFAULT_COST).expect("hash password");

    {
        let payload = json!({
            username: {
                "password": hashed,
                "tier": "premium"
            }
        });
        let mut file = File::create(&users_file).expect("users.json");
        file.write_all(serde_json::to_vec_pretty(&payload).unwrap().as_slice())
            .expect("write users");
    }

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

    let payload = format!(
        "username={}&password={}&csrf_token={}",
        urlencoding::encode(username),
        urlencoding::encode(password),
        urlencoding::encode(&csrf)
    );

    let login_post = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/login")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::COOKIE, common::extract_cookie(&set_cookie))
                .body(Body::from(payload))
                .unwrap(),
        )
        .await
        .expect("POST /login");
    assert_eq!(login_post.status(), StatusCode::FOUND);
    let session_cookie = login_post
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|value| value.to_str().ok())
        .map(common::extract_cookie)
        .expect("set-cookie on login");

    let response = app
        .oneshot(
            Request::builder()
                .uri("/")
                .header(header::COOKIE, &session_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("GET / after login");

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 512 * 1024)
        .await
        .expect("read home body");
    let body = std::str::from_utf8(&body).expect("utf8 body");
    assert!(body.contains("data-logged-in=\"true\""));
    assert!(body.contains("data-user-tier=\"premium\""));

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
        "premium users should see premium models",
    );
}
