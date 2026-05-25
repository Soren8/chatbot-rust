use axum::{
    body::to_bytes,
    body::Body,
    http::{header, Method, Request, StatusCode},
    Router,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use bcrypt::hash;
use chatbot_core::{
    config,
    persistence::DataPersistence,
    user_store::{normalise_username, BCRYPT_COST, SALT_LEN, UserStore},
};
use regex::Regex;
use serde_json::{json, Value};
use std::{
    env, fs,
    path::{Path, PathBuf},
    sync::Once,
};
use tempfile::TempDir;
use tower::ServiceExt;
use tracing_subscriber::EnvFilter;

static TRACING_INIT: Once = Once::new();

/// Initialise tracing once for tests; additional calls become no-ops.
pub fn init_tracing() {
    TRACING_INIT.call_once(|| {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(EnvFilter::from_default_env())
            .with_test_writer()
            .try_init();
    });
}

pub fn extract_csrf_token(html: &str) -> Option<String> {
    let hidden_input = Regex::new(r#"name="csrf_token" value="([^"]+)""#).unwrap();
    if let Some(token) = hidden_input
        .captures(html)
        .and_then(|caps| caps.get(1).map(|m| m.as_str().to_owned()))
    {
        return Some(token);
    }

    let meta_tag = Regex::new(r#"<meta name=\"csrf-token\" content=\"([^\"]+)\""#).unwrap();
    meta_tag
        .captures(html)
        .and_then(|caps| caps.get(1).map(|m| m.as_str().to_owned()))
}

pub fn extract_cookie(set_cookie: &str) -> String {
    set_cookie
        .split(';')
        .next()
        .unwrap_or(set_cookie)
        .trim()
        .to_owned()
}

pub fn auth_header(auth_token: &str) -> String {
    format!("Bearer {auth_token}")
}

pub fn fixed_client_salt() -> [u8; SALT_LEN] {
    [0x11; SALT_LEN]
}

pub fn fixed_auth_salt() -> [u8; SALT_LEN] {
    fixed_client_salt()
}

pub fn fixed_enc_salt() -> [u8; SALT_LEN] {
    fixed_client_salt()
}

pub fn fixed_client_salt_b64() -> String {
    STANDARD.encode(fixed_client_salt())
}

pub fn fixed_auth_salt_b64() -> String {
    fixed_client_salt_b64()
}

pub fn fixed_enc_salt_b64() -> String {
    fixed_client_salt_b64()
}

pub fn fixed_enc_key_b64() -> String {
    STANDARD.encode([0x33; 32])
}

pub fn seed_user(username: &str, auth_token: &str) {
    seed_user_with_profile(username, auth_token, "free", None, None, true, false);
}

pub fn seed_user_with_profile(
    username: &str,
    auth_token: &str,
    tier: &str,
    last_set: Option<&str>,
    last_model: Option<&str>,
    render_markdown: bool,
    autoplay_tts: bool,
) {
    let store = UserStore::new().expect("open user store");
    let base_dir = store.data_dir().clone();
    let users_path = base_dir.join("users.json");
    let salts_dir = base_dir.join("salts");
    fs::create_dir_all(&salts_dir).expect("create salts dir");

    let normalised = normalise_username(username).expect("normalise username");
    let hashed = hash(auth_token, BCRYPT_COST).expect("hash password");

    let mut users = if users_path.exists() {
        let raw = fs::read_to_string(&users_path).expect("read users.json");
        serde_json::from_str::<Value>(&raw).unwrap_or_else(|_| json!({}))
    } else {
        json!({})
    };

    users[normalised.clone()] = json!({
        "password": hashed,
        "tier": tier,
        "last_set": last_set,
        "last_model": last_model,
        "render_markdown": render_markdown,
        "autoplay_tts": autoplay_tts
    });

    fs::write(
        &users_path,
        serde_json::to_vec_pretty(&users).expect("serialize users"),
    )
    .expect("write users.json");

    fs::write(
        salts_dir.join(format!("{normalised}_salt")),
        fixed_client_salt(),
    )
    .expect("write salt");
}

pub fn derive_storage_key(username: &str, password: &str) -> String {
    let store = UserStore::new().expect("open user store");
    let derived = store
        .derive_encryption_key(username, password)
        .expect("derive storage key");
    String::from_utf8(derived).expect("storage key utf8")
}

pub struct AuthedClient {
    auth_token: String,
    enc_key: String,
    username: String,
}

impl AuthedClient {
    pub async fn login(app: Router, username: &str, password: &str) -> Self {
        let storage_key = derive_storage_key(username, password);
        let salt_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri(format!("/auth/salt/{username}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("GET /auth/salt");

        assert_eq!(salt_response.status(), StatusCode::OK);
        let salt_body = to_bytes(salt_response.into_body(), 64 * 1024)
            .await
            .expect("read salt body");
        let salt_json: Value = serde_json::from_slice(&salt_body).expect("salt json");
        let auth_mode = salt_json
            .get("auth_mode")
            .and_then(|value| value.as_str())
            .unwrap_or("derived_token");

        let form_payload = if auth_mode == "legacy_password" {
            format!("username={username}&password={password}")
        } else {
            format!("username={username}&auth_token={storage_key}&enc_key={storage_key}")
        };

        let login_response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/login")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from(form_payload))
                    .unwrap(),
            )
            .await
            .expect("POST /login");

        assert_eq!(login_response.status(), StatusCode::OK);

        Self {
            auth_token: storage_key.clone(),
            enc_key: storage_key,
            username: username.to_string(),
        }
    }

    pub fn request(&self, method: Method, uri: &str) -> axum::http::request::Builder {
        Request::builder()
            .method(method)
            .uri(uri)
            .header(header::AUTHORIZATION, auth_header(&self.auth_token))
            .header("X-Auth-User", &self.username)
            .header("X-Enc-Key", &self.enc_key)
    }
}

pub struct TestWorkspace {
    temp_dir: TempDir,
    original_cwd: PathBuf,
    previous_host_data_dir: Option<String>,
}

impl TestWorkspace {
    pub fn with_openai_provider() -> Self {
        const CONFIG: &str = r#"
llms:
  - provider_name: "default"
    type: "openai"
    model_name: "gpt-test"
    base_url: "https://api.openai.com/v1"
    api_key: "test-key"
    context_size: 4096
"#;

        Self::with_config(CONFIG)
    }

    pub fn with_config(config: &str) -> Self {
        let original_cwd = env::current_dir().expect("missing current dir");
        let temp_dir = TempDir::new().expect("tempdir");

        let config_path = temp_dir.path().join(".config.yml");
        fs::write(&config_path, config).expect("write config");

        env::set_current_dir(temp_dir.path()).expect("set current dir");
        let previous_host_data_dir = env::var("HOST_DATA_DIR").ok();
        env::set_var("HOST_DATA_DIR", temp_dir.path());

        config::reset();

        // Initialise core data directories so tests can assume they exist.
        UserStore::new().expect("initialise user store");
        DataPersistence::new().expect("initialise data persistence");

        Self {
            temp_dir,
            original_cwd,
            previous_host_data_dir,
        }
    }

    pub fn path(&self) -> &Path {
        self.temp_dir.path()
    }
}

impl Drop for TestWorkspace {
    fn drop(&mut self) {
        let _ = env::set_current_dir(&self.original_cwd);
        if let Some(previous) = &self.previous_host_data_dir {
            env::set_var("HOST_DATA_DIR", previous);
        } else {
            env::remove_var("HOST_DATA_DIR");
        }
    }
}
