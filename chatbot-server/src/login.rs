use std::{collections::HashMap, sync::OnceLock};

use axum::{
    body::{self, Body},
    extract::Path,
    http::{header, HeaderValue, Request, Response, StatusCode},
    Json,
};
use bcrypt::hash;
use chatbot_core::{
    config, session,
    user_store::{normalise_username, LoginMode, UserStore, UserStoreError, BCRYPT_COST},
};
use minijinja::{context, AutoEscape, Environment};
use serde_json::json;
use serde_urlencoded::from_bytes;
use tracing::error;

use crate::home::SECURITY_CSP;

const INVALID_CREDENTIALS: &str = "Invalid credentials";

pub async fn handle_get_salt(
    Path(username): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let store = UserStore::new().map_err(map_store_error)?;
    let salt = store.get_client_salt(&username).map_err(map_store_error)?;
    let auth_mode = match store.login_mode(&username).map_err(map_store_error)? {
        LoginMode::LegacyPassword => "legacy_password",
        LoginMode::DerivedToken => "derived_token",
    };
    Ok(Json(json!({
        "salt": salt,
        "auth_mode": auth_mode,
        // Compatibility aliases for the newer client-side draft.
        "auth_salt": salt,
        "enc_salt": salt,
    })))
}

pub async fn handle_login_get(
    _request: Request<Body>,
) -> Result<Response<Body>, (StatusCode, String)> {
    let config = config::app_config();
    let sri = config.cdn_sri.clone();

    let html = render_login_template(&sri).map_err(|err| {
        error!(?err, "failed to render login template");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "template error".to_string(),
        )
    })?;

    build_login_response(html)
}

pub async fn handle_login_post(
    request: Request<Body>,
) -> Result<Response<Body>, (StatusCode, String)> {
    let (parts, body) = request.into_parts();
    let headers = parts.headers;

    let body_bytes = body::to_bytes(body, 64 * 1024).await.map_err(|err| {
        error!(?err, "failed to read login body");
        (StatusCode::BAD_REQUEST, "Invalid request body".to_string())
    })?;

    let form: HashMap<String, String> = from_bytes(&body_bytes).map_err(|err| {
        error!(?err, "failed to parse login form");
        (StatusCode::BAD_REQUEST, "Invalid form payload".to_string())
    })?;

    let username_raw = form.get("username").map(|s| s.trim()).unwrap_or("");
    let auth_token = form.get("auth_token").map(|s| s.trim()).unwrap_or("");
    let enc_key = form.get("enc_key").map(|s| s.trim());
    let plaintext_password = form.get("password").map(|s| s.as_str()).unwrap_or("");

    if username_raw.is_empty() || (auth_token.is_empty() && plaintext_password.is_empty()) {
        return invalid_credentials();
    }

    let username = match normalise_username(username_raw) {
        Ok(value) => value,
        Err(_) => return invalid_credentials(),
    };

    let mut store = UserStore::new().map_err(map_store_error)?;

    let mut session_auth_token = String::new();
    let mut session_enc_key = enc_key
        .filter(|value| !value.is_empty())
        .map(|value| value.to_string());

    if !auth_token.is_empty() {
        let valid = store.validate_user(&username, auth_token).map_err(map_store_error)?;
        if valid {
            session_auth_token = auth_token.to_string();
            if session_enc_key.is_none() {
                session_enc_key = Some(auth_token.to_string());
            }
        }
    }

    if session_auth_token.is_empty() {
        let valid = store
            .validate_password(&username, plaintext_password)
            .map_err(map_store_error)?;
        if !valid {
            let ip = crate::chat_utils::get_ip(&headers, &parts.extensions);
            tracing::info!(username = %username, ip = %ip, "Login failed");
            return invalid_credentials();
        }

        let derived_key = store
            .derive_encryption_key(&username, plaintext_password)
            .map_err(map_store_error)?;
        let derived_token = String::from_utf8(derived_key).map_err(|err| {
            error!(?err, "derived auth token was not valid utf8");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Unable to log in".to_string(),
            )
        })?;
        let hashed_auth_token = hash(&derived_token, BCRYPT_COST).map_err(|err| {
            error!(?err, "failed to hash derived auth token");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Unable to log in".to_string(),
            )
        })?;
        store
            .ensure_auth_hash_from_password(&username, plaintext_password, &hashed_auth_token)
            .map_err(map_store_error)?;
        session_enc_key = Some(derived_token.clone());
        session_auth_token = derived_token;
    }

    session::cache_login(
        &username,
        &session_auth_token,
        session_enc_key
            .as_deref()
            .or(Some(session_auth_token.as_str())),
    )
    .map_err(|err| {
        error!(?err, "failed to cache login");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "session error".to_string(),
        )
    })?;

    let ip = crate::chat_utils::get_ip(&headers, &parts.extensions);
    tracing::info!(username = %username, ip = %ip, "Login successful");

    json_response(StatusCode::OK, json!({ "status": "success", "username": username }))
}

fn invalid_credentials() -> Result<Response<Body>, (StatusCode, String)> {
    Err((StatusCode::UNAUTHORIZED, INVALID_CREDENTIALS.to_string()))
}

fn map_store_error(err: UserStoreError) -> (StatusCode, String) {
    error!(?err, "user store error");
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        "Unable to log in".to_string(),
    )
}

fn render_login_template(sri: &HashMap<String, String>) -> Result<String, minijinja::Error> {
    let env = template_env();
    let template = env.get_template("login.html")?;
    template.render(context! { sri => sri })
}

fn build_login_response(body: String) -> Result<Response<Body>, (StatusCode, String)> {
    let builder = Response::builder()
        .status(StatusCode::OK)
        .header(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/html; charset=utf-8"),
        )
        .header("Content-Security-Policy", SECURITY_CSP)
        .header("X-Content-Type-Options", "nosniff")
        .header("Referrer-Policy", "no-referrer")
        .header("X-Frame-Options", "DENY");

    builder.body(Body::from(body)).map_err(|err| {
        error!(?err, "failed to build login response");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "response build error".to_string(),
        )
    })
}

fn json_response(
    status: StatusCode,
    payload: serde_json::Value,
) -> Result<Response<Body>, (StatusCode, String)> {
    let body = serde_json::to_vec(&payload).map_err(|err| {
        error!(?err, "failed to serialize login payload");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "response build error".to_string(),
        )
    })?;

    Response::builder()
        .status(status)
        .header(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        )
        .body(Body::from(body))
        .map_err(|err| {
            error!(?err, "failed to build login JSON response");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "response build error".to_string(),
            )
        })
}

fn template_env() -> &'static Environment<'static> {
    static ENV: OnceLock<Environment<'static>> = OnceLock::new();
    ENV.get_or_init(|| {
        let mut env = Environment::new();
        env.set_auto_escape_callback(|name| {
            if name.ends_with(".html") {
                AutoEscape::Html
            } else {
                AutoEscape::None
            }
        });
        env.add_template(
            "login.html",
            include_str!("../../static/templates/login.html"),
        )
        .expect("login.html template");
        env
    })
}