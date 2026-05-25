use std::{collections::HashMap, sync::OnceLock};

use axum::{
    body::{self, Body},
    http::{header, HeaderValue, Request, Response, StatusCode},
};
use base64::{engine::general_purpose::STANDARD, Engine};
use bcrypt::hash;
use chatbot_core::{
    config,
    user_store::{normalise_username, CreateOutcome, UserStore, UserStoreError, BCRYPT_COST, SALT_LEN},
};
use minijinja::{context, AutoEscape, Environment};
use serde_json::json;
use serde_urlencoded::from_bytes;
use tracing::error;

use crate::home::SECURITY_CSP;

pub async fn handle_signup_get(
    _request: Request<Body>,
) -> Result<Response<Body>, (StatusCode, String)> {
    let config = config::app_config();
    let sri = config.cdn_sri.clone();

    let html = render_signup_template(&sri).map_err(|err| {
        error!(?err, "failed to render signup template");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "template error".to_string(),
        )
    })?;

    build_signup_response(html)
}

pub async fn handle_signup_post(
    request: Request<Body>,
) -> Result<Response<Body>, (StatusCode, String)> {
    let (parts, body) = request.into_parts();
    let headers = parts.headers;

    let body_bytes = body::to_bytes(body, 64 * 1024).await.map_err(|err| {
        error!(?err, "failed to read signup body");
        (StatusCode::BAD_REQUEST, "Invalid request body".to_string())
    })?;

    let form: HashMap<String, String> = from_bytes(&body_bytes).map_err(|err| {
        error!(?err, "failed to parse signup form");
        (StatusCode::BAD_REQUEST, "Invalid form payload".to_string())
    })?;

    let username_raw = form.get("username").map(|s| s.trim()).unwrap_or("");
    let auth_token = form.get("auth_token").map(|s| s.trim()).unwrap_or("");
    let auth_salt = form.get("auth_salt").map(|s| s.trim()).unwrap_or("");
    let enc_salt = form.get("enc_salt").map(|s| s.trim()).unwrap_or("");
    let plaintext_password = form.get("password").map(|s| s.as_str()).unwrap_or("");

    if username_raw.is_empty() || auth_token.is_empty() || auth_salt.is_empty() || enc_salt.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "Username and derived credentials are required.".to_string(),
        ));
    }

    if !plaintext_password.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "Plaintext password signup is no longer supported.".to_string(),
        ));
    }

    let username = match normalise_username(username_raw) {
        Ok(value) => value,
        Err(message) => {
            return Err((StatusCode::BAD_REQUEST, message));
        }
    };

    let hashed = hash(auth_token, BCRYPT_COST).map_err(|err| {
        error!(?err, "failed to hash password");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Unable to create user".to_string(),
        )
    })?;
    let auth_salt = decode_salt(auth_salt)?;
    let enc_salt = decode_salt(enc_salt)?;

    let mut store = UserStore::new().map_err(map_store_error)?;

    match store.create_user(&username, &hashed, &auth_salt, &enc_salt) {
        Ok(CreateOutcome::Created) => {
            let ip = crate::chat_utils::get_ip(&headers, &parts.extensions);
            tracing::info!(username = %username, ip = %ip, "User created");
        }
        Ok(CreateOutcome::AlreadyExists) => {
            return Err((StatusCode::BAD_REQUEST, "User already exists.".to_string()));
        }
        Err(err) => {
            error!(?err, "failed to persist new user");
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                "Unable to create user".to_string(),
            ));
        }
    }

    json_response(StatusCode::CREATED, json!({ "status": "success" }))
}

fn map_store_error(err: UserStoreError) -> (StatusCode, String) {
    error!(?err, "user store error");
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        "Unable to create user".to_string(),
    )
}

fn render_signup_template(sri: &HashMap<String, String>) -> Result<String, minijinja::Error> {
    let env = template_env();
    let template = env.get_template("signup.html")?;
    template.render(context! { sri => sri })
}

fn build_signup_response(body: String) -> Result<Response<Body>, (StatusCode, String)> {
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
        error!(?err, "failed to build signup response");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "response build error".to_string(),
        )
    })
}

fn decode_salt(encoded: &str) -> Result<[u8; SALT_LEN], (StatusCode, String)> {
    let decoded = STANDARD.decode(encoded).map_err(|err| {
        error!(?err, "failed to decode signup salt");
        (StatusCode::BAD_REQUEST, "Invalid signup salt".to_string())
    })?;
    decoded.try_into().map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            "Invalid signup salt length".to_string(),
        )
    })
}

fn json_response(
    status: StatusCode,
    payload: serde_json::Value,
) -> Result<Response<Body>, (StatusCode, String)> {
    let body = serde_json::to_vec(&payload).map_err(|err| {
        error!(?err, "failed to serialize signup payload");
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
            error!(?err, "failed to build signup JSON response");
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
            "signup.html",
            include_str!("../../static/templates/signup.html"),
        )
        .expect("signup.html template");
        env
    })
}
