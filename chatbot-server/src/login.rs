use std::{collections::HashMap, sync::OnceLock};

use axum::{
    body::{self, Body},
    http::{header, HeaderValue, Request, Response, StatusCode},
};
use chatbot_core::{
    config, session,
    user_store::{normalise_username, UserStore, UserStoreError},
};
use minijinja::{context, AutoEscape, Environment};
use serde_urlencoded::from_bytes;
use tracing::{error, warn};

use crate::home::SECURITY_CSP;

const INVALID_CREDENTIALS: &str = "Invalid credentials";

pub async fn handle_login_get(
    request: Request<Body>,
) -> Result<Response<Body>, (StatusCode, String)> {
    let cookie_header = request
        .headers()
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.to_owned());

    let bootstrap = session::prepare_home_context(cookie_header.as_deref()).map_err(|err| {
        error!(?err, "failed to bootstrap login context");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "session error".to_string(),
        )
    })?;

    let config = config::app_config();
    let sri = config.cdn_sri.clone();

    let html = render_login_template(&bootstrap.csrf_token, &sri).map_err(|err| {
        error!(?err, "failed to render login template");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "template error".to_string(),
        )
    })?;

    build_login_response(html, bootstrap.set_cookie)
}

pub async fn handle_login_post(
    request: Request<Body>,
) -> Result<Response<Body>, (StatusCode, String)> {
    let (parts, body) = request.into_parts();
    let headers = parts.headers;

    let cookie_header = headers
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .map(|s| s.to_owned());

    let body_bytes = body::to_bytes(body, 64 * 1024).await.map_err(|err| {
        error!(?err, "failed to read login body");
        (StatusCode::BAD_REQUEST, "Invalid request body".to_string())
    })?;

    let form: HashMap<String, String> = from_bytes(&body_bytes).map_err(|err| {
        error!(?err, "failed to parse login form");
        (StatusCode::BAD_REQUEST, "Invalid form payload".to_string())
    })?;

    let username_raw = form.get("username").map(|s| s.trim()).unwrap_or("");
    let password = form.get("password").map(|s| s.as_str()).unwrap_or("");
    let csrf_token = form.get("csrf_token").map(|s| s.as_str());

    if username_raw.is_empty() || password.is_empty() {
        return invalid_credentials();
    }

    let csrf_valid =
        session::validate_csrf_token(cookie_header.as_deref(), csrf_token).map_err(|err| {
            error!(?err, "failed to validate CSRF token");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "session error".to_string(),
            )
        })?;

    if !csrf_valid {
        return Ok(Response::builder()
            .status(StatusCode::SEE_OTHER)
            .header(header::LOCATION, "/login")
            .body(Body::empty())
            .unwrap());
    }

    let username = match normalise_username(username_raw) {
        Ok(value) => value,
        Err(_) => return invalid_credentials(),
    };

    let store = UserStore::new().map_err(map_store_error)?;

    let valid = store
        .validate_user(&username, password)
        .map_err(map_store_error)?;

    if !valid {
        return invalid_credentials();
    }

    let encryption_key = store
        .derive_encryption_key(&username, password)
        .map_err(map_store_error)?;

    let finalize = session::finalize_login(cookie_header.as_deref(), &username, &encryption_key)
        .map_err(|err| {
            error!(?err, "failed to finalize login");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "session error".to_string(),
            )
        })?;

    let mut response = Response::builder()
        .status(StatusCode::FOUND)
        .header(header::LOCATION, HeaderValue::from_static("/"));

    match HeaderValue::from_str(&finalize.set_cookie) {
        Ok(value) => {
            response = response.header(header::SET_COOKIE, value);
        }
        Err(err) => {
            error!(?err, "invalid Set-Cookie header from session finalize");
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                "session error".to_string(),
            ));
        }
    }

    response.body(Body::empty()).map_err(|err| {
        error!(?err, "failed to build login redirect response");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "response build error".to_string(),
        )
    })
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

fn render_login_template(
    csrf_token: &str,
    sri: &HashMap<String, String>,
) -> Result<String, minijinja::Error> {
    let env = template_env();
    let template = env.get_template("login.html")?;
    template.render(context! {
        csrf_token => csrf_token,
        sri => sri,
    })
}

fn build_login_response(
    body: String,
    set_cookie: String,
) -> Result<Response<Body>, (StatusCode, String)> {
    let mut builder = Response::builder()
        .status(StatusCode::OK)
        .header(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/html; charset=utf-8"),
        )
        .header("Content-Security-Policy", SECURITY_CSP)
        .header("X-Content-Type-Options", "nosniff")
        .header("Referrer-Policy", "no-referrer")
        .header("X-Frame-Options", "DENY");

    match HeaderValue::from_str(&set_cookie) {
        Ok(value) => {
            builder = builder.header(header::SET_COOKIE, value);
        }
        Err(err) => {
            warn!(
                ?err,
                "discarding invalid Set-Cookie header from session manager"
            );
        }
    }

    builder.body(Body::from(body)).map_err(|err| {
        error!(?err, "failed to build login response");
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
