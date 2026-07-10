use std::{collections::HashMap, sync::OnceLock};

use axum::{
    body::{self, Body},
    extract::Path,
    http::{header, HeaderValue, Request, Response, StatusCode},
    Json,
};
use chatbot_core::{
    config, session,
    user_store::{normalise_username, UserStore},
};
use minijinja::{context, AutoEscape, Environment};
use serde_json::json;
use serde_urlencoded::from_bytes;
use tracing::warn;

use crate::home::SECURITY_CSP;
use crate::http_error::{
    api_error, log_and_api_error, map_body_read_err, map_form_parse_err, map_response_build_err,
    map_session_err, map_user_store_err, HttpError,
};

const INVALID_CREDENTIALS: &str = "Invalid credentials";

pub async fn handle_get_salt(
    Path(username): Path<String>,
) -> Result<Json<serde_json::Value>, HttpError> {
    let store = UserStore::new().map_err(|err| {
        map_user_store_err(err, "login::get_salt", "Unable to log in")
    })?;
    let salt = store
        .get_client_salt(&username)
        .map_err(|err| map_user_store_err(err, "login::get_salt", "Unable to log in"))?;
    Ok(Json(json!({ "salt": salt })))
}

pub async fn handle_login_get(
    request: Request<Body>,
) -> Result<Response<Body>, HttpError> {
    let cookie_header = request
        .headers()
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.to_owned());

    let bootstrap = session::prepare_home_context(cookie_header.as_deref())
        .map_err(|err| map_session_err(err, "login::get"))?;

    let config = config::app_config();
    let sri = config.cdn_sri.clone();

    let html = render_login_template(&bootstrap.csrf_token, &sri).map_err(|err| {
        log_and_api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "template error",
            "login::get::render",
            err,
        )
    })?;

    build_login_response(html, bootstrap.set_cookie)
}

pub async fn handle_login_post(
    request: Request<Body>,
) -> Result<Response<Body>, HttpError> {
    let (parts, body) = request.into_parts();
    let headers = parts.headers;

    let cookie_header = headers
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .map(|s| s.to_owned());

    let body_bytes = body::to_bytes(body, 64 * 1024)
        .await
        .map_err(|err| map_body_read_err(err, "login::post"))?;

    let form: HashMap<String, String> =
        from_bytes(&body_bytes).map_err(|err| map_form_parse_err(err, "login::post"))?;

    let username_raw = form.get("username").map(|s| s.trim()).unwrap_or("");
    let password = form.get("password").map(|s| s.as_str()).unwrap_or("");
    let csrf_token = form.get("csrf_token").map(|s| s.as_str());
    let storage_key = form.get("storage_key").map(|s| s.trim());

    if username_raw.is_empty() || password.is_empty() {
        return invalid_credentials();
    }

    let csrf_valid = session::validate_csrf_token(cookie_header.as_deref(), csrf_token)
        .map_err(|err| map_session_err(err, "login::post::csrf"))?;

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

    let store = UserStore::new().map_err(|err| {
        map_user_store_err(err, "login::post", "Unable to log in")
    })?;

    let valid = store
        .validate_user(&username, password)
        .map_err(|err| map_user_store_err(err, "login::post", "Unable to log in"))?;

    if !valid {
        let ip = crate::chat_utils::get_ip(&headers, &parts.extensions);
        tracing::info!(username = %username, ip = %ip, "Login failed");
        return invalid_credentials();
    }

    let encryption_key = if let Some(key) = storage_key {
        if key.is_empty() {
            store
                .derive_encryption_key(&username, password)
                .map_err(|err| map_user_store_err(err, "login::post", "Unable to log in"))?
        } else {
            key.as_bytes().to_vec()
        }
    } else {
        store
            .derive_encryption_key(&username, password)
            .map_err(|err| map_user_store_err(err, "login::post", "Unable to log in"))?
    };

    store
        .ensure_key_verifier(&username, &encryption_key)
        .map_err(|err| map_user_store_err(err, "login::post", "Unable to log in"))?;

    let finalize = session::finalize_login(cookie_header.as_deref(), &username)
        .map_err(|err| map_session_err(err, "login::post::finalize"))?;

    let ip = crate::chat_utils::get_ip(&headers, &parts.extensions);
    tracing::info!(username = %username, ip = %ip, "Login successful");

    let mut response = Response::builder()
        .status(StatusCode::FOUND)
        .header(header::LOCATION, HeaderValue::from_static("/"));

    match HeaderValue::from_str(&finalize.set_cookie) {
        Ok(value) => {
            response = response.header(header::SET_COOKIE, value);
        }
        Err(err) => {
            return Err(log_and_api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "session error",
                "login::post::set_cookie",
                err,
            ));
        }
    }

    response
        .body(Body::empty())
        .map_err(|err| map_response_build_err(err, "login::post::redirect"))
}

fn invalid_credentials() -> Result<Response<Body>, HttpError> {
    Err(api_error(StatusCode::UNAUTHORIZED, INVALID_CREDENTIALS))
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
) -> Result<Response<Body>, HttpError> {
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

    builder
        .body(Body::from(body))
        .map_err(|err| map_response_build_err(err, "login::get::response"))
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