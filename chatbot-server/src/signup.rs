use std::{collections::HashMap, sync::OnceLock};

use axum::{
    body::{self, Body},
    http::{header, HeaderValue, Request, Response, StatusCode},
};
use bcrypt::{hash, DEFAULT_COST};
use chatbot_core::{
    config, session,
    user_store::{normalise_username, CreateOutcome, UserStore},
};
use minijinja::{context, AutoEscape, Environment};
use serde_urlencoded::from_bytes;
use tracing::warn;

use crate::home::SECURITY_CSP;
use crate::http_error::{
    api_error, log_and_api_error, map_body_read_err, map_form_parse_err, map_response_build_err,
    map_session_err, map_user_store_err, HttpError,
};

pub async fn handle_signup_get(
    request: Request<Body>,
) -> Result<Response<Body>, HttpError> {
    let cookie_header = request
        .headers()
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.to_owned());

    let bootstrap = session::prepare_home_context(cookie_header.as_deref())
        .map_err(|err| map_session_err(err, "signup::get"))?;

    let config = config::app_config();
    let sri = config.cdn_sri.clone();

    let csrf_token = bootstrap.csrf_token;
    let set_cookie = bootstrap.set_cookie;

    let html = render_signup_template(&csrf_token, &sri).map_err(|err| {
        log_and_api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "template error",
            "signup::get::render",
            err,
        )
    })?;

    build_signup_response(html, set_cookie)
}

pub async fn handle_signup_post(
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
        .map_err(|err| map_body_read_err(err, "signup::post"))?;

    let form: HashMap<String, String> =
        from_bytes(&body_bytes).map_err(|err| map_form_parse_err(err, "signup::post"))?;

    let username_raw = form.get("username").map(|s| s.trim()).unwrap_or("");
    let password = form.get("password").map(|s| s.as_str()).unwrap_or("");
    let csrf_token = form.get("csrf_token").map(|s| s.as_str());

    if username_raw.is_empty() || password.is_empty() {
        return Err(api_error(StatusCode::BAD_REQUEST, "Username and password required."));
    }

    let csrf_valid = session::validate_csrf_token(cookie_header.as_deref(), csrf_token)
        .map_err(|err| map_session_err(err, "signup::post::csrf"))?;

    if !csrf_valid {
        return Ok(Response::builder()
            .status(StatusCode::SEE_OTHER)
            .header(header::LOCATION, "/login")
            .body(Body::empty())
            .unwrap());
    }

    let username = match normalise_username(username_raw) {
        Ok(value) => value,
        Err(message) => {
            return Err(api_error(StatusCode::BAD_REQUEST, message));
        }
    };

    let hashed = hash(password, DEFAULT_COST).map_err(|err| {
        log_and_api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Unable to create user",
            "signup::post::hash",
            err,
        )
    })?;

    let mut store = UserStore::new().map_err(|err| {
        map_user_store_err(err, "signup::post", "Unable to create user")
    })?;

    match store.create_user(&username, &hashed) {
        Ok(CreateOutcome::Created) => {
            let ip = crate::chat_utils::get_ip(&headers, &parts.extensions);
            tracing::info!(username = %username, ip = %ip, "User created");
        }
        Ok(CreateOutcome::AlreadyExists) => {
            return Err(api_error(StatusCode::BAD_REQUEST, "User already exists."));
        }
        Err(err) => {
            return Err(map_user_store_err(err, "signup::post::create_user", "Unable to create user"));
        }
    }

    Response::builder()
        .status(StatusCode::FOUND)
        .header(header::LOCATION, HeaderValue::from_static("/login"))
        .body(Body::empty())
        .map_err(|err| map_response_build_err(err, "signup::post::redirect"))
}

fn render_signup_template(
    csrf_token: &str,
    sri: &HashMap<String, String>,
) -> Result<String, minijinja::Error> {
    let env = template_env();
    let template = env.get_template("signup.html")?;
    template.render(context! {
        csrf_token => csrf_token,
        sri => sri,
    })
}

fn build_signup_response(
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
        .map_err(|err| map_response_build_err(err, "signup::get::response"))
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
