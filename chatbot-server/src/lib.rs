use axum::{
    body::Body,
    http::{HeaderName, HeaderValue, StatusCode},
    middleware::{self, Next},
    response::Response,
    routing::{get, post},
    Router,
};
use chatbot_core::{logging, session::ServiceResponse};
use std::{env, net::SocketAddr, path::PathBuf};
use tokio::net::TcpListener;
use tower_http::services::ServeDir;
use tracing::{error, info, warn};

mod background;
mod brave;
mod chat;
pub mod chat_utils;
mod health;
pub mod http_error;
mod home;
mod login;
mod logout;
mod memory;
mod preferences;
mod providers;
mod rate_limit_middleware;
mod regenerate;
mod reset_chat;
mod search;
mod sets;
mod signup;
mod stt;
pub mod test_instrumentation;
mod tools;
mod tts;

pub async fn run() -> anyhow::Result<()> {
    logging::init_logging();

    let static_root = resolve_static_root();
    info!("serving static assets from {}", static_root.display());

    background::spawn_session_purge_task();

    let app = build_router(static_root);

    let bind_addr = env::var("CHATBOT_BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:80".into());
    let listener = TcpListener::bind(&bind_addr).await?;
    let addr = listener.local_addr()?;
    info!("listening on http://{addr}");

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}

async fn set_cross_origin_isolation_headers(
    request: axum::extract::Request<Body>,
    next: Next,
) -> Response {
    let mut response = next.run(request).await;
    response.headers_mut().insert(
        HeaderName::from_static("cross-origin-opener-policy"),
        HeaderValue::from_static("same-origin"),
    );
    response.headers_mut().insert(
        HeaderName::from_static("cross-origin-embedder-policy"),
        HeaderValue::from_static("require-corp"),
    );
    response
}

/// Guarantee: every 5xx response that reaches a client is logged at ERROR
/// level with request context. Handler-level helpers (`log_and_api_error`,
/// `map_*_err`, `api_error`) log the underlying cause; this catches any 5xx
/// built without such a log (direct Response builders, `build_response`
/// ServiceResponses, future handlers). Mounted as the outermost layer so it
/// observes the final status of every route, including nested services.
async fn log_server_error_responses(
    request: axum::extract::Request<Body>,
    next: Next,
) -> Response {
    let method = request.method().clone();
    let path = request.uri().path().to_owned();
    let response = next.run(request).await;
    if response.status().is_server_error() {
        error!(
            status = response.status().as_u16(),
            method = %method,
            path = %path,
            "5xx response returned to client"
        );
    }
    response
}

/// Strip the `Secure` flag from a `Set-Cookie` header value.
///
/// In RFC 6265bis §5.4, clients (such as Android WebView / Chromium) strictly drop
/// any cookie with the `Secure` flag if received over plain HTTP (non-localhost).
/// When running over plain HTTP without HTTPS termination, stripping `Secure`
/// allows mobile WebViews and non-TLS clients to accept and store cookies.
pub fn strip_secure_cookie_flag(cookie: &str) -> String {
    cookie
        .split(';')
        .map(str::trim)
        .filter(|part| !part.is_empty() && !part.eq_ignore_ascii_case("secure"))
        .collect::<Vec<_>>()
        .join("; ")
}

/// Detects whether an incoming request is over plain HTTP (no TLS / reverse-proxy HTTPS).
///
/// When requests run in mock/unit tests using `tower::ServiceExt::oneshot` without a `Host`
/// header or proxy headers, this returns `false` to preserve the configured `Secure` flag
/// expectations in tests.
fn is_plain_http_request(request: &axum::extract::Request<Body>) -> bool {
    if request
        .uri()
        .scheme_str()
        .map(|s| s.eq_ignore_ascii_case("https"))
        .unwrap_or(false)
    {
        return false;
    }

    let headers = request.headers();

    if let Some(proto) = headers.get("x-forwarded-proto").and_then(|v| v.to_str().ok()) {
        if proto
            .split(',')
            .next()
            .map(|s| s.trim().eq_ignore_ascii_case("https"))
            .unwrap_or(false)
        {
            return false;
        }
    }
    if let Some(ssl) = headers.get("x-forwarded-ssl").and_then(|v| v.to_str().ok()) {
        if ssl.trim().eq_ignore_ascii_case("on") {
            return false;
        }
    }
    if let Some(front_end) = headers.get("front-end-https").and_then(|v| v.to_str().ok()) {
        if front_end.trim().eq_ignore_ascii_case("on") {
            return false;
        }
    }
    if let Some(forwarded) = headers.get("forwarded").and_then(|v| v.to_str().ok()) {
        if forwarded.to_ascii_lowercase().contains("proto=https") {
            return false;
        }
    }

    headers.contains_key(axum::http::header::HOST)
        || request.uri().authority().is_some()
        || headers.contains_key("x-forwarded-proto")
}

async fn sanitize_cookies_middleware(
    request: axum::extract::Request<Body>,
    next: Next,
) -> Response {
    let plain_http = is_plain_http_request(&request);
    let mut response = next.run(request).await;

    if plain_http {
        let headers = response.headers_mut();
        if headers.contains_key(axum::http::header::SET_COOKIE) {
            let cookies: Vec<_> = headers
                .get_all(axum::http::header::SET_COOKIE)
                .iter()
                .cloned()
                .collect();
            headers.remove(axum::http::header::SET_COOKIE);
            for cookie in cookies {
                if let Ok(cookie_str) = cookie.to_str() {
                    let sanitized = strip_secure_cookie_flag(cookie_str);
                    if let Ok(new_val) = HeaderValue::from_str(&sanitized) {
                        headers.append(axum::http::header::SET_COOKIE, new_val);
                    } else {
                        headers.append(axum::http::header::SET_COOKIE, cookie);
                    }
                } else {
                    headers.append(axum::http::header::SET_COOKIE, cookie);
                }
            }
        }
    }

    response
}

pub fn build_router(static_root: PathBuf) -> Router {
    let rate_limited = Router::new()
        .route(
            "/signup",
            get(signup::handle_signup_get).post(signup::handle_signup_post),
        )
        .route(
            "/login",
            get(login::handle_login_get).post(login::handle_login_post),
        )
        .route(
            "/login/remember",
            post(login::handle_login_remember_post),
        )
        .route(
            "/login/forget",
            post(login::handle_login_forget_post),
        )
        .route("/chat", post(chat::handle_chat))
        .route("/tts", post(tts::handle_tts))
        .route(
            "/tts_stream/{token}",
            get(tts::handle_tts_stream).delete(tts::handle_tts_cancel),
        )
        .route("/stt", post(stt::handle_stt))
        .route("/regenerate", post(regenerate::handle_regenerate))
        .layer(middleware::from_fn(rate_limit_middleware::middleware));

    Router::new()
        .layer(middleware::from_fn(set_cross_origin_isolation_headers))
        .nest_service("/static", ServeDir::new(static_root))
        .route("/favicon.ico", get(favicon))
        .route("/health", get(health::handle_health))
        .route("/", get(home::handle_home))
        .route("/auth/salt/{username}", get(login::handle_get_salt))
        .route("/logout", get(logout::handle_logout))
        .route("/reset_chat", post(reset_chat::handle_reset_chat))
        .route("/get_sets", get(sets::handle_get_sets))
        .route("/create_set", post(sets::handle_create_set))
        .route("/delete_set", post(sets::handle_delete_set))
        .route("/rename_set", post(sets::handle_rename_set))
        .route("/load_set", post(sets::handle_load_set))
        .route("/history_pair", post(sets::handle_history_pair))
        .route(
            "/history_image/{set_id}/{version}/{pair_index}/{image_index}",
            get(sets::handle_history_image),
        )
        .route("/update_memory", post(memory::handle_update_memory))
        .route(
            "/update_system_prompt",
            post(memory::handle_update_system_prompt),
        )
        .route("/delete_message", post(memory::handle_delete_message))
        .route(
            "/update_preferences",
            post(preferences::handle_update_preferences),
        )
        .merge(rate_limited)
        .layer(middleware::from_fn(sanitize_cookies_middleware))
        .layer(middleware::from_fn(log_server_error_responses))
}

pub fn resolve_static_root() -> PathBuf {
    if let Ok(path) = env::var("CHATBOT_STATIC_ROOT") {
        return PathBuf::from(path);
    }

    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("static")
}

async fn favicon() -> StatusCode {
    StatusCode::NO_CONTENT
}

pub(crate) fn build_response(
    service_response: ServiceResponse,
) -> Result<Response, http_error::HttpError> {
    let status = StatusCode::from_u16(service_response.status)
        .map_err(|_| http_error::api_error(StatusCode::INTERNAL_SERVER_ERROR, "invalid status"))?;

    if service_response.status == 400 {
        let preview: String = String::from_utf8_lossy(&service_response.body)
            .chars()
            .take(500)
            .collect();
        warn!(status = 400, body = %preview, "http 400");
    }

    let mut response = Response::builder()
        .status(status)
        .body(Body::from(service_response.body))
        .map_err(|err| {
            error!(?err, "failed to build response body");
            http_error::api_error(StatusCode::INTERNAL_SERVER_ERROR, "response build error")
        })?;

    {
        let headers = response.headers_mut();
        for (name, value) in service_response.headers {
            if name.eq_ignore_ascii_case("transfer-encoding") {
                continue;
            }
            let header_name = match HeaderName::from_bytes(name.as_bytes()) {
                Ok(name) => name,
                Err(err) => {
                    error!(?err, "invalid header name: {name}");
                    continue;
                }
            };

            let header_value = match HeaderValue::from_str(&value) {
                Ok(value) => value,
                Err(err) => {
                    error!(?err, "invalid header value for {header_name}");
                    continue;
                }
            };

            headers.append(header_name, header_value);
        }
    }

    // Record server-side errors for test instrumentation so integration
    // tests can assert no 500s were emitted during their run.
    if service_response.status >= 500 {
        test_instrumentation::record_error();
    }

    Ok(response)
}
