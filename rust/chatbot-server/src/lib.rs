use anyhow::Error;
use axum::{
    body::Body,
    http::{HeaderName, HeaderValue, StatusCode},
    response::Response,
    routing::{get, post},
    Router,
};
use chatbot_core::bridge::{self, PythonResponse};
use std::{env, path::PathBuf};
use tokio::net::TcpListener;
use tower_http::services::ServeDir;
use tracing::{error, info};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod chat;
mod chat_utils;
mod health;
mod home;
mod login;
mod logout;
mod memory;
mod providers;
mod regenerate;
mod reset_chat;
mod sets;
mod signup;
pub mod test_instrumentation;
mod tts;
mod user_store;

pub async fn run() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::from_default_env())
        .with(tracing_subscriber::fmt::layer())
        .init();

    bridge::initialize_python().map_err(Error::from)?;

    let static_root = resolve_static_root();
    info!("serving static assets from {}", static_root.display());

    let app = build_router(static_root);

    let bind_addr = env::var("CHATBOT_BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:80".into());
    let listener = TcpListener::bind(&bind_addr).await?;
    let addr = listener.local_addr()?;
    info!("listening on http://{addr}");

    axum::serve(listener, app).await?;
    Ok(())
}

pub fn build_router(static_root: PathBuf) -> Router {
    Router::new()
        .nest_service("/static", ServeDir::new(static_root))
        .route("/favicon.ico", get(favicon))
        .route("/health", get(health::handle_health))
        .route("/", get(home::handle_home))
        .route(
            "/signup",
            get(signup::handle_signup_get).post(signup::handle_signup_post),
        )
        .route(
            "/login",
            get(login::handle_login_get).post(login::handle_login_post),
        )
        .route("/logout", get(logout::handle_logout))
        .route("/chat", post(chat::handle_chat))
        // Handle the primary `/tts` endpoint via the bridge so we can
        // enforce CSRF and response semantics in Rust while still
        // delegating audio generation to Python for now.
        .route("/tts", post(tts::handle_tts))
        .route("/api/tts", post(tts::handle_api_tts))
        .route("/api/tts/stream", post(tts::handle_api_tts_stream))
        .route("/regenerate", post(regenerate::handle_regenerate))
        .route("/reset_chat", post(reset_chat::handle_reset_chat))
        .route("/get_sets", get(sets::handle_get_sets))
        .route("/create_set", post(sets::handle_create_set))
        .route("/delete_set", post(sets::handle_delete_set))
        .route("/load_set", post(sets::handle_load_set))
        .route("/update_memory", post(memory::handle_update_memory))
        .route(
            "/update_system_prompt",
            post(memory::handle_update_system_prompt),
        )
        .route("/delete_message", post(memory::handle_delete_message))
}

pub fn resolve_static_root() -> PathBuf {
    if let Ok(path) = env::var("CHATBOT_STATIC_ROOT") {
        return PathBuf::from(path);
    }

    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("app")
        .join("static")
}

async fn favicon() -> StatusCode {
    StatusCode::NO_CONTENT
}

pub(crate) fn build_response(
    py_response: PythonResponse,
) -> Result<Response, (StatusCode, String)> {
    let status = StatusCode::from_u16(py_response.status).map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "invalid status".to_string(),
        )
    })?;

    let mut response = Response::builder()
        .status(status)
        .body(Body::from(py_response.body))
        .map_err(|err| {
            error!(?err, "failed to build response body");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "response build error".to_string(),
            )
        })?;

    {
        let headers = response.headers_mut();
        for (name, value) in py_response.headers {
            if name.eq_ignore_ascii_case("transfer-encoding") {
                continue;
            }
            let header_name = match HeaderName::from_bytes(name.as_bytes()) {
                Ok(name) => name,
                Err(err) => {
                    error!(?err, "invalid header name from python bridge: {name}");
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
    if py_response.status >= 500 {
        test_instrumentation::record_error();
    }

    Ok(response)
}
