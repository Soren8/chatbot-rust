use anyhow::Error;
use axum::{
    body::{self, Body},
    http::{header, HeaderName, HeaderValue, Method, Request, StatusCode},
    response::Response,
    routing::{any, get},
    Router,
};
use chatbot_core::bridge::{self, PythonResponse};
use std::{env, path::PathBuf};
use tokio::net::TcpListener;
use tracing::{error, info};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use tower_http::services::ServeDir;

mod login;
mod logout;
mod signup;
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
        .route("/health", any(proxy_request_handler))
        .route("/", get(proxy_request_handler))
        .route(
            "/signup",
            get(proxy_request_handler).post(signup::handle_signup_post),
        )
        .route(
            "/login",
            get(proxy_request_handler).post(login::handle_login_post),
        )
        .route("/logout", get(logout::handle_logout))
        .route("/chat", any(proxy_request_handler))
        .route("/regenerate", any(proxy_request_handler))
        .route("/reset_chat", any(proxy_request_handler))
        .route("/get_sets", any(proxy_request_handler))
        .route("/create_set", any(proxy_request_handler))
        .route("/delete_set", any(proxy_request_handler))
        .route("/load_set", any(proxy_request_handler))
        .route("/update_memory", any(proxy_request_handler))
        .route("/update_system_prompt", any(proxy_request_handler))
        .route("/delete_message", any(proxy_request_handler))
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

async fn proxy_request_handler(request: Request<Body>) -> Result<Response, (StatusCode, String)> {
    let (parts, body) = request.into_parts();
    let method = parts.method;
    let uri = parts.uri;
    let headers = parts.headers;

    let body_bytes = read_body_bytes(method.clone(), body).await?;

    let cookie_header = headers
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .map(|s| s.to_owned());

    let header_pairs = headers
        .iter()
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|v| (name.to_string(), v.to_owned()))
        })
        .collect::<Vec<_>>();

    match bridge::proxy_request(
        method.as_str(),
        uri.path(),
        uri.query(),
        &header_pairs,
        cookie_header.as_deref(),
        body_bytes.as_deref(),
    ) {
        Ok(py_response) => build_response(py_response),
        Err(err) => {
            error!(
                ?err,
                "Python bridge error while handling {path}",
                path = uri.path()
            );
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                "bridge error".to_string(),
            ))
        }
    }
}

pub(crate) fn build_response(py_response: PythonResponse) -> Result<Response, (StatusCode, String)> {
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

    Ok(response)
}

async fn read_body_bytes(
    method: Method,
    body: Body,
) -> Result<Option<Vec<u8>>, (StatusCode, String)> {
    if method == Method::GET || method == Method::HEAD {
        return Ok(None);
    }

    match body::to_bytes(body, 10 * 1024 * 1024).await {
        Ok(bytes) if bytes.is_empty() => Ok(None),
        Ok(bytes) => Ok(Some(bytes.to_vec())),
        Err(err) => {
            error!(?err, "failed to read request body");
            Err((StatusCode::BAD_GATEWAY, "invalid request body".to_string()))
        }
    }
}
