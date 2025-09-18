use anyhow::Error;
use axum::{body::Body, http::{header, HeaderMap, HeaderName, HeaderValue, StatusCode}, response::Response, routing::get, Router};
use chatbot_core::bridge::{self, PythonResponse};
use tokio::net::TcpListener;
use tracing::{error, info};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::from_default_env())
        .with(tracing_subscriber::fmt::layer())
        .init();

    bridge::initialize_python().map_err(Error::from)?;

    let app = Router::new()
        .route("/health", get(health_check))
        .route("/", get(proxy_home));

    let listener = TcpListener::bind("0.0.0.0:8000").await?;
    let addr = listener.local_addr()?;
    info!("listening on http://{addr}");

    axum::serve(listener, app).await?;
    Ok(())
}

async fn health_check() -> &'static str {
    "{\"status\":\"healthy\"}"
}

async fn proxy_home(headers: HeaderMap) -> Result<Response, (StatusCode, String)> {
    let cookie_header = headers
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .map(|s| s.to_owned());

    let host_header = headers
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .map(|s| s.to_owned());

    let mut forwarded_headers = Vec::new();
    if let Some(host) = host_header.clone() {
        forwarded_headers.push(("Host".to_string(), host));
    }

    match bridge::proxy_request(
        "GET",
        "/",
        None,
        &forwarded_headers,
        cookie_header.as_deref(),
        None,
    ) {
        Ok(py_response) => build_response(py_response),
        Err(err) => {
            error!(?err, "Python bridge error while handling home page");
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                "bridge error".to_string(),
            ))
        }
    }
}

fn build_response(py_response: PythonResponse) -> Result<Response, (StatusCode, String)> {
    let status = StatusCode::from_u16(py_response.status)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "invalid status".to_string()))?;

    let mut response = Response::builder()
        .status(status)
        .body(Body::from(py_response.body))
        .map_err(|err| {
            error!(?err, "failed to build response body");
            (StatusCode::INTERNAL_SERVER_ERROR, "response build error".to_string())
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
