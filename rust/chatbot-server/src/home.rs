use axum::{
    body::Body,
    http::{header, Request, Response, StatusCode},
};
use chatbot_core::bridge;
use tracing::error;

pub async fn handle_home(request: Request<Body>) -> Result<Response<Body>, (StatusCode, String)> {
    let cookie_header = request
        .headers()
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.to_owned());

    match bridge::render_home(cookie_header.as_deref()) {
        Ok(py_response) => crate::build_response(py_response),
        Err(err) => {
            error!(?err, "failed to render home via python bridge");
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                "bridge error".to_string(),
            ))
        }
    }
}
