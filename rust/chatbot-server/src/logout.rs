use axum::{
    body::Body,
    http::{header, Request, Response, StatusCode},
};
use chatbot_core::bridge;
use tracing::error;

pub async fn handle_logout(request: Request<Body>) -> Result<Response<Body>, (StatusCode, String)> {
    let cookie_header = request
        .headers()
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .map(|s| s.to_owned());

    match bridge::logout_user(cookie_header.as_deref()) {
        Ok(py_response) => crate::build_response(py_response),
        Err(err) => {
            error!(?err, "failed to perform logout via python bridge");
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                "bridge error".to_string(),
            ))
        }
    }
}
