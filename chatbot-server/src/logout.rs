use axum::{
    body::Body,
    http::{header, HeaderValue, Request, Response, StatusCode},
};
use chatbot_core::session::{self, SessionRequest};
use tracing::error;

pub async fn handle_logout(request: Request<Body>) -> Result<Response<Body>, (StatusCode, String)> {
    let headers = request.headers();
    let ip = crate::chat_utils::get_ip(headers, request.extensions());
    let username = session::session_context(SessionRequest {
        authorization: headers
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok()),
        auth_user: headers.get("X-Auth-User").and_then(|value| value.to_str().ok()),
        encryption_key: headers.get("X-Enc-Key").and_then(|value| value.to_str().ok()),
        guest_session: headers
            .get("X-Guest-Session")
            .and_then(|value| value.to_str().ok()),
    })
        .ok()
        .and_then(|ctx| ctx.username)
        .unwrap_or_else(|| "guest".to_string());

    session::logout_user(
        headers
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok()),
    )
    .map_err(|err| {
        error!(?err, "failed to perform logout");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "session error".to_string(),
        )
    })?;

    tracing::info!(username = %username, ip = %ip, "Logout successful");

    let body = serde_json::to_vec(&serde_json::json!({ "status": "success" })).map_err(|err| {
        error!(?err, "failed to serialize logout response");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "response build error".to_string(),
        )
    })?;

    Response::builder()
        .status(StatusCode::OK)
        .header(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        )
        .body(Body::from(body))
        .map_err(|err| {
            error!(?err, "failed to build logout response");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "response build error".to_string(),
            )
        })
}
