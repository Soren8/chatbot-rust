use axum::{
    body,
    body::Body,
    http::{header, Request, Response, StatusCode},
};
use chatbot_core::history::{self, HistoryError, SetVersion};
use chatbot_core::session::MutationMirrorError;
use serde::Deserialize;
use serde_json::json;
use crate::http_error::{
    api_error, map_body_read_err, map_encryption_key_validation_err, map_json_parse_err,
    map_response_build_err, map_session_err, map_session_operation_err, HttpError,
};
use crate::services::AppServices;

#[derive(Deserialize, Default)]
struct ResetChatRequest {
    #[serde(default)]
    set_name: Option<String>,
    #[serde(default)]
    set_id: Option<String>,
    #[serde(default)]
    expected_version: Option<u64>,
}

pub async fn handle_reset_chat(
    request: Request<Body>,
) -> Result<Response<Body>, HttpError> {
    if request.method() != axum::http::Method::POST {
        return Err(api_error(StatusCode::METHOD_NOT_ALLOWED, "Only POST allowed"));
    }

    let (parts, body) = request.into_parts();
    let services = AppServices::from_extensions(&parts.extensions);
    let identity = services.identity().clone();
    let chat = services.chat().clone();
    let headers = parts.headers;

    let body_bytes = body::to_bytes(body, 256 * 1024)
        .await
        .map_err(|err| map_body_read_err(err, "reset_chat::post"))?;

    let payload: ResetChatRequest = if body_bytes.is_empty() {
        ResetChatRequest::default()
    } else {
        serde_json::from_slice(&body_bytes)
            .map_err(|err| map_json_parse_err(err, "reset_chat::post"))?
    };

    let cookie_header = crate::request_context::extract_cookie(&headers);
    let csrf_token = crate::request_context::extract_csrf(&headers);

    let csrf_valid = identity
        .validate_csrf_token(cookie_header.as_deref(), csrf_token)
        .map_err(|err| map_session_err(err, "reset_chat::post::csrf"))?;

    if !csrf_valid {
        return Err(api_error(StatusCode::UNAUTHORIZED, "Invalid or missing CSRF token"));
    }

    let data_context = crate::request_context::DataRequestContext::resolve(
        &identity,
        &headers,
        cookie_header.as_deref(),
        "reset_chat::post::session",
    )?;

    let set_name = history::normalise_set_name(payload.set_name.as_deref()).map_err(|err| {
        match err {
            chatbot_core::history::SetNameError::Invalid => {
                api_error(StatusCode::BAD_REQUEST, "invalid set name")
            }
        }
    })?;

    if data_context.session().username.as_deref().is_some() {
        let session = data_context.session();
        let key = data_context.unverified_encryption_key();
        let set_id_raw = payload
            .set_id
            .as_deref()
            .filter(|s| !s.trim().is_empty());
        match chat.apply_reset_history(
            session,
            key,
            &set_name,
            set_id_raw,
            payload.expected_version.map(SetVersion),
        ) {
            Ok(applied) => {
                return build_json_response(
                    StatusCode::OK,
                    json!({
                        "status": "success",
                        "message": "Chat history has been reset.",
                        "set_name": set_name,
                        "set_id": applied.set_id.to_string(),
                        "version": applied.version.get(),
                    }),
                );
            }
            Err(MutationMirrorError::Key(err)) => {
                return Err(map_encryption_key_validation_err(err));
            }
            Err(MutationMirrorError::InvalidSetId) => {
                return Err(api_error(StatusCode::BAD_REQUEST, "invalid set_id"));
            }
            Err(MutationMirrorError::SetNotFound) => {
                return Err(api_error(StatusCode::BAD_REQUEST, "set not found"));
            }
            Err(MutationMirrorError::Conflict {
                set_id,
                current_version,
            }) => {
                return build_json_response(
                    StatusCode::CONFLICT,
                    crate::chat_utils::version_conflict_json(set_id, current_version),
                );
            }
            Err(MutationMirrorError::History(err)) => {
                return Err(history_error_to_http(err));
            }
            Err(MutationMirrorError::Mirror(err)) => {
                return Err(map_session_operation_err(&err));
            }
        }
    }

    chat.update_session_history(&data_context.session().session_id, &[]);
    build_json_response(
        StatusCode::OK,
        json!({
            "status": "success",
            "message": "Chat history has been reset.",
            "set_name": set_name
        }),
    )
}

fn build_json_response(
    status: StatusCode,
    payload: serde_json::Value,
) -> Result<Response<Body>, HttpError> {
    if status == StatusCode::BAD_REQUEST {
        tracing::warn!(status = 400, body = %payload, "http 400");
    }
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(payload.to_string()))
        .map_err(|err| map_response_build_err(err, "reset_chat::post::response"))
}

fn history_error_to_http(err: HistoryError) -> HttpError {
    crate::chat_utils::history_error_to_http(err)
}
