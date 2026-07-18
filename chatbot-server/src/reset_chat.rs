use axum::{
    body,
    body::Body,
    http::{header, Request, Response, StatusCode},
};
use chatbot_core::{
    history::{self, HistoryError, HistoryService, SetId, SetVersion},
    session,
};
use serde::Deserialize;
use serde_json::json;
use crate::http_error::{
    api_error, log_and_api_error, map_body_read_err, map_json_parse_err, map_response_build_err,
    map_session_err, HttpError,
};

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

    let cookie_header = headers
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .map(|s| s.to_owned());
    let csrf_token = headers
        .get("X-CSRF-Token")
        .and_then(|value| value.to_str().ok());

    let csrf_valid = session::validate_csrf_token(cookie_header.as_deref(), csrf_token)
        .map_err(|err| map_session_err(err, "reset_chat::post::csrf"))?;

    if !csrf_valid {
        return Err(api_error(StatusCode::UNAUTHORIZED, "Invalid or missing CSRF token"));
    }

    let encryption_key = crate::chat_utils::extract_enc_key(&headers);

    let session_context = session::session_context(cookie_header.as_deref())
        .map_err(|err| map_session_err(err, "reset_chat::post::session"))?;

    let set_name = history::normalise_set_name(payload.set_name.as_deref()).map_err(|err| {
        match err {
            chatbot_core::persistence::PersistenceError::InvalidSetName => {
                api_error(StatusCode::BAD_REQUEST, "invalid set name")
            }
            other => log_and_api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "invalid set name",
                "reset_chat::post::normalise_set_name",
                other,
            ),
        }
    })?;

    if let Some(username) = session_context.username.as_deref() {
        if let Err(response) =
            session::validate_encryption_key_for_user(username, encryption_key.as_ref())
        {
            return build_service_response(response);
        }
        let key = encryption_key.as_ref().expect("validated encryption key");
        let history = HistoryService::global().map_err(history_error_to_http)?;
        let set_id = if let Some(raw) = payload.set_id.as_deref().filter(|s| !s.trim().is_empty()) {
            SetId::parse(raw)
                .map_err(|_| api_error(StatusCode::BAD_REQUEST, "invalid set_id"))?
        } else {
            match history.find_by_display_name(username, &set_name, key) {
                Ok(Some(s)) => s.set_id,
                Ok(None) if set_name == "default" => history
                    .ensure_default_set(username, key)
                    .map_err(history_error_to_http)?
                    .set_id,
                Ok(None) => {
                    return Err(api_error(StatusCode::BAD_REQUEST, "set not found"));
                }
                Err(err) => return Err(history_error_to_http(err)),
            }
        };
        let expected = match payload.expected_version {
            Some(v) => SetVersion(v),
            None => history
                .load(username, set_id, key)
                .map_err(history_error_to_http)?
                .version,
        };
        let version = match history.reset_history(username, set_id, expected, key) {
            Ok(v) => v,
            Err(HistoryError::Conflict { current_version }) => {
                return build_json_response(
                    StatusCode::CONFLICT,
                    crate::chat_utils::version_conflict_json(set_id, current_version),
                );
            }
            Err(err) => return Err(history_error_to_http(err)),
        };

        if let Err(response) = session::set_session_history_for_request(
            &session_context.session_id,
            Some(username),
            Some(set_id),
            Vec::new(),
            encryption_key.as_ref(),
        ) {
            return build_service_response(response);
        }

        return build_json_response(
            StatusCode::OK,
            json!({
                "status": "success",
                "message": "Chat history has been reset.",
                "set_name": set_name,
                "set_id": set_id.to_string(),
                "version": version.get(),
            }),
        );
    }

    session::update_session_history(&session_context.session_id, &[]);
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
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(payload.to_string()))
        .map_err(|err| map_response_build_err(err, "reset_chat::post::response"))
}

fn build_service_response(
    response: session::ServiceResponse,
) -> Result<Response<Body>, HttpError> {
    crate::build_response(response)
}

fn history_error_to_http(err: HistoryError) -> HttpError {
    crate::chat_utils::history_error_to_http(err)
}
