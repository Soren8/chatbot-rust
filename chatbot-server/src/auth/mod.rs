use axum::{
    extract::FromRequestParts,
    http::{header, request::Parts, StatusCode},
    response::{IntoResponse, Response},
};
use chatbot_core::session::{self, SessionContext, SessionRequest};
use serde_json::json;
use tracing::error;

use crate::responses;

pub struct Session(pub SessionContext);

pub struct RequireUser(pub SessionContext);

fn authorization_header(parts: &Parts) -> Option<&str> {
    parts
        .headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
}

fn auth_user_header(parts: &Parts) -> Option<&str> {
    parts
        .headers
        .get("X-Auth-User")
        .and_then(|value| value.to_str().ok())
}

fn encryption_key_header(parts: &Parts) -> Option<&str> {
    parts
        .headers
        .get("X-Enc-Key")
        .and_then(|value| value.to_str().ok())
}

fn guest_session_header(parts: &Parts) -> Option<&str> {
    parts
        .headers
        .get("X-Guest-Session")
        .and_then(|value| value.to_str().ok())
}

#[axum::async_trait]
impl<S> FromRequestParts<S> for Session
where
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        let context = session::session_context(SessionRequest {
            authorization: authorization_header(parts),
            auth_user: auth_user_header(parts),
            encryption_key: encryption_key_header(parts),
            guest_session: guest_session_header(parts),
        })
        .map_err(|err| {
            error!(?err, method = %parts.method, "failed to obtain session context");
            (StatusCode::UNAUTHORIZED, "unauthorized").into_response()
        })?;

        Ok(Self(context))
    }
}

#[axum::async_trait]
impl<S> FromRequestParts<S> for RequireUser
where
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &S,
    ) -> Result<Self, Self::Rejection> {
        let Session(context) = Session::from_request_parts(parts, state).await?;

        if context.username.is_none() {
            return Err(
                responses::json_response(
                    StatusCode::UNAUTHORIZED,
                    json!({ "error": "Not authenticated" }),
                ),
            );
        }

        Ok(Self(context))
    }
}
