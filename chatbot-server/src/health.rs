use axum::{http::StatusCode, Json};
use serde::Serialize;
use tracing::info;

#[derive(Serialize)]
pub(crate) struct HealthPayload {
    status: &'static str,
}

pub(crate) async fn handle_health() -> (StatusCode, Json<HealthPayload>) {
    info!("health check requested");
    (StatusCode::OK, Json(HealthPayload { status: "healthy" }))
}
