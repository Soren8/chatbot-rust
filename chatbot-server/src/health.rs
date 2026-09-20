use axum::{
    extract::{Extension, Query},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::time::Duration;
use tracing::{info, warn};

use crate::services::AppServices;

#[derive(Debug, Default, Serialize)]
pub(crate) struct HealthPayload {
    status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    checks: Option<Value>,
}

#[derive(Debug, Default, Deserialize)]
pub(crate) struct HealthQuery {
    #[serde(default)]
    deep: bool,
}

pub(crate) async fn handle_health(
    Extension(services): Extension<AppServices>,
    Query(query): Query<HealthQuery>,
) -> (StatusCode, Json<HealthPayload>) {
    info!(deep = query.deep, "health check requested");

    if !query.deep {
        return (
            StatusCode::OK,
            Json(HealthPayload {
                status: "healthy",
                checks: None,
            }),
        );
    }

    // Scoped history check through this router's chat service: compatibility
    // routers resolve the process-global service (same `is_ok` as before with
    // no extra `redb` open), while owned routers check only their explicit
    // history without initializing the unrelated global database.
    let history_ok = services.chat().history().is_ok();
    let voice_ok = probe_voice_service_with_base(&services.config_source().voice_service_base_url()).await;

    let checks = json!({
        "history": if history_ok { "ok" } else { "unavailable" },
        "voice_service": if voice_ok { "ok" } else { "unavailable" },
    });

    let healthy = history_ok && voice_ok;
    let status = if healthy { "healthy" } else { "degraded" };
    let code = if healthy {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };

    if !healthy {
        warn!(?checks, "deep health check reported degraded status");
    }

    (
        code,
        Json(HealthPayload {
            status,
            checks: Some(checks),
        }),
    )
}

async fn probe_voice_service_with_base(base_url: &str) -> bool {
    let url = format!("{}/health", base_url.trim_end_matches('/'));

    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
    {
        Ok(client) => client,
        Err(err) => {
            warn!(?err, "failed to build voice-service health probe client");
            return false;
        }
    };

    match client.get(&url).send().await {
        Ok(response) if response.status().is_success() => true,
        Ok(response) => {
            warn!(
                status = %response.status(),
                url = %url,
                "voice-service health probe returned non-success status"
            );
            false
        }
        Err(err) => {
            warn!(?err, url = %url, "voice-service health probe failed");
            false
        }
    }
}