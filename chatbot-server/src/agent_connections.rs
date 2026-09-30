use axum::{
    body::{self, Body},
    http::{header, Request, Response, StatusCode},
};
use std::{collections::{HashMap, VecDeque}, sync::{Arc, Mutex, OnceLock, atomic::{AtomicBool, Ordering}}, time::{Duration, Instant}};
use tokio::sync::Semaphore;
use chatbot_core::{
    agent_connections::{ConnectionError, ConnectionInput, ConnectionPatch, ConnectionRecord, ConnectionService, MAX_BODY_BYTES},
    config::{agent_egress, app_config, ExternalConnectionsConfig},
};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::{
    http_error::{api_error, api_error_json, map_response_build_err, map_serialization_err, map_session_err, map_user_store_err, HttpError},
    request_context::{extract_cookie, extract_csrf, DataRequestContext, VerifiedDataContext},
    services::AppServices,
};

use chatbot_core::{connection_receipts, operation_receipt::{Receipt, ReceiptClock, ReceiptOutcome, SystemReceiptClock}};
use crate::idempotency::{operation_request, replay, reused, InFlightOperations};

pub(crate) struct ConnectionOperations {
    flights: InFlightOperations,
    pub(crate) clock: Arc<dyn ReceiptClock>,
}
impl Default for ConnectionOperations {
    fn default() -> Self { Self { flights: InFlightOperations::default(), clock: Arc::new(SystemReceiptClock) } }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateInput {
    name: String,
    kind: String,
    base_url: String,
    username: String,
    password: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PatchInput {
    expected_revision: u64,
    name: Option<String>,
    kind: Option<String>,
    base_url: Option<String>,
    username: Option<String>,
    password: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeleteInput {
    expected_revision: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CheckInput {
    expected_revision: u64,
}

struct CheckBudget {
    slots: Arc<Semaphore>,
    attempts: VecDeque<Instant>,
}

static CHECK_BUDGETS: OnceLock<Mutex<HashMap<String, CheckBudget>>> = OnceLock::new();

fn check_slot(user: &str) -> Result<tokio::sync::OwnedSemaphorePermit, HttpError> {
    let now = Instant::now();
    let mut budgets = CHECK_BUDGETS.get_or_init(|| Mutex::new(HashMap::new()))
        .lock().unwrap_or_else(|e| e.into_inner());
    let budget = budgets.entry(user.to_owned()).or_insert_with(|| CheckBudget {
        slots: Arc::new(Semaphore::new(2)), attempts: VecDeque::new(),
    });
    let slot = budget.slots.clone().try_acquire_owned()
        .map_err(|_| api_error(StatusCode::TOO_MANY_REQUESTS, "agent_check_busy"))?;
    while budget.attempts.front().is_some_and(|time| now.duration_since(*time) >= Duration::from_secs(60)) {
        budget.attempts.pop_front();
    }
    if budget.attempts.len() >= 6 {
        return Err(api_error(StatusCode::TOO_MANY_REQUESTS, "agent_check_rate_limited"));
    }
    budget.attempts.push_back(now);
    Ok(slot)
}

fn map_check(err: agent_egress::EgressError) -> HttpError {
    use agent_egress::EgressError;
    match err {
        EgressError::InvalidUrl => api_error(StatusCode::BAD_REQUEST, "invalid_base_url"),
        EgressError::Blocked => api_error(StatusCode::FORBIDDEN, "connection_target_forbidden"),
        EgressError::Timeout => api_error(StatusCode::GATEWAY_TIMEOUT, "agent_timeout"),
        EgressError::Authentication => api_error(StatusCode::BAD_GATEWAY, "agent_auth_failed"),
        EgressError::InvalidHealth => api_error(StatusCode::BAD_GATEWAY, "agent_invalid_health"),
        EgressError::Unhealthy => api_error(StatusCode::BAD_GATEWAY, "agent_unhealthy"),
        EgressError::Transport | EgressError::Resolve => api_error(StatusCode::BAD_GATEWAY, "agent_unavailable"),
    }
}

fn authorized<'a>(
    services: &AppServices,
    data: &'a DataRequestContext,
) -> Result<(VerifiedDataContext<'a>, ConnectionService, ExternalConnectionsConfig), HttpError> {
    let verified = data.require_authenticated(services.chat())?;
    let policy = app_config().external_connections.clone();
    if !policy.enabled || !policy.allowed_users.iter().any(|user| user == verified.username()) {
        return Err(api_error(StatusCode::FORBIDDEN, "agent_connections_forbidden"));
    }
    let users = services.accounts().users().map_err(|err| map_user_store_err(err, "agent_connections::users", "Unable to check account"))?;
    if !users.has_key_verifier(verified.username()).map_err(|err| map_user_store_err(err, "agent_connections::account", "Unable to check account"))? {
        return Err(api_error(StatusCode::FORBIDDEN, "agent_connections_forbidden"));
    }
    let connections = services.connections().cloned().ok_or_else(|| api_error(StatusCode::FORBIDDEN, "agent_connections_forbidden"))?;
    Ok((verified, connections, policy))
}

fn csrf(services: &AppServices, headers: &axum::http::HeaderMap, cookie: Option<&str>) -> Result<(), HttpError> {
    if !services.identity().validate_csrf_token(cookie, extract_csrf(headers))
        .map_err(|err| map_session_err(err, "agent_connections::csrf"))? {
        return Err(api_error(StatusCode::UNAUTHORIZED, "Invalid or missing CSRF token"));
    }
    Ok(())
}

fn context(services: &AppServices, headers: &axum::http::HeaderMap, cookie: Option<&str>) -> Result<DataRequestContext, HttpError> {
    DataRequestContext::resolve(services.identity(), headers, cookie, "agent_connections::session")
}

fn mutation_context(services: &AppServices, headers: &axum::http::HeaderMap) -> Result<DataRequestContext, HttpError> {
    let cookie = extract_cookie(headers);
    csrf(services, headers, cookie.as_deref())?;
    context(services, headers, cookie.as_deref())
}

fn map_connection(err: ConnectionError) -> HttpError {
    match err {
        ConnectionError::InvalidInput => api_error(StatusCode::BAD_REQUEST, "invalid_connection_input"),
        ConnectionError::InvalidKey => api_error(StatusCode::UNAUTHORIZED, "Invalid encryption key."),
        ConnectionError::NotFound => api_error(StatusCode::NOT_FOUND, "connection_not_found"),
        ConnectionError::Conflict { current_revision } => api_error_json(StatusCode::CONFLICT, json!({"error":"connection_version_conflict","current_revision":current_revision})),
        ConnectionError::LimitReached => api_error(StatusCode::BAD_REQUEST, "connection_limit_reached"),
        ConnectionError::Corrupt | ConnectionError::UnsupportedSchema | ConnectionError::Storage => api_error(StatusCode::INTERNAL_SERVER_ERROR, "connection_storage_unavailable"),
    }
}

fn canonical(policy: &ExternalConnectionsConfig, user: &str, url: &str) -> Result<String, HttpError> {
    agent_egress::validate_endpoint(policy, user, url)
        .map(|base| base.as_str().to_owned())
        .map_err(|err| match err {
            agent_egress::EgressError::InvalidUrl => api_error(StatusCode::BAD_REQUEST, "invalid_base_url"),
            _ => api_error(StatusCode::FORBIDDEN, "connection_target_forbidden"),
        })
}

async fn parse<T: for<'de> Deserialize<'de>>(body: Body) -> Result<T, HttpError> {
    let bytes = body::to_bytes(body, MAX_BODY_BYTES).await
        .map_err(|_| api_error(StatusCode::PAYLOAD_TOO_LARGE, "connection_body_too_large"))?;
    serde_json::from_slice(&bytes).map_err(|_| api_error(StatusCode::BAD_REQUEST, "invalid_connection_input"))
}

fn json_response(status: StatusCode, value: Value) -> Result<Response<Body>, HttpError> {
    let bytes = serde_json::to_vec(&value).map_err(|err| map_serialization_err(err, "agent_connections::serialize"))?;
    Response::builder().status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::CACHE_CONTROL, "no-store")
        .body(Body::from(bytes)).map_err(|err| map_response_build_err(err, "agent_connections::response"))
}

fn redacted(record: ConnectionRecord, connections: &ConnectionService, user: &str, key: &chatbot_core::enc_key::EncryptionKey, policy: &ExternalConnectionsConfig) -> Result<Value, HttpError> {
    let availability = if agent_egress::validate_endpoint(policy, user, &record.base_url).is_err() {
        json!({"status":"blocked_by_policy"})
    } else {
        let check = connections.last_check(user, key, record.id).map_err(map_connection)?;
        match check {
            Some(check) if connections.credentials(user, key, record.id).map_err(map_connection)?.0 == record.revision =>
                json!({"status":check.status,"version":check.version,"checked_at":check.checked_at}),
            _ => Value::Null,
        }
    };
    let mut value = created_projection(&record);
    value["last_check"] = availability;
    Ok(value)
}

pub async fn list(request: Request<Body>) -> Result<Response<Body>, HttpError> {
    let services = AppServices::from_extensions(request.extensions());
    let cookie = extract_cookie(request.headers());
    let data = context(&services, request.headers(), cookie.as_deref())?;
    let (verified, connections, policy) = authorized(&services, &data)?;
    let records = connections.list(verified.username(), verified.key()).map_err(map_connection)?;
    let records = records.into_iter().map(|record| redacted(record, &connections, verified.username(), verified.key(), &policy))
        .collect::<Result<Vec<_>, _>>()?;
    json_response(StatusCode::OK, json!(records))
}

fn created_projection(record: &ConnectionRecord) -> Value {
    json!({"id":record.id,"revision":record.revision,"name":record.name,"kind":record.kind,
        "base_url":record.base_url,"username":record.username,"has_password":record.has_password,
        "privacy_level":"non_private","last_check":Value::Null})
}

pub async fn create(request: Request<Body>) -> Result<Response<Body>, HttpError> {
    let (parts, body) = request.into_parts();
    let services = AppServices::from_extensions(&parts.extensions);
    let data = mutation_context(&services, &parts.headers)?;
    let (verified, connections, policy) = authorized(&services, &data)?;
    let mut semantic: Value = parse(body).await?;
    if let Some(url) = semantic.get("base_url").and_then(Value::as_str) {
        if let Ok(url) = canonical(&policy, verified.username(), url) {
            semantic["base_url"] = Value::String(url);
        }
    }
    let operation = operation_request(&parts.headers, "agent_connections.create", &semantic)?;
    let operations = services.connection_operations().expect("connection service operations");
    let _guard = match &operation {
        Some(operation) => Some(operations.flights.acquire(verified.username(), &operation.id).await),
        None => None,
    };
    let now = operations.clock.now_secs();
    if let Some(operation) = &operation {
        if let Some(receipt) = connections.receipt_read(verified.username(), verified.key(), |tx, owner| {
            connection_receipts::read(tx, owner, &operation.id, verified.key(), now)
        }).map_err(map_connection)? {
            return if receipt.matches(operation) { replay(&receipt) } else { Err(reused()) };
        }
    }
    let prepared = (|| {
        let input: CreateInput = serde_json::from_value(semantic).map_err(|_| api_error(StatusCode::BAD_REQUEST, "invalid_connection_input"))?;
        if input.kind != "opencode" { return Err(api_error(StatusCode::BAD_REQUEST, "invalid_connection_kind")); }
        let base_url = canonical(&policy, verified.username(), &input.base_url)?;
        Ok(ConnectionInput { name: input.name, base_url, username: input.username, password: input.password })
    })();
    let result = prepared.and_then(|input| {
        connections.create_with_hook(verified.username(), verified.key(), input, |tx, record| {
            if let Some(operation) = &operation {
                let receipt = Receipt::new(operation, ReceiptOutcome::Applied, 201,
                    serde_json::to_vec(&created_projection(record)).map_err(|_| ConnectionError::Storage)?, now);
                connection_receipts::write(tx, verified.username(), &receipt, verified.key(), now)?;
            }
            Ok(())
        }).map_err(map_connection)
    });
    match result {
        Ok(record) => json_response(StatusCode::CREATED, created_projection(&record)),
        Err(error) => {
            if let Some(operation) = &operation {
                if error.0 == StatusCode::BAD_REQUEST || error.0 == StatusCode::FORBIDDEN {
                    let receipt = Receipt::new(operation, ReceiptOutcome::Rejected, error.0.as_u16(),
                        serde_json::to_vec(&error.1.0).map_err(|err| map_serialization_err(err, "agent_connections::receipt"))?, now);
                    connections.receipt_write(verified.username(), verified.key(), |tx, owner| {
                        connection_receipts::write(tx, owner, &receipt, verified.key(), now)
                    }).map_err(map_connection)?;
                }
            }
            Err(error)
        }
    }
}

pub async fn update(request: Request<Body>) -> Result<Response<Body>, HttpError> {
    let (parts, body) = request.into_parts();
    let services = AppServices::from_extensions(&parts.extensions);
    let data = mutation_context(&services, &parts.headers)?;
    let (verified, connections, policy) = authorized(&services, &data)?;
    let id = parse_id(&parts.uri)?;
    let input: PatchInput = parse(body).await?;
    if input.kind.as_deref().is_some_and(|kind| kind != "opencode") { return Err(api_error(StatusCode::BAD_REQUEST, "invalid_connection_kind")); }
    // Resolve ownership before inspecting any supplied destination so foreign IDs
    // are indistinguishable from unknown ones even for disallowed URLs.
    let (_, current) = connections.credentials(verified.username(), verified.key(), id).map_err(map_connection)?;
    let base_url = match input.base_url {
        Some(url) => Some(canonical(&policy, verified.username(), &url)?),
        None => {
            canonical(&policy, verified.username(), &current.base_url)?;
            None
        }
    };
    let record = connections.update(verified.username(), verified.key(), id, input.expected_revision,
        ConnectionPatch {name: input.name, base_url, username: input.username, password: input.password}).map_err(map_connection)?;
    json_response(StatusCode::OK, redacted(record, &connections, verified.username(), verified.key(), &policy)?)
}

pub async fn delete(request: Request<Body>) -> Result<Response<Body>, HttpError> {
    let (parts, body) = request.into_parts();
    let services = AppServices::from_extensions(&parts.extensions);
    let data = mutation_context(&services, &parts.headers)?;
    let (verified, connections, _) = authorized(&services, &data)?;
    let id = parse_id(&parts.uri)?;
    let input: DeleteInput = parse(body).await?;
    connections.delete(verified.username(), verified.key(), id, input.expected_revision).map_err(map_connection)?;
    Response::builder().status(StatusCode::NO_CONTENT).header(header::CACHE_CONTROL, "no-store")
        .body(Body::empty()).map_err(|err| map_response_build_err(err, "agent_connections::delete"))
}

pub async fn check(request: Request<Body>) -> Result<Response<Body>, HttpError> {
    let (parts, body) = request.into_parts();
    let services = AppServices::from_extensions(&parts.extensions);
    let data = mutation_context(&services, &parts.headers)?;
    let (verified, connections, policy) = authorized(&services, &data)?;
    let id = parts.uri.path().strip_prefix("/agent_connections/")
        .and_then(|rest| rest.strip_suffix("/check"))
        .and_then(|id| id.parse().ok())
        .ok_or_else(|| api_error(StatusCode::NOT_FOUND, "connection_not_found"))?;
    let input: CheckInput = parse(body).await?;
    let user = verified.username();
    let key = verified.key();
    let (revision, credentials) = connections.credentials(user, key, id).map_err(map_connection)?;
    if revision != input.expected_revision {
        return Err(map_connection(ConnectionError::Conflict { current_revision: revision }));
    }
    canonical(&policy, user, &credentials.base_url)?;
    let _slot = check_slot(user)?;
    let user_owned = user.to_owned();
    let policy_owned = policy.clone();
    let deadline = Instant::now() + Duration::from_secs(10);
    let cancelled = Arc::new(AtomicBool::new(false));
    let worker_cancelled = cancelled.clone();
    let worker = tokio::task::spawn_blocking(move || {
        agent_egress::OpenCodeClient::new(
            agent_egress::DeadlineResolver::new(deadline, worker_cancelled.clone()),
            agent_egress::HealthTransport::new(deadline, worker_cancelled),
        )
            .check(&policy_owned, &user_owned, &credentials.base_url, &credentials.username, &credentials.password)
    });
    let outcome = tokio::time::timeout(Duration::from_secs(10), worker).await
        .map_err(|_| { cancelled.store(true, Ordering::Release); api_error(StatusCode::GATEWAY_TIMEOUT, "agent_timeout") })?
        .map_err(|_| api_error(StatusCode::BAD_GATEWAY, "agent_unavailable"))?;
    // Never publish a check result against a removed or rotated record. Policy
    // may also have changed while the network request was outstanding.
    let (current, current_credentials) = connections.credentials(user, key, id).map_err(map_connection)?;
    if current != revision {
        return Err(map_connection(ConnectionError::Conflict { current_revision: current }));
    }
    canonical(&app_config().external_connections, user, &current_credentials.base_url)?;
    let version = outcome.map_err(map_check)?;
    let observation = connections.record_check(user, key, id, revision, "reachable".into(), Some(version.clone())).map_err(map_connection)?;
    json_response(StatusCode::OK, json!({"status":"reachable","version":version,"checked_at":observation.checked_at}))
}

fn parse_id<T: std::str::FromStr>(uri: &axum::http::Uri) -> Result<T, HttpError> {
    uri.path().strip_prefix("/agent_connections/").and_then(|s| s.parse().ok())
        .ok_or_else(|| api_error(StatusCode::NOT_FOUND, "connection_not_found"))
}
