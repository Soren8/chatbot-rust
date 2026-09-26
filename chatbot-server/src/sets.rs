use axum::{
    body::{self, Body},
    http::{header, Method, Request, Response, StatusCode},
};
use chatbot_core::{
    config::PrivacyLevel,
    chat_images,
    history::{self, HistoryError, HistoryService, SetId, SetVersion},
    session::MutationMirrorError,
};
use serde::Deserialize;
use serde_json::json;
use crate::http_error::{
    api_error, map_body_read_err, map_encryption_key_validation_err, map_json_parse_err,
    map_response_build_err, map_serialization_err, map_session_err, map_session_operation_err,
    HttpError,
};
use crate::identity::RequestIdentity;
use crate::request_context::{extract_cookie, extract_csrf};
use crate::services::AppServices;

#[derive(Deserialize, Default)]
struct SetRequest {
    #[serde(default)]
    set_name: Option<String>,
    #[serde(default)]
    set_id: Option<String>,
    #[serde(default)]
    expected_version: Option<u64>,
    /// Max pairs to return. Absent = full history (legacy clients / tests).
    #[serde(default)]
    limit: Option<usize>,
    /// Return pairs with index `< before` (older page). Absent = tail of history.
    #[serde(default)]
    before: Option<usize>,
    /// When true, strip image bytes from the JSON (`[IMAGE:]` markers only).
    /// The client loads previews via `GET /history_image/...?size=thumb`.
    #[serde(default)]
    thumbnails: Option<bool>,
}

#[derive(Deserialize)]
struct HistoryPairRequest {
    #[serde(default)]
    set_name: Option<String>,
    #[serde(default)]
    set_id: Option<String>,
    pair_index: i32,
    #[serde(default)]
    image_index: Option<usize>,
}

#[derive(Deserialize)]
struct RenameSetRequest {
    #[serde(default)]
    old_name: Option<String>,
    #[serde(default)]
    new_name: Option<String>,
    #[serde(default)]
    set_id: Option<String>,
    #[serde(default)]
    expected_version: Option<u64>,
}

#[derive(Deserialize, Default)]
struct ForkSetRequest {
    #[serde(default)]
    set_id: Option<String>,
    #[serde(default)]
    set_name: Option<String>,
    #[serde(default)]
    expected_version: Option<u64>,
    #[serde(default)]
    pair_index: Option<i32>,
    #[serde(default)]
    new_name: Option<String>,
}

#[derive(Deserialize)]
struct SetPrivacyRequest {
    set_id: String,
    expected_version: u64,
    privacy_level: PrivacyLevel,
}

pub async fn handle_set_privacy(request: Request<Body>) -> Result<Response<Body>, HttpError> {
    if request.method() != Method::POST {
        return Err(api_error(StatusCode::METHOD_NOT_ALLOWED, "Only POST allowed"));
    }

    let (parts, body) = request.into_parts();
    let services = AppServices::from_extensions(&parts.extensions);
    let identity = services.identity().clone();
    let chat = services.chat().clone();
    let headers = parts.headers;
    let bytes = body::to_bytes(body, 128 * 1024)
        .await
        .map_err(|err| map_body_read_err(err, "sets::set_privacy"))?;
    let payload: SetPrivacyRequest = serde_json::from_slice(&bytes)
        .map_err(|err| map_json_parse_err(err, "sets::set_privacy"))?;

    let cookie = extract_cookie(&headers);
    validate_csrf(&identity, cookie.as_deref(), extract_csrf(&headers))?;
    let context = crate::request_context::DataRequestContext::resolve(
        &identity,
        &headers,
        cookie.as_deref(),
        "sets::set_privacy::session",
    )?;
    let verified = context.require_authenticated(&chat)?;
    let id = SetId::parse(&payload.set_id)
        .map_err(|_| api_error(StatusCode::BAD_REQUEST, "invalid set_id"))?;
    let Some(_permit) = services.set_privacy().try_update(verified.username(), id) else {
        return build_json_response(StatusCode::CONFLICT, json!({"error":"privacy_busy"}));
    };
    let history = chat.history().map_err(history_error_to_http)?;
    match history.change_privacy_level(
        verified.username(),
        id,
        SetVersion(payload.expected_version),
        payload.privacy_level,
        verified.key(),
    ) {
        Ok(version) => {
            // Invalidate queued/cached voice tokens for this set while the
            // exclusive permit is still held; active synthesis holds a shared
            // permit and already forced privacy_busy above.
            services
                .pending_tts()
                .invalidate_owner_set(verified.username(), id);
            build_json_response(
                StatusCode::OK,
                json!({"status":"success","set_id":id.to_string(),"version":version.get(),"privacy_level":payload.privacy_level}),
            )
        }
        Err(HistoryError::Conflict { current_version }) => build_json_response(
            StatusCode::CONFLICT,
            json!({"error":"version_conflict","set_id":id.to_string(),"current_version":current_version.get()}),
        ),
        Err(err) => Err(history_error_to_http(err)),
    }
}

pub async fn handle_get_sets(
    request: Request<Body>,
) -> Result<Response<Body>, HttpError> {
    if request.method() != Method::GET {
        return Err(api_error(StatusCode::METHOD_NOT_ALLOWED, "Only GET allowed"));
    }

    let services = AppServices::from_extensions(request.extensions());
    let identity = services.identity().clone();
    let chat = services.chat().clone();
    let cookie_header = extract_cookie(request.headers());
    let data_context = crate::request_context::DataRequestContext::resolve(
        &identity,
        request.headers(),
        cookie_header.as_deref(),
        "sets::get_sets::session",
    )?;
    let verified = data_context.require_authenticated(&chat)?;
    let username = verified.username();
    let key = verified.key();

    let history = chat.history().map_err(history_error_to_http)?;
    // Single list_sets call. Decrypts sealed display names only; history blobs stay closed.
    let mut sets = history.list_sets(username, key).map_err(history_error_to_http)?;
    if sets.is_empty() {
        history
            .ensure_default_set(username, key)
            .map_err(history_error_to_http)?;
        sets = history.list_sets(username, key).map_err(history_error_to_http)?;
    }

    let payload = json!(sets
        .into_iter()
        .map(|s| {
            json!({
                "set_id": s.set_id.to_string(),
                "name": s.display_name,
                "version": s.version.get(),
                "modified": (s.updated_at as f64) / 1000.0,
                "created": (s.updated_at as f64) / 1000.0,
                "is_default": s.is_default,
                "encrypted": true
            })
        })
        .collect::<Vec<_>>());

    build_json_response(StatusCode::OK, payload)
}

pub async fn handle_create_set(
    request: Request<Body>,
) -> Result<Response<Body>, HttpError> {
    if request.method() != Method::POST {
        return Err(api_error(StatusCode::METHOD_NOT_ALLOWED, "Only POST allowed"));
    }

    let (parts, body) = request.into_parts();
    let services = AppServices::from_extensions(&parts.extensions);
    let identity = services.identity().clone();
    let chat = services.chat().clone();
    let headers = parts.headers;

    let body_bytes = body::to_bytes(body, 128 * 1024)
        .await
        .map_err(|err| map_body_read_err(err, "sets::create_set"))?;

    let payload = if body_bytes.is_empty() {
        SetRequest::default()
    } else {
        serde_json::from_slice::<SetRequest>(&body_bytes)
            .map_err(|err| map_json_parse_err(err, "sets::create_set"))?
    };

    let cookie_header = extract_cookie(&headers);
    let csrf_token = extract_csrf(&headers);
    validate_csrf(&identity, cookie_header.as_deref(), csrf_token)?;
    let data_context = crate::request_context::DataRequestContext::resolve(
        &identity,
        &headers,
        cookie_header.as_deref(),
        "sets::create_set::session",
    )?;
    let verified = data_context.require_authenticated(&chat)?;
    let username = verified.username();
    let key = verified.key();

    // Empty name = auto placeholder (`New Chat`, `New Chat 2`, ...). The first
    // chat message replaces it with a contextual name server-side.
    let set_name_raw = payload.set_name.unwrap_or_default();
    let set_name = if set_name_raw.trim().is_empty() {
        String::new()
    } else {
        match history::normalise_custom_set_name(&set_name_raw) {
            Ok(value) => value,
            Err(_) => {
                return build_json_response(
                    StatusCode::OK,
                    json!({
                        "status": "error",
                        "error": "Set already exists or invalid name"
                    }),
                );
            }
        }
    };

    let history = chat.history().map_err(history_error_to_http)?;
    match history.create_set(username, &set_name, key) {
        Ok(summary) => build_json_response(
            StatusCode::OK,
            json!({
                "status": "success",
                "set_id": summary.set_id.to_string(),
                "name": summary.display_name,
                "version": summary.version.get(),
            }),
        ),
        Err(HistoryError::InvalidInput(_)) => build_json_response(
            StatusCode::OK,
            json!({
                "status": "error",
                "error": "Set already exists or invalid name"
            }),
        ),
        Err(err) => Err(history_error_to_http(err)),
    }
}

pub async fn handle_delete_set(
    request: Request<Body>,
) -> Result<Response<Body>, HttpError> {
    if request.method() != Method::POST {
        return Err(api_error(StatusCode::METHOD_NOT_ALLOWED, "Only POST allowed"));
    }

    let (parts, body) = request.into_parts();
    let services = AppServices::from_extensions(&parts.extensions);
    let identity = services.identity().clone();
    let chat = services.chat().clone();
    let headers = parts.headers;

    let body_bytes = body::to_bytes(body, 128 * 1024)
        .await
        .map_err(|err| map_body_read_err(err, "sets::delete_set"))?;

    let payload = if body_bytes.is_empty() {
        SetRequest::default()
    } else {
        serde_json::from_slice::<SetRequest>(&body_bytes)
            .map_err(|err| map_json_parse_err(err, "sets::delete_set"))?
    };

    let cookie_header = extract_cookie(&headers);
    let csrf_token = extract_csrf(&headers);
    validate_csrf(&identity, cookie_header.as_deref(), csrf_token)?;
    let data_context = crate::request_context::DataRequestContext::resolve(
        &identity,
        &headers,
        cookie_header.as_deref(),
        "sets::delete_set::session",
    )?;
    let verified = data_context.require_authenticated(&chat)?;
    let username = verified.username();
    let key = verified.key();
    let history = chat.history().map_err(history_error_to_http)?;

    let snap = match resolve_set(
        &history,
        username,
        payload.set_id.as_deref(),
        payload.set_name.as_deref(),
        key,
    ) {
        Ok(s) => s,
        Err(err) => {
            return build_json_response(
                StatusCode::OK,
                json!({"status": "error", "error": err}),
            );
        }
    };

    if snap.is_default || snap.display_name == "default" {
        return build_json_response(
            StatusCode::OK,
            json!({"status": "error", "error": "Cannot delete set"}),
        );
    }

    let expected = payload
        .expected_version
        .map(SetVersion)
        .unwrap_or(snap.version);

    match history.delete_set(username, snap.set_id, expected, key) {
        Ok(()) => build_json_response(StatusCode::OK, json!({"status": "success"})),
        Err(HistoryError::Conflict { current_version }) => build_json_response(
            StatusCode::CONFLICT,
            json!({
                "error": "version_conflict",
                "set_id": snap.set_id.to_string(),
                "current_version": current_version.get(),
            }),
        ),
        Err(HistoryError::InvalidInput(_)) => build_json_response(
            StatusCode::OK,
            json!({"status": "error", "error": "Cannot delete set"}),
        ),
        Err(err) => Err(history_error_to_http(err)),
    }
}

pub async fn handle_rename_set(
    request: Request<Body>,
) -> Result<Response<Body>, HttpError> {
    if request.method() != Method::POST {
        return Err(api_error(StatusCode::METHOD_NOT_ALLOWED, "Only POST allowed"));
    }

    let (parts, body) = request.into_parts();
    let services = AppServices::from_extensions(&parts.extensions);
    let identity = services.identity().clone();
    let chat = services.chat().clone();
    let headers = parts.headers;

    let body_bytes = body::to_bytes(body, 128 * 1024)
        .await
        .map_err(|err| map_body_read_err(err, "sets::rename_set"))?;

    let payload: RenameSetRequest = serde_json::from_slice(&body_bytes)
        .map_err(|err| map_json_parse_err(err, "sets::rename_set"))?;

    let cookie_header = extract_cookie(&headers);
    let csrf_token = extract_csrf(&headers);
    validate_csrf(&identity, cookie_header.as_deref(), csrf_token)?;
    let data_context = crate::request_context::DataRequestContext::resolve(
        &identity,
        &headers,
        cookie_header.as_deref(),
        "sets::rename_set::session",
    )?;
    let verified = data_context.require_authenticated(&chat)?;
    let username = verified.username();
    let key = verified.key();
    let new_name_raw = payload.new_name.unwrap_or_default();
    let new_name = match history::normalise_custom_set_name(&new_name_raw) {
        Ok(v) => v,
        Err(_) => {
            return build_json_response(
                StatusCode::OK,
                json!({
                    "status": "error",
                    "error": "Invalid set name or set already exists"
                }),
            );
        }
    };

    let history = chat.history().map_err(history_error_to_http)?;
    let snap = match resolve_set(
        &history,
        username,
        payload.set_id.as_deref(),
        payload.old_name.as_deref(),
        key,
    ) {
        Ok(s) => s,
        Err(_) => {
            return build_json_response(
                StatusCode::OK,
                json!({
                    "status": "error",
                    "error": "Invalid set name or set already exists"
                }),
            );
        }
    };

    let expected = payload
        .expected_version
        .map(SetVersion)
        .unwrap_or(snap.version);

    match history.rename_set(username, snap.set_id, expected, &new_name, key) {
        Ok(version) => build_json_response(
            StatusCode::OK,
            json!({
                "status": "success",
                "set_id": snap.set_id.to_string(),
                "name": new_name,
                "version": version.get(),
            }),
        ),
        Err(HistoryError::Conflict { current_version }) => build_json_response(
            StatusCode::CONFLICT,
            json!({
                "error": "version_conflict",
                "set_id": snap.set_id.to_string(),
                "current_version": current_version.get(),
            }),
        ),
        Err(HistoryError::InvalidInput(_)) => build_json_response(
            StatusCode::OK,
            json!({
                "status": "error",
                "error": "Invalid set name or set already exists"
            }),
        ),
        Err(err) => Err(history_error_to_http(err)),
    }
}

pub async fn handle_load_set(
    request: Request<Body>,
) -> Result<Response<Body>, HttpError> {
    if request.method() != Method::POST {
        return Err(api_error(StatusCode::METHOD_NOT_ALLOWED, "Only POST allowed"));
    }

    let (parts, body) = request.into_parts();
    let services = AppServices::from_extensions(&parts.extensions);
    let identity = services.identity().clone();
    let chat = services.chat().clone();
    let headers = parts.headers;

    let body_bytes = body::to_bytes(body, 128 * 1024)
        .await
        .map_err(|err| map_body_read_err(err, "sets::load_set"))?;

    let payload = if body_bytes.is_empty() {
        SetRequest::default()
    } else {
        serde_json::from_slice::<SetRequest>(&body_bytes)
            .map_err(|err| map_json_parse_err(err, "sets::load_set"))?
    };

    let cookie_header = extract_cookie(&headers);
    let csrf_token = extract_csrf(&headers);
    validate_csrf(&identity, cookie_header.as_deref(), csrf_token)?;
    let data_context = crate::request_context::DataRequestContext::resolve(
        &identity,
        &headers,
        cookie_header.as_deref(),
        "sets::load_set::session",
    )?;
    if data_context.session().username.as_deref().is_none() {
        return Err(api_error(StatusCode::UNAUTHORIZED, "Not authenticated"));
    }
    let session = data_context.session();
    let key = data_context.unverified_encryption_key();
    let thumbnails = payload.thumbnails.unwrap_or(false);
    // Keep session set_id / memory / prompt in sync. Do not copy multi-MB history
    // into the session cipher (durable store is SoT for authed history).
    let loaded = match chat.apply_load_set(
        session,
        key,
        payload.set_id.as_deref(),
        payload.set_name.as_deref(),
        payload.limit,
        payload.before,
        thumbnails,
    ) {
        Ok(page) => page,
        Err(MutationMirrorError::Key(err)) => {
            return Err(map_encryption_key_validation_err(err));
        }
        Err(MutationMirrorError::InvalidSetId) => {
            return build_json_response(
                StatusCode::BAD_REQUEST,
                json!({"error": "invalid set_id"}),
            );
        }
        Err(MutationMirrorError::SetNotFound) => {
            return build_json_response(
                StatusCode::BAD_REQUEST,
                json!({"error": "set not found"}),
            );
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
    };

    let history_json = loaded
        .history
        .iter()
        .map(|(user, assistant)| json!([user, assistant]))
        .collect::<Vec<_>>();

    build_json_response(
        StatusCode::OK,
        json!({
            "set_id": loaded.set_id.to_string(),
            "name": loaded.display_name,
            "version": loaded.version.get(),
            "memory": loaded.memory,
            "system_prompt": loaded.system_prompt,
            "history": history_json,
            "history_start": loaded.history_start,
            "history_total": loaded.history_total,
            "has_more": loaded.has_more,
            "encrypted": true,
            "is_default": loaded.is_default,
        }),
    )
}

/// Return one history pair at full fidelity (for lightbox / edit / regenerate).
pub async fn handle_history_pair(
    request: Request<Body>,
) -> Result<Response<Body>, HttpError> {
    if request.method() != Method::POST {
        return Err(api_error(StatusCode::METHOD_NOT_ALLOWED, "Only POST allowed"));
    }

    let (parts, body) = request.into_parts();
    let services = AppServices::from_extensions(&parts.extensions);
    let identity = services.identity().clone();
    let chat = services.chat().clone();
    let headers = parts.headers;

    let body_bytes = body::to_bytes(body, 128 * 1024)
        .await
        .map_err(|err| map_body_read_err(err, "sets::history_pair"))?;

    let payload: HistoryPairRequest = serde_json::from_slice(&body_bytes)
        .map_err(|err| map_json_parse_err(err, "sets::history_pair"))?;

    if payload.pair_index < 0 {
        return build_json_response(
            StatusCode::BAD_REQUEST,
            json!({"error": "pair_index is required"}),
        );
    }
    let pair_index = payload.pair_index as usize;

    let cookie_header = extract_cookie(&headers);
    let csrf_token = extract_csrf(&headers);
    validate_csrf(&identity, cookie_header.as_deref(), csrf_token)?;
    let data_context = crate::request_context::DataRequestContext::resolve(
        &identity,
        &headers,
        cookie_header.as_deref(),
        "sets::history_pair::session",
    )?;

    if data_context.session().username.as_deref().is_some() {
        let verified = data_context.require_authenticated(&chat)?;
        let username = verified.username();
        let key = verified.key();
        let history = chat.history().map_err(history_error_to_http)?;
        let set_id = match resolve_set_id(
            &history,
            username,
            payload.set_id.as_deref(),
            payload.set_name.as_deref(),
            key,
        ) {
            Ok(id) => id,
            Err(msg) => {
                return build_json_response(StatusCode::BAD_REQUEST, json!({"error": msg}));
            }
        };
        if let Some(idx) = payload.image_index {
            return match history.load_image(username, set_id, pair_index, idx, key) {
                Ok((mime, bytes)) => {
                    let image_src = format!(
                        "data:{mime};base64,{}",
                        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, bytes)
                    );
                    build_json_response(
                        StatusCode::OK,
                        json!({
                            "set_id": set_id.to_string(),
                            "pair_index": pair_index,
                            "image_src": image_src,
                        }),
                    )
                }
                Err(_) => build_json_response(
                    StatusCode::NOT_FOUND,
                    json!({"error": "image not found"}),
                ),
            };
        }
        return match history.load_pair(username, set_id, pair_index, key) {
            Ok((version, (user, assistant))) => build_json_response(
                StatusCode::OK,
                json!({
                    "set_id": set_id.to_string(),
                    "version": version.get(),
                    "pair_index": pair_index,
                    "user": user,
                    "assistant": assistant,
                }),
            ),
            Err(_) => build_json_response(
                StatusCode::NOT_FOUND,
                json!({"error": "pair_index out of range"}),
            ),
        };
    }

    let guest_history = chat.session_history(&data_context.session().session_id);
    history_pair_json(&guest_history, pair_index, payload.image_index, None, None)
}

/// GET a stored attachment as a real image so the browser/WebView HTTP cache
/// can reuse it. Version in the path is a cache key only (not CAS).
///
/// `<img src>` cannot send `X-Enc-Key`; the client mirrors the key in a
/// Path=/history_image cookie (`hist_enc_key`).
pub async fn handle_history_image(
    request: Request<Body>,
) -> Result<Response<Body>, HttpError> {
    if request.method() != Method::GET {
        return Err(api_error(StatusCode::METHOD_NOT_ALLOWED, "Only GET allowed"));
    }

    let path = request.uri().path();
    let (set_id, _version, pair_index, image_index) = match parse_history_image_path(path) {
        Some(parts) => parts,
        None => {
            return build_json_response(
                StatusCode::BAD_REQUEST,
                json!({"error": "invalid history image path"}),
            );
        }
    };

    let services = AppServices::from_extensions(request.extensions());
    let identity = services.identity().clone();
    let chat = services.chat().clone();
    let headers = request.headers();
    let cookie_header = extract_cookie(headers);
    let data_context = crate::request_context::DataRequestContext::resolve_for_history_image(
        &identity,
        headers,
        cookie_header.as_deref(),
        "sets::history_image::session",
    )?;
    let verified = data_context.require_authenticated(&chat)?;
    let username = verified.username();
    let key = verified.key();
    let history = chat.history().map_err(history_error_to_http)?;
    let id = match SetId::parse(&set_id) {
        Ok(id) => id,
        Err(_) => {
            return build_json_response(
                StatusCode::BAD_REQUEST,
                json!({"error": "invalid set_id"}),
            );
        }
    };
    let want_thumb = uri_wants_thumb(request.uri().query());
    let loaded = if want_thumb {
        history.load_thumb(username, id, pair_index, image_index, key)
    } else {
        history.load_image(username, id, pair_index, image_index, key)
    };
    match loaded {
        Ok((mime, bytes)) => build_image_response(&mime, bytes),
        Err(_) => build_json_response(
            StatusCode::NOT_FOUND,
            json!({"error": "image not found"}),
        ),
    }
}

fn uri_wants_thumb(query: Option<&str>) -> bool {
    let Some(q) = query else {
        return false;
    };
    q.split('&').any(|part| {
        let part = part.trim();
        part == "size=thumb" || part == "thumb=1" || part == "thumb=true"
    })
}

fn parse_history_image_path(path: &str) -> Option<(String, u64, usize, usize)> {
    let rest = path.strip_prefix("/history_image/")?;
    let mut parts = rest.split('/');
    let set_id = parts.next()?.to_owned();
    if set_id.is_empty() {
        return None;
    }
    let version = parts.next()?.parse().ok()?;
    let pair_index = parts.next()?.parse().ok()?;
    let image_index = parts.next()?.parse().ok()?;
    if parts.next().is_some() {
        return None;
    }
    Some((set_id, version, pair_index, image_index))
}

fn history_pair_json(
    history: &[(String, String)],
    pair_index: usize,
    image_index: Option<usize>,
    set_id: Option<String>,
    version: Option<u64>,
) -> Result<Response<Body>, HttpError> {
    if pair_index >= history.len() {
        return build_json_response(
            StatusCode::NOT_FOUND,
            json!({"error": "pair_index out of range"}),
        );
    }
    let (user, assistant) = &history[pair_index];
    if let Some(idx) = image_index {
        let image_src = chat_images::nth_image_data_url(user, idx);
        if image_src.is_none() {
            return build_json_response(
                StatusCode::NOT_FOUND,
                json!({"error": "image not found"}),
            );
        }
        return build_json_response(
            StatusCode::OK,
            json!({
                "set_id": set_id,
                "version": version,
                "pair_index": pair_index,
                "image_src": image_src,
            }),
        );
    }
    build_json_response(
        StatusCode::OK,
        json!({
            "set_id": set_id,
            "version": version,
            "pair_index": pair_index,
            "user": user,
            "assistant": assistant,
        }),
    )
}

fn resolve_set_id(
    history: &HistoryService,
    username: &str,
    set_id: Option<&str>,
    set_name: Option<&str>,
    key: &chatbot_core::enc_key::EncryptionKey,
) -> Result<SetId, &'static str> {
    if let Some(id_str) = set_id.filter(|s| !s.trim().is_empty()) {
        return SetId::parse(id_str).map_err(|_| "invalid set_id");
    }
    Ok(resolve_set(history, username, None, set_name, key)?.set_id)
}

/// Fork a prefix of a set (inclusive `pair_index`) into a new set.
///
/// Copies memory, system prompt, and history with full fidelity. The source
/// set is untouched. Empty `new_name` auto-derives `<source> - branch`.
pub async fn handle_fork_set(
    request: Request<Body>,
) -> Result<Response<Body>, HttpError> {
    if request.method() != Method::POST {
        return Err(api_error(StatusCode::METHOD_NOT_ALLOWED, "Only POST allowed"));
    }

    let (parts, body) = request.into_parts();
    let services = AppServices::from_extensions(&parts.extensions);
    let identity = services.identity().clone();
    let chat = services.chat().clone();
    let headers = parts.headers;

    let body_bytes = body::to_bytes(body, 128 * 1024)
        .await
        .map_err(|err| map_body_read_err(err, "sets::fork_set"))?;

    let payload = if body_bytes.is_empty() {
        ForkSetRequest::default()
    } else {
        serde_json::from_slice::<ForkSetRequest>(&body_bytes)
            .map_err(|err| map_json_parse_err(err, "sets::fork_set"))?
    };

    let pair_index = match payload.pair_index {
        Some(i) if i >= 0 => i as usize,
        _ => {
            return build_json_response(
                StatusCode::BAD_REQUEST,
                json!({"status": "error", "error": "pair_index is required"}),
            );
        }
    };

    let cookie_header = extract_cookie(&headers);
    let csrf_token = extract_csrf(&headers);
    validate_csrf(&identity, cookie_header.as_deref(), csrf_token)?;
    let data_context = crate::request_context::DataRequestContext::resolve(
        &identity,
        &headers,
        cookie_header.as_deref(),
        "sets::fork_set::session",
    )?;
    let verified = data_context.require_authenticated(&chat)?;
    let username = verified.username();
    let key = verified.key();
    let history = chat.history().map_err(history_error_to_http)?;

    let source_id = match resolve_set_id(
        &history,
        username,
        payload.set_id.as_deref(),
        payload.set_name.as_deref(),
        key,
    ) {
        Ok(id) => id,
        Err(msg) => {
            return build_json_response(StatusCode::BAD_REQUEST, json!({"error": msg}));
        }
    };
    let _source_permit = services.set_privacy().content(username, source_id).await;
    let expected = payload.expected_version.map(SetVersion);
    let new_name = payload.new_name.as_deref().filter(|s| !s.trim().is_empty());

    match history.fork_set(username, source_id, expected, pair_index, new_name, key) {
        Ok(summary) => build_json_response(
            StatusCode::OK,
            json!({
                "status": "success",
                "set_id": summary.set_id.to_string(),
                "name": summary.display_name,
                "version": summary.version.get(),
            }),
        ),
        Err(HistoryError::Conflict { current_version }) => build_json_response(
            StatusCode::CONFLICT,
            crate::chat_utils::version_conflict_json(source_id, current_version),
        ),
        Err(HistoryError::InvalidInput("pair_index out of range")) => build_json_response(
            StatusCode::NOT_FOUND,
            json!({"status": "error", "error": "pair_index out of range"}),
        ),
        Err(HistoryError::InvalidInput(msg)) => build_json_response(
            StatusCode::BAD_REQUEST,
            json!({"status": "error", "error": msg}),
        ),
        Err(err) => Err(history_error_to_http(err)),
    }
}

fn resolve_set(
    history: &HistoryService,
    username: &str,
    set_id: Option<&str>,
    set_name: Option<&str>,
    key: &chatbot_core::enc_key::EncryptionKey,
) -> Result<chatbot_core::history::SetSnapshot, &'static str> {
    if let Some(id_str) = set_id.filter(|s| !s.trim().is_empty()) {
        let id = SetId::parse(id_str).map_err(|_| "invalid set_id")?;
        return history
            .load(username, id, key)
            .map_err(|_| "set not found");
    }
    let name = set_name.map(str::trim).filter(|s| !s.is_empty()).unwrap_or("default");
    match history.find_by_display_name(username, name, key) {
        Ok(Some(snap)) => Ok(snap),
        Ok(None) if name == "default" => history
            .ensure_default_set(username, key)
            .map_err(|_| "set not found"),
        Ok(None) => Err("set not found"),
        Err(_) => Err("set not found"),
    }
}

fn validate_csrf(
    identity: &RequestIdentity,
    cookie_header: Option<&str>,
    csrf_token: Option<&str>,
) -> Result<(), HttpError> {
    let valid = identity
        .validate_csrf_token(cookie_header, csrf_token)
        .map_err(|err| map_session_err(err, "sets::csrf"))?;

    if !valid {
        return Err(api_error(StatusCode::UNAUTHORIZED, "Invalid or missing CSRF token"));
    }

    Ok(())
}

fn history_error_to_http(err: HistoryError) -> HttpError {
    crate::chat_utils::history_error_to_http(err)
}

fn build_json_response(
    status: StatusCode,
    payload: serde_json::Value,
) -> Result<Response<Body>, HttpError> {
    if status == StatusCode::BAD_REQUEST {
        tracing::warn!(status = 400, body = %payload, "http 400");
    }
    let body = serde_json::to_vec(&payload)
        .map_err(|err| map_serialization_err(err, "sets::json_response"))?;

    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body))
        .map_err(|err| map_response_build_err(err, "sets::json_response"))
}

fn build_image_response(mime: &str, bytes: Vec<u8>) -> Result<Response<Body>, HttpError> {
    let len = bytes.len();
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, mime)
        .header(header::CACHE_CONTROL, "private, max-age=31536000, immutable")
        .header(header::CONTENT_LENGTH, len.to_string())
        .body(Body::from(bytes))
        .map_err(|err| map_response_build_err(err, "sets::image_response"))
}
