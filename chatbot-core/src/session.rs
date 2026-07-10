use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use dashmap::DashMap;
use once_cell::sync::Lazy;
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use serde_json::json;
use thiserror::Error;
use tracing::{debug, error, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CachedSetPayload {
    memory: String,
    system_prompt: String,
    history: Vec<(String, String)>,
    #[serde(default)]
    set_id: Option<String>,
}

use crate::{
    config::{self, ProviderConfig},
    enc_key::EncryptionKey,
    history::{
        HistoryError, HistoryService, PrepareCapture, SetId, SetSnapshot, SetVersion,
    },
    persistence::{DataPersistence, EncryptionMode, PersistenceError},
    user_store::{normalise_username, UserStore, UserStoreError, DEFAULT_TIER},
};

#[derive(Debug, Clone)]
pub struct ServiceResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct SessionContext {
    pub session_id: String,
    pub username: Option<String>,
}

#[derive(Debug, Clone)]
pub struct HomeBootstrap {
    pub session_id: String,
    pub username: Option<String>,
    pub csrf_token: String,
    pub set_cookie: String,
}

#[derive(Debug, Clone)]
pub struct LoginFinalize {
    pub session_id: String,
    pub set_cookie: String,
}

#[derive(Debug, Clone)]
pub struct LogoutFinalize {
    pub session_id: String,
    pub set_cookie: String,
}

#[derive(Debug, Error)]
pub enum SessionError {
    #[error("invalid session")]
    InvalidSession,
}

#[derive(Debug, Clone)]
pub struct ChatContext {
    pub session_id: String,
    pub username: Option<String>,
    pub set_name: String,
    pub set_id: Option<SetId>,
    pub set_version: Option<SetVersion>,
    pub memory_text: String,
    pub system_prompt: String,
    pub history: Vec<(String, String)>,
    pub encrypted: bool,
    pub model_name: String,
    pub provider: ProviderConfig,
    pub test_chunks: Option<Vec<String>>,
    pub send_thoughts: bool,
    /// Immutable prepare snapshot for authenticated durable commits.
    pub prepare_capture: Option<PrepareCapture>,
}

pub struct ChatPrepareResult {
    pub context: Option<ChatContext>,
    pub error: Option<ServiceResponse>,
}

pub struct ChatRequestData<'a> {
    pub message: &'a str,
    pub system_prompt: Option<&'a str>,
    pub set_name: Option<&'a str>,
    /// Preferred durable address for authenticated users; name is fallback only.
    pub set_id: Option<&'a str>,
    pub model_name: Option<&'a str>,
    pub encrypted: bool,
    pub send_thoughts: bool,
}

pub struct RegeneratePrepareResult {
    pub context: Option<ChatContext>,
    pub insertion_index: Option<usize>,
    pub error: Option<ServiceResponse>,
}

pub struct RegenerateRequestData<'a> {
    pub message: &'a str,
    pub system_prompt: Option<&'a str>,
    pub set_name: Option<&'a str>,
    /// Preferred durable address for authenticated users; name is fallback only.
    pub set_id: Option<&'a str>,
    pub model_name: Option<&'a str>,
    pub encrypted: bool,
    pub pair_index: Option<i32>,
    pub send_thoughts: bool,
}

const SESSION_COOKIE_NAME: &str = "session";
const SESSION_GUEST_PREFIX: &str = "guest_";
const CSRF_TOKEN_BYTES: usize = 32;
const COOKIE_TOKEN_BYTES: usize = 32;
const GUEST_TOKEN_BYTES: usize = 16;

#[derive(Clone)]
struct HttpSessionRecord {
    guest_id: String,
    username: Option<String>,
    csrf_token: String,
    last_used: Instant,
}

struct HttpSessionStore {
    sessions: Mutex<HashMap<String, HttpSessionRecord>>,
    timeout: Duration,
}

impl HttpSessionStore {
    fn global() -> &'static HttpSessionStore {
        static STORE: Lazy<HttpSessionStore> = Lazy::new(|| {
            let config = config::app_config();
            let timeout = Duration::from_secs(std::cmp::max(60, config.session_timeout));
            HttpSessionStore {
                sessions: Mutex::new(HashMap::new()),
                timeout,
            }
        });
        &STORE
    }

    fn clean_expired(&self, sessions: &mut HashMap<String, HttpSessionRecord>, now: Instant) {
        let timeout = self.timeout;
        sessions.retain(|_, record| now.duration_since(record.last_used) <= timeout);
    }

    fn new_record(&self, now: Instant) -> (String, HttpSessionRecord) {
        let cookie_value = random_token(COOKIE_TOKEN_BYTES);
        let guest_id = random_token(GUEST_TOKEN_BYTES);
        let csrf_token = random_token(CSRF_TOKEN_BYTES);

        (
            cookie_value,
            HttpSessionRecord {
                guest_id,
                username: None,
                csrf_token,
                last_used: now,
            },
        )
    }

    fn ensure_record(
        &self,
        sessions: &mut HashMap<String, HttpSessionRecord>,
        cookie_header: Option<&str>,
        now: Instant,
    ) -> (String, bool) {
        if let Some(cookie_value) = extract_session_cookie(cookie_header) {
            if let Some(record) = sessions.get_mut(&cookie_value) {
                if now.duration_since(record.last_used) <= self.timeout {
                    record.last_used = now;
                    return (cookie_value, false);
                }
            }
            sessions.remove(&cookie_value);
        }

        let (cookie_value, mut record) = self.new_record(now);
        record.last_used = now;
        sessions.insert(cookie_value.clone(), record);
        (cookie_value, true)
    }

    fn build_set_cookie(&self, value: &str) -> String {
        let max_age = self.timeout.as_secs().clamp(60, 31_536_000);
        let secure = if config::app_config().csrf {
            " Secure;"
        } else {
            ""
        };
        format!(
            "{SESSION_COOKIE_NAME}={value}; Path=/;{secure} HttpOnly; SameSite=Lax; Max-Age={max_age}"
        )
    }
}

fn random_token(size: usize) -> String {
    let mut bytes = vec![0u8; size];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn extract_session_cookie(header: Option<&str>) -> Option<String> {
    let header = header?;
    for part in header.split(';') {
        let trimmed = part.trim();
        if let Some(value) = trimmed.strip_prefix(SESSION_COOKIE_NAME) {
            if let Some(rest) = value.strip_prefix('=') {
                if !rest.is_empty() {
                    return Some(rest.to_string());
                }
            }
        }
    }
    None
}

fn session_identifier(record: &HttpSessionRecord) -> String {
    match record.username.as_deref() {
        Some(username) => username.to_string(),
        None => format!("{SESSION_GUEST_PREFIX}{}", record.guest_id),
    }
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut diff = 0u8;
    for (l, r) in left.iter().zip(right.iter()) {
        diff |= l ^ r;
    }
    diff == 0
}

pub fn prepare_home_context(cookie_header: Option<&str>) -> Result<HomeBootstrap, SessionError> {
    let store = HttpSessionStore::global();
    let mut sessions = store.sessions.lock().unwrap();
    let now = Instant::now();
    store.clean_expired(&mut sessions, now);

    let (cookie_value, _) = store.ensure_record(&mut sessions, cookie_header, now);
    let snapshot = sessions
        .get(&cookie_value)
        .expect("session record should exist")
        .clone();
    drop(sessions);

    let session_id = session_identifier(&snapshot);
    let username = snapshot.username.clone();
    let csrf_token = snapshot.csrf_token.clone();
    let set_cookie = store.build_set_cookie(&cookie_value);

    Ok(HomeBootstrap {
        session_id,
        username,
        csrf_token,
        set_cookie,
    })
}

pub fn validate_csrf_token(cookie_header: Option<&str>, token: Option<&str>) -> Result<bool, SessionError> {
    if !config::app_config().csrf {
        return Ok(true);
    }

    let Some(token) = token else {
        return Ok(false);
    };

    if token.is_empty() {
        return Ok(false);
    }

    let store = HttpSessionStore::global();
    let mut sessions = store.sessions.lock().unwrap();
    let now = Instant::now();
    store.clean_expired(&mut sessions, now);

    if let Some(cookie_value) = extract_session_cookie(cookie_header) {
        if let Some(record) = sessions.get_mut(&cookie_value) {
            if now.duration_since(record.last_used) > store.timeout {
                sessions.remove(&cookie_value);
                return Ok(false);
            }
            record.last_used = now;
            return Ok(constant_time_eq(
                record.csrf_token.as_bytes(),
                token.as_bytes(),
            ));
        }
    }

    Ok(false)
}

pub fn session_context(cookie_header: Option<&str>) -> Result<SessionContext, SessionError> {
    let store = HttpSessionStore::global();
    let mut sessions = store.sessions.lock().unwrap();
    let now = Instant::now();
    store.clean_expired(&mut sessions, now);

    let (cookie_value, _) = store.ensure_record(&mut sessions, cookie_header, now);
    let snapshot = sessions
        .get(&cookie_value)
        .expect("session record should exist")
        .clone();
    drop(sessions);

    let session_id = session_identifier(&snapshot);

    Ok(SessionContext {
        session_id,
        username: snapshot.username.clone(),
    })
}

pub fn finalize_login(
    cookie_header: Option<&str>,
    username: &str,
) -> Result<LoginFinalize, SessionError> {
    let store = HttpSessionStore::global();
    let mut sessions = store.sessions.lock().unwrap();
    let now = Instant::now();
    store.clean_expired(&mut sessions, now);

    if let Some(cookie_value) = extract_session_cookie(cookie_header) {
        sessions.remove(&cookie_value);
    }

    let (cookie_value, mut record) = store.new_record(now);
    record.username = Some(username.to_string());
    record.last_used = now;
    let session_id = session_identifier(&record);
    let set_cookie = store.build_set_cookie(&cookie_value);
    sessions.insert(cookie_value, record);
    drop(sessions);

    Ok(LoginFinalize {
        session_id,
        set_cookie,
    })
}

pub fn logout_user(cookie_header: Option<&str>) -> Result<LogoutFinalize, SessionError> {
    let store = HttpSessionStore::global();
    let mut sessions = store.sessions.lock().unwrap();
    let now = Instant::now();
    store.clean_expired(&mut sessions, now);

    if let Some(cookie_value) = extract_session_cookie(cookie_header) {
        sessions.remove(&cookie_value);
    }

    let (cookie_value, record) = store.new_record(now);
    let session_id = session_identifier(&record);
    let set_cookie = store.build_set_cookie(&cookie_value);
    sessions.insert(cookie_value, record);
    drop(sessions);

    Ok(LogoutFinalize {
        session_id,
        set_cookie,
    })
}

struct SessionData {
    memory: String,
    system_prompt: String,
    history: Vec<(String, String)>,
    /// Which durable set the in-memory cache currently mirrors (authed only).
    active_set_id: Option<SetId>,
    encrypted: bool,
    initialised: bool,
    last_used: Instant,
    cipher_blob: Option<Vec<u8>>,
    requires_cipher: bool,
}

struct SessionEntry {
    data: Mutex<SessionData>,
    locked: AtomicBool,
}

impl SessionEntry {
    fn new(default_prompt: &str, requires_cipher: bool) -> Self {
        Self {
            data: Mutex::new(SessionData {
                system_prompt: default_prompt.to_owned(),
                memory: String::new(),
                history: Vec::new(),
                active_set_id: None,
                encrypted: false,
                initialised: false,
                last_used: Instant::now(),
                cipher_blob: None,
                requires_cipher,
            }),
            locked: AtomicBool::new(false),
        }
    }

    fn try_lock(&self) -> bool {
        self.locked
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
    }

    fn unlock(&self) {
        self.locked.store(false, Ordering::SeqCst);
    }
}

struct SessionStore {
    entries: DashMap<String, Arc<SessionEntry>>,
    timeout: Duration,
    default_prompt: String,
}

impl SessionStore {
    fn global() -> &'static SessionStore {
        static STORE: Lazy<SessionStore> = Lazy::new(|| {
            let config = config::app_config();
            SessionStore {
                entries: DashMap::new(),
                timeout: Duration::from_secs(config.session_timeout),
                default_prompt: config.default_system_prompt.clone(),
            }
        });
        &STORE
    }

    fn clean_expired(&self) {
        let now = Instant::now();
        let timeout = self.timeout;
        self.entries.retain(|session_id, entry| {
            let data = entry.data.lock().unwrap();
            let expired = now.duration_since(data.last_used) > timeout;
            if expired {
                debug!(session_id, "dropping expired session from store");
            }
            !expired
        });
    }

    fn entry(&self, session_id: &str) -> Arc<SessionEntry> {
        if let Some(existing) = self.entries.get(session_id) {
            return Arc::clone(&existing);
        }

        let requires_cipher = !session_id.starts_with(SESSION_GUEST_PREFIX);
        let entry = Arc::new(SessionEntry::new(&self.default_prompt, requires_cipher));
        match self.entries.entry(session_id.to_string()) {
            dashmap::mapref::entry::Entry::Occupied(existing) => Arc::clone(&existing.get()),
            dashmap::mapref::entry::Entry::Vacant(vacant) => {
                let inserted = vacant.insert(entry);
                Arc::clone(&*inserted)
            }
        }
    }
}

fn build_json_response(status: u16, payload: serde_json::Value) -> ServiceResponse {
    let body = serde_json::to_vec(&payload).unwrap_or_else(|err| {
        error!(?err, "failed to serialise error payload");
        json!({"error": "internal server error"})
            .to_string()
            .into_bytes()
    });
    ServiceResponse {
        status,
        headers: vec![("Content-Type".to_string(), "application/json".to_string())],
        body,
    }
}

fn invalid_request(message: &str) -> ServiceResponse {
    build_json_response(400, json!({ "error": message }))
}

fn forbidden(message: &str) -> ServiceResponse {
    build_json_response(403, json!({ "error": message }))
}

fn unauthorized(message: &str) -> ServiceResponse {
    build_json_response(401, json!({ "error": message }))
}

fn server_error(message: &str) -> ServiceResponse {
    build_json_response(500, json!({ "error": message }))
}

pub fn release_session_lock(session_id: &str) {
    let store = SessionStore::global();
    if let Some(entry) = store.entries.get(session_id) {
        entry.unlock();
    }
}

fn seal_session_data(data: &mut SessionData, key: &[u8]) -> Result<(), ServiceResponse> {
    if !data.requires_cipher {
        return Ok(());
    }
    let payload = CachedSetPayload {
        memory: data.memory.clone(),
        system_prompt: data.system_prompt.clone(),
        history: data.history.clone(),
        set_id: data.active_set_id.map(|id| id.to_string()),
    };
    let json = serde_json::to_string(&payload)
        .map_err(|_| server_error("internal error while accessing chat history"))?;
    let encrypted = DataPersistence::encrypt_bytes(json.as_bytes(), EncryptionMode::Fernet(key))
        .map_err(|err| map_persistence_error("failed to seal session cache", &err))?;
    data.cipher_blob = Some(encrypted);
    data.memory.clear();
    data.system_prompt.clear();
    data.history.clear();
    Ok(())
}

fn unseal_session_data(
    data: &mut SessionData,
    key: &[u8],
    default_prompt: &str,
) -> Result<(), ServiceResponse> {
    if !data.requires_cipher {
        return Ok(());
    }
    let Some(blob) = data.cipher_blob.as_ref() else {
        if data.system_prompt.is_empty() {
            data.system_prompt = default_prompt.to_owned();
        }
        return Ok(());
    };
    let decrypted = DataPersistence::decrypt_bytes(blob, EncryptionMode::Fernet(key))
        .map_err(|err| map_persistence_error("failed to decrypt session cache", &err))?;
    let payload: CachedSetPayload = serde_json::from_slice(&decrypted)
        .map_err(|_| server_error("internal error while accessing chat history"))?;
    data.memory = payload.memory;
    data.system_prompt = payload.system_prompt;
    data.history = payload.history;
    data.active_set_id = payload
        .set_id
        .as_deref()
        .and_then(|s| SetId::parse(s).ok());
    Ok(())
}

pub fn validate_encryption_key_for_user(
    username: &str,
    key: Option<&EncryptionKey>,
) -> Result<(), ServiceResponse> {
    let Some(key) = key else {
        return Err(unauthorized("Encryption key required. Please unlock."));
    };

    let store =
        UserStore::new().map_err(|err| map_store_error("failed to open user store", &err))?;

    if store
        .has_key_verifier(username)
        .map_err(|err| map_store_error("failed to check key verifier", &err))?
    {
        if !store
            .verify_encryption_key(username, key.as_bytes())
            .map_err(|err| map_store_error("failed to verify encryption key", &err))?
        {
            return Err(unauthorized("Invalid encryption key."));
        }
    } else {
        store
            .ensure_key_verifier(username, key.as_bytes())
            .map_err(|_| unauthorized("Invalid encryption key."))?;
    }

    Ok(())
}

pub fn require_encryption_key<'a>(
    username: Option<&str>,
    key: Option<&'a EncryptionKey>,
) -> Result<Option<&'a EncryptionKey>, ServiceResponse> {
    match username {
        Some(name) => {
            validate_encryption_key_for_user(name, key)?;
            Ok(key)
        }
        None => Ok(None),
    }
}

// Additional chat/regenerate logic will be implemented here.

fn normalise_set_name(candidate: Option<&str>) -> Result<String, ServiceResponse> {
    DataPersistence::normalise_set_name(candidate).map_err(|_| invalid_request("invalid set name"))
}

fn resolve_default_prompt() -> String {
    SessionStore::global().default_prompt.clone()
}

fn initialise_session_data(
    data: &mut SessionData,
    session: &SessionContext,
    set_name: &str,
    key: Option<&EncryptionKey>,
) -> Result<(), ServiceResponse> {
    if let Some(username) = session.username.as_deref() {
        require_encryption_key(Some(username), key)?;
        let key_bytes = key.expect("validated encryption key").as_bytes();
        let username =
            normalise_username(username).map_err(|_| invalid_request("invalid session"))?;
        let persistence = DataPersistence::new()
            .map_err(|err| map_persistence_error("failed to open persistence store", &err))?;

        let loaded = persistence
            .load_set(
                &username,
                set_name,
                Some(EncryptionMode::Fernet(key_bytes)),
            )
            .map_err(|err| match err {
                PersistenceError::MissingEncryptionKey => {
                    unauthorized("Encryption key required. Please unlock.")
                }
                PersistenceError::InvalidSetName => invalid_request("invalid set name"),
                PersistenceError::DecryptionFailed => {
                    unauthorized("Invalid encryption key.")
                }
                other => map_persistence_error("failed to load user set", &other),
            })?;

        data.memory = loaded.memory;
        data.system_prompt = loaded.system_prompt;
        data.history = loaded.history;
        data.encrypted = loaded.encrypted;
    } else {
        if set_name != "default" {
            return Err(unauthorized("Login required for custom sets"));
        }
        data.memory.clear();
        data.system_prompt = resolve_default_prompt();
        data.history.clear();
        data.encrypted = false;
        data.cipher_blob = None;
    }

    data.initialised = true;
    data.last_used = Instant::now();
    Ok(())
}

fn persist_system_prompt(
    username: &str,
    set_name: &str,
    prompt: &str,
    key: &[u8],
) -> Result<(), ServiceResponse> {
    let persistence = DataPersistence::new()
        .map_err(|err| map_persistence_error("failed to open persistence store", &err))?;

    persistence
        .store_system_prompt(
            username,
            set_name,
            prompt,
            EncryptionMode::Fernet(key),
        )
        .map_err(|err| map_persistence_error("failed to persist system prompt", &err))
}

fn ensure_model_allowed(
    provider: &ProviderConfig,
    username: Option<&str>,
) -> Result<(), ServiceResponse> {
    let tier = provider
        .tier
        .as_deref()
        .unwrap_or(DEFAULT_TIER)
        .to_ascii_lowercase();
    if tier != "premium" {
        return Ok(());
    }

    let Some(username) = username else {
        return Err(forbidden("This model requires a Premium account"));
    };

    let user_store =
        UserStore::new().map_err(|err| map_store_error("failed to open user store", &err))?;
    let user_tier = user_store
        .user_tier(username)
        .map_err(|err| map_store_error("failed to resolve user tier", &err))?;

    if !user_tier.eq_ignore_ascii_case("premium") {
        return Err(forbidden("This model requires a Premium account"));
    }

    Ok(())
}

fn resolve_test_chunks(provider: &ProviderConfig) -> Option<Vec<String>> {
    if let Ok(env_value) = std::env::var("CHATBOT_TEST_OPENAI_CHUNKS") {
        match serde_json::from_str::<Vec<String>>(&env_value) {
            Ok(chunks) => return Some(chunks),
            Err(err) => {
                warn!(?err, "invalid CHATBOT_TEST_OPENAI_CHUNKS payload; ignoring");
            }
        }
    }
    provider.test_chunks.clone()
}

fn map_persistence_error(context: &str, err: &PersistenceError) -> ServiceResponse {
    error!(?err, "{context}");
    server_error("internal error while accessing chat history")
}

fn map_store_error(context: &str, err: &UserStoreError) -> ServiceResponse {
    error!(?err, "{context}");
    server_error("internal error while accessing user store")
}

pub fn chat_prepare(
    session: &SessionContext,
    request: &ChatRequestData<'_>,
    provider: &ProviderConfig,
    encryption_key: Option<&EncryptionKey>,
) -> ChatPrepareResult {
    let store = SessionStore::global();
    store.clean_expired();

    if request.message.trim().is_empty() {
        return ChatPrepareResult {
            context: None,
            error: Some(invalid_request("message is required")),
        };
    }

    let set_name = match normalise_set_name(request.set_name) {
        Ok(name) => name,
        Err(response) => {
            return ChatPrepareResult {
                context: None,
                error: Some(response),
            }
        }
    };
    let resolved_set_id = match parse_optional_set_id(request.set_id) {
        Ok(id) => id,
        Err(response) => {
            return ChatPrepareResult {
                context: None,
                error: Some(response),
            }
        }
    };

    let entry = store.entry(&session.session_id);
    if !entry.try_lock() {
        return ChatPrepareResult {
            context: None,
            error: Some(build_json_response(
                429,
                json!({
                    "error": "A response is currently being generated. Please wait and try again."
                }),
            )),
        };
    }

    let context = match build_chat_context(
        session,
        request,
        provider,
        &set_name,
        resolved_set_id,
        &entry,
        encryption_key,
    ) {
        Ok(ctx) => ctx,
        Err(response) => {
            entry.unlock();
            return ChatPrepareResult {
                context: None,
                error: Some(response),
            };
        }
    };

    ChatPrepareResult {
        context: Some(context),
        error: None,
    }
}

fn build_chat_context(
    session: &SessionContext,
    request: &ChatRequestData<'_>,
    provider: &ProviderConfig,
    set_name: &str,
    request_set_id: Option<SetId>,
    entry: &Arc<SessionEntry>,
    encryption_key: Option<&EncryptionKey>,
) -> Result<ChatContext, ServiceResponse> {
    let _default_prompt = resolve_default_prompt();
    let mut data = entry.data.lock().unwrap();
    data.last_used = Instant::now();

    let mut prepare_capture = None;
    let mut set_id = None;
    let mut set_version = None;
    let mut display_set_name = set_name.to_owned();

    if data.requires_cipher {
        let key = require_encryption_key(session.username.as_deref(), encryption_key)?;
        let key = key.expect("validated encryption key");
        let username = session.username.as_deref().expect("cipher requires user");

        let mut snapshot = load_history_snapshot(username, request_set_id, set_name, key)?;
        display_set_name = snapshot.display_name.clone();
        if let Some(prompt) = request.system_prompt {
            if prompt != snapshot.system_prompt {
                let new_v = HistoryService::global()
                    .map_err(map_history_error)?
                    .update_system_prompt(
                        username,
                        snapshot.set_id,
                        snapshot.version,
                        prompt,
                        key,
                    )
                    .map_err(map_history_error)?;
                snapshot.system_prompt = prompt.to_owned();
                snapshot.version = new_v;
            }
        }

        // Refresh session cache from durable snapshot (display only; not SoT for finalize).
        data.memory = snapshot.memory.clone();
        data.system_prompt = snapshot.system_prompt.clone();
        data.history = snapshot.history.clone();
        data.active_set_id = Some(snapshot.set_id);
        data.encrypted = true;
        data.initialised = true;
        let _ = seal_session_data(&mut data, key.as_bytes());

        set_id = Some(snapshot.set_id);
        set_version = Some(snapshot.version);
        prepare_capture = Some(PrepareCapture::from_snapshot(&snapshot));
    } else if !data.initialised {
        initialise_session_data(&mut data, session, set_name, None)?;
        if let Some(prompt) = request.system_prompt {
            data.system_prompt = prompt.to_owned();
        }
    } else if let Some(prompt) = request.system_prompt {
        data.system_prompt = prompt.to_owned();
    }

    ensure_model_allowed(provider, session.username.as_deref())?;
    data.encrypted = request.encrypted;

    let model_name = request
        .model_name
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| provider.provider_name.as_str())
        .to_string();

    let test_chunks = resolve_test_chunks(provider);

    let (memory_text, system_prompt, history) = if let Some(ref cap) = prepare_capture {
        (
            cap.memory.clone(),
            cap.system_prompt.clone(),
            cap.history.clone(),
        )
    } else {
        (
            data.memory.clone(),
            data.system_prompt.clone(),
            data.history.clone(),
        )
    };

    Ok(ChatContext {
        session_id: session.session_id.clone(),
        username: session.username.clone(),
        set_name: display_set_name,
        set_id,
        set_version,
        memory_text,
        system_prompt,
        history,
        encrypted: request.encrypted,
        model_name,
        provider: provider.clone(),
        test_chunks,
        send_thoughts: request.send_thoughts,
        prepare_capture,
    })
}

pub fn chat_finalize(
    session: &SessionContext,
    set_name: &str,
    user_message: &str,
    assistant_response: &str,
    encryption_key: Option<&EncryptionKey>,
) -> Vec<String> {
    chat_finalize_with_capture(
        session,
        set_name,
        user_message,
        assistant_response,
        encryption_key,
        None,
    )
}

/// Finalize chat using an optional prepare capture (preferred for authed users).
pub fn chat_finalize_with_capture(
    session: &SessionContext,
    set_name: &str,
    user_message: &str,
    assistant_response: &str,
    encryption_key: Option<&EncryptionKey>,
    prepare_capture: Option<PrepareCapture>,
) -> Vec<String> {
    let store = SessionStore::global();
    let mut extras = Vec::new();

    if let Some(entry) = store.entries.get(&session.session_id) {
        {
            let mut data = entry.data.lock().unwrap();
            data.last_used = Instant::now();

            if let Some(username) = session.username.as_deref() {
                match require_encryption_key(Some(username), encryption_key) {
                    Ok(Some(key)) => {
                        let commit = if let Some(capture) = prepare_capture.as_ref() {
                            HistoryService::global().and_then(|hs| {
                                hs.commit_chat_append(
                                    username,
                                    capture,
                                    user_message,
                                    assistant_response,
                                    key,
                                )
                            })
                        } else {
                            match load_history_snapshot(username, None, set_name, key) {
                                Ok(snap) => HistoryService::global().and_then(|hs| {
                                    hs.append_pair(
                                        username,
                                        snap.set_id,
                                        snap.version,
                                        user_message,
                                        assistant_response,
                                        key,
                                    )
                                }),
                                Err(_) => Err(HistoryError::Internal),
                            }
                        };
                        match commit {
                            Ok(_) => {
                                let reload_id = prepare_capture.as_ref().map(|c| c.set_id);
                                if let Ok(snap) =
                                    load_history_snapshot(username, reload_id, set_name, key)
                                {
                                    data.history = snap.history;
                                    data.memory = snap.memory;
                                    data.system_prompt = snap.system_prompt;
                                    data.active_set_id = Some(snap.set_id);
                                } else {
                                    data.history.push((
                                        user_message.to_owned(),
                                        assistant_response.to_owned(),
                                    ));
                                    if let Some(id) = reload_id {
                                        data.active_set_id = Some(id);
                                    }
                                }
                                if let Err(response) = seal_session_data(&mut data, key.as_bytes())
                                {
                                    error!(
                                        status = response.status,
                                        "failed to seal session cache after chat finalize"
                                    );
                                }
                            }
                            Err(HistoryError::Conflict { .. }) => {
                                extras.push(
                                    "\n[Error] Chat history conflict — reload the set and retry."
                                        .to_string(),
                                );
                            }
                            Err(err) => {
                                error!(?err, "failed to commit chat history");
                                extras.push("\n[Error] Failed to save chat history".to_string());
                            }
                        }
                    }
                    _ => {
                        extras.push(
                            "\n[Error] Failed to save chat history: missing encryption key"
                                .to_string(),
                        );
                    }
                }
            } else {
                data.history
                    .push((user_message.to_owned(), assistant_response.to_owned()));
            }
        }

        entry.unlock();
    }

    extras
}

fn parse_optional_set_id(raw: Option<&str>) -> Result<Option<SetId>, ServiceResponse> {
    match raw.map(str::trim).filter(|s| !s.is_empty()) {
        None => Ok(None),
        Some(s) => SetId::parse(s)
            .map(Some)
            .map_err(|_| invalid_request("invalid set_id")),
    }
}

fn load_history_snapshot(
    username: &str,
    set_id: Option<SetId>,
    set_name: &str,
    key: &EncryptionKey,
) -> Result<SetSnapshot, ServiceResponse> {
    let hs = HistoryService::global().map_err(map_history_error)?;
    if let Some(id) = set_id {
        return hs.load(username, id, key).map_err(map_history_error);
    }
    match hs.find_by_display_name(username, set_name, key) {
        Ok(Some(snap)) => Ok(snap),
        Ok(None) if set_name == "default" => hs
            .ensure_default_set(username, key)
            .map_err(map_history_error),
        Ok(None) => Err(invalid_request("invalid set name")),
        Err(err) => Err(map_history_error(err)),
    }
}

fn map_history_error(err: HistoryError) -> ServiceResponse {
    match err {
        HistoryError::MissingKey | HistoryError::DecryptFailed => {
            unauthorized("Encryption key required. Please unlock.")
        }
        HistoryError::NotFound => invalid_request("invalid set name"),
        HistoryError::Conflict { current_version } => build_json_response(
            409,
            json!({
                "error": "version_conflict",
                "current_version": current_version.get(),
            }),
        ),
        HistoryError::InvalidInput(msg) => invalid_request(msg),
        HistoryError::Forbidden => forbidden("forbidden"),
        HistoryError::Internal => {
            error!("history service internal error");
            server_error("internal error while accessing chat history")
        }
    }
}

pub fn regenerate_prepare(
    session: &SessionContext,
    request: &RegenerateRequestData<'_>,
    provider: &ProviderConfig,
    encryption_key: Option<&EncryptionKey>,
) -> RegeneratePrepareResult {
    let store = SessionStore::global();
    store.clean_expired();

    if request.message.trim().is_empty() {
        return RegeneratePrepareResult {
            context: None,
            insertion_index: None,
            error: Some(invalid_request("message is required")),
        };
    }

    let set_name = match normalise_set_name(request.set_name) {
        Ok(name) => name,
        Err(response) => {
            return RegeneratePrepareResult {
                context: None,
                insertion_index: None,
                error: Some(response),
            }
        }
    };
    let resolved_set_id = match parse_optional_set_id(request.set_id) {
        Ok(id) => id,
        Err(response) => {
            return RegeneratePrepareResult {
                context: None,
                insertion_index: None,
                error: Some(response),
            }
        }
    };

    let entry = store.entry(&session.session_id);
    if !entry.try_lock() {
        return RegeneratePrepareResult {
            context: None,
            insertion_index: None,
            error: Some(build_json_response(
                429,
                json!({
                    "error": "A response is currently being generated. Please wait and try again."
                }),
            )),
        };
    }

    match build_regenerate_context(
        session,
        request,
        provider,
        &set_name,
        resolved_set_id,
        &entry,
        encryption_key,
    ) {
        Ok((context, insertion_index)) => RegeneratePrepareResult {
            context: Some(context),
            insertion_index,
            error: None,
        },
        Err(response) => {
            entry.unlock();
            RegeneratePrepareResult {
                context: None,
                insertion_index: None,
                error: Some(response),
            }
        }
    }
}

fn build_regenerate_context(
    session: &SessionContext,
    request: &RegenerateRequestData<'_>,
    provider: &ProviderConfig,
    set_name: &str,
    request_set_id: Option<SetId>,
    entry: &Arc<SessionEntry>,
    encryption_key: Option<&EncryptionKey>,
) -> Result<(ChatContext, Option<usize>), ServiceResponse> {
    let mut data = entry.data.lock().unwrap();
    data.last_used = Instant::now();

    let mut prepare_capture = None;
    let mut set_id = None;
    let mut set_version = None;
    let mut full_history: Vec<(String, String)>;
    let memory_text: String;
    let system_prompt: String;
    let mut display_set_name = set_name.to_owned();

    if data.requires_cipher {
        let key = require_encryption_key(session.username.as_deref(), encryption_key)?;
        let key = key.expect("validated encryption key");
        let username = session.username.as_deref().expect("cipher requires user");
        let mut snapshot = load_history_snapshot(username, request_set_id, set_name, key)?;
        display_set_name = snapshot.display_name.clone();
        if let Some(prompt) = request.system_prompt {
            if prompt != snapshot.system_prompt {
                let new_v = HistoryService::global()
                    .map_err(map_history_error)?
                    .update_system_prompt(
                        username,
                        snapshot.set_id,
                        snapshot.version,
                        prompt,
                        key,
                    )
                    .map_err(map_history_error)?;
                snapshot.system_prompt = prompt.to_owned();
                snapshot.version = new_v;
            }
        }
        data.memory = snapshot.memory.clone();
        data.system_prompt = snapshot.system_prompt.clone();
        data.history = snapshot.history.clone();
        data.active_set_id = Some(snapshot.set_id);
        data.initialised = true;
        let _ = seal_session_data(&mut data, key.as_bytes());

        full_history = snapshot.history.clone();
        memory_text = snapshot.memory.clone();
        system_prompt = snapshot.system_prompt.clone();
        set_id = Some(snapshot.set_id);
        set_version = Some(snapshot.version);
        prepare_capture = Some(PrepareCapture::from_snapshot(&snapshot));
    } else {
        if !data.initialised {
            initialise_session_data(&mut data, session, set_name, None)?;
        }
        if let Some(prompt) = request.system_prompt {
            data.system_prompt = prompt.to_owned();
        }
        full_history = data.history.clone();
        memory_text = data.memory.clone();
        system_prompt = data.system_prompt.clone();
    }

    // Non-destructive: compute insertion index without mutating durable/shared history.
    // Fail fast on invalid indices so we never stream then fail commit.
    let insertion_index = if let Some(index) = request.pair_index {
        if index < 0 || (index as usize) >= full_history.len() {
            return Err(invalid_request("pair_index out of range"));
        }
        index as usize
    } else if full_history
        .last()
        .map(|(user, _)| user == request.message)
        .unwrap_or(false)
    {
        full_history.len().saturating_sub(1)
    } else {
        return Err(invalid_request(
            "pair_index is required when message is not the last user turn",
        ));
    };

    if let Some(cap) = prepare_capture.as_mut() {
        *cap = cap.clone().with_regenerate(insertion_index, request.message);
    }

    // Guest path: still adjust in-memory history for finalize insert semantics
    // (issue follow-up makes this non-destructive for guests too).
    if !data.requires_cipher {
        if insertion_index < data.history.len() {
            data.history.remove(insertion_index);
        }
    }

    ensure_model_allowed(provider, session.username.as_deref())?;
    data.encrypted = request.encrypted;

    let model_name = request
        .model_name
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| provider.provider_name.as_str())
        .to_string();

    let test_chunks = resolve_test_chunks(provider);

    let history = full_history.into_iter().take(insertion_index).collect();

    let context = ChatContext {
        session_id: session.session_id.clone(),
        username: session.username.clone(),
        set_name: display_set_name,
        set_id,
        set_version,
        memory_text,
        system_prompt,
        history,
        encrypted: request.encrypted,
        model_name,
        provider: provider.clone(),
        test_chunks,
        send_thoughts: request.send_thoughts,
        prepare_capture,
    };

    Ok((context, Some(insertion_index)))
}

pub fn regenerate_finalize(
    session: &SessionContext,
    set_name: &str,
    user_message: &str,
    assistant_response: &str,
    insertion_index: Option<usize>,
    encryption_key: Option<&EncryptionKey>,
) -> Vec<String> {
    regenerate_finalize_with_capture(
        session,
        set_name,
        user_message,
        assistant_response,
        insertion_index,
        encryption_key,
        None,
    )
}

pub fn regenerate_finalize_with_capture(
    session: &SessionContext,
    set_name: &str,
    user_message: &str,
    assistant_response: &str,
    insertion_index: Option<usize>,
    encryption_key: Option<&EncryptionKey>,
    prepare_capture: Option<PrepareCapture>,
) -> Vec<String> {
    let store = SessionStore::global();
    let mut extras = Vec::new();

    if let Some(entry) = store.entries.get(&session.session_id) {
        {
            let mut data = entry.data.lock().unwrap();
            data.last_used = Instant::now();

            if let Some(username) = session.username.as_deref() {
                match require_encryption_key(Some(username), encryption_key) {
                    Ok(Some(key)) => {
                        let commit = if let Some(mut capture) = prepare_capture.clone() {
                            if capture.insertion_index.is_none() {
                                if let Some(idx) = insertion_index {
                                    capture = capture.with_regenerate(idx, user_message);
                                }
                            }
                            HistoryService::global().and_then(|hs| {
                                hs.commit_regenerate(username, &capture, assistant_response, key)
                            })
                        } else {
                            match load_history_snapshot(username, None, set_name, key) {
                                Ok(snap) => {
                                    let mut cap = PrepareCapture::from_snapshot(&snap);
                                    if let Some(idx) = insertion_index {
                                        cap = cap.with_regenerate(idx, user_message);
                                    }
                                    HistoryService::global().and_then(|hs| {
                                        hs.commit_regenerate(
                                            username,
                                            &cap,
                                            assistant_response,
                                            key,
                                        )
                                    })
                                }
                                Err(_) => Err(HistoryError::Internal),
                            }
                        };
                        match commit {
                            Ok(_) => {
                                let reload_id = prepare_capture.as_ref().map(|c| c.set_id);
                                if let Ok(snap) =
                                    load_history_snapshot(username, reload_id, set_name, key)
                                {
                                    data.history = snap.history;
                                    data.memory = snap.memory;
                                    data.system_prompt = snap.system_prompt;
                                    data.active_set_id = Some(snap.set_id);
                                }
                                let _ = seal_session_data(&mut data, key.as_bytes());
                            }
                            Err(HistoryError::Conflict { .. }) => {
                                extras.push(
                                    "\n[Error] Chat history conflict — reload the set and retry."
                                        .to_string(),
                                );
                            }
                            Err(err) => {
                                error!(?err, "failed to commit regenerate history");
                                extras.push(
                                    "\n[Error] Failed to save chat history".to_string(),
                                );
                            }
                        }
                    }
                    _ => {
                        extras.push(
                            "\n[Error] Failed to save chat history: missing encryption key"
                                .to_string(),
                        );
                    }
                }
            } else {
                let pair = (user_message.to_owned(), assistant_response.to_owned());
                if let Some(index) = insertion_index {
                    if index <= data.history.len() {
                        data.history.insert(index, pair);
                    } else {
                        data.history.push(pair);
                    }
                } else {
                    data.history.push(pair);
                }
            }
        }

        entry.unlock();
    }

    extras
}

pub fn update_session_memory(session_id: &str, memory: &str) {
    let store = SessionStore::global();
    if let Some(entry) = store.entries.get(session_id) {
        let mut data = entry.data.lock().unwrap();
        data.memory = memory.to_owned();
        data.initialised = true;
        data.last_used = Instant::now();
    }
}

pub fn update_session_system_prompt(session_id: &str, prompt: &str) {
    let store = SessionStore::global();
    if let Some(entry) = store.entries.get(session_id) {
        let mut data = entry.data.lock().unwrap();
        data.system_prompt = prompt.to_owned();
        data.initialised = true;
        data.last_used = Instant::now();
    }
}

/// Update session memory only when the cache currently mirrors `set_id`.
pub fn update_session_memory_for_request(
    session_id: &str,
    username: &str,
    set_id: SetId,
    memory: &str,
    key: &EncryptionKey,
) -> Result<(), ServiceResponse> {
    let store = SessionStore::global();
    let entry = store.entry(session_id);
    let mut data = entry.data.lock().unwrap();
    validate_encryption_key_for_user(username, Some(key))?;
    let key_bytes = key.as_bytes();
    unseal_session_data(&mut data, key_bytes, &resolve_default_prompt())?;
    if data.active_set_id != Some(set_id) {
        // Durable store was updated; leave cache alone so another set stays intact.
        let _ = seal_session_data(&mut data, key_bytes);
        return Ok(());
    }
    data.memory = memory.to_owned();
    data.initialised = true;
    data.last_used = Instant::now();
    seal_session_data(&mut data, key_bytes)
}

/// Update session system prompt only when the cache currently mirrors `set_id`.
pub fn update_session_system_prompt_for_request(
    session_id: &str,
    username: &str,
    set_id: SetId,
    prompt: &str,
    key: &EncryptionKey,
) -> Result<(), ServiceResponse> {
    let store = SessionStore::global();
    let entry = store.entry(session_id);
    let mut data = entry.data.lock().unwrap();
    validate_encryption_key_for_user(username, Some(key))?;
    let key_bytes = key.as_bytes();
    unseal_session_data(&mut data, key_bytes, &resolve_default_prompt())?;
    if data.active_set_id != Some(set_id) {
        let _ = seal_session_data(&mut data, key_bytes);
        return Ok(());
    }
    data.system_prompt = prompt.to_owned();
    data.initialised = true;
    data.last_used = Instant::now();
    seal_session_data(&mut data, key_bytes)
}

pub fn replace_session_set(
    session_id: &str,
    username: Option<&str>,
    set_id: Option<SetId>,
    memory: &str,
    system_prompt: &str,
    history: &[(String, String)],
    encrypted: bool,
    key: Option<&EncryptionKey>,
) -> Result<(), ServiceResponse> {
    let store = SessionStore::global();
    let entry = store.entry(session_id);
    let mut data = entry.data.lock().unwrap();
    data.memory = memory.to_owned();
    data.system_prompt = system_prompt.to_owned();
    data.history = history.to_vec();
    data.active_set_id = set_id;
    data.encrypted = encrypted;
    data.initialised = true;
    data.last_used = Instant::now();

    if data.requires_cipher {
        require_encryption_key(username, key)?;
        let key_bytes = key.expect("validated encryption key").as_bytes();
        seal_session_data(&mut data, key_bytes)?;
    }

    Ok(())
}

pub fn session_history_for_request(
    session_id: &str,
    username: Option<&str>,
    key: Option<&EncryptionKey>,
) -> Result<Vec<(String, String)>, ServiceResponse> {
    let store = SessionStore::global();
    let Some(entry) = store.entries.get(session_id) else {
        return Ok(Vec::new());
    };
    let mut data = entry.data.lock().unwrap();
    if data.requires_cipher {
        require_encryption_key(username, key)?;
        let key_bytes = key.expect("validated encryption key").as_bytes();
        unseal_session_data(&mut data, key_bytes, &resolve_default_prompt())?;
    }
    Ok(data.history.clone())
}

/// Replace session history only when the cache currently mirrors `set_id` (authed).
pub fn set_session_history_for_request(
    session_id: &str,
    username: Option<&str>,
    set_id: Option<SetId>,
    history: Vec<(String, String)>,
    key: Option<&EncryptionKey>,
) -> Result<(), ServiceResponse> {
    let store = SessionStore::global();
    let Some(entry) = store.entries.get(session_id) else {
        return Ok(());
    };
    let mut data = entry.data.lock().unwrap();
    if let Some(expected) = set_id {
        if data.requires_cipher {
            if let Some(k) = key {
                let _ = unseal_session_data(&mut data, k.as_bytes(), &resolve_default_prompt());
            }
            if data.active_set_id != Some(expected) {
                if let Some(k) = key {
                    let _ = seal_session_data(&mut data, k.as_bytes());
                }
                return Ok(());
            }
        }
    }
    data.history = history;
    if let Some(id) = set_id {
        data.active_set_id = Some(id);
    }
    data.last_used = Instant::now();
    data.initialised = true;

    if data.requires_cipher {
        require_encryption_key(username, key)?;
        let key_bytes = key.expect("validated encryption key").as_bytes();
        seal_session_data(&mut data, key_bytes)?;
    }

    Ok(())
}

pub fn update_session_history(session_id: &str, history: &[(String, String)]) {
    let store = SessionStore::global();
    let entry = store.entry(session_id);
    let mut data = entry.data.lock().unwrap();
    data.history = history.to_owned();
    data.initialised = true;
    data.last_used = Instant::now();
}

pub fn session_history(session_id: &str) -> Vec<(String, String)> {
    let store = SessionStore::global();
    store
        .entries
        .get(session_id)
        .map(|entry| {
            let data = entry.data.lock().unwrap();
            data.history.clone()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn regenerate_truncates_future_context() {
        let session_id = "guest_test-session-regen";
        let history = vec![
            ("User1".to_string(), "AI1".to_string()),
            ("User2".to_string(), "AI2".to_string()),
            ("User3".to_string(), "AI3".to_string()),
        ];
        
        // Setup initial state
        SessionStore::global().entry(session_id);
        update_session_history(session_id, &history);
        
        let session = SessionContext {
            session_id: session_id.to_string(),
            username: None,
        };
        
        let provider = ProviderConfig {
            provider_name: "default".to_string(),
            provider_type: "openai".to_string(),
            tier: None,
            model_name: "default".to_string(),
            context_size: Some(4096),
            base_url: "http://localhost".to_string(),
            api_key: None,
            allowed_providers: vec![],
            request_timeout: None,
            test_chunks: None,
            search: false,
            xai_search: true,
        };

        let request = RegenerateRequestData {
            set_id: None,
            message: "User2",
            system_prompt: None,
            set_name: Some("default"),
            model_name: None,
            encrypted: false,
            pair_index: Some(1),
            send_thoughts: false,
        };

        let result = regenerate_prepare(&session, &request, &provider, None);
        assert!(result.error.is_none(), "regenerate_prepare failed: {:?}", result.error);
        
        let context = result.context.expect("context should be present");
        
        // The context sent to LLM should ONLY contain history BEFORE index 1
        assert_eq!(context.history.len(), 1, "Context history should have 1 item");
        assert_eq!(context.history[0].0, "User1");
        
        // The stored session history should contain everything except the removed item (User2)
        // So it should have User1 and User3
        let stored_history = session_history(session_id);
        assert_eq!(stored_history.len(), 2, "Stored history should have 2 items");
        assert_eq!(stored_history[0].0, "User1");
        assert_eq!(stored_history[1].0, "User3");
        
        // Cleanup
        release_session_lock(session_id);
    }
}
