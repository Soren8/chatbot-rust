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
}

use crate::{
    config::{self, ProviderConfig},
    enc_key::EncryptionKey,
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
    pub memory_text: String,
    pub system_prompt: String,
    pub history: Vec<(String, String)>,
    pub encrypted: bool,
    pub model_name: String,
    pub provider: ProviderConfig,
    pub test_chunks: Option<Vec<String>>,
    pub send_thoughts: bool,
}

pub struct ChatPrepareResult {
    pub context: Option<ChatContext>,
    pub error: Option<ServiceResponse>,
}

pub struct ChatRequestData<'a> {
    pub message: &'a str,
    pub system_prompt: Option<&'a str>,
    pub set_name: Option<&'a str>,
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
    entry: &Arc<SessionEntry>,
    encryption_key: Option<&EncryptionKey>,
) -> Result<ChatContext, ServiceResponse> {
    let default_prompt = resolve_default_prompt();
    let mut data = entry.data.lock().unwrap();
    data.last_used = Instant::now();

    if data.requires_cipher {
        let key = require_encryption_key(session.username.as_deref(), encryption_key)?;
        let key_bytes = key.expect("validated encryption key").as_bytes();
        if !data.initialised {
            initialise_session_data(&mut data, session, set_name, encryption_key)?;
        } else {
            unseal_session_data(&mut data, key_bytes, &default_prompt)?;
        }

        if let Some(prompt) = request.system_prompt {
            if let Some(username) = session.username.as_deref() {
                persist_system_prompt(username, set_name, prompt, key_bytes)?;
            }
            data.system_prompt = prompt.to_owned();
        }
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

    Ok(ChatContext {
        session_id: session.session_id.clone(),
        username: session.username.clone(),
        set_name: set_name.to_owned(),
        memory_text: data.memory.clone(),
        system_prompt: data.system_prompt.clone(),
        history: data.history.clone(),
        encrypted: request.encrypted,
        model_name,
        provider: provider.clone(),
        test_chunks,
        send_thoughts: request.send_thoughts,
    })
}

pub fn chat_finalize(
    session: &SessionContext,
    set_name: &str,
    user_message: &str,
    assistant_response: &str,
    encryption_key: Option<&EncryptionKey>,
) -> Vec<String> {
    let store = SessionStore::global();
    let mut extras = Vec::new();

    if let Some(entry) = store.entries.get(&session.session_id) {
        {
            let mut data = entry.data.lock().unwrap();
            data.history
                .push((user_message.to_owned(), assistant_response.to_owned()));
            data.last_used = Instant::now();

            if let Some(username) = session.username.as_deref() {
                if let Ok(key) = require_encryption_key(Some(username), encryption_key) {
                    let key_bytes = key.expect("validated encryption key").as_bytes();
                    if let Err(msg) = persist_history(username, set_name, Some(key_bytes), &data.history)
                    {
                        extras.push(msg);
                    }
                    if let Err(response) = seal_session_data(&mut data, key_bytes) {
                        error!(status = response.status, "failed to seal session cache after chat finalize");
                    }
                } else {
                    extras.push("\n[Error] Failed to save chat history: missing encryption key".to_string());
                }
            }
        }

        entry.unlock();
    }

    extras
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
    entry: &Arc<SessionEntry>,
    encryption_key: Option<&EncryptionKey>,
) -> Result<(ChatContext, Option<usize>), ServiceResponse> {
    let default_prompt = resolve_default_prompt();
    let mut data = entry.data.lock().unwrap();
    data.last_used = Instant::now();

    if data.requires_cipher {
        let key = require_encryption_key(session.username.as_deref(), encryption_key)?;
        let key_bytes = key.expect("validated encryption key").as_bytes();
        if !data.initialised {
            initialise_session_data(&mut data, session, set_name, encryption_key)?;
        } else {
            unseal_session_data(&mut data, key_bytes, &default_prompt)?;
        }

        if let Some(prompt) = request.system_prompt {
            if let Some(username) = session.username.as_deref() {
                persist_system_prompt(username, set_name, prompt, key_bytes)?;
            }
            data.system_prompt = prompt.to_owned();
        }
    } else if !data.initialised {
        initialise_session_data(&mut data, session, set_name, None)?;
        if let Some(prompt) = request.system_prompt {
            data.system_prompt = prompt.to_owned();
        }
    } else if let Some(prompt) = request.system_prompt {
        data.system_prompt = prompt.to_owned();
    }

    let insertion_index = if let Some(index) = request.pair_index {
        if index >= 0 && (index as usize) < data.history.len() {
            data.history.remove(index as usize);
            Some(index as usize)
        } else {
            None
        }
    } else if data
        .history
        .last()
        .map(|(user, _)| user == request.message)
        .unwrap_or(false)
    {
        data.history.pop();
        Some(data.history.len())
    } else {
        None
    };

    ensure_model_allowed(provider, session.username.as_deref())?;
    data.encrypted = request.encrypted;

    let model_name = request
        .model_name
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| provider.provider_name.as_str())
        .to_string();

    let test_chunks = resolve_test_chunks(provider);

    let history = if let Some(index) = insertion_index {
        data.history.iter().take(index).cloned().collect()
    } else {
        data.history.clone()
    };

    let context = ChatContext {
        session_id: session.session_id.clone(),
        username: session.username.clone(),
        set_name: set_name.to_owned(),
        memory_text: data.memory.clone(),
        system_prompt: data.system_prompt.clone(),
        history,
        encrypted: request.encrypted,
        model_name,
        provider: provider.clone(),
        test_chunks,
        send_thoughts: request.send_thoughts,
    };

    Ok((context, insertion_index))
}

pub fn regenerate_finalize(
    session: &SessionContext,
    set_name: &str,
    user_message: &str,
    assistant_response: &str,
    insertion_index: Option<usize>,
    encryption_key: Option<&EncryptionKey>,
) -> Vec<String> {
    let store = SessionStore::global();
    let mut extras = Vec::new();

    if let Some(entry) = store.entries.get(&session.session_id) {
        {
            let mut data = entry.data.lock().unwrap();
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

            data.last_used = Instant::now();

            if let Some(username) = session.username.as_deref() {
                if let Ok(key) = require_encryption_key(Some(username), encryption_key) {
                    let key_bytes = key.expect("validated encryption key").as_bytes();
                    if let Err(msg) =
                        persist_history(username, set_name, Some(key_bytes), &data.history)
                    {
                        extras.push(msg);
                    }
                    if let Err(response) = seal_session_data(&mut data, key_bytes) {
                        error!(
                            status = response.status,
                            "failed to seal session cache after regenerate finalize"
                        );
                    }
                } else {
                    extras.push("\n[Error] Failed to save chat history: missing encryption key".to_string());
                }
            }
        }

        entry.unlock();
    }

    extras
}

fn persist_history(
    username: &str,
    set_name: &str,
    encryption_key: Option<&[u8]>,
    history: &[(String, String)],
) -> Result<(), String> {
    let Some(key) = encryption_key else {
        return Err("\n[Error] Failed to save chat history: missing encryption key".to_string());
    };

    let persistence = DataPersistence::new().map_err(|err| {
        error!(?err, "failed to open persistence store for chat history");
        "\n[Error] Unexpected error saving chat history".to_string()
    })?;

    persistence
        .store_history(username, set_name, history, EncryptionMode::Fernet(key))
        .map_err(|err| {
            error!(?err, "failed to persist chat history");
            "\n[Error] Failed to save chat history".to_string()
        })
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

pub fn update_session_memory_for_request(
    session_id: &str,
    username: &str,
    memory: &str,
    key: &EncryptionKey,
) -> Result<(), ServiceResponse> {
    let store = SessionStore::global();
    let entry = store.entry(session_id);
    let mut data = entry.data.lock().unwrap();
    validate_encryption_key_for_user(username, Some(key))?;
    let key_bytes = key.as_bytes();
    unseal_session_data(&mut data, key_bytes, &resolve_default_prompt())?;
    data.memory = memory.to_owned();
    data.initialised = true;
    data.last_used = Instant::now();
    seal_session_data(&mut data, key_bytes)
}

pub fn update_session_system_prompt_for_request(
    session_id: &str,
    username: &str,
    prompt: &str,
    key: &EncryptionKey,
) -> Result<(), ServiceResponse> {
    let store = SessionStore::global();
    let entry = store.entry(session_id);
    let mut data = entry.data.lock().unwrap();
    validate_encryption_key_for_user(username, Some(key))?;
    let key_bytes = key.as_bytes();
    unseal_session_data(&mut data, key_bytes, &resolve_default_prompt())?;
    data.system_prompt = prompt.to_owned();
    data.initialised = true;
    data.last_used = Instant::now();
    seal_session_data(&mut data, key_bytes)
}

pub fn replace_session_set(
    session_id: &str,
    username: Option<&str>,
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

pub fn set_session_history_for_request(
    session_id: &str,
    username: Option<&str>,
    history: Vec<(String, String)>,
    key: Option<&EncryptionKey>,
) -> Result<(), ServiceResponse> {
    let store = SessionStore::global();
    let Some(entry) = store.entries.get(session_id) else {
        return Ok(());
    };
    let mut data = entry.data.lock().unwrap();
    data.history = history;
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
