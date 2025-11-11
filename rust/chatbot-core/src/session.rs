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
use serde_json::json;
use thiserror::Error;
use tracing::{debug, error, warn};

use crate::{
    config::{self, ProviderConfig},
    persistence::{DataPersistence, EncryptionMode, PersistenceError},
    user_store::{normalise_username, UserStore, UserStoreError, DEFAULT_TIER},
};

#[derive(Debug, Clone)]
pub struct PythonResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct SessionContext {
    pub session_id: String,
    pub username: Option<String>,
    pub encryption_key: Option<Vec<u8>>,
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
    pub encryption_key: Option<Vec<u8>>,
    pub test_chunks: Option<Vec<String>>,
}

pub struct ChatPrepareResult {
    pub context: Option<ChatContext>,
    pub error: Option<PythonResponse>,
}

pub struct ChatRequestData<'a> {
    pub message: &'a str,
    pub system_prompt: Option<&'a str>,
    pub set_name: Option<&'a str>,
    pub model_name: Option<&'a str>,
    pub encrypted: bool,
}

pub struct RegeneratePrepareResult {
    pub context: Option<ChatContext>,
    pub insertion_index: Option<usize>,
    pub error: Option<PythonResponse>,
}

pub struct RegenerateRequestData<'a> {
    pub message: &'a str,
    pub system_prompt: Option<&'a str>,
    pub set_name: Option<&'a str>,
    pub model_name: Option<&'a str>,
    pub encrypted: bool,
    pub pair_index: Option<i32>,
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
    encryption_key: Option<Vec<u8>>,
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
                encryption_key: None,
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
        format!(
            "{SESSION_COOKIE_NAME}={value}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age={max_age}"
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

pub fn validate_csrf_token(cookie_header: Option<&str>, token: &str) -> Result<bool, SessionError> {
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
        encryption_key: snapshot.encryption_key.clone(),
    })
}

pub fn finalize_login(
    cookie_header: Option<&str>,
    username: &str,
    encryption_key: &[u8],
) -> Result<LoginFinalize, SessionError> {
    let store = HttpSessionStore::global();
    let mut sessions = store.sessions.lock().unwrap();
    let now = Instant::now();
    store.clean_expired(&mut sessions, now);

    let (cookie_value, _) = store.ensure_record(&mut sessions, cookie_header, now);
    let record = sessions
        .get_mut(&cookie_value)
        .expect("session record should exist");
    record.username = Some(username.to_string());
    record.encryption_key = Some(encryption_key.to_vec());
    record.last_used = now;
    let session_id = session_identifier(record);
    let set_cookie = store.build_set_cookie(&cookie_value);
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
    system_prompt: String,
    memory: String,
    history: Vec<(String, String)>,
    encrypted: bool,
    initialised: bool,
    last_used: Instant,
}

struct SessionEntry {
    data: Mutex<SessionData>,
    locked: AtomicBool,
}

impl SessionEntry {
    fn new(default_prompt: &str) -> Self {
        Self {
            data: Mutex::new(SessionData {
                system_prompt: default_prompt.to_owned(),
                memory: String::new(),
                history: Vec::new(),
                encrypted: false,
                initialised: false,
                last_used: Instant::now(),
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

        let entry = Arc::new(SessionEntry::new(&self.default_prompt));
        match self.entries.entry(session_id.to_string()) {
            dashmap::mapref::entry::Entry::Occupied(existing) => Arc::clone(&existing.get()),
            dashmap::mapref::entry::Entry::Vacant(vacant) => {
                let inserted = vacant.insert(entry);
                Arc::clone(&*inserted)
            }
        }
    }
}

fn build_json_response(status: u16, payload: serde_json::Value) -> PythonResponse {
    let body = serde_json::to_vec(&payload).unwrap_or_else(|err| {
        error!(?err, "failed to serialise error payload");
        json!({"error": "internal server error"})
            .to_string()
            .into_bytes()
    });
    PythonResponse {
        status,
        headers: vec![("Content-Type".to_string(), "application/json".to_string())],
        body,
    }
}

fn invalid_request(message: &str) -> PythonResponse {
    build_json_response(400, json!({ "error": message }))
}

fn forbidden(message: &str) -> PythonResponse {
    build_json_response(403, json!({ "error": message }))
}

fn unauthorized(message: &str) -> PythonResponse {
    build_json_response(401, json!({ "error": message }))
}

fn server_error(message: &str) -> PythonResponse {
    build_json_response(500, json!({ "error": message }))
}

pub fn release_session_lock(session_id: &str) {
    let store = SessionStore::global();
    if let Some(entry) = store.entries.get(session_id) {
        entry.unlock();
    }
}

// Additional chat/regenerate logic will be implemented here.

fn normalise_set_name(candidate: Option<&str>) -> Result<String, PythonResponse> {
    DataPersistence::normalise_set_name(candidate).map_err(|_| invalid_request("invalid set name"))
}

fn resolve_default_prompt() -> String {
    SessionStore::global().default_prompt.clone()
}

fn initialise_session_data(
    data: &mut SessionData,
    session: &SessionContext,
    set_name: &str,
) -> Result<(), PythonResponse> {
    if let Some(username) = session.username.as_deref() {
        let username =
            normalise_username(username).map_err(|_| invalid_request("invalid session"))?;
        let persistence = DataPersistence::new()
            .map_err(|err| map_persistence_error("failed to open persistence store", &err))?;

        let encryption_mode = session
            .encryption_key
            .as_ref()
            .map(|key| EncryptionMode::Fernet(key.as_slice()));

        let loaded = persistence
            .load_set(&username, set_name, encryption_mode)
            .map_err(|err| match err {
                PersistenceError::MissingEncryptionKey => {
                    unauthorized("Session expired or invalid. Please log in again.")
                }
                PersistenceError::InvalidSetName => invalid_request("invalid set name"),
                other => map_persistence_error("failed to load user set", &other),
            })?;

        data.memory = loaded.memory;
        data.system_prompt = loaded.system_prompt;
        data.history = loaded.history;
        data.encrypted = loaded.encrypted;
    } else {
        data.memory.clear();
        data.system_prompt = resolve_default_prompt();
        data.history.clear();
        data.encrypted = false;
    }

    data.initialised = true;
    data.last_used = Instant::now();
    Ok(())
}

fn persist_system_prompt(
    session: &SessionContext,
    set_name: &str,
    prompt: &str,
) -> Result<(), PythonResponse> {
    let Some(username) = session.username.as_deref() else {
        return Ok(());
    };

    let Some(key) = session.encryption_key.as_ref() else {
        return Err(unauthorized(
            "Session expired or invalid. Please log in again.",
        ));
    };

    let persistence = DataPersistence::new()
        .map_err(|err| map_persistence_error("failed to open persistence store", &err))?;

    persistence
        .store_system_prompt(
            username,
            set_name,
            prompt,
            EncryptionMode::Fernet(key.as_slice()),
        )
        .map_err(|err| map_persistence_error("failed to persist system prompt", &err))
}

fn ensure_model_allowed(
    provider: &ProviderConfig,
    username: Option<&str>,
) -> Result<(), PythonResponse> {
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

fn map_persistence_error(context: &str, err: &PersistenceError) -> PythonResponse {
    error!(?err, "{context}");
    server_error("internal error while accessing chat history")
}

fn map_store_error(context: &str, err: &UserStoreError) -> PythonResponse {
    error!(?err, "{context}");
    server_error("internal error while accessing user store")
}

pub fn chat_prepare(
    session: &SessionContext,
    request: &ChatRequestData<'_>,
    provider: &ProviderConfig,
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

    let context = match build_chat_context(session, request, provider, &set_name, &entry) {
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
) -> Result<ChatContext, PythonResponse> {
    let mut data = entry.data.lock().unwrap();
    data.last_used = Instant::now();

    if !data.initialised {
        initialise_session_data(&mut data, session, set_name)?;
    }

    if let Some(prompt) = request.system_prompt {
        persist_system_prompt(session, set_name, prompt)?;
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
        encryption_key: session.encryption_key.clone(),
        test_chunks,
    })
}

pub fn chat_finalize(
    session: &SessionContext,
    set_name: &str,
    user_message: &str,
    assistant_response: &str,
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
                if let Err(msg) = persist_history(
                    username,
                    set_name,
                    session.encryption_key.as_deref(),
                    &data.history,
                ) {
                    extras.push(msg);
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

    match build_regenerate_context(session, request, provider, &set_name, &entry) {
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
) -> Result<(ChatContext, Option<usize>), PythonResponse> {
    let mut data = entry.data.lock().unwrap();
    data.last_used = Instant::now();

    if !data.initialised {
        initialise_session_data(&mut data, session, set_name)?;
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

    if let Some(prompt) = request.system_prompt {
        persist_system_prompt(session, set_name, prompt)?;
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

    let context = ChatContext {
        session_id: session.session_id.clone(),
        username: session.username.clone(),
        set_name: set_name.to_owned(),
        memory_text: data.memory.clone(),
        system_prompt: data.system_prompt.clone(),
        history: data.history.clone(),
        encrypted: request.encrypted,
        model_name,
        provider: provider.clone(),
        encryption_key: session.encryption_key.clone(),
        test_chunks,
    };

    Ok((context, insertion_index))
}

pub fn regenerate_finalize(
    session: &SessionContext,
    set_name: &str,
    user_message: &str,
    assistant_response: &str,
    insertion_index: Option<usize>,
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
                if let Err(msg) = persist_history(
                    username,
                    set_name,
                    session.encryption_key.as_deref(),
                    &data.history,
                ) {
                    extras.push(msg);
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

pub fn update_session_history(session_id: &str, history: &[(String, String)]) {
    let store = SessionStore::global();
    if let Some(entry) = store.entries.get(session_id) {
        let mut data = entry.data.lock().unwrap();
        data.history = history.to_owned();
        data.initialised = true;
        data.last_used = Instant::now();
    }
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
