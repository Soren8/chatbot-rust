use std::{
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};

use dashmap::DashMap;
use once_cell::sync::{Lazy, OnceCell};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{debug, error, warn};

pub use crate::session_identity::{
    finalize_login, logout_user, prepare_home_context, rate_limit_identity, session_context,
    validate_csrf_token, HomeBootstrap, LoginFinalize, LogoutFinalize, SessionContext,
    SessionError,
};
use crate::session_identity::SESSION_GUEST_PREFIX;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CachedSetPayload {
    memory: String,
    system_prompt: String,
    history: Vec<(String, String)>,
    #[serde(default)]
    set_id: Option<String>,
}

use crate::{
    account_service::AccountService,
    config::{self, ProviderConfig},
    enc_key::EncryptionKey,
    fernet_crypto::{self, FernetError},
    history::{
        HistoryError, HistoryService, PrepareCapture, SetId, SetSnapshot, SetVersion,
    },
    user_store::{UserStoreError, DEFAULT_TIER},
};

#[derive(Debug, Clone)]
pub struct ServiceResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
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
    pub error: Option<PrepareError>,
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
    pub error: Option<PrepareError>,
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

/// Pure prepare-time validation failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrepareValidationError {
    MessageRequired,
    InvalidSetName,
    InvalidSetId,
    PairIndexOutOfRange,
    PairIndexRequired,
}

impl PrepareValidationError {
    pub fn message(&self) -> &'static str {
        match self {
            PrepareValidationError::MessageRequired => "message is required",
            PrepareValidationError::InvalidSetName => "invalid set name",
            PrepareValidationError::InvalidSetId => "invalid set_id",
            PrepareValidationError::PairIndexOutOfRange => "pair_index out of range",
            PrepareValidationError::PairIndexRequired => {
                "pair_index is required when message is not the last user turn"
            }
        }
    }
}

/// Policy gates evaluated during prepare (generation lock, model tier).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreparePolicyError {
    Busy,
    PremiumRequired,
}

impl PreparePolicyError {
    pub fn message(&self) -> &'static str {
        match self {
            PreparePolicyError::Busy => {
                "A response is currently being generated. Please wait and try again."
            }
            PreparePolicyError::PremiumRequired => "This model requires a Premium account",
        }
    }
}

/// Typed history failures from chat/regenerate prepare.
///
/// Narrow cloneable projection of [`HistoryError`] for the prepare path only:
/// `HistoryError` itself is not `Clone`, so [`PrepareError`] (which is
/// `Clone`) cannot carry it directly. Finalize paths keep matching on
/// `HistoryError`; other `ServiceResponse` carriers (encryption, store,
/// session init) are unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrepareHistoryError {
    Unauthorized,
    NotFound,
    Conflict { current_version: SetVersion },
    InvalidInput(&'static str),
    Forbidden,
    Internal,
}

impl PrepareHistoryError {
    /// Saved-turn message for 400 variants; other statuses map directly.
    pub fn saved_error_message(&self) -> Option<&'static str> {
        match self {
            PrepareHistoryError::NotFound => Some("invalid set name"),
            PrepareHistoryError::InvalidInput(msg) => Some(*msg),
            _ => None,
        }
    }
}

/// Prepare outcome: validation, policy and history failures are typed;
/// every other failure stays a carried service response.
#[derive(Debug, Clone)]
pub enum PrepareError {
    Validation(PrepareValidationError),
    Policy(PreparePolicyError),
    History(PrepareHistoryError),
    Service(ServiceResponse),
}

impl From<ServiceResponse> for PrepareError {
    fn from(response: ServiceResponse) -> Self {
        PrepareError::Service(response)
    }
}

impl From<PrepareHistoryError> for PrepareError {
    fn from(err: PrepareHistoryError) -> Self {
        PrepareError::History(err)
    }
}

/// Typed persistence outcome for chat/regenerate finalization.
///
/// Canonical result of the `*_finalize_outcome*` methods and the lease
/// `complete_*_outcome` methods. Production stream-error text is owned by the
/// server renderer; the legacy `Vec<String>` finalizers remain as
/// compatibility adapters rendering this outcome once with no extra IO.
///
/// Current contract:
/// - guest session write (append or replace) → `GuestUpdated` (no extras)
/// - durable commit `Ok` (mirror seal failure still succeeds) → `DurableCommitted` (no extras)
/// - missing session entry → `NoSession` (no-op, no extras)
/// - any key-gate failure (`Missing`/`Invalid`/`StoreUnavailable`) →
///   `KeyValidationFailed` (one shared missing-key string, intentionally)
/// - `HistoryError::Conflict` → `Conflict`
/// - `HistoryError::InvalidInput(msg)` → `InvalidInput(msg)`
/// - every other commit failure (including fallback snapshot `Internal` and
///   history-open failures) → `StoreFailure`
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FinalizeOutcome {
    GuestUpdated,
    DurableCommitted,
    NoSession,
    KeyValidationFailed,
    Conflict,
    InvalidInput(String),
    StoreFailure,
}

/// Compatibility-only rendering of a finalize outcome.
///
/// Production routes must use the server-owned renderer. This renders the
/// exact stream-error chunks for the legacy `Vec<String>` finalizers and
/// lease `complete_*` adapters.
fn render_finalize_outcome_compat(outcome: &FinalizeOutcome) -> Vec<String> {
    match outcome {
        FinalizeOutcome::GuestUpdated
        | FinalizeOutcome::DurableCommitted
        | FinalizeOutcome::NoSession => Vec::new(),
        FinalizeOutcome::KeyValidationFailed => vec![
            "\n[Error] Failed to save chat history: missing encryption key".to_string(),
        ],
        FinalizeOutcome::Conflict => vec![
            "\n[Error] Chat history conflict — reload the set and retry.".to_string(),
        ],
        FinalizeOutcome::InvalidInput(msg) => {
            vec![format!("\n[Error] Failed to save chat history: {msg}")]
        }
        FinalizeOutcome::StoreFailure => {
            vec!["\n[Error] Failed to save chat history".to_string()]
        }
    }
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

/// Owned chat session state: guest RAM mirror plus generation locks.
///
/// Two instances share nothing; production keeps one process-global instance
/// behind the free functions below. Authenticated durability stays with
/// `HistoryService` and key checks with `UserStore` (used by the
/// prepare/finalize and `*_for_request` paths, not by these owned methods).
pub struct ChatSessionStore {
    entries: DashMap<String, Arc<SessionEntry>>,
    timeout: Duration,
    default_prompt: String,
}

impl ChatSessionStore {
    /// Explicit owned construction from a raw `session_timeout` value and the
    /// default system prompt. Unlike `HttpSessionStore::new`, the timeout is
    /// kept raw (zero allowed, no 60s floor).
    pub fn new(timeout_secs: u64, default_prompt: String) -> Self {
        ChatSessionStore {
            entries: DashMap::new(),
            timeout: Duration::from_secs(timeout_secs),
            default_prompt,
        }
    }

    fn global() -> &'static ChatSessionStore {
        static STORE: Lazy<ChatSessionStore> = Lazy::new(|| {
            let config = config::app_config();
            ChatSessionStore::new(config.session_timeout, config.default_system_prompt.clone())
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

    /// Owned purge hook. Public so composed servers can purge the same
    /// instance that backs their router; the global delegate stays composed
    /// in `purge_expired_chat_sessions`.
    pub fn purge_expired(&self) -> usize {
        let before = self.entries.len();
        self.clean_expired();
        before.saturating_sub(self.entries.len())
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

    /// Owned session history read. Unknown sessions report empty history.
    pub fn history(&self, session_id: &str) -> Vec<(String, String)> {
        self.entries
            .get(session_id)
            .map(|entry| {
                let data = entry.data.lock().unwrap();
                data.history.clone()
            })
            .unwrap_or_default()
    }

    /// Owned history replace. Creates the session (seeded with this store's
    /// default prompt) when missing.
    pub fn update_history(&self, session_id: &str, history: &[(String, String)]) {
        let entry = self.entry(session_id);
        let mut data = entry.data.lock().unwrap();
        data.history = history.to_owned();
        data.initialised = true;
        data.last_used = Instant::now();
    }

    /// Owned memory read. Unknown sessions report empty memory.
    pub fn memory(&self, session_id: &str) -> String {
        self.entries
            .get(session_id)
            .map(|entry| entry.data.lock().unwrap().memory.clone())
            .unwrap_or_default()
    }

    /// Owned memory replace. No-op when the session does not exist.
    pub fn update_memory(&self, session_id: &str, memory: &str) {
        if let Some(entry) = self.entries.get(session_id) {
            let mut data = entry.data.lock().unwrap();
            data.memory = memory.to_owned();
            data.initialised = true;
            data.last_used = Instant::now();
        }
    }

    /// Owned system-prompt read. Unknown sessions report empty; created
    /// sessions start at this store's default prompt.
    pub fn system_prompt(&self, session_id: &str) -> String {
        self.entries
            .get(session_id)
            .map(|entry| entry.data.lock().unwrap().system_prompt.clone())
            .unwrap_or_default()
    }

    /// Owned system-prompt replace. No-op when the session does not exist.
    pub fn update_system_prompt(&self, session_id: &str, prompt: &str) {
        if let Some(entry) = self.entries.get(session_id) {
            let mut data = entry.data.lock().unwrap();
            data.system_prompt = prompt.to_owned();
            data.initialised = true;
            data.last_used = Instant::now();
        }
    }

    /// Default system prompt seeding new sessions in this store.
    pub fn default_prompt(&self) -> &str {
        &self.default_prompt
    }

    /// Owned generation-lock acquire. Creates the session when missing, like
    /// the prepare path. Returns false when the session is already locked.
    pub fn try_acquire_generation(&self, session_id: &str) -> bool {
        self.entry(session_id).try_lock()
    }

    /// Owned generation-lock release. No-op when the session does not exist.
    pub fn release_generation(&self, session_id: &str) {
        if let Some(entry) = self.entries.get(session_id) {
            entry.unlock();
        }
    }
}

/// Owned chat orchestration: session RAM mirror plus durable history plus
/// account checks.
///
/// Concrete composition root for chat/regenerate prepare/finalize and the
/// authenticated mirror helpers. `Clone` shares one `Arc` of owned
/// dependencies; two services built from separate stores/roots share
/// nothing even for the same session IDs.
///
/// Compatibility: [`ChatService::global`] constructs a handle that touches
/// neither config nor any store. Each of its operations delegates to the
/// existing process-global stores with their lazy first-use timing untouched
/// (per-call account stores plus live verifier secret,
/// `HistoryService::global`, `ChatSessionStore::global`). Owned handles
/// ([`ChatService::new`]) use only their explicit stores/accounts and the
/// session store's default prompt, and never read ambient config, except
/// [`resolve_test_chunks`], which intentionally keeps the explicit
/// `CHATBOT_TEST_OPENAI_CHUNKS` env plus `provider.test_chunks`
/// compatibility hook on both paths.
///
/// Only the HMAC verifier secret is stored via the account service; no live
/// data-key is retained.
#[derive(Clone)]
pub struct ChatService {
    owned: Option<Arc<OwnedChatDependencies>>,
}

struct OwnedChatDependencies {
    sessions: Arc<ChatSessionStore>,
    history: OwnedHistory,
    accounts: AccountService,
}

/// Owned durable history: either a ready service or a lazily opened one.
///
/// The lazy variant opens `{data_root}/history/redb` via
/// `HistoryService::open_with_data_dir` on first `history()` use with
/// `get_or_try_init` retry semantics: a failed open leaves the cell empty so
/// the next request retries instead of freezing the failure, and a missing
/// database never fails process startup.
enum OwnedHistory {
    Ready(Arc<HistoryService>),
    Lazy(LazyOwnedHistory),
}

struct LazyOwnedHistory {
    cell: OnceCell<HistoryService>,
    redb_path: PathBuf,
    data_dir: PathBuf,
    default_prompt: String,
}

impl ChatService {
    /// Explicit owned construction from concrete dependencies. Touches no
    /// config/store; inputs are used as-is. The default prompt stays owned
    /// by `sessions` (see `ChatSessionStore::new`).
    pub fn new(
        sessions: Arc<ChatSessionStore>,
        history: Arc<HistoryService>,
        account_root: PathBuf,
        verifier_secret: String,
    ) -> Self {
        Self::new_with_accounts(
            sessions,
            history,
            AccountService::with_root_and_secret(account_root, verifier_secret),
        )
    }

    /// Explicit owned construction sharing an [`AccountService`] for key/tier
    /// gates. Touches no config/store; inputs are used as-is.
    pub fn new_with_accounts(
        sessions: Arc<ChatSessionStore>,
        history: Arc<HistoryService>,
        accounts: AccountService,
    ) -> Self {
        Self {
            owned: Some(Arc::new(OwnedChatDependencies {
                sessions,
                history: OwnedHistory::Ready(history),
                accounts,
            })),
        }
    }

    /// Owned construction with lazily opened durable history.
    ///
    /// `data_root` is the host data dir containing `history/redb` plus the
    /// legacy `user_sets/` migration tree; `account_root` is the explicit
    /// account store root (same `HOST_DATA_DIR` semantics as `UserStore::new`
    /// when both are the production host dir, separate temp roots in tests).
    /// `verifier_secret` is the explicit HMAC secret (production
    /// `secret_key`). Constructing this touches neither config nor any store;
    /// the first `history()` call opens via
    /// `HistoryService::open_with_data_dir` with `get_or_try_init` retry, so a
    /// database failure is fallible per request and never fatal at startup,
    /// and the same database file is never opened twice by this service.
    /// The history default prompt is taken from `sessions.default_prompt()`.
    pub fn with_storage(
        sessions: Arc<ChatSessionStore>,
        data_root: PathBuf,
        account_root: PathBuf,
        verifier_secret: String,
    ) -> Self {
        Self::with_storage_and_accounts(
            sessions,
            data_root,
            AccountService::with_root_and_secret(account_root, verifier_secret),
        )
    }

    /// Owned construction with lazily opened durable history sharing an
    /// [`AccountService`] for key/tier gates.
    ///
    /// `data_root` is the host data dir containing `history/redb` plus the
    /// legacy `user_sets/` migration tree. Constructing this touches neither
    /// config nor any store; history opens lazily with `get_or_try_init`
    /// retry. The history default prompt is taken from
    /// `sessions.default_prompt()`.
    pub fn with_storage_and_accounts(
        sessions: Arc<ChatSessionStore>,
        data_root: PathBuf,
        accounts: AccountService,
    ) -> Self {
        let default_prompt = sessions.default_prompt().to_owned();
        let redb_path = data_root.join("history").join("redb");
        Self {
            owned: Some(Arc::new(OwnedChatDependencies {
                sessions,
                history: OwnedHistory::Lazy(LazyOwnedHistory {
                    cell: OnceCell::new(),
                    redb_path,
                    data_dir: data_root,
                    default_prompt,
                }),
                accounts,
            })),
        }
    }

    /// Compatibility handle. Constructing it touches neither config nor any
    /// store; each operation resolves the existing process-global dependencies
    /// lazily, preserving per-call `UserStore::new`/live-secret timing and
    /// first-use freezes.
    pub fn global() -> Self {
        Self { owned: None }
    }

    /// Session store, resolving the owned store or the process-global store
    /// lazily for server composition.
    pub fn sessions(&self) -> &ChatSessionStore {
        match &self.owned {
            Some(deps) => deps.sessions.as_ref(),
            None => ChatSessionStore::global(),
        }
    }

    /// Durable history, resolving the owned service or the process-global
    /// service lazily for server composition.
    pub fn history(&self) -> Result<&HistoryService, HistoryError> {
        match &self.owned {
            Some(deps) => match &deps.history {
                OwnedHistory::Ready(history) => Ok(history.as_ref()),
                OwnedHistory::Lazy(lazy) => lazy.cell.get_or_try_init(|| {
                    HistoryService::open_with_data_dir(
                        &lazy.redb_path,
                        &lazy.data_dir,
                        lazy.default_prompt.clone(),
                    )
                }),
            },
            None => HistoryService::global(),
        }
    }

    /// Account service backing key/tier gates: the owned service or the
    /// process-global accounts, resolved lazily per operation.
    fn accounts(&self) -> AccountService {
        match self.owned.as_ref() {
            Some(deps) => deps.accounts.clone(),
            None => AccountService::global(),
        }
    }

    fn default_prompt_resolved(&self) -> String {
        self.sessions().default_prompt().to_owned()
    }

    fn history_for_prepare(&self) -> Result<&HistoryService, PrepareHistoryError> {
        self.history().map_err(map_history_to_prepare)
    }

    fn history_for_commit(&self) -> Result<&HistoryService, HistoryError> {
        self.history()
    }

    /// Owned key validation through the shared account service. The global
    /// handle preserves the original per-call open plus live-secret timing
    /// with the same single-has-plus-single-verify reads; the owned handle
    /// opens its explicit root with its explicit secret.
    pub fn validate_encryption_key_for_user(
        &self,
        username: &str,
        key: Option<&EncryptionKey>,
    ) -> Result<(), EncryptionKeyValidationError> {
        let Some(key) = key else {
            return Err(EncryptionKeyValidationError::Missing);
        };
        let store = self
            .accounts()
            .users()
            .map_err(|err| map_store_unavailable("failed to open user store", &err))?;
        if !store
            .has_key_verifier(username)
            .map_err(|err| map_store_unavailable("failed to check key verifier", &err))?
        {
            return Err(EncryptionKeyValidationError::Missing);
        }
        if !store
            .verify_encryption_key(username, key.as_bytes())
            .map_err(|err| map_store_unavailable("failed to verify encryption key", &err))?
        {
            return Err(EncryptionKeyValidationError::Invalid);
        }
        Ok(())
    }

    /// Owned key gate: same 401/500 strings as the free adapter, via the
    /// owned/global validator above.
    pub fn require_encryption_key<'a>(
        &self,
        username: Option<&str>,
        key: Option<&'a EncryptionKey>,
    ) -> Result<Option<&'a EncryptionKey>, ServiceResponse> {
        match username {
            Some(name) => match self.validate_encryption_key_for_user(name, key) {
                Ok(()) => Ok(key),
                Err(EncryptionKeyValidationError::Missing) => {
                    Err(unauthorized("Encryption key required. Please unlock."))
                }
                Err(EncryptionKeyValidationError::Invalid) => {
                    Err(unauthorized("Invalid encryption key."))
                }
                Err(EncryptionKeyValidationError::StoreUnavailable) => {
                    Err(server_error("internal error while accessing user store"))
                }
            },
            None => Ok(None),
        }
    }

    fn ensure_model_allowed(
        &self,
        provider: &ProviderConfig,
        username: Option<&str>,
    ) -> Result<(), PrepareError> {
        let tier = provider
            .tier
            .as_deref()
            .unwrap_or(DEFAULT_TIER)
            .to_ascii_lowercase();
        if tier != "premium" {
            return Ok(());
        }
        let Some(username) = username else {
            return Err(PrepareError::Policy(PreparePolicyError::PremiumRequired));
        };
        let user_store = self
            .accounts()
            .users()
            .map_err(|err| map_store_error("failed to open user store", &err))?;
        let user_tier = user_store
            .user_tier(username)
            .map_err(|err| map_store_error("failed to resolve user tier", &err))?;
        if !user_tier.eq_ignore_ascii_case("premium") {
            return Err(PrepareError::Policy(PreparePolicyError::PremiumRequired));
        }
        Ok(())
    }

    fn load_history_snapshot(
        &self,
        username: &str,
        set_id: Option<SetId>,
        set_name: &str,
        key: &EncryptionKey,
    ) -> Result<SetSnapshot, PrepareHistoryError> {
        let hs = self.history_for_prepare()?;
        if let Some(id) = set_id {
            return hs.load(username, id, key).map_err(map_history_to_prepare);
        }
        match hs.find_by_display_name(username, set_name, key) {
            Ok(Some(snap)) => Ok(snap),
            Ok(None) if set_name == "default" => hs
                .ensure_default_set(username, key)
                .map_err(map_history_to_prepare),
            Ok(None) => Err(history_not_found()),
            Err(err) => Err(map_history_to_prepare(err)),
        }
    }

    /// Guest-only session bootstrap. Authenticated users always load via HistoryService.
    fn initialise_session_data(
        &self,
        data: &mut SessionData,
        session: &SessionContext,
        set_name: &str,
        _key: Option<&EncryptionKey>,
    ) -> Result<(), ServiceResponse> {
        if session.username.is_some() {
            // Authed paths must use HistoryService + PrepareCapture, not sets.json.
            return Err(invalid_request(
                "authenticated session must load via history store",
            ));
        }
        if set_name != "default" {
            return Err(unauthorized("Login required for custom sets"));
        }
        data.memory.clear();
        data.system_prompt = self.default_prompt_resolved();
        data.history.clear();
        data.encrypted = false;
        data.cipher_blob = None;
        data.active_set_id = None;
        data.initialised = true;
        data.last_used = Instant::now();
        Ok(())
    }
}

impl ChatService {
    fn build_chat_context(
        &self,
        session: &SessionContext,
        request: &ChatRequestData<'_>,
        provider: &ProviderConfig,
        set_name: &str,
        request_set_id: Option<SetId>,
        entry: &Arc<SessionEntry>,
        encryption_key: Option<&EncryptionKey>,
    ) -> Result<ChatContext, PrepareError> {
        let _default_prompt = self.default_prompt_resolved();
        let mut data = entry.data.lock().unwrap();
        data.last_used = Instant::now();

        let mut prepare_capture = None;
        let mut set_id = None;
        let mut set_version = None;
        let mut display_set_name = set_name.to_owned();

        if data.requires_cipher {
            let key = self.require_encryption_key(session.username.as_deref(), encryption_key)?;
            let key = key.expect("validated encryption key");
            let username = session.username.as_deref().expect("cipher requires user");

            let mut snapshot =
                self.load_history_snapshot(username, request_set_id, set_name, key)?;
            display_set_name = snapshot.display_name.clone();
            if let Some(prompt) = request.system_prompt {
                if prompt != snapshot.system_prompt {
                    let new_v = self
                        .history_for_prepare()?
                        .update_system_prompt(
                            username,
                            snapshot.set_id,
                            snapshot.version,
                            prompt,
                            key,
                        )
                        .map_err(map_history_to_prepare)?;
                    snapshot.system_prompt = prompt.to_owned();
                    snapshot.version = new_v;
                }
            }

            // Session mirror keeps small fields only; full history is not Fernet-sealed
            // (durable HistoryService is SoT). Avoid cloning multi-MB history into RAM here.
            data.memory = snapshot.memory.clone();
            data.system_prompt = snapshot.system_prompt.clone();
            data.history.clear();
            data.active_set_id = Some(snapshot.set_id);
            data.encrypted = true;
            data.initialised = true;
            let _ = seal_session_data(&mut data, key.as_bytes());

            set_id = Some(snapshot.set_id);
            set_version = Some(snapshot.version);
            prepare_capture = Some(PrepareCapture::from_snapshot(&snapshot));
        } else if !data.initialised {
            self.initialise_session_data(&mut data, session, set_name, None)?;
            if let Some(prompt) = request.system_prompt {
                data.system_prompt = prompt.to_owned();
            }
        } else if let Some(prompt) = request.system_prompt {
            data.system_prompt = prompt.to_owned();
        }

        self.ensure_model_allowed(provider, session.username.as_deref())?;
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

    /// Owned chat prepare: same empty-message clean-expired-first, key-before-history,
    /// guest-default, lock, and capture ordering as the compatibility delegate.
    pub fn chat_prepare(
        &self,
        session: &SessionContext,
        request: &ChatRequestData<'_>,
        provider: &ProviderConfig,
        encryption_key: Option<&EncryptionKey>,
    ) -> ChatPrepareResult {
        let store = self.sessions();
        store.clean_expired();

        if request.message.trim().is_empty() {
            return ChatPrepareResult {
                context: None,
                error: Some(validation_failed(
                    PrepareValidationError::MessageRequired,
                )),
            };
        }

        let set_name = match normalise_set_name(request.set_name) {
            Ok(name) => name,
            Err(err) => {
                return ChatPrepareResult {
                    context: None,
                    error: Some(err),
                }
            }
        };
        let resolved_set_id = match parse_optional_set_id(request.set_id) {
            Ok(id) => id,
            Err(err) => {
                return ChatPrepareResult {
                    context: None,
                    error: Some(err),
                }
            }
        };

        let entry = store.entry(&session.session_id);
        if !entry.try_lock() {
            return ChatPrepareResult {
                context: None,
                error: Some(PrepareError::Policy(PreparePolicyError::Busy)),
            };
        }

        let context = match self.build_chat_context(
            session,
            request,
            provider,
            &set_name,
            resolved_set_id,
            &entry,
            encryption_key,
        ) {
            Ok(ctx) => ctx,
            Err(err) => {
                entry.unlock();
                return ChatPrepareResult {
                    context: None,
                    error: Some(err),
                };
            }
        };

        ChatPrepareResult {
            context: Some(context),
            error: None,
        }
    }

    /// Owned chat finalize with capture: commit then mirror then unlock, with the
    /// same capture-vs-fallback, conflict/invalid/internal outcome, and logging.
    ///
    /// Canonical typed API. The legacy `Vec<String>` wrapper renders this
    /// outcome once with no extra IO.
    pub fn chat_finalize_outcome_with_capture(
        &self,
        session: &SessionContext,
        set_name: &str,
        user_message: &str,
        assistant_response: &str,
        encryption_key: Option<&EncryptionKey>,
        prepare_capture: Option<PrepareCapture>,
    ) -> FinalizeOutcome {
        let store = self.sessions();
        let mut outcome = FinalizeOutcome::NoSession;

        if let Some(entry) = store.entries.get(&session.session_id) {
            {
                let mut data = entry.data.lock().unwrap();
                data.last_used = Instant::now();

                if let Some(username) = session.username.as_deref() {
                    match self.require_encryption_key(Some(username), encryption_key) {
                        Ok(Some(key)) => {
                            let commit = if let Some(capture) = prepare_capture.as_ref() {
                                self.history_for_commit().and_then(|hs| {
                                    hs.commit_chat_append(
                                        username,
                                        capture,
                                        user_message,
                                        assistant_response,
                                        key,
                                    )
                                })
                            } else {
                                match self.load_history_snapshot(username, None, set_name, key) {
                                    Ok(snap) => self.history_for_commit().and_then(|hs| {
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
                                    // Cache already updated by HistoryService; do not re-load
                                    // multi-MB history into the session just to seal empty.
                                    if let Some(cap) = prepare_capture.as_ref() {
                                        data.active_set_id = Some(cap.set_id);
                                        data.memory = cap.memory.clone();
                                        data.system_prompt = cap.system_prompt.clone();
                                    }
                                    data.history.clear();
                                    if let Err(response) =
                                        seal_session_data(&mut data, key.as_bytes())
                                    {
                                        error!(
                                            status = response.status,
                                            "failed to seal session cache after chat finalize"
                                        );
                                    }
                                    outcome = FinalizeOutcome::DurableCommitted;
                                }
                                Err(HistoryError::Conflict { .. }) => {
                                    outcome = FinalizeOutcome::Conflict;
                                }
                                Err(HistoryError::InvalidInput(msg)) => {
                                    error!(%msg, "failed to commit chat history");
                                    outcome = FinalizeOutcome::InvalidInput(msg.to_owned());
                                }
                                Err(err) => {
                                    error!(?err, "failed to commit chat history");
                                    outcome = FinalizeOutcome::StoreFailure;
                                }
                            }
                        }
                        _ => {
                            outcome = FinalizeOutcome::KeyValidationFailed;
                        }
                    }
                } else {
                    data.history
                        .push((user_message.to_owned(), assistant_response.to_owned()));
                    outcome = FinalizeOutcome::GuestUpdated;
                }
            }

            entry.unlock();
        }

        outcome
    }

    /// Owned chat finalize with capture (compatibility adapter).
    ///
    /// Renders the typed outcome once with no extra IO. New code should use
    /// [`ChatService::chat_finalize_outcome_with_capture`] plus the
    /// server-owned renderer.
    pub fn chat_finalize_with_capture(
        &self,
        session: &SessionContext,
        set_name: &str,
        user_message: &str,
        assistant_response: &str,
        encryption_key: Option<&EncryptionKey>,
        prepare_capture: Option<PrepareCapture>,
    ) -> Vec<String> {
        let outcome = self.chat_finalize_outcome_with_capture(
            session,
            set_name,
            user_message,
            assistant_response,
            encryption_key,
            prepare_capture,
        );
        render_finalize_outcome_compat(&outcome)
    }

    /// Owned chat finalize outcome without a prepare capture (fallback path).
    pub fn chat_finalize_outcome(
        &self,
        session: &SessionContext,
        set_name: &str,
        user_message: &str,
        assistant_response: &str,
        encryption_key: Option<&EncryptionKey>,
    ) -> FinalizeOutcome {
        self.chat_finalize_outcome_with_capture(
            session,
            set_name,
            user_message,
            assistant_response,
            encryption_key,
            None,
        )
    }

    /// Owned chat finalize without a prepare capture (fallback path,
    /// compatibility adapter).
    pub fn chat_finalize(
        &self,
        session: &SessionContext,
        set_name: &str,
        user_message: &str,
        assistant_response: &str,
        encryption_key: Option<&EncryptionKey>,
    ) -> Vec<String> {
        self.chat_finalize_with_capture(
            session,
            set_name,
            user_message,
            assistant_response,
            encryption_key,
            None,
        )
    }

    fn build_regenerate_context(
        &self,
        session: &SessionContext,
        request: &RegenerateRequestData<'_>,
        provider: &ProviderConfig,
        set_name: &str,
        request_set_id: Option<SetId>,
        entry: &Arc<SessionEntry>,
        encryption_key: Option<&EncryptionKey>,
    ) -> Result<(ChatContext, Option<usize>), PrepareError> {
        let mut data = entry.data.lock().unwrap();
        data.last_used = Instant::now();

        let mut prepare_capture = None;
        let mut set_id = None;
        let mut set_version = None;
        let full_history: Vec<(String, String)>;
        let memory_text: String;
        let system_prompt: String;
        let mut display_set_name = set_name.to_owned();

        if data.requires_cipher {
            let key = self.require_encryption_key(session.username.as_deref(), encryption_key)?;
            let key = key.expect("validated encryption key");
            let username = session.username.as_deref().expect("cipher requires user");
            let mut snapshot =
                self.load_history_snapshot(username, request_set_id, set_name, key)?;
            display_set_name = snapshot.display_name.clone();
            if let Some(prompt) = request.system_prompt {
                if prompt != snapshot.system_prompt {
                    let new_v = self
                        .history_for_prepare()?
                        .update_system_prompt(
                            username,
                            snapshot.set_id,
                            snapshot.version,
                            prompt,
                            key,
                        )
                        .map_err(map_history_to_prepare)?;
                    snapshot.system_prompt = prompt.to_owned();
                    snapshot.version = new_v;
                }
            }
            data.memory = snapshot.memory.clone();
            data.system_prompt = snapshot.system_prompt.clone();
            data.history.clear();
            data.active_set_id = Some(snapshot.set_id);
            data.initialised = true;
            let _ = seal_session_data(&mut data, key.as_bytes());

            memory_text = snapshot.memory.clone();
            system_prompt = snapshot.system_prompt.clone();
            set_id = Some(snapshot.set_id);
            set_version = Some(snapshot.version);
            let capture = PrepareCapture::from_snapshot(&snapshot);
            // One ownership move of history for index checks / model prefix.
            full_history = snapshot.history;
            prepare_capture = Some(capture);
        } else {
            if !data.initialised {
                self.initialise_session_data(&mut data, session, set_name, None)?;
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
        // pair_index == history.len() is the live index for an in-flight unsaved
        // turn (voice amend of two quick utterances). Finalize appends that pair.
        let insertion_index = if let Some(index) = request.pair_index {
            if index < 0 || (index as usize) > full_history.len() {
                warn!(
                    pair_index = index,
                    history_len = full_history.len(),
                    message_chars = request.message.chars().count(),
                    set = %set_name,
                    "regenerate rejected: pair_index out of range"
                );
                return Err(validation_failed(
                    PrepareValidationError::PairIndexOutOfRange,
                ));
            }
            index as usize
        } else if full_history
            .last()
            .map(|(user, _)| user == request.message)
            .unwrap_or(false)
        {
            full_history.len().saturating_sub(1)
        } else {
            warn!(
                history_len = full_history.len(),
                message_chars = request.message.chars().count(),
                set = %set_name,
                "regenerate rejected: pair_index required (message is not the last user turn)"
            );
            return Err(validation_failed(
                PrepareValidationError::PairIndexRequired,
            ));
        };

        let effective_user = if insertion_index < full_history.len() {
            crate::chat_images::coalesce_edit_user_message(
                request.message,
                &full_history[insertion_index].0,
            )
        } else {
            request.message.to_owned()
        };
        if let Some(cap) = prepare_capture.as_mut() {
            cap.insertion_index = Some(insertion_index);
            cap.replace_user_message = Some(effective_user);
        }

        // Guest and authed: prepare is non-destructive. Model context is a prefix only;
        // shared history is replaced at finalize.

        self.ensure_model_allowed(provider, session.username.as_deref())?;
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

    /// Owned regenerate prepare with the same ordering as the delegate.
    pub fn regenerate_prepare(
        &self,
        session: &SessionContext,
        request: &RegenerateRequestData<'_>,
        provider: &ProviderConfig,
        encryption_key: Option<&EncryptionKey>,
    ) -> RegeneratePrepareResult {
        let store = self.sessions();
        store.clean_expired();

        if request.message.trim().is_empty() {
            return RegeneratePrepareResult {
                context: None,
                insertion_index: None,
                error: Some(validation_failed(
                    PrepareValidationError::MessageRequired,
                )),
            };
        }

        let set_name = match normalise_set_name(request.set_name) {
            Ok(name) => name,
            Err(err) => {
                return RegeneratePrepareResult {
                    context: None,
                    insertion_index: None,
                    error: Some(err),
                }
            }
        };
        let resolved_set_id = match parse_optional_set_id(request.set_id) {
            Ok(id) => id,
            Err(err) => {
                return RegeneratePrepareResult {
                    context: None,
                    insertion_index: None,
                    error: Some(err),
                }
            }
        };

        let entry = store.entry(&session.session_id);
        if !entry.try_lock() {
            return RegeneratePrepareResult {
                context: None,
                insertion_index: None,
                error: Some(PrepareError::Policy(PreparePolicyError::Busy)),
            };
        }

        match self.build_regenerate_context(
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
            Err(err) => {
                entry.unlock();
                RegeneratePrepareResult {
                    context: None,
                    insertion_index: None,
                    error: Some(err),
                }
            }
        }
    }

    /// Owned regenerate finalize with capture: commit then mirror then unlock.
    ///
    /// Canonical typed API. The legacy `Vec<String>` wrapper renders this
    /// outcome once with no extra IO.
    pub fn regenerate_finalize_outcome_with_capture(
        &self,
        session: &SessionContext,
        set_name: &str,
        user_message: &str,
        assistant_response: &str,
        insertion_index: Option<usize>,
        encryption_key: Option<&EncryptionKey>,
        prepare_capture: Option<PrepareCapture>,
    ) -> FinalizeOutcome {
        let store = self.sessions();
        let mut outcome = FinalizeOutcome::NoSession;

        if let Some(entry) = store.entries.get(&session.session_id) {
            {
                let mut data = entry.data.lock().unwrap();
                data.last_used = Instant::now();

                if let Some(username) = session.username.as_deref() {
                    match self.require_encryption_key(Some(username), encryption_key) {
                        Ok(Some(key)) => {
                            let commit = if let Some(mut capture) = prepare_capture.clone() {
                                if capture.insertion_index.is_none() {
                                    if let Some(idx) = insertion_index {
                                        capture = capture.with_regenerate(idx, user_message);
                                    }
                                }
                                self.history_for_commit().and_then(|hs| {
                                    hs.commit_regenerate(
                                        username,
                                        &capture,
                                        assistant_response,
                                        key,
                                    )
                                })
                            } else {
                                match self.load_history_snapshot(username, None, set_name, key) {
                                    Ok(snap) => {
                                        let mut cap = PrepareCapture::from_snapshot(&snap);
                                        if let Some(idx) = insertion_index {
                                            cap = cap.with_regenerate(idx, user_message);
                                        }
                                        self.history_for_commit().and_then(|hs| {
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
                                    if let Some(cap) = prepare_capture.as_ref() {
                                        data.active_set_id = Some(cap.set_id);
                                        data.memory = cap.memory.clone();
                                        data.system_prompt = cap.system_prompt.clone();
                                    }
                                    data.history.clear();
                                    let _ = seal_session_data(&mut data, key.as_bytes());
                                    outcome = FinalizeOutcome::DurableCommitted;
                                }
                                Err(HistoryError::Conflict { .. }) => {
                                    outcome = FinalizeOutcome::Conflict;
                                }
                                Err(HistoryError::InvalidInput(msg)) => {
                                    error!(%msg, "failed to commit regenerate history");
                                    outcome = FinalizeOutcome::InvalidInput(msg.to_owned());
                                }
                                Err(err) => {
                                    error!(?err, "failed to commit regenerate history");
                                    outcome = FinalizeOutcome::StoreFailure;
                                }
                            }
                        }
                        _ => {
                            outcome = FinalizeOutcome::KeyValidationFailed;
                        }
                    }
                } else {
                    let pair = (user_message.to_owned(), assistant_response.to_owned());
                    if let Some(index) = insertion_index {
                        if index < data.history.len() {
                            data.history[index] = pair;
                        } else {
                            data.history.push(pair);
                        }
                    } else {
                        data.history.push(pair);
                    }
                    outcome = FinalizeOutcome::GuestUpdated;
                }
            }

            entry.unlock();
        }

        outcome
    }

    /// Owned regenerate finalize with capture (compatibility adapter).
    ///
    /// Renders the typed outcome once with no extra IO. New code should use
    /// [`ChatService::regenerate_finalize_outcome_with_capture`] plus the
    /// server-owned renderer.
    pub fn regenerate_finalize_with_capture(
        &self,
        session: &SessionContext,
        set_name: &str,
        user_message: &str,
        assistant_response: &str,
        insertion_index: Option<usize>,
        encryption_key: Option<&EncryptionKey>,
        prepare_capture: Option<PrepareCapture>,
    ) -> Vec<String> {
        let outcome = self.regenerate_finalize_outcome_with_capture(
            session,
            set_name,
            user_message,
            assistant_response,
            insertion_index,
            encryption_key,
            prepare_capture,
        );
        render_finalize_outcome_compat(&outcome)
    }

    /// Owned regenerate finalize outcome without a prepare capture (fallback path).
    pub fn regenerate_finalize_outcome(
        &self,
        session: &SessionContext,
        set_name: &str,
        user_message: &str,
        assistant_response: &str,
        insertion_index: Option<usize>,
        encryption_key: Option<&EncryptionKey>,
    ) -> FinalizeOutcome {
        self.regenerate_finalize_outcome_with_capture(
            session,
            set_name,
            user_message,
            assistant_response,
            insertion_index,
            encryption_key,
            None,
        )
    }

    /// Owned regenerate finalize without a prepare capture (fallback path,
    /// compatibility adapter).
    pub fn regenerate_finalize(
        &self,
        session: &SessionContext,
        set_name: &str,
        user_message: &str,
        assistant_response: &str,
        insertion_index: Option<usize>,
        encryption_key: Option<&EncryptionKey>,
    ) -> Vec<String> {
        self.regenerate_finalize_with_capture(
            session,
            set_name,
            user_message,
            assistant_response,
            insertion_index,
            encryption_key,
            None,
        )
    }

    /// Owned leased chat prepare: binds this service clone plus the
    /// prepare-time session. Completion/drop releases the same service by
    /// current-ID lookup; expiry/recreation semantics are unchanged.
    pub fn chat_prepare_leased(
        &self,
        session: &SessionContext,
        request: &ChatRequestData<'_>,
        provider: &ProviderConfig,
        encryption_key: Option<&EncryptionKey>,
    ) -> LeasedChatPrepare {
        let ChatPrepareResult { context, error } =
            self.chat_prepare(session, request, provider, encryption_key);
        let lease = context
            .as_ref()
            .map(|_| GenerationLease::new(self.clone(), session.clone()));
        LeasedChatPrepare {
            context,
            lease,
            error,
        }
    }

    /// Owned leased regenerate prepare, binding this service clone.
    pub fn regenerate_prepare_leased(
        &self,
        session: &SessionContext,
        request: &RegenerateRequestData<'_>,
        provider: &ProviderConfig,
        encryption_key: Option<&EncryptionKey>,
    ) -> LeasedRegeneratePrepare {
        let RegeneratePrepareResult {
            context,
            insertion_index,
            error,
        } = self.regenerate_prepare(session, request, provider, encryption_key);
        let lease = context
            .as_ref()
            .map(|_| GenerationLease::new(self.clone(), session.clone()));
        LeasedRegeneratePrepare {
            context,
            insertion_index,
            lease,
            error,
        }
    }

    /// Owned memory mirror for the active set only (same set-id gate and
    /// seal/ordering as the delegate).
    pub fn update_session_memory_for_request(
        &self,
        session_id: &str,
        username: &str,
        set_id: SetId,
        memory: &str,
        key: &EncryptionKey,
    ) -> Result<(), ServiceResponse> {
        let store = self.sessions();
        let entry = store.entry(session_id);
        let mut data = entry.data.lock().unwrap();
        self.require_encryption_key(Some(username), Some(key))?;
        let key_bytes = key.as_bytes();
        unseal_session_data(&mut data, key_bytes, &self.default_prompt_resolved())?;
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

    /// Owned system-prompt mirror for the active set only.
    pub fn update_session_system_prompt_for_request(
        &self,
        session_id: &str,
        username: &str,
        set_id: SetId,
        prompt: &str,
        key: &EncryptionKey,
    ) -> Result<(), ServiceResponse> {
        let store = self.sessions();
        let entry = store.entry(session_id);
        let mut data = entry.data.lock().unwrap();
        self.require_encryption_key(Some(username), Some(key))?;
        let key_bytes = key.as_bytes();
        unseal_session_data(&mut data, key_bytes, &self.default_prompt_resolved())?;
        if data.active_set_id != Some(set_id) {
            let _ = seal_session_data(&mut data, key_bytes);
            return Ok(());
        }
        data.system_prompt = prompt.to_owned();
        data.initialised = true;
        data.last_used = Instant::now();
        seal_session_data(&mut data, key_bytes)
    }

    /// Owned working-mirror replace for the active set only. Not durable.
    pub fn replace_session_set(
        &self,
        session_id: &str,
        username: Option<&str>,
        set_id: Option<SetId>,
        memory: &str,
        system_prompt: &str,
        history: &[(String, String)],
        encrypted: bool,
        key: Option<&EncryptionKey>,
    ) -> Result<(), ServiceResponse> {
        let store = self.sessions();
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
            self.require_encryption_key(username, key)?;
            let key_bytes = key.expect("validated encryption key").as_bytes();
            seal_session_data(&mut data, key_bytes)?;
        }

        Ok(())
    }

    /// Owned session history read with the same cipher gate as the delegate.
    pub fn session_history_for_request(
        &self,
        session_id: &str,
        username: Option<&str>,
        key: Option<&EncryptionKey>,
    ) -> Result<Vec<(String, String)>, ServiceResponse> {
        let store = self.sessions();
        let Some(entry) = store.entries.get(session_id) else {
            return Ok(Vec::new());
        };
        let mut data = entry.data.lock().unwrap();
        if data.requires_cipher {
            self.require_encryption_key(username, key)?;
            let key_bytes = key.expect("validated encryption key").as_bytes();
            unseal_session_data(&mut data, key_bytes, &self.default_prompt_resolved())?;
        }
        Ok(data.history.clone())
    }

    /// Owned history replace gated on the mirrored `set_id` (authed).
    pub fn set_session_history_for_request(
        &self,
        session_id: &str,
        username: Option<&str>,
        set_id: Option<SetId>,
        history: Vec<(String, String)>,
        key: Option<&EncryptionKey>,
    ) -> Result<(), ServiceResponse> {
        let store = self.sessions();
        let Some(entry) = store.entries.get(session_id) else {
            return Ok(());
        };
        let mut data = entry.data.lock().unwrap();
        if let Some(expected) = set_id {
            if data.requires_cipher {
                if let Some(k) = key {
                    let _ = unseal_session_data(
                        &mut data,
                        k.as_bytes(),
                        &self.default_prompt_resolved(),
                    );
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
            self.require_encryption_key(username, key)?;
            let key_bytes = key.expect("validated encryption key").as_bytes();
            seal_session_data(&mut data, key_bytes)?;
        }

        Ok(())
    }

    /// Owned history read for server composition (unknown sessions are empty).
    pub fn session_history(&self, session_id: &str) -> Vec<(String, String)> {
        self.sessions().history(session_id)
    }

    /// Owned history replace for server composition.
    pub fn update_session_history(&self, session_id: &str, history: &[(String, String)]) {
        self.sessions().update_history(session_id, history);
    }

    /// Owned memory replace for server composition (no-op when missing).
    pub fn update_session_memory(&self, session_id: &str, memory: &str) {
        self.sessions().update_memory(session_id, memory);
    }

    /// Owned system-prompt replace for server composition (no-op when missing).
    pub fn update_session_system_prompt(&self, session_id: &str, prompt: &str) {
        self.sessions().update_system_prompt(session_id, prompt);
    }

    /// Owned generation-lock release for server composition.
    pub fn release_session_lock(&self, session_id: &str) {
        self.sessions().release_generation(session_id);
    }

    /// Owned generation-lock acquire for server composition.
    pub fn try_acquire_generation(&self, session_id: &str) -> bool {
        self.sessions().try_acquire_generation(session_id)
    }

    /// Owned expiry purge for server composition.
    pub fn purge_expired_chat_sessions(&self) -> usize {
        self.sessions().purge_expired()
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
    warn!(error = message, "bad request");
    build_json_response(400, json!({ "error": message }))
}

fn validation_failed(err: PrepareValidationError) -> PrepareError {
    warn!(error = err.message(), "bad request");
    PrepareError::Validation(err)
}

fn history_not_found() -> PrepareHistoryError {
    warn!(error = "invalid set name", "bad request");
    PrepareHistoryError::NotFound
}

/// Log the cause at the prepare point and project `HistoryError` onto the
/// cloneable prepare representation. Response rendering and the 500 counter
/// belong to the server adapter.
fn map_history_to_prepare(err: HistoryError) -> PrepareHistoryError {
    match err {
        HistoryError::MissingKey | HistoryError::DecryptFailed => {
            PrepareHistoryError::Unauthorized
        }
        HistoryError::NotFound => history_not_found(),
        HistoryError::Conflict { current_version } => PrepareHistoryError::Conflict {
            current_version,
        },
        HistoryError::InvalidInput(msg) => {
            warn!(error = msg, "bad request");
            PrepareHistoryError::InvalidInput(msg)
        }
        HistoryError::Forbidden => PrepareHistoryError::Forbidden,
        HistoryError::Internal => {
            error!("history service internal error");
            PrepareHistoryError::Internal
        }
    }
}

fn unauthorized(message: &str) -> ServiceResponse {
    build_json_response(401, json!({ "error": message }))
}

fn server_error(message: &str) -> ServiceResponse {
    build_json_response(500, json!({ "error": message }))
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SessionPurgeStats {
    pub http_sessions_removed: usize,
    pub chat_sessions_removed: usize,
}

impl SessionPurgeStats {
    pub fn total_removed(&self) -> usize {
        self.http_sessions_removed + self.chat_sessions_removed
    }
}

/// Proactively drop expired HTTP and chat session records (also runs lazily on requests).
pub fn purge_expired_sessions() -> SessionPurgeStats {
    let http_sessions_removed = crate::session_identity::purge_expired_http_sessions();
    let chat_sessions_removed = purge_expired_chat_sessions();
    SessionPurgeStats {
        http_sessions_removed,
        chat_sessions_removed,
    }
}

/// Drop expired chat session records only. Owned server identities purge
/// their own HTTP store and reuse this for the shared chat store.
///
/// Production entry point: delegates to the single process-global store.
pub fn purge_expired_chat_sessions() -> usize {
    ChatService::global().purge_expired_chat_sessions()
}

/// Drop expired HTTP session records only, without touching chat state.
///
/// Production entry point: delegates to the single process-global HTTP store.
/// Composed servers purge their owned HTTP store plus their owned chat
/// service separately so an owned router never initializes the global stores.
pub fn purge_expired_http_sessions() -> usize {
    crate::session_identity::purge_expired_http_sessions()
}

/// Production entry point: delegates to the single process-global store.
pub fn release_session_lock(session_id: &str) {
    ChatService::global().release_session_lock(session_id);
}

impl std::fmt::Debug for ChatService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChatService")
            .field("owned", &self.owned.is_some())
            .finish_non_exhaustive()
    }
}

/// Owns settlement for one successful prepare.
///
/// The lease binds its service clone plus the prepare-time session and settles
/// by session ID through the current entry of that same service. It never
/// holds the entry across awaits and cannot be cloned. Expiry/recreation
/// semantics are unchanged from the ID-lookup path.
#[derive(Debug)]
pub struct GenerationLease {
    service: ChatService,
    session: SessionContext,
    settled: bool,
}

impl GenerationLease {
    fn new(service: ChatService, session: SessionContext) -> Self {
        Self {
            service,
            session,
            settled: false,
        }
    }

    /// Session settled by this lease.
    pub fn session_id(&self) -> &str {
        &self.session.session_id
    }

    fn settle(&mut self) {
        if !self.settled {
            self.settled = true;
            self.service.release_session_lock(&self.session.session_id);
        }
    }

    /// Persist a `/chat` turn with the bound session, then settle.
    ///
    /// Canonical typed completion: consumes the lease and settles the same
    /// finalize-then-unlock flow. The legacy `Vec<String>` wrapper renders
    /// this outcome once with no extra IO.
    pub fn complete_chat_outcome(
        mut self,
        set_name: &str,
        user_message: &str,
        assistant_response: &str,
        encryption_key: Option<&EncryptionKey>,
        prepare_capture: Option<PrepareCapture>,
    ) -> FinalizeOutcome {
        let outcome = self.service.chat_finalize_outcome_with_capture(
            &self.session,
            set_name,
            user_message,
            assistant_response,
            encryption_key,
            prepare_capture,
        );
        // The finalize above already settled this session.
        self.settled = true;
        outcome
    }

    /// Persist a `/chat` turn with the bound session, then settle
    /// (compatibility adapter).
    pub fn complete_chat(
        self,
        set_name: &str,
        user_message: &str,
        assistant_response: &str,
        encryption_key: Option<&EncryptionKey>,
        prepare_capture: Option<PrepareCapture>,
    ) -> Vec<String> {
        let outcome = self.complete_chat_outcome(
            set_name,
            user_message,
            assistant_response,
            encryption_key,
            prepare_capture,
        );
        render_finalize_outcome_compat(&outcome)
    }

    /// Persist a `/regenerate` turn with the bound session, then settle.
    ///
    /// Canonical typed completion: consumes the lease and settles the same
    /// finalize-then-unlock flow. The legacy `Vec<String>` wrapper renders
    /// this outcome once with no extra IO.
    pub fn complete_regenerate_outcome(
        mut self,
        set_name: &str,
        user_message: &str,
        assistant_response: &str,
        insertion_index: Option<usize>,
        encryption_key: Option<&EncryptionKey>,
        prepare_capture: Option<PrepareCapture>,
    ) -> FinalizeOutcome {
        let outcome = self.service.regenerate_finalize_outcome_with_capture(
            &self.session,
            set_name,
            user_message,
            assistant_response,
            insertion_index,
            encryption_key,
            prepare_capture,
        );
        // The finalize above already settled this session.
        self.settled = true;
        outcome
    }

    /// Persist a `/regenerate` turn with the bound session, then settle
    /// (compatibility adapter).
    pub fn complete_regenerate(
        self,
        set_name: &str,
        user_message: &str,
        assistant_response: &str,
        insertion_index: Option<usize>,
        encryption_key: Option<&EncryptionKey>,
        prepare_capture: Option<PrepareCapture>,
    ) -> Vec<String> {
        let outcome = self.complete_regenerate_outcome(
            set_name,
            user_message,
            assistant_response,
            insertion_index,
            encryption_key,
            prepare_capture,
        );
        render_finalize_outcome_compat(&outcome)
    }

    /// Settle without persisting.
    pub fn release_without_persist(mut self) {
        self.settle();
    }
}

impl Drop for GenerationLease {
    fn drop(&mut self) {
        self.settle();
    }
}

/// Successful leased chat prepare: context with its settlement lease.
///
/// On success, `context` and `lease` are `Some`; on error, `error` is `Some`
/// with no lease.
pub struct LeasedChatPrepare {
    pub context: Option<ChatContext>,
    pub lease: Option<GenerationLease>,
    pub error: Option<PrepareError>,
}

/// Prepare a chat generation and bind its settlement lease.
pub fn chat_prepare_leased(
    session: &SessionContext,
    request: &ChatRequestData<'_>,
    provider: &ProviderConfig,
    encryption_key: Option<&EncryptionKey>,
) -> LeasedChatPrepare {
    ChatService::global().chat_prepare_leased(session, request, provider, encryption_key)
}

/// Successful leased regenerate prepare: context, replace index, and lease.
///
/// On success, `context` and `lease` are `Some`; on error, `error` is `Some`
/// with no lease.
pub struct LeasedRegeneratePrepare {
    pub context: Option<ChatContext>,
    pub insertion_index: Option<usize>,
    pub lease: Option<GenerationLease>,
    pub error: Option<PrepareError>,
}

/// Prepare regeneration and bind its settlement lease.
pub fn regenerate_prepare_leased(
    session: &SessionContext,
    request: &RegenerateRequestData<'_>,
    provider: &ProviderConfig,
    encryption_key: Option<&EncryptionKey>,
) -> LeasedRegeneratePrepare {
    ChatService::global().regenerate_prepare_leased(session, request, provider, encryption_key)
}

fn seal_session_data(data: &mut SessionData, key: &[u8]) -> Result<(), ServiceResponse> {
    if !data.requires_cipher {
        return Ok(());
    }
    // Authenticated chat history is stored durably in HistoryService (redb AEAD).
    // Re-Fernet-sealing multi-MB image histories into the session on every load/delete
    // pegged a core for seconds. Session only needs active set_id + small fields;
    // prepare/load always re-reads history from the durable store with X-Enc-Key.
    let payload = CachedSetPayload {
        memory: data.memory.clone(),
        system_prompt: data.system_prompt.clone(),
        history: Vec::new(),
        set_id: data.active_set_id.map(|id| id.to_string()),
    };
    let json = serde_json::to_string(&payload)
        .map_err(|_| server_error("internal error while accessing chat history"))?;
    let encrypted = fernet_crypto::encrypt_bytes(json.as_bytes(), key)
        .map_err(|err| map_fernet_error("failed to seal session cache", &err))?;
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
    let decrypted = fernet_crypto::decrypt_bytes(blob, key)
        .map_err(|err| map_fernet_error("failed to decrypt session cache", &err))?;
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

/// Typed outcome of per-request encryption-key validation.
///
/// `Missing` covers both a missing key and a missing key verifier (no
/// enrollment happens on data requests); `Invalid` is a wrong key;
/// `StoreUnavailable` is a `UserStore` failure (already logged at the
/// validation point).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncryptionKeyValidationError {
    Missing,
    Invalid,
    StoreUnavailable,
}

pub fn validate_encryption_key_for_user(
    username: &str,
    key: Option<&EncryptionKey>,
) -> Result<(), EncryptionKeyValidationError> {
    ChatService::global().validate_encryption_key_for_user(username, key)
}

pub fn require_encryption_key<'a>(
    username: Option<&str>,
    key: Option<&'a EncryptionKey>,
) -> Result<Option<&'a EncryptionKey>, ServiceResponse> {
    ChatService::global().require_encryption_key(username, key)
}

fn normalise_set_name(candidate: Option<&str>) -> Result<String, PrepareError> {
    crate::history::normalise_set_name(candidate)
        .map_err(|_| validation_failed(PrepareValidationError::InvalidSetName))
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

fn map_fernet_error(context: &str, err: &FernetError) -> ServiceResponse {
    error!(?err, "{context}");
    server_error("internal error while accessing chat history")
}

fn map_store_error(context: &str, err: &UserStoreError) -> ServiceResponse {
    error!(?err, "{context}");
    server_error("internal error while accessing user store")
}

/// Log a `UserStore` failure at the validation point and report it as a typed
/// outcome; the HTTP mapper must not log the cause again.
fn map_store_unavailable(
    context: &str,
    err: &UserStoreError,
) -> EncryptionKeyValidationError {
    error!(?err, "{context}");
    EncryptionKeyValidationError::StoreUnavailable
}

pub fn chat_prepare(
    session: &SessionContext,
    request: &ChatRequestData<'_>,
    provider: &ProviderConfig,
    encryption_key: Option<&EncryptionKey>,
) -> ChatPrepareResult {
    ChatService::global().chat_prepare(session, request, provider, encryption_key)
}

pub fn chat_finalize(
    session: &SessionContext,
    set_name: &str,
    user_message: &str,
    assistant_response: &str,
    encryption_key: Option<&EncryptionKey>,
) -> Vec<String> {
    ChatService::global().chat_finalize(
        session,
        set_name,
        user_message,
        assistant_response,
        encryption_key,
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
    ChatService::global().chat_finalize_with_capture(
        session,
        set_name,
        user_message,
        assistant_response,
        encryption_key,
        prepare_capture,
    )
}

fn parse_optional_set_id(raw: Option<&str>) -> Result<Option<SetId>, PrepareError> {
    match raw.map(str::trim).filter(|s| !s.is_empty()) {
        None => Ok(None),
        Some(s) => SetId::parse(s)
            .map(Some)
            .map_err(|_| validation_failed(PrepareValidationError::InvalidSetId)),
    }
}

pub fn regenerate_prepare(
    session: &SessionContext,
    request: &RegenerateRequestData<'_>,
    provider: &ProviderConfig,
    encryption_key: Option<&EncryptionKey>,
) -> RegeneratePrepareResult {
    ChatService::global().regenerate_prepare(session, request, provider, encryption_key)
}

pub fn regenerate_finalize(
    session: &SessionContext,
    set_name: &str,
    user_message: &str,
    assistant_response: &str,
    insertion_index: Option<usize>,
    encryption_key: Option<&EncryptionKey>,
) -> Vec<String> {
    ChatService::global().regenerate_finalize(
        session,
        set_name,
        user_message,
        assistant_response,
        insertion_index,
        encryption_key,
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
    ChatService::global().regenerate_finalize_with_capture(
        session,
        set_name,
        user_message,
        assistant_response,
        insertion_index,
        encryption_key,
        prepare_capture,
    )
}

/// Production entry point: delegates to the single process-global store.
pub fn update_session_memory(session_id: &str, memory: &str) {
    ChatService::global().update_session_memory(session_id, memory);
}

/// Production entry point: delegates to the single process-global store.
pub fn update_session_system_prompt(session_id: &str, prompt: &str) {
    ChatService::global().update_session_system_prompt(session_id, prompt);
}

/// Update session memory only when the cache currently mirrors `set_id`.
pub fn update_session_memory_for_request(
    session_id: &str,
    username: &str,
    set_id: SetId,
    memory: &str,
    key: &EncryptionKey,
) -> Result<(), ServiceResponse> {
    ChatService::global().update_session_memory_for_request(
        session_id,
        username,
        set_id,
        memory,
        key,
    )
}

/// Update session system prompt only when the cache currently mirrors `set_id`.
pub fn update_session_system_prompt_for_request(
    session_id: &str,
    username: &str,
    set_id: SetId,
    prompt: &str,
    key: &EncryptionKey,
) -> Result<(), ServiceResponse> {
    ChatService::global().update_session_system_prompt_for_request(
        session_id, username, set_id, prompt, key,
    )
}

/// Update the **session working mirror** for the active set only.
///
/// Not durable. Authenticated durability is exclusively via [`HistoryService`].
/// Prefer this only after a successful HistoryService load/commit for `set_id`.
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
    ChatService::global().replace_session_set(
        session_id,
        username,
        set_id,
        memory,
        system_prompt,
        history,
        encrypted,
        key,
    )
}

pub fn session_history_for_request(
    session_id: &str,
    username: Option<&str>,
    key: Option<&EncryptionKey>,
) -> Result<Vec<(String, String)>, ServiceResponse> {
    ChatService::global().session_history_for_request(session_id, username, key)
}

/// Replace session history only when the cache currently mirrors `set_id` (authed).
pub fn set_session_history_for_request(
    session_id: &str,
    username: Option<&str>,
    set_id: Option<SetId>,
    history: Vec<(String, String)>,
    key: Option<&EncryptionKey>,
) -> Result<(), ServiceResponse> {
    ChatService::global().set_session_history_for_request(session_id, username, set_id, history, key)
}

/// Production entry point: delegates to the single process-global store.
pub fn update_session_history(session_id: &str, history: &[(String, String)]) {
    ChatService::global().update_session_history(session_id, history);
}

/// Production entry point: delegates to the single process-global store.
pub fn session_history(session_id: &str) -> Vec<(String, String)> {
    ChatService::global().session_history(session_id)
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
        ChatSessionStore::global().entry(session_id);
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
            rate_limit_retries: None,
            rate_limit_max_wait_secs: None,
            test_chunks: None,
            search: false,
            xai_search: true,
            xai_zdr: false,
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
        
        // Prepare is non-destructive: full history remains until finalize.
        let stored_history = session_history(session_id);
        assert_eq!(stored_history.len(), 3, "Stored history unchanged after prepare");
        assert_eq!(stored_history[0].0, "User1");
        assert_eq!(stored_history[1].0, "User2");
        assert_eq!(stored_history[2].0, "User3");

        regenerate_finalize(
            &session,
            "default",
            "User2",
            "new-a2",
            result.insertion_index,
            None,
        );
        let after = session_history(session_id);
        assert_eq!(after.len(), 3);
        assert_eq!(after[1], ("User2".into(), "new-a2".into()));
        assert_eq!(after[2].0, "User3");

        // Cleanup
        release_session_lock(session_id);
    }

    #[test]
    fn regenerate_pair_index_equal_len_appends_in_flight_turn() {
        let session_id = "guest_test-session-regen-append";
        ChatSessionStore::global().entry(session_id);
        update_session_history(
            session_id,
            &[("User1".to_string(), "AI1".to_string())],
        );

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
            rate_limit_retries: None,
            rate_limit_max_wait_secs: None,
            test_chunks: None,
            search: false,
            xai_search: true,
            xai_zdr: false,
        };
        let request = RegenerateRequestData {
            set_id: None,
            message: "User1 more words",
            system_prompt: None,
            set_name: Some("default"),
            model_name: None,
            encrypted: false,
            pair_index: Some(1),
            send_thoughts: false,
        };

        let result = regenerate_prepare(&session, &request, &provider, None);
        assert!(
            result.error.is_none(),
            "pair_index == history.len() must prepare as an append, not out of range: {:?}",
            result.error
        );
        assert_eq!(result.insertion_index, Some(1));
        let context = result.context.expect("context");
        assert_eq!(context.history.len(), 1);
        assert_eq!(context.history[0].0, "User1");

        regenerate_finalize(
            &session,
            "default",
            "User1 more words",
            "joined-reply",
            result.insertion_index,
            None,
        );
        let after = session_history(session_id);
        assert_eq!(after.len(), 2);
        assert_eq!(after[0], ("User1".into(), "AI1".into()));
        assert_eq!(after[1], ("User1 more words".into(), "joined-reply".into()));

        release_session_lock(session_id);
    }

    fn lease_test_provider() -> ProviderConfig {
        ProviderConfig {
            provider_name: "default".to_string(),
            provider_type: "openai".to_string(),
            tier: None,
            model_name: "default".to_string(),
            context_size: Some(4096),
            base_url: "http://localhost".to_string(),
            api_key: None,
            allowed_providers: vec![],
            request_timeout: None,
            rate_limit_retries: None,
            rate_limit_max_wait_secs: None,
            test_chunks: None,
            search: false,
            xai_search: true,
            xai_zdr: false,
        }
    }

    fn lease_test_chat_request<'a>() -> ChatRequestData<'a> {
        ChatRequestData {
            message: "hello",
            system_prompt: None,
            set_name: Some("default"),
            set_id: None,
            model_name: None,
            encrypted: false,
            send_thoughts: false,
        }
    }

    #[test]
    fn leased_chat_prepare_holds_lock_until_explicit_release() {
        let session_id = "guest_test-lease-holds-lock";
        let session = SessionContext {
            session_id: session_id.to_string(),
            username: None,
        };
        let provider = lease_test_provider();

        let prepared = chat_prepare_leased(&session, &lease_test_chat_request(), &provider, None);
        assert!(prepared.error.is_none());
        assert!(prepared.context.is_some());
        let lease = prepared.lease.expect("success must mint a lease");
        assert_eq!(lease.session_id(), session_id);

        // Lock is held: a second prepare reports Busy, never blocking.
        let busy = chat_prepare(&session, &lease_test_chat_request(), &provider, None);
        assert!(
            matches!(
                busy.error,
                Some(PrepareError::Policy(PreparePolicyError::Busy))
            ),
            "expected Busy while the lease is outstanding: {:?}",
            busy.error
        );

        // Explicit release without persisting frees the lock and saves nothing.
        lease.release_without_persist();
        assert!(session_history(session_id).is_empty());

        let retry = chat_prepare(&session, &lease_test_chat_request(), &provider, None);
        assert!(retry.error.is_none());
        assert!(retry.context.is_some());
        release_session_lock(session_id);
    }

    #[test]
    fn leased_chat_complete_persists_and_settles_exactly_once() {
        let session_id = "guest_test-lease-complete-once";
        let session = SessionContext {
            session_id: session_id.to_string(),
            username: None,
        };
        let provider = lease_test_provider();

        let prepared = chat_prepare_leased(&session, &lease_test_chat_request(), &provider, None);
        assert!(prepared.error.is_none());
        let lease = prepared.lease.expect("success must mint a lease");

        let extras = lease.complete_chat("default", "hello", "hi there", None, None);
        assert!(extras.is_empty());
        assert_eq!(
            session_history(session_id),
            vec![("hello".to_string(), "hi there".to_string())]
        );

        // The lock is free after completion.
        let retry = chat_prepare(&session, &lease_test_chat_request(), &provider, None);
        assert!(retry.error.is_none());
        release_session_lock(session_id);
    }

    #[test]
    fn completing_one_lease_leaves_another_session_busy() {
        let session_a = SessionContext {
            session_id: "guest_test-lease-two-a".to_string(),
            username: None,
        };
        let session_b = SessionContext {
            session_id: "guest_test-lease-two-b".to_string(),
            username: None,
        };
        let provider = lease_test_provider();

        let prepared_a =
            chat_prepare_leased(&session_a, &lease_test_chat_request(), &provider, None);
        let prepared_b =
            chat_prepare_leased(&session_b, &lease_test_chat_request(), &provider, None);
        assert!(prepared_a.error.is_none());
        assert!(prepared_b.error.is_none());
        let lease_a = prepared_a.lease.expect("success must mint a lease");
        let lease_b = prepared_b.lease.expect("success must mint a lease");
        assert_eq!(lease_a.session_id(), "guest_test-lease-two-a");
        assert_eq!(lease_b.session_id(), "guest_test-lease-two-b");

        let extras = lease_a.complete_chat("default", "a user", "a answer", None, None);
        assert!(extras.is_empty());

        // Completing A settled only A: B is still locked.
        let busy_b = chat_prepare(&session_b, &lease_test_chat_request(), &provider, None);
        assert!(
            matches!(
                busy_b.error,
                Some(PrepareError::Policy(PreparePolicyError::Busy))
            ),
            "expected B to stay Busy after A completed: {:?}",
            busy_b.error
        );

        // A is reusable and B persisted nothing.
        let retry_a = chat_prepare(&session_a, &lease_test_chat_request(), &provider, None);
        assert!(retry_a.error.is_none());
        release_session_lock("guest_test-lease-two-a");
        assert_eq!(
            session_history("guest_test-lease-two-a"),
            vec![("a user".to_string(), "a answer".to_string())]
        );
        assert!(session_history("guest_test-lease-two-b").is_empty());

        lease_b.release_without_persist();
        let retry_b = chat_prepare(&session_b, &lease_test_chat_request(), &provider, None);
        assert!(retry_b.error.is_none());
        release_session_lock("guest_test-lease-two-b");
    }

    #[test]
    fn dropped_lease_releases_without_persisting() {
        let session_id = "guest_test-lease-drop-releases";
        let session = SessionContext {
            session_id: session_id.to_string(),
            username: None,
        };
        let provider = lease_test_provider();

        let prepared = chat_prepare_leased(&session, &lease_test_chat_request(), &provider, None);
        assert!(prepared.error.is_none());
        drop(prepared.lease.expect("success must mint a lease"));

        assert!(session_history(session_id).is_empty());
        let retry = chat_prepare(&session, &lease_test_chat_request(), &provider, None);
        assert!(retry.error.is_none());
        release_session_lock(session_id);
    }

    #[test]
    fn leased_prepare_error_mints_no_lease_and_holds_no_lock() {
        let session_id = "guest_test-lease-error-no-lock";
        let session = SessionContext {
            session_id: session_id.to_string(),
            username: None,
        };
        let provider = lease_test_provider();
        let bad = ChatRequestData {
            message: "   ",
            system_prompt: None,
            set_name: Some("default"),
            set_id: None,
            model_name: None,
            encrypted: false,
            send_thoughts: false,
        };

        let prepared = chat_prepare_leased(&session, &bad, &provider, None);
        assert!(prepared.context.is_none());
        assert!(prepared.lease.is_none());
        assert!(matches!(
            prepared.error,
            Some(PrepareError::Validation(
                PrepareValidationError::MessageRequired
            ))
        ));

        // No lock was ever taken: an immediate retry prepares cleanly.
        let retry = chat_prepare(&session, &lease_test_chat_request(), &provider, None);
        assert!(retry.error.is_none());
        release_session_lock(session_id);
    }

    #[test]
    fn leased_regenerate_complete_replaces_and_releases() {
        let session_id = "guest_test-lease-regen-complete";
        ChatSessionStore::global().entry(session_id);
        update_session_history(session_id, &[("u1".to_string(), "a1".to_string())]);

        let session = SessionContext {
            session_id: session_id.to_string(),
            username: None,
        };
        let provider = lease_test_provider();
        let request = RegenerateRequestData {
            set_id: None,
            message: "u1",
            system_prompt: None,
            set_name: Some("default"),
            model_name: None,
            encrypted: false,
            pair_index: Some(0),
            send_thoughts: false,
        };

        let prepared = regenerate_prepare_leased(&session, &request, &provider, None);
        assert!(prepared.error.is_none());
        assert_eq!(prepared.insertion_index, Some(0));
        let lease = prepared.lease.expect("success must mint a lease");

        let extras = lease.complete_regenerate("default", "u1", "a2", Some(0), None, None);
        assert!(extras.is_empty());
        assert_eq!(
            session_history(session_id),
            vec![("u1".to_string(), "a2".to_string())]
        );

        let retry = regenerate_prepare(&session, &request, &provider, None);
        assert!(retry.error.is_none());
        release_session_lock(session_id);
    }
}
