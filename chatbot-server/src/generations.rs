//! RAM-owned generation workers and disposable NDJSON views.
use std::{
    collections::{HashMap, VecDeque},
    sync::{Arc, Mutex},
    time::Duration,
};

use axum::{
    body::{to_bytes, Body},
    extract::{Path, Query},
    http::{header, Request, Response, StatusCode},
};
use bytes::Bytes;
use chatbot_core::{
    operation_receipt::{Receipt, ReceiptClock, ReceiptOutcome, SystemReceiptClock},
    session::FinalizeOutcome,
};
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::sync::{broadcast, watch, Mutex as AsyncMutex, OwnedMutexGuard};

use crate::{
    http_error::{api_error, api_error_json, HttpError},
    request_context::DataRequestContext,
    services::AppServices,
};

const BUFFER_BYTES: usize = 4 * 1024 * 1024;

#[derive(Clone, Copy)]
pub struct GenerationTiming {
    pub heartbeat: Duration,
    pub deadline: Duration,
    pub grace: Duration,
}
impl Default for GenerationTiming {
    fn default() -> Self {
        Self {
            heartbeat: Duration::from_secs(5),
            deadline: Duration::from_secs(30 * 60),
            grace: Duration::from_secs(120),
        }
    }
}

/// Private feedback from the shared leased stream pipeline, never from a viewer.
#[derive(Clone)]
pub(crate) struct GenerationFeedback {
    pub expected_version: u64,
    pub base_version: Arc<Mutex<u64>>,
    pub outcome: Arc<Mutex<Option<FinalizeOutcome>>>,
    pub provider_failed: Arc<Mutex<bool>>,
}
impl GenerationFeedback {
    pub fn capture(&self, capture: Option<&chatbot_core::history::PrepareCapture>) -> Result<(), HttpError> {
        let version = capture.map(|c| c.version.0).unwrap_or(0);
        if self.expected_version != version {
            return Err(api_error_json(
                StatusCode::CONFLICT,
                capture.map(|c| chatbot_core::history::HistoryService::version_conflict_body(c.set_id, c.version)).unwrap_or_else(|| json!({"error":"version_conflict", "current_version":version})),
            ));
        }
        *self.base_version.lock().unwrap_or_else(|e| e.into_inner()) = version;
        Ok(())
    }
    pub fn finalized(&self, outcome: &FinalizeOutcome) {
        *self.outcome.lock().unwrap_or_else(|e| e.into_inner()) = Some(outcome.clone());
    }
    pub fn failed(&self) {
        *self
            .provider_failed
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = true;
    }
}

#[derive(Clone, Serialize)]
struct Descriptor {
    generation_id: String,
    state: String,
    base_version: u64,
}
#[derive(Clone, Serialize)]
struct Event {
    generation_id: String,
    seq: u64,
    #[serde(rename = "type")]
    kind: String,
    channel: String,
    text: String,
}
struct State {
    descriptor: Descriptor,
    events: VecDeque<Event>,
    bytes: usize,
    seq: u64,
    settled: bool,
}
impl State {
    /// Buffered events after `cursor`. Sequences are contiguous (eviction
    /// only drops the front), so this is an index, not a scan.
    fn events_after(&self, cursor: u64) -> Vec<Event> {
        let Some(first) = self.events.front().map(|e| e.seq) else { return Vec::new() };
        let skip = usize::try_from((cursor + 1).saturating_sub(first)).unwrap_or(usize::MAX);
        self.events.range(skip.min(self.events.len())..).cloned().collect()
    }
}
struct Generation {
    owner: String,
    set_id: String,
    state: Mutex<State>,
    events: broadcast::Sender<Event>,
    stop: watch::Sender<bool>,
}
impl Generation {
    fn descriptor(&self) -> Descriptor {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .descriptor
            .clone()
    }
    fn emit(&self, kind: &str, text: &str) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.seq += 1;
        let event = Event {
            generation_id: state.descriptor.generation_id.clone(),
            seq: state.seq,
            kind: kind.into(),
            channel: if kind == "thinking" {
                "thinking"
            } else {
                "answer"
            }
            .into(),
            text: text.into(),
        };
        state.bytes += text.len();
        state.events.push_back(event.clone());
        while state.bytes > BUFFER_BYTES || state.events.len() > 8192 {
            if let Some(old) = state.events.pop_front() {
                state.bytes -= old.text.len();
            }
        }
        let _ = self.events.send(event);
    }
}

pub(crate) struct GenerationRegistry {
    entries: Mutex<HashMap<String, Arc<Generation>>>,
    receipts: Mutex<HashMap<(String, String), Receipt>>,
    admission: Mutex<HashMap<String, std::sync::Weak<AsyncMutex<()>>>>,
    pub timing: GenerationTiming,
}
impl Default for GenerationRegistry {
    fn default() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            receipts: Mutex::new(HashMap::new()),
            admission: Mutex::new(HashMap::new()),
            timing: GenerationTiming::default(),
        }
    }
}
impl GenerationRegistry {
    /// Serializes admission and Stop for one owner. Receipts and running
    /// generations are owner-scoped, so owners never wait on each other.
    async fn admission_lock(&self, owner: &str) -> OwnedMutexGuard<()> {
        let lock = {
            let mut locks = self.admission.lock().unwrap_or_else(|e| e.into_inner());
            locks.retain(|_, lock| lock.strong_count() > 0);
            match locks.get(owner).and_then(std::sync::Weak::upgrade) {
                Some(lock) => lock,
                None => {
                    let lock = Arc::new(AsyncMutex::new(()));
                    locks.insert(owner.to_owned(), Arc::downgrade(&lock));
                    lock
                }
            }
        };
        lock.lock_owned().await
    }
    pub(crate) fn replay(
        &self,
        owner: &str,
        operation: &chatbot_core::operation_receipt::OperationRequest,
    ) -> Result<Option<Response<Body>>, HttpError> {
        let mut receipts = self.receipts.lock().unwrap_or_else(|e| e.into_inner());
        let now = SystemReceiptClock.now_secs();
        receipts.retain(|_, receipt| !receipt.expired(now));
        match receipts.get(&(owner.into(), operation.id.as_str().into())) {
            Some(receipt) if !receipt.matches(operation) => Err(crate::idempotency::reused()),
            Some(receipt) => crate::idempotency::replay(receipt).map(Some),
            None => Ok(None),
        }
    }
    pub(crate) fn record(
        &self,
        owner: &str,
        operation: &chatbot_core::operation_receipt::OperationRequest,
        status: StatusCode,
        value: impl Serialize,
    ) {
        let outcome = if status.is_success() {
            ReceiptOutcome::Applied
        } else {
            ReceiptOutcome::Rejected
        };
        let receipt = Receipt::new(
            operation,
            outcome,
            status.as_u16(),
            serde_json::to_vec(&value).expect("receipt"),
            SystemReceiptClock.now_secs(),
        );
        self.receipts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert((owner.into(), operation.id.as_str().into()), receipt);
    }
    fn owned(&self, owner: &str, id: &str) -> Result<Arc<Generation>, HttpError> {
        self.entries
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(id)
            .filter(|g| g.owner == owner)
            .cloned()
            .ok_or_else(|| api_error(StatusCode::NOT_FOUND, "generation not found"))
    }
    fn running(&self, owner: &str, set_id: &str) -> Vec<Descriptor> {
        self.entries
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .filter(|g| g.owner == owner && g.set_id == set_id)
            .filter_map(|g| {
                let state = g.state.lock().unwrap_or_else(|e| e.into_inner());
                (!state.settled).then(|| state.descriptor.clone())
            })
            .collect()
    }
}

fn json_response(status: StatusCode, value: impl Serialize) -> Response<Body> {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::CACHE_CONTROL, "no-store")
        .body(Body::from(
            serde_json::to_vec(&value).expect("JSON serialization"),
        ))
        .expect("valid response")
}
fn owner(services: &AppServices, request: &Request<Body>, csrf: bool) -> Result<String, HttpError> {
    let cookie = crate::request_context::extract_cookie(request.headers());
    if csrf
        && !services
            .identity()
            .validate_csrf_token(
                cookie.as_deref(),
                crate::request_context::extract_csrf(request.headers()),
            )
            .map_err(|e| crate::http_error::map_session_err(e, "generations::csrf"))?
    {
        return Err(api_error(
            StatusCode::UNAUTHORIZED,
            "Invalid or missing CSRF token",
        ));
    }
    let context = DataRequestContext::resolve(
        services.identity(),
        request.headers(),
        cookie.as_deref(),
        "generations::identity",
    )?;
    let session = context.session();
    if let Some(username) = &session.username {
        services
            .chat()
            .validate_encryption_key_for_user(username, context.unverified_encryption_key())
            .map_err(crate::http_error::map_encryption_key_validation_err)?;
        Ok(format!("user:{username}"))
    } else {
        Ok(format!("guest:{}", session.session_id))
    }
}

pub(crate) async fn admit(request: Request<Body>, kind: &str) -> Result<Response<Body>, HttpError> {
    let services = AppServices::from_extensions(request.extensions());
    let owner = owner(&services, &request, true)?;
    let (mut parts, body) = request.into_parts();
    let bytes = to_bytes(body, 5 * 1024 * 1024)
        .await
        .map_err(|e| crate::http_error::map_body_read_err(e, "generations::create"))?;
    let payload: Value = serde_json::from_slice(&bytes)
        .map_err(|e| crate::http_error::map_json_parse_err(e, "generations::create"))?;
    let route = if kind == "chat" { "/chat" } else { "/regenerate" };
    let mut set_id = payload["set_id"]
        .as_str()
        .ok_or_else(|| api_error(StatusCode::BAD_REQUEST, "missing set_id"))?
        .to_owned();
    if owner.starts_with("user:") {
        set_id = chatbot_core::history::SetId::parse(&set_id)
            .map_err(|_| api_error(StatusCode::BAD_REQUEST, "invalid set_id"))?
            .to_string();
    } else if !set_id.is_empty() {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            "guests cannot use saved sets",
        ));
    }
    let expected_version = payload["expected_version"]
        .as_u64()
        .ok_or_else(|| api_error(StatusCode::BAD_REQUEST, "missing expected_version"))?;
    let operation =
        crate::idempotency::operation_request(&parts.headers, route, &payload)?;
    let registry = services.generations();
    let _admission = registry.admission_lock(&owner).await;
    if let Some(operation) = &operation {
        if let Some(response) = registry.replay(&owner, operation)? {
            if !response.status().is_success() { return Ok(response); }
            let bytes = to_bytes(response.into_body(), 1024 * 1024).await
                .map_err(|e| crate::http_error::map_body_read_err(e, "generations::replay"))?;
            let descriptor: Value = serde_json::from_slice(&bytes).expect("recorded descriptor");
            let generation = registry.owned(&owner, descriptor["generation_id"].as_str().expect("generation id"))?;
            return Ok(event_response(generation, registry.timing.heartbeat, 0, StatusCode::ACCEPTED));
        }
    }
    if let Some(active) = registry.running(&owner, &set_id).into_iter().next() {
        return Err(api_error_json(
            StatusCode::CONFLICT,
            json!({"error":"generation_active", "generation":active}),
        ));
    }
    let feedback = GenerationFeedback {
        expected_version,
        base_version: Arc::new(Mutex::new(0)),
        outcome: Arc::new(Mutex::new(None)),
        provider_failed: Arc::new(Mutex::new(false)),
    };
    parts.extensions.insert(feedback.clone());
    let legacy = Request::from_parts(parts, Body::from(bytes));
    let response = match if kind == "chat" {
        crate::chat::handle_chat_legacy(legacy).await
    } else {
        crate::regenerate::handle_regenerate_legacy(legacy).await
    } {
        Ok(response) => response,
        Err(error) => {
            if error.0 == StatusCode::BAD_REQUEST || error.0 == StatusCode::CONFLICT {
                if let Some(operation) = &operation { registry.record(&owner, operation, error.0, &error.1.0); }
            }
            return Err(error);
        }
    };
    let id = format!("{:032x}", rand::random::<u128>());
    let descriptor = Descriptor {
        generation_id: id.clone(),
        state: "running".into(),
        base_version: *feedback
            .base_version
            .lock()
            .unwrap_or_else(|e| e.into_inner()),
    };
    let (events, _) = broadcast::channel(256);
    let (stop, _) = watch::channel(false);
    let generation = Arc::new(Generation {
        owner: owner.clone(),
        set_id,
        state: Mutex::new(State {
            descriptor: descriptor.clone(),
            events: VecDeque::new(),
            bytes: 0,
            seq: 0,
            settled: false,
        }),
        events,
        stop,
    });
    registry
        .entries
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(id, generation.clone());
    if let Some(operation) = operation {
        registry.record(&owner, &operation, StatusCode::ACCEPTED, &descriptor);
    }
    generation.emit("status", "running");
    tokio::spawn(worker(
        registry.clone(),
        generation.clone(),
        response.into_body(),
        feedback,
    ));
    Ok(event_response(generation, registry.timing.heartbeat, 0, StatusCode::ACCEPTED))
}

#[derive(Default)]
struct EventText {
    pending: String,
    thinking: bool,
}
impl EventText {
    fn push(&mut self, generation: &Generation, text: &str, end: bool) {
        self.pending.push_str(text);
        loop {
            let tags: &[&str] = if self.thinking {
                &["</think>", "</thinking>"]
            } else {
                &["<think>", "<thinking>"]
            };
            let found = tags
                .iter()
                .filter_map(|tag| self.pending.find(tag).map(|at| (at, *tag)))
                .min_by_key(|(at, _)| *at);
            let channel = if self.thinking { "thinking" } else { "delta" };
            if let Some((at, tag)) = found {
                if at > 0 {
                    generation.emit(channel, &self.pending[..at]);
                }
                self.pending.drain(..at + tag.len());
                self.thinking = !self.thinking;
                continue;
            }
            let held = if end {
                0
            } else {
                (1..=self.pending.len().min(10))
                    .filter(|len| {
                        self.pending.is_char_boundary(self.pending.len() - len)
                            && tags.iter().any(|tag| {
                                tag.starts_with(&self.pending[self.pending.len() - len..])
                            })
                    })
                    .max()
                    .unwrap_or(0)
            };
            let visible = self.pending.len() - held;
            if visible > 0 {
                generation.emit(channel, &self.pending[..visible]);
                self.pending.drain(..visible);
            }
            break;
        }
    }
}

async fn worker(
    registry: Arc<GenerationRegistry>,
    generation: Arc<Generation>,
    body: Body,
    feedback: GenerationFeedback,
) {
    let mut stop = generation.stop.subscribe();
    let deadline = tokio::time::sleep(registry.timing.deadline.min(Duration::from_secs(1800)));
    tokio::pin!(deadline);
    let mut stream = body.into_data_stream();
    let mut terminal = "completed";
    let mut text = EventText::default();
    loop {
        if *stop.borrow() {
            terminal = "stopped";
            break;
        }
        tokio::select! {
            biased;
            _ = stop.changed() => { terminal = "stopped"; break; }
            _ = &mut deadline => { terminal = "stopped"; break; }
            item = stream.next() => match item {
                Some(Ok(bytes)) => text.push(&generation, &String::from_utf8_lossy(&bytes), false),
                Some(Err(_)) => { terminal = "failed"; break; }
                None => break,
            }
        }
    }
    // Dropping the exclusively worker-owned stream invokes the shared partial
    // finalizer; subscriber streams contain no lease, key or privacy permit.
    drop(stream);
    text.push(&generation, "", true);
    if *feedback
        .provider_failed
        .lock()
        .unwrap_or_else(|e| e.into_inner())
    {
        terminal = "failed";
    }
    generation.emit("ended", terminal);
    let saved = matches!(
        *feedback.outcome.lock().unwrap_or_else(|e| e.into_inner()),
        Some(FinalizeOutcome::GuestUpdated | FinalizeOutcome::DurableCommitted)
    );
    if saved {
        generation.emit("saved", "");
    } else {
        generation.emit("error", "Failed to save chat history");
        terminal = "failed";
    }
    {
        let mut state = generation.state.lock().unwrap_or_else(|e| e.into_inner());
        state.descriptor.state = terminal.into();
        state.settled = true;
    }
    tokio::time::sleep(registry.timing.grace).await;
    registry
        .entries
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(&generation.descriptor().generation_id);
}

pub async fn status(
    Path(id): Path<String>,
    request: Request<Body>,
) -> Result<Response<Body>, HttpError> {
    let services = AppServices::from_extensions(request.extensions());
    let owner = owner(&services, &request, false)?;
    Ok(json_response(
        StatusCode::OK,
        services.generations().owned(&owner, &id)?.descriptor(),
    ))
}
#[derive(Deserialize)]
pub struct ActivityQuery {
    set_id: String,
}
pub async fn activity(
    Query(query): Query<ActivityQuery>,
    request: Request<Body>,
) -> Result<Response<Body>, HttpError> {
    let services = AppServices::from_extensions(request.extensions());
    let owner = owner(&services, &request, false)?;
    let set_id = if owner.starts_with("user:") {
        chatbot_core::history::SetId::parse(&query.set_id).map_err(|_| api_error(StatusCode::BAD_REQUEST, "invalid set_id"))?.to_string()
    } else { query.set_id };
    Ok(json_response(
        StatusCode::OK,
        json!({"generations": services.generations().running(&owner, &set_id)}),
    ))
}
pub async fn stop(
    Path(id): Path<String>,
    request: Request<Body>,
) -> Result<Response<Body>, HttpError> {
    let services = AppServices::from_extensions(request.extensions());
    let owner = owner(&services, &request, true)?;
    let registry = services.generations();
    let generation = registry.owned(&owner, &id)?;
    let operation = crate::idempotency::operation_request(
        request.headers(),
        "/generations/stop",
        &json!({"generation_id":id}),
    )?;
    let _admission = registry.admission_lock(&owner).await;
    if let Some(operation) = &operation {
        if let Some(response) = registry.replay(&owner, operation)? { return Ok(response); }
    }
    if !generation
        .state
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .settled
    {
        generation.stop.send_replace(true);
    }
    let descriptor = generation.descriptor();
    if let Some(operation) = &operation { registry.record(&owner, operation, StatusCode::OK, &descriptor); }
    Ok(json_response(StatusCode::OK, descriptor))
}
#[derive(Default, Deserialize)]
pub struct EventsQuery {
    #[serde(default)]
    after: u64,
}
pub async fn events(
    Path(id): Path<String>,
    Query(query): Query<EventsQuery>,
    request: Request<Body>,
) -> Result<Response<Body>, HttpError> {
    let services = AppServices::from_extensions(request.extensions());
    let owner = owner(&services, &request, false)?;
    let registry = services.generations();
    let generation = registry.owned(&owner, &id)?;
    Ok(event_response(generation, registry.timing.heartbeat, query.after, StatusCode::OK))
}
fn event_response(generation: Arc<Generation>, heartbeat: Duration, after: u64, status: StatusCode) -> Response<Body> {
    let descriptor = generation.descriptor();
    let mut receiver = generation.events.subscribe();
    let stream = async_stream::stream! {
        let mut cursor = after;
        let mut timer = tokio::time::interval(heartbeat);
        timer.tick().await;
        loop {
            let (replay, settled) = {
                let state = generation.state.lock().unwrap_or_else(|e| e.into_inner());
                (state.events_after(cursor), state.settled)
            };
            for event in replay { cursor = event.seq; yield Ok::<Bytes, std::convert::Infallible>(line(&event)); }
            if settled { break; }
            tokio::select! {
                event = receiver.recv() => match event {
                    Ok(event) if event.seq > cursor => { cursor = event.seq; yield Ok(line(&event)); }
                    Ok(_) => {}
                    Err(_) => break,
                },
                _ = timer.tick() => { yield Ok(Bytes::from_static(b"{\"type\":\"heartbeat\"}\n")); }
            }
        }
    };
    Response::builder()
        .status(status)
        .header("X-Generation-Id", descriptor.generation_id)
        .header("X-Generation-Base-Version", descriptor.base_version)
        .header(header::CONTENT_TYPE, "application/x-ndjson")
        .header(header::CACHE_CONTROL, "no-store")
        .header("X-Accel-Buffering", "no")
        .body(Body::from_stream(stream))
        .expect("valid stream response")
}
fn line(event: &Event) -> Bytes {
    let mut bytes = serde_json::to_vec(event).expect("event serialization");
    bytes.push(b'\n');
    Bytes::from(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state_with(seqs: std::ops::RangeInclusive<u64>) -> State {
        let mut state = State {
            descriptor: Descriptor { generation_id: "g".into(), state: "running".into(), base_version: 0 },
            events: VecDeque::new(),
            bytes: 0,
            seq: *seqs.end(),
            settled: false,
        };
        for seq in seqs {
            state.events.push_back(Event { generation_id: "g".into(), seq, kind: "delta".into(), channel: "answer".into(), text: seq.to_string() });
        }
        state
    }

    #[test]
    fn events_after_slices_the_contiguous_buffer_by_sequence() {
        let state = state_with(5..=9);
        let seqs = |cursor| state.events_after(cursor).into_iter().map(|e| e.seq).collect::<Vec<_>>();
        assert_eq!(seqs(0), vec![5, 6, 7, 8, 9], "a cursor before the evicted prefix replays what remains");
        assert_eq!(seqs(4), vec![5, 6, 7, 8, 9]);
        assert_eq!(seqs(6), vec![7, 8, 9]);
        assert_eq!(seqs(9), Vec::<u64>::new());
        assert_eq!(seqs(42), Vec::<u64>::new());
        assert!(state_with(1..=0).events_after(0).is_empty());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn admission_serializes_each_owner_independently() {
        let registry = GenerationRegistry::default();
        let held = registry.admission_lock("user:a").await;
        let other = tokio::time::timeout(Duration::from_millis(50), registry.admission_lock("user:b")).await;
        assert!(other.is_ok(), "another owner's admission or Stop must not wait");
        let same = tokio::time::timeout(Duration::from_millis(50), registry.admission_lock("user:a")).await;
        assert!(same.is_err(), "the same owner stays serialized");
        drop(held);
        let again = tokio::time::timeout(Duration::from_millis(50), registry.admission_lock("user:a")).await;
        assert!(again.is_ok(), "released owner admits again");
    }
}
