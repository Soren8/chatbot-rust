//! Contract for `static/session-client.js`: owned browser HTTP/session client
//! (MOD009).
//!
//! The shared unit owns fetch bootstrap/CSRF refresh/401 retry, generate
//! retry and voice HTTP helpers with explicit dependencies (fetch, bootstrap
//! fetch, login/CSRF/redirect callbacks, sleep, XHR) and per-instance state
//! (single shared bootstrap promise). `static/chat.js` keeps one instance
//! plus thin adapters and all DOM rendering/callbacks; no duplicate mutable
//! authority. Behavioral coverage lives in
//! `fixtures/session_client_test.js` through the stable import.

use std::path::Path;
use std::process::Command;

fn unit_js() -> &'static str {
    include_str!("../../static/session-client.js")
}

fn chat_js() -> &'static str {
    include_str!("../../static/chat.js")
}

fn function_body<'a>(src: &'a str, fn_name: &str) -> Option<&'a str> {
    let header = format!("function {fn_name}(");
    let start = src.find(&header)?;
    let body = &src[start..];
    let open = body.find('{')?;
    let mut depth = 0i32;
    for (i, ch) in body[open..].char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(&body[open..=open + i]);
                }
            }
            _ => {}
        }
    }
    None
}

fn function_contains(src: &str, fn_name: &str, needle: &str) -> bool {
    function_body(src, fn_name).is_some_and(|body| body.contains(needle))
}

#[test]
fn session_client_projects_owned_retry() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let run = Command::new("node")
        .arg(root.join("chatbot-server/tests/fixtures/session_client_test.js"))
        .arg(root.join("static/session-client.js"))
        .output()
        .expect("test image must provide the JS behavior-test runtime");
    assert!(
        run.status.success(),
        "JS session-client behavior: {}",
        String::from_utf8_lossy(&run.stderr)
    );
}

#[test]
fn session_client_js_parses() {
    let source = unit_js();
    let allocator = oxc_allocator::Allocator::default();
    let source_type = oxc_span::SourceType::default()
        .with_module(false)
        .with_jsx(false);
    let ret = oxc_parser::Parser::new(&allocator, source, source_type).parse();
    let errors: Vec<String> = ret.diagnostics.errors().map(ToString::to_string).collect();
    assert!(
        errors.is_empty(),
        "static/session-client.js failed to parse ({} error(s)):\n{}",
        errors.len(),
        errors.join("\n")
    );
}

/// Packaging contract: the chat page loads the shared session unit before the
/// application script, and chat.js delegates owned HTTP state to it instead of
/// keeping a second mutable copy.
#[test]
fn chat_page_wires_session_client_before_app_script() {
    let html = include_str!("../../static/templates/chat.html");
    let unit = html
        .find("/static/session-client.js")
        .expect("chat page must load the shared session-client unit");
    let app = html
        .find("/static/chat.js")
        .expect("chat page must load the chat application");
    assert!(
        unit < app,
        "session-client.js must load before chat.js so ChatSessionClient exists"
    );

    let src = chat_js();
    for marker in [
        "ChatSessionClient.createSessionClient",
        "sessionClient.installFetchInterceptor()",
        "sessionClient.refreshSession()",
        "sessionClient.refreshCsrfInit",
        "sessionClient.fetchVoiceRetry",
        "sessionClient.postVoiceSttXhr",
        "sessionClient.withCsrf",
        "sessionClient.handle401OrRetry",
        "sessionClient.fetchWithGenerateRetry",
    ] {
        assert!(
            src.contains(marker),
            "chat.js must delegate owned session HTTP to the shared unit; missing: {marker}"
        );
    }
    for duplicate in [
        "const originalFetch",
        "var sessionRefreshPromise",
        "originalFetch('/login')",
        "xhr.upload.onprogress",
        "new XMLHttpRequest()",
        "name=\"csrf_token\" value",
    ] {
        assert!(
            !src.contains(duplicate),
            "single authority lives in the shared unit; chat.js must not keep {duplicate}"
        );
    }
}

/// Single bootstrap sharing with error recovery: concurrent callers share one
/// attempt, failures clear the promise, guests never bootstrap.
#[test]
fn bootstrap_shares_single_attempt_with_error_recovery() {
    let unit = unit_js();
    assert!(
        unit.contains("var sessionRefreshPromise = null"),
        "one shared bootstrap promise per instance"
    );
    let refresh = function_body(unit, "refreshSession").expect("refreshSession");
    assert!(
        refresh.contains("if (sessionRefreshPromise)")
            && refresh.contains("sessionRefreshPromise.finally")
            && refresh.contains("sessionRefreshPromise = null"),
        "concurrent callers share one attempt and recovery clears it; got: {refresh}"
    );
    assert!(
        refresh.contains("return Promise.resolve(false)")
            && refresh.contains("getLoggedIn()"),
        "guests resolve false without bootstrapping; got: {refresh}"
    );
    assert!(
        refresh.contains("'/login'")
            && refresh.contains("'/login/remember'")
            && refresh.contains("name=\"csrf_token\" value=\"([^\"]+)\"")
            && refresh.contains("'Content-Type': 'application/x-www-form-urlencoded'")
            && refresh.contains("'csrf_token=' + encodeURIComponent"),
        "bootstrap keeps GET /login + form-encoded POST /login/remember; got: {refresh}"
    );
    assert!(
        refresh.contains(".catch(function ()")
            && refresh.contains("return false"),
        "bootstrap failures resolve false for error recovery; got: {refresh}"
    );
    assert!(
        refresh.contains("setCsrfToken(data.csrf_token)"),
        "the restored CSRF is adopted via the explicit setter; got: {refresh}"
    );
    let src = chat_js();
    assert!(
        function_contains(src, "refreshSession", "sessionClient.refreshSession()"),
        "chat keeps only the thin refresh adapter"
    );
}

/// Headers, cookie credentials, and URLs stay exactly as before.
#[test]
fn headers_credentials_urls_preserved() {
    let unit = unit_js();
    let csrf = function_body(unit, "withCsrf").expect("withCsrf");
    assert!(
        csrf.contains("X-CSRF-Token") && csrf.contains("getCsrfToken()"),
        "CSRF header rides the explicit token getter; got: {csrf}"
    );
    let refresh = function_body(unit, "refreshCsrfInit").expect("refreshCsrfInit");
    assert!(
        refresh.contains("x-csrf-token") && refresh.contains("toLowerCase()"),
        "CSRF rebuild stays case-insensitive; got: {refresh}"
    );
    assert!(
        refresh.contains("instanceof Headers") && refresh.contains("forEach"),
        "Headers instances rebuild without mutating the cached init; got: {refresh}"
    );
    assert!(
        !unit.contains("credentials"),
        "cookie credentials stay ambient (same-origin default); no explicit credentials mode"
    );
    assert!(
        unit.contains("'/login'") && unit.contains("'/login/remember'"),
        "bootstrap URLs stay fixed"
    );
    let src = chat_js();
    assert!(
        function_contains(src, "withCsrf", "sessionClient.withCsrf")
            && function_contains(src, "refreshCsrfInit", "sessionClient.refreshCsrfInit"),
        "chat keeps only header thin adapters"
    );
}

/// AbortSignal stays wired through every helper.
#[test]
fn abort_signal_preserved() {
    let unit = unit_js();
    let voice = function_body(unit, "fetchVoiceRetry").expect("fetchVoiceRetry");
    assert!(
        voice.contains("new AbortController()")
            && voice.contains("60000")
            && voice.contains("userAborted")
            && voice.contains("userSignal.aborted")
            && voice.contains("addEventListener('abort'")
            && voice.contains("removeEventListener('abort'"),
        "voice fetch links the user signal to its own 60s stall controller; got: {voice}"
    );
    let stt = function_body(unit, "postVoiceSttXhr").expect("postVoiceSttXhr");
    assert!(
        stt.contains("userSignal.aborted")
            && stt.contains("xhr.abort()")
            && stt.contains("AbortError"),
        "STT XHR aborts on the user signal and surfaces AbortError; got: {stt}"
    );
    let gen = function_body(unit, "fetchWithGenerateRetry").expect("fetchWithGenerateRetry");
    assert!(
        gen.contains("init.signal.aborted") && gen.contains("name = 'AbortError'"),
        "generate retry checks the caller signal before reissuing; got: {gen}"
    );
}

/// Retry eligibility, counts, delays, and per-attempt bodies stay exact.
#[test]
fn retry_eligibility_count_delay_body_preserved() {
    let unit = unit_js();
    let eligible =
        function_body(unit, "isRetryableVoiceStatus").expect("isRetryableVoiceStatus");
    assert!(
        eligible.contains("status === 408")
            && eligible.contains("status === 429")
            && eligible.contains("status === 502")
            && eligible.contains("status >= 500"),
        "voice retry stays 408/429/5xx-only; got: {eligible}"
    );
    let voice = function_body(unit, "fetchVoiceRetry").expect("fetchVoiceRetry");
    assert!(
        voice.contains("attempts = attempts || 3")
            && voice.contains("400 * Math.pow(2, attempts - n)")
            && voice.contains("typeof buildOptions === 'function' ? buildOptions()"),
        "voice fetch retries 3x with exponential backoff and a fresh body per attempt; got: {voice}"
    );
    assert!(
        voice.contains("res.status === 401")
            && voice.contains("Session expired")
            && voice.contains("err.name === 'AbortError' && userAborted"),
        "401 and user aborts never retry; got: {voice}"
    );
    let stt = function_body(unit, "postVoiceSttXhr").expect("postVoiceSttXhr");
    assert!(
        stt.contains("retryableVoice = isRetryableVoiceStatus")
            && stt.contains("retryableVoice = true")
            && stt.contains("retryableVoice === false"),
        "STT marks transport failures retryable and honors the flag; got: {stt}"
    );
    let gen = function_body(unit, "fetchWithGenerateRetry").expect("fetchWithGenerateRetry");
    assert!(
        gen.contains("res.status === 429")
            && gen.contains("res.status === 400 && attempt < 8")
            && gen.contains("attempt < 12")
            && gen.contains("200 + attempt * 150"),
        "generate retries 429 plus early 400s with linear backoff; got: {gen}"
    );
    assert!(
        gen.contains("res.status === 401 && !afterRefresh")
            && gen.contains("refreshSession()")
            && gen.contains("refreshCsrfInit(init)")
            && gen.contains("attempt, true"),
        "generate refreshes once with a rebuilt CSRF header; got: {gen}"
    );
}

/// Guest/native login compatibility: no new auth architecture, no silent race
/// fixes. Guests bypass bootstrap and redirect home; logged-in callers get the
/// response for refresh handling; enc-key 401s never refresh.
#[test]
fn guest_native_login_compatibility_preserved() {
    let unit = unit_js();
    let gate = function_body(unit, "redirectHomeOnAuthFailure")
        .expect("redirectHomeOnAuthFailure");
    assert!(
        gate.contains("getLoggedIn()") && gate.contains("redirectHome()"),
        "the gate reads explicit login state and redirects via callback; got: {gate}"
    );
    let kind = function_body(unit, "response401Kind").expect("response401Kind");
    assert!(
        kind.contains("/encryption key|unlock|invalid encryption key/i"),
        "enc-key 401s classify separately; got: {kind}"
    );
    let handle = function_body(unit, "handle401OrRetry").expect("handle401OrRetry");
    assert!(
        handle.contains("Could not unlock chats")
            && handle.contains("refreshSession()")
            && handle.contains("Session expired. Sign out and log in again."),
        "enc-key throws to unlock, session refreshes once, unrestored throws to sign-in; got: {handle}"
    );
    assert!(
        !unit.contains("/login/keyauth"),
        "the data key must not mint a session"
    );
    let src = chat_js();
    assert!(
        function_contains(src, "redirectHomeOnAuthFailure", "sessionClient.redirectHomeOnAuthFailure")
            && function_contains(src, "handle401OrRetry", "sessionClient.handle401OrRetry"),
        "chat keeps only auth thin adapters"
    );
}

/// Global fetch interception routes through the single allowlist owner.
#[test]
fn global_fetch_interception_semantics_preserved() {
    let unit = unit_js();
    let owner =
        function_body(unit, "isAuthAllowlistedUrl").expect("isAuthAllowlistedUrl");
    for marker in [
        "url.includes('/chat')",
        "url.includes('/regenerate')",
        "url.includes('/get_sets')",
        "url.includes('/load_set')",
        "url.includes('/update_preferences')",
        "url.includes('/history_image')",
    ] {
        assert!(
            owner.contains(marker),
            "allowlist owner must keep {marker}; got: {owner}"
        );
    }
    let install =
        function_body(unit, "installFetchInterceptor").expect("installFetchInterceptor");
    assert!(
        install.contains("isAuthAllowlistedUrl(url)")
            || install.contains("isAuthAllowlistedUrl("),
        "interceptor must route through the single allowlist owner; got: {install}"
    );
    assert!(
        !install.contains("url.includes('/chat')"),
        "allowlist must not duplicate in the interceptor; got: {install}"
    );
    for marker in [
        "instanceof Request",
        "redirectHomeOnAuthFailure()",
        "throw new Error('Session expired')",
    ] {
        assert!(
            install.contains(marker),
            "interceptor must keep {marker}; got: {install}"
        );
    }
    let src = chat_js();
    assert!(
        src.contains("sessionClient.installFetchInterceptor()"),
        "chat installs the owned interceptor instead of wrapping fetch inline"
    );
    assert!(
        !src.contains("window.fetch = function"),
        "single authority lives in the shared unit"
    );
}

/// Callback failures keep precise exception behavior (no broad swallowing).
/// Behavioral regressions live in the fixture; here guards the source shape.
#[test]
fn callback_failures_keep_precise_exceptions() {
    let unit = unit_js();
    let gate = function_body(unit, "redirectHomeOnAuthFailure")
        .expect("redirectHomeOnAuthFailure");
    assert!(
        !gate.contains("try"),
        "redirect failures were uncaught; got: {gate}"
    );
    let refresh = function_body(unit, "refreshSession").expect("refreshSession");
    assert!(
        refresh.contains("setCsrfToken(data.csrf_token)"),
        "setter failure must reach the shared catch (resolve false); got: {refresh}"
    );
    assert!(
        !refresh.contains("try {"),
        "login/token reads must not swallow to defaults; got: {refresh}"
    );
    let csrf = function_body(unit, "withCsrf").expect("withCsrf");
    assert!(
        !csrf.contains("try"),
        "token getter failure must propagate; got: {csrf}"
    );
    let rebuild = function_body(unit, "refreshCsrfInit").expect("refreshCsrfInit");
    assert!(
        !rebuild.contains("try"),
        "token/header reads must propagate; got: {rebuild}"
    );
    let stt = function_body(unit, "postVoiceSttXhr").expect("postVoiceSttXhr");
    assert!(
        stt.contains("userSignal.addEventListener('abort', onUserAbort);"),
        "signal listener failure must reject into the retry loop; got: {stt}"
    );
    assert!(
        !unit.contains("defaultGet")
            && !unit.contains("defaultSetCsrfToken")
            && !unit.contains("defaultRedirectHome")
            && !unit.contains("window.APP_DATA")
            && !unit.contains("window.CSRF_TOKEN")
            && !unit.contains("window.location")
            && !unit.contains("document.querySelector"),
        "no window/document querying in the client; callbacks are explicit required"
    );
    assert!(
        !unit.contains("sleepImpl")
            && !unit.contains("globalFetchNow")
            && !unit.contains("voiceTimeoutMs")
            && !unit.contains("extractFetchUrl")
            && !unit.contains("isRefreshing"),
        "no speculative fallback APIs"
    );
}
