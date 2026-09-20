//! Contract for `static/conversation-state.js`: owned browser
//! conversation/request/history-window state (MOD009).
//!
//! The shared unit owns set-version transitions (reads advance only,
//! mutations/409 authoritative), exact set-identity payloads, retry-once
//! decisions, stale fencing (request sequence + set generation), ghost-turn
//! routing, history-window offsets/pagination and the three abort behaviors.
//! `static/chat.js` keeps one history window plus one request tracker and all
//! DOM rendering/callbacks; TTS queue fixtures drive generating state through
//! the real tracker. No duplicate mutable authority.

use std::path::Path;
use std::process::Command;

fn unit_js() -> &'static str {
    include_str!("../../static/conversation-state.js")
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
fn conversation_state_projects_owned_transitions() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let run = Command::new("node")
        .arg(root.join("chatbot-server/tests/fixtures/conversation_state_test.js"))
        .arg(root.join("static/conversation-state.js"))
        .output()
        .expect("test image must provide the JS behavior-test runtime");
    assert!(
        run.status.success(),
        "JS conversation-state behavior: {}",
        String::from_utf8_lossy(&run.stderr)
    );
}

#[test]
fn conversation_state_js_parses() {
    let source = unit_js();
    let allocator = oxc_allocator::Allocator::default();
    let source_type = oxc_span::SourceType::default()
        .with_module(false)
        .with_jsx(false);
    let ret = oxc_parser::Parser::new(&allocator, source, source_type).parse();
    let errors: Vec<String> = ret.diagnostics.errors().map(ToString::to_string).collect();
    assert!(
        errors.is_empty(),
        "static/conversation-state.js failed to parse ({} error(s)):\n{}",
        errors.len(),
        errors.join("\n")
    );
}

/// Packaging contract: the chat page loads the shared conversation unit
/// before the application script, and chat.js delegates owned state to it
/// instead of keeping a second mutable copy.
#[test]
fn chat_page_wires_conversation_state_before_app_script() {
    let html = include_str!("../../static/templates/chat.html");
    let unit = html
        .find("/static/conversation-state.js")
        .expect("chat page must load the shared conversation-state unit");
    let app = html
        .find("/static/chat.js")
        .expect("chat page must load the chat application");
    assert!(
        unit < app,
        "conversation-state.js must load before chat.js so ChatConversationState exists"
    );

    let src = chat_js();
    for marker in [
        "ChatConversationState.createHistoryWindow",
        "ChatConversationState.createChatRequestTracker",
        "ChatConversationState.applySetVersionTo",
        "ChatConversationState.buildActiveSetPayload",
        "ChatConversationState.noteSetVersionFromResponseTo",
        "ChatConversationState.noteSetVersionFromReadTo",
        "ChatConversationState.noteLocalVersionBumpAfterPersistTo",
        "ChatConversationState.shouldRetryVersionOnce",
        "ChatConversationState.isGhostTurn",
        "ChatConversationState.userPairIndexForDomIndex",
        "chatRequests.isGenerating()",
        "historyWindow.",
    ] {
        assert!(
            src.contains(marker),
            "chat.js must delegate owned conversation state to the shared unit; missing: {marker}"
        );
    }
    for duplicate in [
        "var HISTORY_OFFSET",
        "var HISTORY_TOTAL",
        "var HISTORY_HAS_MORE",
        "var HISTORY_LOADING_OLDER",
        "var HISTORY_SET_GEN",
        "let chatRequestSeq",
        "let currentAbortController",
    ] {
        assert!(
            !src.contains(duplicate),
            "single authority lives in the shared unit; chat.js must not keep {duplicate}"
        );
    }
}

/// Reads advance only; mutations and 409 bodies are authoritative.
#[test]
fn version_rewind_policy_reads_advance_only_mutations_authoritative() {
    let unit = unit_js();
    let apply = function_body(unit, "applySetVersionTo").expect("applySetVersionTo");
    assert!(
        apply.contains("allowRewind"),
        "applySetVersionTo must gate rewinds on allowRewind; got: {apply}"
    );
    assert!(
        apply.contains("next < current"),
        "same-set versions must never rewind without allowRewind; got: {apply}"
    );
    assert!(
        apply.contains("lastSetId") && apply.contains("switchedSet"),
        "set switches adopt the new version; got: {apply}"
    );
    let read = function_body(unit, "noteSetVersionFromReadTo").expect("noteSetVersionFromReadTo");
    assert!(
        !read.contains("allowRewind: true"),
        "read sync (load_set/history_pair) must stay advance-only; got: {read}"
    );
    let mutation = function_body(unit, "noteSetVersionFromResponseTo")
        .expect("noteSetVersionFromResponseTo");
    assert!(
        mutation.contains("allowRewind: true"),
        "mutation/409 sync must stay authoritative; got: {mutation}"
    );
    let bump = function_body(unit, "noteLocalVersionBumpAfterPersistTo")
        .expect("noteLocalVersionBumpAfterPersistTo");
    assert!(
        bump.contains("+ 1") && bump.contains("applySetVersionTo"),
        "persist must optimistically advance by one so delete/reset do not race loadSets; got: {bump}"
    );
    let src = chat_js();
    assert!(
        function_contains(src, "applySetVersion", "ChatConversationState.applySetVersionTo")
            && function_contains(src, "applySetVersion", "syncSelectedOptionVersion"),
        "chat keeps only the DOM sync callback for version updates"
    );
}

/// Exact set-identity payload shape shared by every mutating request.
#[test]
fn active_set_payload_carries_name_id_and_expected_version() {
    let unit = unit_js();
    let body = function_body(unit, "buildActiveSetPayload").expect("buildActiveSetPayload");
    assert!(
        body.contains("set_name") && body.contains("setName || 'default'"),
        "payload must carry set_name with the default fallback; got: {body}"
    );
    assert!(
        body.contains("payload.set_id = id.setId") || body.contains("set_id"),
        "payload must carry set_id when known; got: {body}"
    );
    assert!(
        body.contains("expected_version") && body.contains("Number(id.setVersion)"),
        "payload must carry numeric expected_version; got: {body}"
    );
    let src = chat_js();
    assert!(
        function_contains(src, "activeSetPayload", "ChatConversationState.buildActiveSetPayload")
            && function_contains(src, "activeSetPayload", "option:selected"),
        "chat adapter reads the selected option and forwards explicit identity"
    );
}

/// History window offsets and set-generation fencing.
#[test]
fn history_window_offsets_and_pagination_fencing() {
    let unit = unit_js();
    assert!(
        unit.contains("HISTORY_PAGE_SIZE = 40"),
        "history pages stay 40 items"
    );
    let reset = function_body(unit, "reset").expect("history reset");
    assert!(
        reset.contains("offset = 0") && reset.contains("hasMore = false"),
        "reset must clear offset/total/has-more/loading; got: {reset}"
    );
    let apply = function_body(unit, "applyPage").expect("applyPage");
    assert!(
        apply.contains("hasMore = !!(data && data.has_more)")
            && apply.contains("offset = start"),
        "applyPage must adopt total/has-more/offset from the page; got: {apply}"
    );
    let older = function_body(unit, "beginOlderLoad").expect("beginOlderLoad");
    assert!(
        older.contains("loadingOlder = true")
            && older.contains("before: offset")
            && older.contains("limit: size"),
        "older-page request must fence concurrent loads and page before the offset; got: {older}"
    );
    assert!(
        unit.contains("gen !== setGen") || unit.contains("isLiveGen"),
        "a set switch must discard the stale older page"
    );
    assert!(
        unit.contains("userPairIndexForDomIndex"),
        "live DOM order plus window offset resolves the server pair index"
    );
    let src = chat_js();
    assert!(
        function_contains(src, "liveUserPairIndex", "userPairIndexForDomIndex")
            && function_contains(src, "reindexUserPairIndices", "userPairIndexForDomIndex")
            && function_contains(src, "loadOlderMessages", "beginOlderLoad")
            && function_contains(src, "loadOlderMessages", "isLiveGen")
            && function_contains(src, "applyHistoryPage", "historyWindow.applyPage"),
        "chat renders from the owned window instead of parallel globals"
    );
}

/// Stale stream callbacks must not clobber the replacement request.
#[test]
fn stale_request_fencing_guards_stream_callbacks() {
    let unit = unit_js();
    assert!(
        unit.contains("var seq = 0;"),
        "request fencing needs a monotonic sequence"
    );
    assert!(
        function_contains(unit, "isLive", "s === seq")
            || unit.contains("return s === seq;"),
        "liveness is exact sequence equality"
    );
    let begin = unit
        .find("begin: function ()")
        .expect("tracker begin");
    let begin_chunk = &unit[begin..(begin + 300).min(unit.len())];
    assert!(
        begin_chunk.contains("seq += 1")
            && begin_chunk.contains("abortCaught()")
            && begin_chunk.contains("makeController()"),
        "begin must invalidate the prior request and own the new signal; got: {begin_chunk}"
    );
    let finish = unit
        .find("finish: function (s)")
        .expect("tracker finish");
    let finish_chunk = &unit[finish..(finish + 200).min(unit.len())];
    assert!(
        finish_chunk.contains("s !== seq") && finish_chunk.contains("controller = null"),
        "only the live request may clear the controller; got: {finish_chunk}"
    );
    let src = chat_js();
    for (caller, needle) in [
        ("sendMessage", "isLiveChatRequest(seq)"),
        ("performRegeneration", "isLiveChatRequest(seq)"),
    ] {
        assert!(
            function_contains(src, caller, needle) || src.contains(needle),
            "{caller} stream/error callbacks must fence on the live sequence"
        );
    }
    assert!(
        function_contains(unit, "abortCaught", ".abort()"),
        "the shared abort helper must abort the live controller"
    );
}

/// Three abort behaviors stay distinct: quiet replace, user stop, voice interrupt.
#[test]
fn three_abort_behaviors_stay_distinct() {
    let unit = unit_js();
    let quiet = unit
        .find("abortQuietly: function ()")
        .expect("tracker abortQuietly");
    let quiet_chunk = &unit[quiet..(quiet + 250).min(unit.len())];
    assert!(
        quiet_chunk.contains("seq += 1")
            && quiet_chunk.contains("abortCaught()")
            && quiet_chunk.contains("controller = null"),
        "quiet replace (voice amend) must bump the sequence so the aborted /chat stays silent; got: {quiet_chunk}"
    );
    let stop = unit
        .find("stopForUser: function ()")
        .expect("tracker stopForUser");
    let stop_chunk = &unit[stop..(stop + 250).min(unit.len())];
    assert!(
        !stop_chunk.contains("seq += 1")
            && stop_chunk.contains("controller.abort()")
            && !stop_chunk.contains("try"),
        "user stop must abort uncaught without bumping, so AbortError paints [Stopped]; got: {stop_chunk}"
    );
    let interrupt = unit
        .find("interruptForVoiceTurn: function ()")
        .expect("tracker interruptForVoiceTurn");
    let interrupt_chunk = &unit[interrupt..(interrupt + 350).min(unit.len())];
    assert!(
        interrupt_chunk.contains("if (!controller) return false")
            && interrupt_chunk.contains("controller.abort()")
            && interrupt_chunk.contains("seq += 1")
            && !interrupt_chunk.contains("try"),
        "voice interrupt must abort uncaught and bump only when generation was active; got: {interrupt_chunk}"
    );
    let src = chat_js();
    assert!(
        function_contains(src, "handleStopClick", "stopForUser")
            && function_contains(src, "handleStopClick", "stopAllTtsPlayback"),
        "Send/Stop must halt TTS and abort generation"
    );
    assert!(
        function_contains(src, "interruptVoiceReplyForNewTurn", "interruptForVoiceTurn")
            && function_contains(src, "interruptVoiceReplyForNewTurn", "[Stopped]"),
        "a new voice turn must halt TTS, invalidate the stream, and finalize the bubble"
    );
    assert!(
        function_contains(src, "handleBargeIn", "VOICE_AMEND_WINDOW_MS")
            && function_contains(src, "handleBargeIn", "interruptVoiceReplyForNewTurn"),
        "barge-in after the amend window must interrupt immediately"
    );
}

/// Every version_conflict path retries exactly once with the authoritative version.
#[test]
fn version_conflict_retries_once_with_authoritative_version() {
    let src = chat_js();
    for marker in [
        "error === 'version_conflict'",
        "noteSetVersionFromResponse",
        "shouldRetryVersionOnce",
    ] {
        assert!(
            src.contains(marker),
            "retry-once paths must adopt the authoritative version; missing: {marker}"
        );
    }
    assert!(
        function_contains(src, "sendMessage", "reuseLastUser: true"),
        "chat retry must replay the same turn instead of opening a new one"
    );
    assert!(
        src.contains("return window.performRegeneration(aiMessageElement, userText, pairIndex, { versionRetried: true });"),
        "regenerate retry must preserve the same pair"
    );
    for (caller, retry_flag) in [
        ("handleDeleteMessage", "handleDeleteMessage(buttonElement, true)"),
        ("handleForkMessage", "handleForkMessage(buttonElement, true)"),
        ("submitResetChat", "submitResetChat(true)"),
        ("saveSystemPromptNow", "saveSystemPromptNow(sysPromptText, true"),
        ("saveMemoryNow", "saveMemoryNow(memText, true"),
        ("submitRenameSet", "submitRenameSet(setId, oldName, newName, true)"),
        ("submitDeleteSet", "submitDeleteSet(setId, setName, true)"),
    ] {
        assert!(
            src.contains(retry_flag),
            "{caller} must retry once after adopting the authoritative version"
        );
    }
    let unit = unit_js();
    assert!(
        function_contains(unit, "shouldRetryVersionOnce", "!alreadyRetried"),
        "the shared unit owns the exactly-once decision"
    );
}

/// Ghost (never-saved) turns never hit pair-indexed endpoints.
#[test]
fn ghost_turns_route_to_chat_resend_not_indexed_endpoints() {
    let unit = unit_js();
    assert!(
        function_contains(unit, "isGhostTurn", "attrLocalOnly")
            && function_contains(unit, "resolveRegenerateAction", "resend-chat")
            && function_contains(unit, "canForkTurn", "!isGhost"),
        "the shared unit owns ghost routing"
    );
    let src = chat_js();
    assert!(
        function_contains(src, "paintFailedAiTurn", "markLocalOnlyTurn"),
        "failed turns stay ghost-marked so they remain resendable/deletable"
    );
    assert!(
        function_contains(src, "regenerateMessage", "resolveRegenerateAction")
            && function_contains(src, "regenerateMessage", "reuseLastUser: true"),
        "regenerating a ghost turn must resend /chat, not /regenerate"
    );
    let delete = function_body(src, "handleDeleteMessage").expect("handleDeleteMessage");
    assert!(
        delete.contains("userMessageElement.attr('data-local-only') === '1' || isLocalOnlyTurn(userMessageElement)")
            && delete.contains("if (aiMessageElement.length === 0)"),
        "delete keeps the original separated branches: ghost bypass first, missing-AI second; got: {delete}"
    );
    assert!(
        delete.contains("removeLocalOnlyTurn"),
        "both local branches remove the turn without a server round-trip"
    );
    assert!(
        src.contains("pair_index: pairIndex") && src.contains("user_message: userText"),
        "saved deletes must match pair_index plus user text exactly"
    );
    assert!(
        function_contains(src, "handleForkMessage", "canForkTurn")
            && src.contains("only saved turns can be branched"),
        "forks require a saved turn"
    );
    assert!(
        function_contains(src, "flushVoiceContinuation", "performRegeneration")
            && function_contains(src, "flushVoiceContinuation", "sendMessage({ reuseLastUser: true"),
        "voice amend must regenerate the live pair or resend the ghost turn"
    );
}

/// Exact request shapes for chat, regenerate, history, and voice routing.
#[test]
fn request_shapes_match_server_contract() {
    let src = chat_js();
    for marker in [
        "fetchWithGenerateRetry('/chat'",
        "fetchWithGenerateRetry('/regenerate'",
        "signal: chatRequests.signal()",
        "system_prompt: systemPrompt",
        "model_name: $('#modelSelect').val()",
        "web_search: $('#web-search-toggle').hasClass('btn-primary')",
        "save_thoughts: $('#check-save-thoughts').is(':checked')",
        "send_thoughts: $('#check-send-thoughts').is(':checked')",
        "pair_index: pairIndex",
        "user_message: userText",
        "set_id: setId",
        "set_name: setName",
        "limit: historyWindow.getPageSize()",
        "thumbnails: true",
        "before: before",
    ] {
        assert!(src.contains(marker), "request shape must keep {marker}");
    }
    assert!(
        !src.contains("signal: currentAbortController.signal"),
        "signals must come from the owned tracker, not a parallel global"
    );
    assert!(
        function_contains(src, "submitVoiceUtterance", "shouldAmendLastVoiceTurn")
            && function_contains(src, "submitVoiceUtterance", "queueVoiceContinuation")
            && function_contains(src, "submitVoiceUtterance", "interruptVoiceReplyForNewTurn")
            && function_contains(src, "submitVoiceUtterance", "sendMessage()"),
        "voice routing must amend within the window, interrupt a live reply, else send a new turn"
    );
    assert!(
        function_contains(src, "queueVoiceContinuation", "abortChatRequestQuietly"),
        "amend must quietly replace the in-flight /chat before regenerating"
    );
}
