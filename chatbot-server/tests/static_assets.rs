use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
};
use chatbot_server::build_router;
use tower::ServiceExt;

#[tokio::test]
async fn serves_static_files_from_configured_root() {
    let temp_dir = tempfile::tempdir().unwrap();
    let css_path = temp_dir.path().join("style.css");
    std::fs::write(&css_path, "body { color: red; }").unwrap();

    let app = build_router(temp_dir.path().to_path_buf());
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/static/style.css")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("static file request");

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 64 * 1024)
        .await
        .expect("read body");
    assert!(body.starts_with(b"body"));
}

#[tokio::test]
async fn serves_placeholder_favicon() {
    let temp_dir = tempfile::tempdir().unwrap();
    let app = build_router(temp_dir.path().to_path_buf());

    let response = app
        .oneshot(
            Request::builder()
                .uri("/favicon.ico")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("favicon request");

    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn rejects_dotfiles_and_sensitive_paths() {
    let temp_dir = tempfile::tempdir().unwrap();
    let app = build_router(temp_dir.path().to_path_buf());

    for path in ["/.env", "/.config.yml"] {
        let response = app
            .clone()
            .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
            .await
            .expect("dotfile request");

        assert!(
            matches!(
                response.status(),
                StatusCode::NOT_FOUND | StatusCode::FORBIDDEN
            ),
            "{path} should not be served (status was {})",
            response.status()
        );
    }
}

#[tokio::test]
async fn blocks_static_directory_traversal() {
    let temp_dir = tempfile::tempdir().unwrap();
    let app = build_router(temp_dir.path().to_path_buf());

    for path in [
        "/static/../.env",
        "/static/../.config.yml",
        "/static/%2e%2e/.env",
    ] {
        let response = app
            .clone()
            .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
            .await
            .expect("traversal request");

        assert!(
            matches!(
                response.status(),
                StatusCode::NOT_FOUND | StatusCode::FORBIDDEN
            ),
            "Traversal path {path} should be blocked (status was {})",
            response.status()
        );
    }
}

/// Regression: editing a user message that has an image must not dump the
/// base64 payload into the textarea (browser freezes on ~1MB of text), and
/// the edit box must be tall enough for multiline text.
#[test]
fn message_edit_ui_shows_image_preview_not_base64_in_textarea() {
    let chat_js = include_str!("../../static/chat.js");
    let style_css = include_str!("../../static/style.css");

    assert!(
        chat_js.contains("function parseUserMessageContent"),
        "expected parseUserMessageContent helper to strip [IMAGE:...] from edit text"
    );
    assert!(
        chat_js.contains("function composeUserMessageContent"),
        "expected composeUserMessageContent to reattach image on save"
    );
    assert!(
        chat_js.contains("edit-image-preview") && chat_js.contains("edit-image-thumb"),
        "edit mode should render an image preview alongside the text box"
    );
    assert!(
        chat_js.contains(".val(parsed.text)"),
        "edit textarea must be seeded with text only (not the full original with base64)"
    );
    assert!(
        !chat_js.contains(".val(originalText)"),
        "must not put full data-original (incl. base64 image) into the edit textarea"
    );
    assert!(
        chat_js.contains("sizeEditTextarea") && style_css.contains("min-height: 140px"),
        "edit textarea should grow beyond the default ~3-line height"
    );
}

/// History paging calls formatAiMessage from a top-level helper. A nested
/// definition inside document.ready is a ReferenceError on Capacitor/WebView.
#[test]
fn format_ai_message_is_top_level_for_history_paging() {
    let chat_js = include_str!("../../static/chat.js");
    let fmt = chat_js
        .find("function formatAiMessage(text)")
        .expect("formatAiMessage helper");
    let append = chat_js
        .find("function appendHistoryPair(")
        .expect("appendHistoryPair");
    assert!(
        fmt < append,
        "formatAiMessage must be defined at top level before appendHistoryPair"
    );
    assert_eq!(
        chat_js.matches("function formatAiMessage(text)").count(),
        1,
        "formatAiMessage must not also be nested inside document.ready"
    );
    let html = include_str!("../../static/templates/chat.html");
    assert!(
        html.contains("id=\"reload-ui\""),
        "Capacitor/WebView needs a reload control (no browser refresh chrome)"
    );
    assert!(
        chat_js.contains("function historyImageUrl")
            && chat_js.contains("openImageLightbox(historyImageUrl"),
        "thumbnail expand must use a GET /history_image URL, not POST JSON"
    );
    assert!(
        chat_js.contains("Path=/history_image"),
        "<img src> cannot send X-Enc-Key; hist_enc_key cookie is Path=/history_image only"
    );
}

/// CodeQL js/xss-through-dom: getAttribute('data-pending-src') is DOM text and
/// must not flow into img src. Reconstruct via sanitizeLightboxSrc first.
#[test]
fn deferred_thumbs_resanitize_dom_src() {
    let chat_js = include_str!("../../static/chat.js");
    let start = chat_js
        .find("function startDeferredThumbs(")
        .expect("startDeferredThumbs helper");
    let next = chat_js[start + 1..]
        .find("\nfunction ")
        .map(|i| start + 1 + i)
        .expect("function after startDeferredThumbs");
    let body = &chat_js[start..next];
    assert!(
        body.contains("sanitizeLightboxSrc("),
        "data-pending-src is DOM text; must reconstruct via sanitizeLightboxSrc before img src"
    );
    assert!(
        !body.contains("setAttribute('src', url)"),
        "must not assign unsanitized getAttribute('data-pending-src') to img src"
    );

    let sanitize = chat_js
        .find("function sanitizeLightboxSrc(")
        .expect("sanitizeLightboxSrc helper");
    let sanitize_next = chat_js[sanitize + 1..]
        .find("\nfunction ")
        .map(|i| sanitize + 1 + i)
        .expect("function after sanitizeLightboxSrc");
    let sanitize_body = &chat_js[sanitize..sanitize_next];
    assert!(
        !sanitize_body.contains("u.pathname + u.search"),
        "sanitizeLightboxSrc must reconstruct history_image URLs, not pass through URL components"
    );
    assert!(
        sanitize_body.contains(".replace(/[^A-Za-z0-9._~-]/g, '')")
            && sanitize_body.contains("?size=thumb"),
        "history_image path segments must be character-class-filtered; thumb query is a literal"
    );
}

/// Regression: AI message body supports speak-from-sentence (hover highlight +
/// click speaks that exact DOM sentence list; restartable HTMLAudio playback).
#[test]
fn ai_message_supports_speak_from_text_position() {
    let chat_js = include_str!("../../static/chat.js");
    let style_css = include_str!("../../static/style.css");

    assert!(
        chat_js.contains("function getDomPlainText"),
        "highlight and caret offsets must use textContent (not innerText)"
    );
    assert!(
        chat_js.contains("function splitSentences")
            && chat_js.contains("function sentenceIndexAtOffset"),
        "highlight and click must share one sentence splitter"
    );
    assert!(
        chat_js.contains("function highlightSentenceInElement"),
        "expected hover sentence highlight under the cursor"
    );
    assert!(
        chat_js.contains("options.sentences")
            && chat_js.contains("stopCurrentDesktopTts")
            && chat_js.contains("playFixedSentenceList"),
        "click path must pass exact sentence strings into a fixed playlist"
    );
    assert!(
        chat_js.contains("getCaretOffsetInElement(textEl, e.clientX, e.clientY)")
            && chat_js.contains("splitSentences(domText)"),
        "click must resolve the sentence from click coordinates, not a hover cache"
    );
    assert!(
        chat_js.contains("resetDesktopTtsAudioElement")
            && chat_js.contains("getDesktopTtsAudio"),
        "HTMLAudioElement must be fully reset between plays (2nd play after stop)"
    );
    assert!(
        chat_js.contains("e.detail !== 1") || chat_js.contains("e.detail != 1"),
        "only single-clicks should start speech"
    );
    assert!(
        chat_js.contains("tts-is-playing") && style_css.contains("tts-can-play"),
        "play/stop affordances on AI text"
    );
    assert!(
        style_css.contains(".tts-sentence-highlight")
            && style_css.contains(".tts-hover-play-icon"),
        "CSS for highlight and play/stop badge"
    );
    assert!(
        chat_js.contains("Consume the whole run")
            && chat_js.contains("text.charAt(end) === '.'"),
        "ellipsis \"...\" must be one terminator, not three \".\" sentences"
    );
    assert!(
        chat_js.contains("function sentenceEndsWithTerminator"),
        "shared complete-sentence check for streaming discover"
    );

    let click_handler = ai_message_text_click_handler(chat_js);
    assert!(
        click_handler.contains("playTTS(playBtn, { sentences: toPlay })")
            || click_handler.contains("playMessageTts(playBtn, { sentences: toPlay })"),
        "sentence click must start TTS with the clicked sentence list, not the full message"
    );
    assert!(
        !click_handler.contains("playTTSVoiceMode(playBtn)"),
        "voice-mode must not hijack sentence click into full-message playTTSVoiceMode(playBtn)"
    );
    assert!(
        function_contains(chat_js, "playTTS", "playFixedSentenceList")
            && function_contains(chat_js, "playTTS", "options.sentences"),
        "playTTS must speak options.sentences via playFixedSentenceList"
    );
}

fn ai_message_text_click_handler(chat_js: &str) -> &str {
    const START: &str = "$(document).on('click', '.ai-message-text', function (e) {";
    const END: &str = "// Delegation for play, delete, and edit";
    let start = chat_js
        .find(START)
        .expect("ai-message-text click handler");
    let rest = &chat_js[start..];
    let end = rest.find(END).expect("end of ai-message-text click handler");
    &rest[..end]
}

fn function_contains(src: &str, fn_name: &str, needle: &str) -> bool {
    let header = format!("function {fn_name}(");
    let Some(start) = src.find(&header) else {
        return false;
    };
    let body = &src[start..];
    let Some(open) = body.find('{') else {
        return false;
    };
    let mut depth = 0i32;
    for (i, ch) in body[open..].char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return body[open..=open + i].contains(needle);
                }
            }
            _ => {}
        }
    }
    false
}

/// Version numbers like "4.6" must NOT be split as two sentences. Otherwise
/// TTS pauses between "4" and "6" — the whole reason this regression exists.
#[test]
fn split_sentences_keeps_version_numbers_together() {
    let chat_js = include_str!("../../static/chat.js");

    assert!(
        chat_js.contains("function isAsciiDigit"),
        "isAsciiDigit helper is required for the digit-digit period rule"
    );
    let body = function_body(chat_js, "splitSentences").expect("splitSentences body");
    assert!(
        body.contains("isAsciiDigit")
            && body.contains("Decimal/version dot")
            && body.contains("continue;"),
        "splitSentences must skip a '.' when both sides are digits (decimals / versions); got: {body}"
    );
}

/// Streaming TTS must react to new visible text quickly. After the web-search /
/// tool-calling change the final answer only streams once the search + second
/// LLM hop completes — a 120 ms poll cycle on top of that felt high latency.
/// We now wake the pump from a MutationObserver and shrink the polling fallback.
#[test]
fn streaming_tts_reacts_to_text_updates_immediately() {
    let chat_js = include_str!("../../static/chat.js");

    let desktop_body = function_body(chat_js, "playMessageBodyTts")
        .expect("playMessageBodyTts body");
    assert!(
        desktop_body.contains("MutationObserver"),
        "playMessageBodyTts must use MutationObserver to react to streaming text"
    );
    assert!(
        desktop_body.contains("disconnect()"),
        "playMessageBodyTts must disconnect the observer when the session ends"
    );
    assert!(
        !desktop_body.contains(", 120)"),
        "playMessageBodyTts polling interval should no longer be 120 ms; got: {desktop_body}"
    );

    let native_body = function_body(chat_js, "playNativeVoiceModeTts")
        .expect("playNativeVoiceModeTts body");
    assert!(
        native_body.contains("MutationObserver"),
        "playNativeVoiceModeTts must use MutationObserver to react to streaming text"
    );
    assert!(
        !native_body.contains(", 200)"),
        "playNativeVoiceModeTts polling interval should no longer be 200 ms; got: {native_body}"
    );
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

/// Regression: the code block copy button used to call
/// `navigator.clipboard.writeText` directly. On insecure origins (plain HTTP,
/// sandboxed iframes) `navigator.clipboard` is undefined, so the call threw
/// synchronously and `.catch()` never ran — the click appeared to do nothing.
/// The handler must now go through a helper that falls back to
/// `document.execCommand('copy')` so the button works in any context and the
/// failure path stays visible (no modal alert).
#[test]
fn code_block_copy_works_in_insecure_contexts() {
    let chat_js = include_str!("../../static/chat.js");
    let style_css = include_str!("../../static/style.css");

    let handler = ai_message_text_click_handler_region(
        chat_js,
        "$(document).on('click', '.copy-code-button'",
        "// Load sets for logged-in users (wait for encryption key from login storage first)",
    )
    .expect("copy-code-button click handler");
    assert!(
        handler.contains("copyToClipboard("),
        "copy-code-button handler must call the copyToClipboard helper, not navigator.clipboard.writeText directly; got: {handler}"
    );
    assert!(
        !handler.contains("navigator.clipboard.writeText"),
        "copy-code-button handler must not call navigator.clipboard.writeText directly; got: {handler}"
    );

    let helper = function_body(chat_js, "copyToClipboard").expect("copyToClipboard helper");
    assert!(
        helper.contains("navigator.clipboard")
            && helper.contains("document.execCommand('copy')"),
        "copyToClipboard must use navigator.clipboard when available and fall back to document.execCommand('copy') otherwise; got: {helper}"
    );

    assert!(
        style_css.contains(".copy-code-button.copy-failed"),
        ".copy-code-button.copy-failed rule must exist so the failure state is visible"
    );
}

fn ai_message_text_click_handler_region<'a>(
    src: &'a str,
    start_marker: &str,
    end_marker: &str,
) -> Option<&'a str> {
    let start = src.find(start_marker)?;
    let rest = &src[start..];
    let end = rest.find(end_marker)?;
    Some(&rest[..end])
}
