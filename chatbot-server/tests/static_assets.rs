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
        chat_js.contains("hist_enc_key="),
        "img src cannot send X-Enc-Key; key must be a Path=/history_image cookie"
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
}
