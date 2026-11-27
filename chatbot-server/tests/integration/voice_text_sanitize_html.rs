//! Regression for CodeQL #70 `js/incomplete-multi-character-sanitization`:
//! `sanitizeForTTS` in `static/voice-text.js` must strip HTML tags completely.
//! A tag carrying a URL attribute left a `"<a href=""` fragment because the
//! URL strip ran before tag stripping and ate the tag's closing bracket.
//! The sanitized text only feeds the `/tts` JSON body (spoken text, never an
//! HTML sink), so the impact is spoken markup fragments, not script execution.

use std::path::Path;
use std::process::Command;

#[test]
fn voice_text_sanitize_html_strips_tags_completely() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let run = Command::new("node")
        .arg(root.join("chatbot-server/tests/fixtures/voice_text_sanitize_html_test.js"))
        .arg(root.join("static/voice-text.js"))
        .output()
        .expect("test image must provide the JS behavior-test runtime");
    assert!(
        run.status.success(),
        "JS voice-text HTML sanitize: {}",
        String::from_utf8_lossy(&run.stderr)
    );
}
