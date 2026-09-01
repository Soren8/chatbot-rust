//! Parse first-party browser JS with oxc (Rust). No Node/npm.
//! Vendor files under static/deps/ are not checked here.

use oxc_allocator::Allocator;
use oxc_parser::Parser;
use oxc_span::SourceType;

fn assert_script_parses(name: &str, source: &str) {
    let allocator = Allocator::default();
    let source_type = SourceType::default().with_module(false).with_jsx(false);
    let ret = Parser::new(&allocator, source, source_type).parse();
    let errors: Vec<String> = ret.diagnostics.errors().map(ToString::to_string).collect();
    assert!(
        errors.is_empty(),
        "{name} failed to parse ({} error(s)):\n{}",
        errors.len(),
        errors.join("\n")
    );
}

#[test]
fn first_party_static_js_parses() {
    assert_script_parses("static/chat.js", include_str!("../../static/chat.js"));
    assert_script_parses("static/login.js", include_str!("../../static/login.js"));
    assert_script_parses(
        "static/native-audio.js",
        include_str!("../../static/native-audio.js"),
    );
    assert_script_parses(
        "static/native-bridge.js",
        include_str!("../../static/native-bridge.js"),
    );
    assert_script_parses("static/enc-key.js", include_str!("../../static/enc-key.js"));
}

#[test]
fn login_js_does_not_use_opaque_manual_redirect() {
    let src = include_str!("../../static/login.js");
    assert!(
        !src.contains("redirect: 'manual'") && !src.contains("redirect: \"manual\""),
        "fetch redirect: 'manual' yields an opaque response (status 0) in browsers; \
         postLogin then treats a successful 302 to / as invalid credentials"
    );
}

#[test]
fn chat_js_401_interceptor_allowlists_preference_saves() {
    let src = include_str!("../../static/chat.js");
    let start = src.find("window.fetch = function").expect("fetch wrap");
    let chunk = &src[start..start.saturating_add(1800).min(src.len())];
    assert!(
        chunk.contains("/update_preferences"),
        "POST /update_preferences 401s without X-Enc-Key; if the fetch interceptor \
         is not allowlisted it assigns location.href = '/' and reloads the enc-key \
         gate in a loop after every logged-in load"
    );
}

#[test]
fn chat_js_enc_key_gate_cannot_loop_on_401() {
    let src = include_str!("../../static/chat.js");
    assert!(
        src.contains("chatbot_enc_gate_reloads"),
        "enc-key gate must stop after repeated failures so it cannot loop between \
         'Loading encryption key' and 'Loading your sets'"
    );
    assert!(
        src.contains("redirectHomeOnAuthFailure"),
        "401 handlers must not send logged-in users to / (that restarts the enc-key gate)"
    );
}
