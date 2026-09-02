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
    assert_script_parses("static/tt.js", include_str!("../../static/tt.js"));
}

#[test]
fn login_js_remembered_accounts_sign_in_without_password() {
    let src = include_str!("../../static/login.js");
    assert!(
        src.contains("/login/keyauth"),
        "cached-account Login must sign in with the stored encryption key"
    );
    assert!(
        src.contains("/login/remember"),
        "cached-account Login falls back to the remember cookie when no key is stored"
    );
    assert!(
        src.contains("$('#password').prop('required', !cached)"),
        "cached-account mode may omit the password, but the field must stay on the form"
    );
    assert!(
        !src.contains("$('#password-fields').toggleClass('d-none', cached)"),
        "hiding #password-fields also hides Remember-this-computer and makes a \
         username/password login look like a failed cached restore"
    );
}

#[test]
fn login_js_password_login_not_swallowed_by_cached_account() {
    // HTTP tests POST /login directly and never run login.js, so they cannot
    // catch this. A selected cached account used to call loginCachedAccount
    // and return even when the user had typed a password (Remember checked),
    // producing "This computer is not remembered for that account."
    let src = include_str!("../../static/login.js");
    let start = src
        .find("$('form').on('submit'")
        .expect("login form submit handler");
    let handler = &src[start..];
    assert!(
        handler.contains("cachedModeActive() && !$('#password').val()")
            || handler.contains("cachedModeActive() && !$(\"#password\").val()"),
        "password-free cached login must run only when #password is empty"
    );
    assert!(
        !handler.contains("await loginCachedAccount();\n      return;"),
        "must not return from cachedModeActive before a filled password can postLogin"
    );
    assert!(
        handler.contains("$('#username').prop('disabled', false)")
            || handler.contains("$(\"#username\").prop('disabled', false)"),
        "disabled username is omitted from FormData; re-enable before postLogin"
    );
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
