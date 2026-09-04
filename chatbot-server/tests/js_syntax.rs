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
        !src.contains("/login/keyauth"),
        "the Fernet key must not mint a session; cached Login uses /login/remember"
    );
    assert!(
        src.contains("/login/remember"),
        "cached-account Login signs in with the remember cookie"
    );
    assert!(
        src.contains("$('#password-fields').toggleClass('d-none', cached)"),
        "cached-account mode must hide the password field so Login is password-free"
    );
    assert!(
        src.contains("$('#password').prop('required', !cached)"),
        "hidden password must not be HTML-required or the browser blocks cached Login"
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
        "POST /update_preferences 401s without an enc-key cookie; if the fetch interceptor \
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

#[test]
fn page_js_does_not_touch_enc_key() {
    // HttpOnly enc_key / enc_key-{user} cookies carry the Fernet key.
    // Page JS must not read, unwrap, or send it (XSS export).
    for (name, src) in [
        ("static/login.js", include_str!("../../static/login.js")),
        ("static/chat.js", include_str!("../../static/chat.js")),
    ] {
        assert!(
            !src.contains("X-Enc-Key"),
            "{name} must not send X-Enc-Key; tests use that header, browsers use cookies"
        );
        assert!(
            !src.contains("hist_enc_key"),
            "{name} must not write hist_enc_key; Path=/ enc_key is sent on <img>"
        );
        assert!(
            !src.contains("getKeyForUsername"),
            "{name} must not unwrap a stored data key"
        );
        assert!(
            !src.contains("getKeyForRequest"),
            "{name} must not read the data key for fetch"
        );
        assert!(
            !src.contains("document.cookie"),
            "{name} must not put the data key in document.cookie"
        );
    }
    let enc = include_str!("../../static/enc-key.js");
    assert!(
        !enc.contains("headers['X-Enc-Key']") && !enc.contains("headers[\"X-Enc-Key\"]"),
        "enc-key.js must not send X-Enc-Key"
    );
    let get_key = enc
        .find("async function getKeyForUsername")
        .expect("getKeyForUsername");
    let next = enc[get_key + 1..]
        .find("async function ")
        .map(|i| get_key + 1 + i)
        .unwrap_or(enc.len());
    let body = &enc[get_key..next];
    assert!(
        body.contains("return null"),
        "getKeyForUsername must not unwrap or return a stored data key"
    );
    assert!(
        !body.contains("unwrapDataKey") && !body.contains("NativeSecureKey"),
        "getKeyForUsername must not unwrap IndexedDB or call native getKey"
    );
}

#[test]
fn mobile_cached_login_requires_biometric_unlock() {
    let src = include_str!("../../static/login.js");
    let login_cached = src
        .find("async function loginCachedAccount")
        .expect("loginCachedAccount function");
    let next = src[login_cached + 1..]
        .find("async function ")
        .map(|i| login_cached + 1 + i)
        .unwrap_or(src.len());
    let body = &src[login_cached..next];
    assert!(
        body.contains("unlockCachedLogin"),
        "mobile cached login must prompt biometric unlock via NativeSecureKey before /login/remember"
    );

    let plugin_src = include_str!("../../android/app/src/main/java/com/chatbot/app/NativeSecureKey/NativeSecureKeyPlugin.java");
    assert!(
        plugin_src.contains("unlockCachedLogin") && plugin_src.contains("sealCachedCredentials"),
        "NativeSecureKeyPlugin must support unlockCachedLogin and sealCachedCredentials"
    );

    let main_activity_src = include_str!("../../android/app/src/main/java/com/chatbot/app/MainActivity.java");
    assert!(
        main_activity_src.contains("FLAG_SECURE"),
        "MainActivity must set FLAG_SECURE to prevent app switcher leaks"
    );
    assert!(
        main_activity_src.contains("RESUME_LOCK_GRACE_MS"),
        "MainActivity must enforce 1-minute resume lock grace period"
    );
}

#[test]
fn login_js_does_not_ask_user_to_reload() {
    let src = include_str!("../../static/login.js");
    assert!(
        !src.to_lowercase().contains("reload and try again"),
        "login.js must never tell users to reload (Capacitor apps have no reload button)"
    );
    assert!(
        !src.contains("Session expired. Reload"),
        "login.js must not mention 'Reload' when session expires"
    );
    assert!(
        src.contains("Session expired. Please try signing in again."),
        "login.js must suggest signing in again instead of reloading"
    );
    assert!(
        src.contains("postLogin(form, onSuccess, true)"),
        "login.js must auto-retry postLogin with refreshed CSRF token"
    );

    let main_activity_src = include_str!("../../android/app/src/main/java/com/chatbot/app/MainActivity.java");
    assert!(
        !main_activity_src.contains("trimmed.startsWith(\"session=\")"),
        "MainActivity must not treat guest session cookie as logged in"
    );
    assert!(
        main_activity_src.contains("remember=") && main_activity_src.contains("enc_key="),
        "MainActivity must check authenticated remember and enc_key cookies"
    );
}


