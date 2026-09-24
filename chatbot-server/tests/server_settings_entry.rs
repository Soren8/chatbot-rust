//! Structural wiring for the Android server-selection entry.
//!
//! These are source-structure checks only, not runtime or pixel assertions:
//! they verify the entry sits in the existing settings/login controls,
//! stays hidden in normal browsers, dispatches through the Capacitor bridge,
//! and that the native screens wire the shared login-card styling. Visual
//! appearance still needs on-device review.

use oxc_allocator::Allocator;
use oxc_parser::Parser;
use oxc_span::SourceType;

const CHAT_HTML: &str = include_str!("../../static/templates/chat.html");
const LOGIN_HTML: &str = include_str!("../../static/templates/login.html");
const NATIVE_BRIDGE_JS: &str = include_str!("../../static/native-bridge.js");
const LOGIN_JS: &str = include_str!("../../static/login.js");
const CHAT_JS: &str = include_str!("../../static/chat.js");
const MAIN_ACTIVITY: &str =
    include_str!("../../android/app/src/main/java/com/chatbot/app/MainActivity.java");
const SERVER_SETTINGS_ACTIVITY: &str = include_str!(
    "../../android/app/src/main/java/com/chatbot/app/ServerSettingsActivity.java"
);
const SERVER_UI_STYLE: &str = include_str!(
    "../../android/app/src/main/java/com/chatbot/app/util/ServerUiStyle.java"
);
const MANIFEST: &str = include_str!("../../android/app/src/main/AndroidManifest.xml");

fn plugin_src() -> String {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf();
    std::fs::read_to_string(
        root.join("android/app/src/main/java/com/chatbot/app/ServerSettingsPlugin.java"),
    )
    .expect("ServerSettingsPlugin.java must exist")
}

/// Fixed-size window around a marker; isolates the relevant element without
/// scanning the whole file (a global `contains` would match unrelated code).
fn window_around<'a>(hay: &'a str, needle: &str, before: usize, after: usize) -> &'a str {
    let pos = hay
        .find(needle)
        .unwrap_or_else(|| panic!("marker missing: {needle}"));
    let start = pos.saturating_sub(before);
    let end = (pos + needle.len() + after).min(hay.len());
    &hay[start..end]
}

/// Enclosing `<...>` tag for `id="..."`; verifies the element's own classes
/// and inline hiding rather than any same-string elsewhere.
fn element_tag_for_id<'a>(html: &'a str, id: &str) -> &'a str {
    let needle = format!("id=\"{id}\"");
    let pos = html
        .find(&needle)
        .unwrap_or_else(|| panic!("element missing: {id}"));
    let tag_start = html[..pos].rfind('<').expect("tag start");
    let rest = &html[pos..];
    let tag_end = rest.find('>').expect("tag end");
    &html[tag_start..pos + tag_end + 1]
}

/// Section between two markers (e.g. navbar or settings panel region).
fn section_between<'a>(html: &'a str, start: &str, end: &str) -> &'a str {
    let s = html.find(start).unwrap_or_else(|| panic!("section start: {start}"));
    let e = html[s..].find(end).unwrap_or_else(|| panic!("section end: {end}"));
    &html[s..s + e + end.len()]
}

fn assert_js_parses(name: &str, src: &str) {
    let allocator = Allocator::default();
    let source_type = SourceType::default().with_module(false).with_jsx(false);
    let ret = Parser::new(&allocator, src, source_type).parse();
    let errors: Vec<String> = ret.diagnostics.errors().map(ToString::to_string).collect();
    assert!(
        errors.is_empty(),
        "{name} must parse via the existing oxc harness:\n{}",
        errors.join("\n")
    );
}

#[test]
fn no_floating_gear_overlaps_web_content() {
    // Navbar keeps only its two existing controls; the brand stays absolute-
    // centered per style.css (321-352) with controls at z-index 10 above it.
    let nav = section_between(CHAT_HTML, "<nav", "</nav>");
    assert!(
        !nav.contains("native-server-settings"),
        "chat navbar must not gain a third icon; Server lives in the settings panel"
    );
    assert!(
        nav.contains("settings-toggle") && nav.contains("reload-ui"),
        "navbar keeps its existing gear + reload controls"
    );
    // Settings-panel card carries its own hiding; no floating positioning.
    let card_tag = element_tag_for_id(CHAT_HTML, "native-server-card");
    assert!(
        card_tag.contains("display: none") || card_tag.contains("display:none"),
        "settings Server card wires hidden-by-default in its own tag"
    );
    for snippet in [card_tag, element_tag_for_id(LOGIN_HTML, "native-server-settings-wrap")] {
        assert!(
            !snippet.contains("position: absolute") && !snippet.contains("position:fixed"),
            "Server entry wires in-flow layout, not a floating overlay"
        );
    }
    // Entry points are the web card plus the offline overlay: one definition
    // plus one MainActivity call site (offline); a floating menu would add a
    // second call site.
    assert_eq!(
        MAIN_ACTIVITY.matches("openServerSettings").count(),
        2,
        "MainActivity wires a single native call site (offline overlay); web goes via the bridge"
    );
}

#[test]
fn native_server_entry_lives_in_web_layout_and_stays_hidden_in_browsers() {
    assert_js_parses("static/native-bridge.js", NATIVE_BRIDGE_JS);
    assert_js_parses("static/login.js", LOGIN_JS);
    assert_js_parses("static/chat.js", CHAT_JS);

    // Chat entry sits inside the existing settings panel with the panel's
    // own card/button classes.
    let collapse = section_between(CHAT_HTML, "settingsCollapse", "chat-area");
    assert!(
        collapse.contains("native-server-card") && collapse.contains("native-server-settings"),
        "chat Server entry wires inside the existing settings panel"
    );
    let card_tag = element_tag_for_id(CHAT_HTML, "native-server-card");
    assert!(
        card_tag.contains("card"),
        "chat Server entry reuses the settings card container"
    );
    let chat_btn = element_tag_for_id(CHAT_HTML, "native-server-settings");
    assert!(
        chat_btn.contains("btn-outline-secondary"),
        "chat Server button wires the panel's outline-button class"
    );
    // Login entry stays in its card with a hidden wrapper (no extra spacing
    // in browsers).
    let login_wrap = element_tag_for_id(LOGIN_HTML, "native-server-settings-wrap");
    assert!(
        login_wrap.contains("display: none") || login_wrap.contains("display:none"),
        "login Server wrap wires hidden-by-default"
    );
    let login_btn = element_tag_for_id(LOGIN_HTML, "native-server-settings");
    assert!(
        login_btn.contains("btn-outline-secondary"),
        "login Server button wires the card's outline-button class"
    );

    // Reveal runs only on the native platform; dispatch goes through the
    // bridge's ServerSettings opener. Windows isolate each page's wiring.
    for (name, src) in [("login.js", LOGIN_JS), ("chat.js", CHAT_JS)] {
        let wiring = window_around(src, "native-server-settings", 600, 600);
        let gate = wiring.find("isNativePlatform").unwrap_or_else(|| {
            panic!("{name} wiring must gate the reveal on the native platform")
        });
        let reveal = wiring.find("style.display").unwrap_or_else(|| {
            panic!("{name} wiring must reveal the hidden entry")
        });
        assert!(
            gate < reveal,
            "{name} wiring must check the native platform before revealing"
        );
        assert!(
            wiring.contains("openServerSettings") && wiring.contains("ServerSettings"),
            "{name} wiring must dispatch through the ServerSettings bridge opener"
        );
        assert!(
            wiring.contains("addEventListener"),
            "{name} wiring must attach a click dispatch, not navigate"
        );
    }
    let bridge_wiring = window_around(NATIVE_BRIDGE_JS, "openServerSettings", 200, 200);
    assert!(
        bridge_wiring.contains("ServerSettings") && bridge_wiring.contains("open"),
        "bridge opener wires the ServerSettings open dispatch"
    );
}

#[test]
fn server_bridge_preserves_result_recreate_semantics() {
    let plugin = plugin_src();
    let open_wiring = window_around(&plugin, "open", 400, 400);
    assert!(
        open_wiring.contains("MainActivity") && open_wiring.contains("openServerSettings"),
        "plugin open wires delegation to MainActivity"
    );
    let register_wiring = window_around(MAIN_ACTIVITY, "ServerSettingsPlugin", 200, 100);
    assert!(
        register_wiring.contains("registerPlugin"),
        "MainActivity wires the ServerSettings bridge registration"
    );
    // Result/recreate ordering stays in its handler window.
    let result_wiring = window_around(MAIN_ACTIVITY, "onActivityResult", 200, 1200);
    for marker in [
        "SETTINGS_REQUEST",
        "RESULT_OK",
        "recreate()",
        "onServerSelectionChanged",
    ] {
        assert!(
            result_wiring.contains(marker),
            "result handler wiring must keep {marker}"
        );
    }
    let resolve_wiring = window_around(MAIN_ACTIVITY, "resolveServerUrl", 200, 400);
    assert!(
        resolve_wiring.contains("ServerUrlSetting.selected")
            && resolve_wiring.contains("ServerUrlResolver.resolveCanonical"),
        "origin wiring stays flavor-resource plus persisted override"
    );
    // Resume lock and offline entry stay in their own windows.
    let lock_wiring = window_around(MAIN_ACTIVITY, "private void checkResumeLock", 100, 800);
    assert!(
        lock_wiring.contains("RESUME_LOCK_GRACE_MS"),
        "resume-lock wiring keeps its grace period"
    );
    let secure_wiring = window_around(MAIN_ACTIVITY, "private void updateWindowSecurity", 100, 600);
    assert!(
        secure_wiring.contains("FLAG_SECURE"),
        "window-security wiring keeps its lock flag"
    );
    let offline_wiring = window_around(MAIN_ACTIVITY, "ensureOfflineOverlay", 100, 5000);
    assert!(
        offline_wiring.contains("Change server"),
        "offline wiring keeps its Change-server entry"
    );
}

#[test]
fn server_settings_activity_matches_dark_theme() {
    // Structural wiring only: shared helper plus card/field/button wiring
    // matching the login card tokens. Not a pixel assertion.
    assert!(
        SERVER_UI_STYLE.contains("0xFF212529")
            && SERVER_UI_STYLE.contains("0xFFF8F9FA")
            && SERVER_UI_STYLE.contains("0xFF6C757D")
            && SERVER_UI_STYLE.contains("0xFF0D6EFD"),
        "shared helper wires the login bg-dark/light/border/primary tokens"
    );
    let helper_buttons = window_around(SERVER_UI_STYLE, "stylePrimaryButton", 100, 800);
    assert!(
        helper_buttons.contains("setAllCaps(false)") && helper_buttons.contains("setTextSize(16"),
        "shared buttons wire sentence-case 16sp"
    );
    assert!(
        SERVER_UI_STYLE.contains("RippleDrawable"),
        "shared buttons wire touch ripple"
    );
    assert!(
        SERVER_UI_STYLE.contains("setAlpha") && SERVER_UI_STYLE.contains("setEnabled"),
        "shared helper wires a dimmed disabled state"
    );
    assert!(
        SERVER_UI_STYLE.contains("setStatusBarColor")
            && SERVER_UI_STYLE.contains("setNavigationBarColor"),
        "shared helper wires dark system bars"
    );
    let activity_wiring = window_around(SERVER_SETTINGS_ACTIVITY, "onCreate", 200, 5000);
    assert!(
        activity_wiring.contains("ServerUiStyle.cardBackground")
            && activity_wiring.contains("ServerUiStyle.styleField"),
        "settings screen wires the shared card and field"
    );
    assert!(
        activity_wiring.contains("ServerUiStyle.stylePrimaryButton")
            && activity_wiring.contains("ServerUiStyle.styleOutlineButton"),
        "settings screen wires primary Apply plus outlined Reset/Cancel"
    );
    assert!(
        activity_wiring.contains("TYPE_TEXT_VARIATION_URI"),
        "settings input wires URL keyboard"
    );
    assert!(
        activity_wiring.contains("ScrollView") && activity_wiring.contains("420"),
        "settings screen wires a scrollable max-width card"
    );
    let manifest_block = window_around(MANIFEST, "ServerSettingsActivity", 300, 300);
    assert!(
        manifest_block.contains("NoActionBar"),
        "settings activity wires no light action bar"
    );
    assert!(
        manifest_block.contains("adjustResize"),
        "settings activity wires keyboard resize for small screens"
    );
    let offline_wiring = window_around(MAIN_ACTIVITY, "ensureOfflineOverlay", 100, 5000);
    assert!(
        offline_wiring.contains("ServerUiStyle.cardBackground")
            && offline_wiring.contains("ServerUiStyle.stylePrimaryButton")
            && offline_wiring.contains("ServerUiStyle.styleOutlineButton"),
        "offline overlay wires the same shared card/buttons"
    );
}
