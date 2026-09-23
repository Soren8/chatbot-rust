//! Distribution-input guards: native origin wiring, versioned Capacitor
//! manifests, and Helm sample-only values. No network, no npm/gradle
//! invocation. Resolver behavior executes the shipped Java directly: the
//! cargo harness compiles `ServerUrlResolver.java` with `javac` and runs
//! the pure-Java behavior fixture with `java` (same pattern as
//! native_voice_coordinator.rs), since the Android JUnit suite never runs
//! in CI.
//!
//! Native origins: the build flavor is the single authority (MOD017). The
//! tracked root `capacitor.config.json` defines BOTH `serverUrls` entries
//! (emulator + physical) with no ambiguous `server.url` override;
//! `android/app/build.gradle` projects the matching entry per flavor into
//! the `server_url` resource; every native caller (MainActivity,
//! NativeSecureKeyPlugin, ClientLogReporter, car VoiceScreen) reads only
//! that flavor resource through `ServerUrlResolver::resolveCanonical`.

use std::path::Path;
use std::process::Command;

const RESOLVER: &str = include_str!(
    "../../android/app/src/main/java/com/chatbot/app/util/ServerUrlResolver.java"
);
const MAIN_ACTIVITY: &str =
    include_str!("../../android/app/src/main/java/com/chatbot/app/MainActivity.java");
const SECURE_KEY_PLUGIN: &str = include_str!(
    "../../android/app/src/main/java/com/chatbot/app/NativeSecureKey/NativeSecureKeyPlugin.java"
);
const CLIENT_LOG_REPORTER: &str = include_str!(
    "../../android/app/src/main/java/com/chatbot/app/util/ClientLogReporter.java"
);
const VOICE_SCREEN: &str =
    include_str!("../../android/app/src/main/java/com/chatbot/app/car/VoiceScreen.java");

const CAPACITOR_CONFIG: &str = include_str!("../../capacitor.config.json");
const BUILD_GRADLE: &str = include_str!("../../android/app/build.gradle");

const PACKAGE_JSON: &str = include_str!("../../package.json");
const PACKAGE_LOCK_JSON: &str = include_str!("../../package-lock.json");
const GITIGNORE: &str = include_str!("../../.gitignore");

const HELM_VALUES: &str = include_str!("../../deploy/helm/chatbot/values.yaml");
const HELM_README: &str = include_str!("../../deploy/helm/chatbot/README.md");
const HELM_DEPLOYMENT: &str = include_str!(
    "../../deploy/helm/chatbot/templates/webserver-deployment.yaml"
);
const HELM_PVC: &str =
    include_str!("../../deploy/helm/chatbot/templates/webserver-pvc.yaml");
const HELM_SERVICE: &str = include_str!(
    "../../deploy/helm/chatbot/templates/webserver-service.yaml"
);
const HELM_CONFIGMAP: &str =
    include_str!("../../deploy/helm/chatbot/templates/configmap.yaml");
const HELM_HELPERS: &str =
    include_str!("../../deploy/helm/chatbot/templates/_helpers.tpl");

const STT_ROUTE: &str = include_str!("../src/stt.rs");

/// Canonical emulator origin: dev-machine loopback, never Tailnet.
const EMULATOR_URL: &str = "http://10.0.2.2:80";
/// Canonical physical origin: Tailscale Serve https (secure context for WebCodecs).
const PHYSICAL_URL: &str = "https://desktop-1.tailfc0df0.ts.net";

#[test]
fn capacitor_config_defines_both_server_urls_without_ambiguous_override() {
    let config: serde_json::Value =
        serde_json::from_str(CAPACITOR_CONFIG).expect("root capacitor.config.json must parse as JSON");
    let server_url = config
        .get("server")
        .and_then(|server| server.get("url"))
        .and_then(|url| url.as_str());
    assert!(
        server_url.is_none(),
        "capacitor.config.json must not carry a single ambiguous server.url override \
         (build flavor selects the origin); got `{server_url:?}`"
    );
    let urls = config
        .get("serverUrls")
        .expect("capacitor.config.json must define serverUrls with emulator + physical");
    assert_eq!(
        urls.get("emulator").and_then(|v| v.as_str()),
        Some(EMULATOR_URL),
        "serverUrls.emulator must stay the dev-machine loopback"
    );
    assert_eq!(
        urls.get("physical").and_then(|v| v.as_str()),
        Some(PHYSICAL_URL),
        "serverUrls.physical must stay the Tailscale Serve https origin"
    );
    let emulator = urls["emulator"].as_str().unwrap();
    let physical = urls["physical"].as_str().unwrap();
    assert!(
        !emulator.contains("ts.net"),
        "the emulator always runs on the dev machine without Tailscale"
    );
    assert!(
        emulator.starts_with("http://"),
        "emulator origin stays plain HTTP loopback; got `{emulator}`"
    );
    assert!(
        physical.starts_with("https://"),
        "physical origin must stay https (WebView secure context); got `{physical}`"
    );
}

#[test]
fn gradle_projects_flavor_urls_from_shared_config() {
    for flavor in ["emulator", "physical"] {
        assert!(
            BUILD_GRADLE.contains(flavor),
            "android/app/build.gradle must define the `{flavor}` product flavor"
        );
        assert!(
            BUILD_GRADLE.contains("serverUrls") && BUILD_GRADLE.contains("capacitor.config.json"),
            "android/app/build.gradle must project server_url per flavor from the shared \
             capacitor.config.json serverUrls (single source of truth)"
        );
    }
    assert!(
        BUILD_GRADLE.contains("resValue \"string\", \"server_url\""),
        "each flavor must generate the server_url resource the native code reads"
    );
    for literal in [EMULATOR_URL, PHYSICAL_URL] {
        assert!(
            !BUILD_GRADLE.contains(literal),
            "android/app/build.gradle must not hardcode endpoint literals (`{literal}` lives \
             only in capacitor.config.json; flavors project it)"
        );
    }
}

#[test]
fn native_origin_is_flavor_canonical_not_bridge() {
    for token in [
        "package com.chatbot.app.util;",
        "resolveCanonical",
        "normalizeResource",
        "FALLBACK_URL",
        "private static boolean isNonEmpty",
    ] {
        assert!(
            RESOLVER.contains(token),
            "ServerUrlResolver must expose `{token}` for the single flavor authority"
        );
    }
    for banned in [
        "resolveBridgeAware",
        "resolveCarResource",
        "CANONICAL_ORIGIN_DECISION",
        "UNRESOLVED",
        "getServerUrl",
        "getBridge",
        "public static boolean isNonEmpty",
        "import android",
    ] {
        assert!(
            !RESOLVER.contains(banned),
            "ServerUrlResolver must not contain `{banned}`: the flavor resource is the only \
             input, never the Bridge/Config URL, and only the canonical accessors are exposed"
        );
    }
}

#[test]
fn all_native_consumers_read_only_the_flavor_resource() {
    for (name, src) in [
        ("MainActivity", MAIN_ACTIVITY),
        ("NativeSecureKeyPlugin", SECURE_KEY_PLUGIN),
        ("ClientLogReporter", CLIENT_LOG_REPORTER),
        ("VoiceScreen", VOICE_SCREEN),
    ] {
        assert!(
            src.contains("R.string.server_url"),
            "{name} must read the flavor server_url resource"
        );
        assert!(
            !src.contains("getServerUrl"),
            "{name} must never read Bridge.getServerUrl()/CapConfig URL: \
             build flavor always has precedence"
        );
        assert!(
            !src.contains("10.0.2.2") && !src.contains("tailfc0df0"),
            "{name} must not hardcode endpoint literals; the flavor resource carries them \
             (ServerUrlResolver keeps only the localhost last-resort fallback)"
        );
    }
    assert!(
        MAIN_ACTIVITY.contains("setServerUrl"),
        "MainActivity must pin the CapConfig WebView origin to the flavor resource"
    );
    for (name, src) in [
        ("MainActivity", MAIN_ACTIVITY),
        ("NativeSecureKeyPlugin", SECURE_KEY_PLUGIN),
    ] {
        assert!(
            src.contains("ServerUrlResolver.resolveCanonical"),
            "{name} must resolve cookies against the canonical flavor origin"
        );
    }
    assert!(
        CLIENT_LOG_REPORTER.contains("ServerUrlResolver.normalizeResource"),
        "ClientLogReporter must normalize the flavor resource via the shared resolver"
    );
    assert!(
        CLIENT_LOG_REPORTER.contains("BuildConfig.DEBUG"),
        "ClientLogReporter must keep its debug-only gate; origin work changes no behavior"
    );
    assert!(
        VOICE_SCREEN.contains("ServerUrlResolver.resolveCanonical"),
        "car VoiceScreen must use the canonical flavor origin (car context has no Bridge)"
    );
}

/// The shipped resolver is pure Java (no Android imports, so no stubs are
/// needed) — this harness compiles the real `ServerUrlResolver.java` and
/// runs the pure-Java behavior fixture: canonical flavor passthrough
/// for both endpoints, localhost fallback, legacy whitespace handling, and
/// resource normalization.
#[test]
fn canonical_resolver_behavior_runs_on_shipped_java() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let output_dir = tempfile::tempdir().unwrap();
    let compile = Command::new("javac")
        .args(["-encoding", "UTF-8"])
        .arg("-d")
        .arg(output_dir.path())
        .arg(root.join("android/app/src/main/java/com/chatbot/app/util/ServerUrlResolver.java"))
        .arg(root.join("chatbot-server/tests/fixtures/ServerUrlResolverBehaviorTest.java"))
        .output()
        .expect("test image must provide javac");
    assert!(
        compile.status.success(),
        "Java compilation: {}",
        String::from_utf8_lossy(&compile.stderr)
    );
    let run = Command::new("java")
        .arg("-cp")
        .arg(output_dir.path())
        .arg("ServerUrlResolverBehaviorTest")
        .output()
        .expect("run native origin behavior tests");
    assert!(
        run.status.success(),
        "native origin behavior: {}",
        String::from_utf8_lossy(&run.stderr)
    );
}

/// The shipped pure-Java `ServerUrlSetting` behavior — persisted
/// override selection over the flavor default, https-origin validation for
/// user-entered overrides, defensive fallback for corrupt/empty overrides,
/// and origin-scoped credential slots — runs under the same javac fixture.
#[test]
fn server_setting_behavior_runs_on_shipped_java() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let output_dir = tempfile::tempdir().unwrap();
    let compile = Command::new("javac")
        .args(["-encoding", "UTF-8"])
        .arg("-d")
        .arg(output_dir.path())
        .arg(root.join("android/app/src/main/java/com/chatbot/app/util/ServerUrlResolver.java"))
        .arg(root.join("android/app/src/main/java/com/chatbot/app/util/ServerUrlSetting.java"))
        .arg(root.join("chatbot-server/tests/fixtures/ServerSettingBehaviorTest.java"))
        .output()
        .expect("test image must provide javac");
    assert!(
        compile.status.success(),
        "Java compilation: {}",
        String::from_utf8_lossy(&compile.stderr)
    );
    let run = Command::new("java")
        .arg("-cp")
        .arg(output_dir.path())
        .arg("ServerSettingBehaviorTest")
        .output()
        .expect("run native server setting behavior tests");
    assert!(
        run.status.success(),
        "native server setting behavior: {}",
        String::from_utf8_lossy(&run.stderr)
    );
}

fn package_json_dependencies() -> serde_json::Value {
    serde_json::from_str(PACKAGE_JSON).expect("root package.json must parse as JSON")
}

#[test]
fn capacitor_lockfile_requirements_match_manifest() {
    let manifest = package_json_dependencies();
    let deps = manifest
        .get("dependencies")
        .expect("root package.json must declare dependencies");
    let lock: serde_json::Value =
        serde_json::from_str(PACKAGE_LOCK_JSON).expect("root package-lock.json must parse as JSON");
    let packages = lock
        .get("packages")
        .expect("package-lock.json must have a packages map");
    let lock_root_deps = packages
        .get("")
        .and_then(|root| root.get("dependencies"))
        .expect("package-lock.json root entry must declare dependencies");
    // Stale-lock guard only; npm owns semver/integrity resolution.
    for pkg in ["@capacitor/android", "@capacitor/cli", "@capacitor/core"] {
        let declared = deps
            .get(pkg)
            .and_then(|v| v.as_str())
            .unwrap_or_else(|| panic!("root package.json must declare {pkg}"));
        assert!(
            !declared.trim().is_empty(),
            "package.json must declare non-empty {pkg} requirement"
        );
        let locked_req = lock_root_deps
            .get(pkg)
            .and_then(|v| v.as_str())
            .unwrap_or_else(|| panic!("package-lock.json root entry must require {pkg}"));
        assert_eq!(locked_req, declared,
            "lock root requirement for {pkg} must mirror package.json (`{declared}` vs `{locked_req}`)");
        let key = format!("node_modules/{pkg}");
        let version = packages
            .get(key.as_str())
            .and_then(|e| e.get("version"))
            .and_then(|v| v.as_str())
            .unwrap_or_else(|| panic!("package-lock.json must pin {key} to a version"));
        assert!(
            !version.trim().is_empty(),
            "lock entry {key} must carry a non-empty version"
        );
    }
}

#[test]
fn root_manifests_are_tracked_inputs_not_ignored() {
    for ignored in GITIGNORE.lines() {
        let line = ignored.trim();
        assert!(
            line != "package.json"
                && line != "package-lock.json"
                && line != "capacitor.config.json",
            ".gitignore must not ignore the versioned root Capacitor inputs: `{line}`"
        );
    }
}

#[test]
fn helm_voice_service_enabled_is_sample_only_without_template() {
    assert!(
        HELM_VALUES.contains("voiceService:"),
        "values.yaml must keep the voiceService sample block"
    );
    assert!(
        HELM_VALUES.contains("SAMPLE ONLY"),
        "values.yaml must mark voiceService as sample-only/unsupported"
    );
    for (name, template) in [
        ("webserver-deployment.yaml", HELM_DEPLOYMENT),
        ("webserver-pvc.yaml", HELM_PVC),
        ("webserver-service.yaml", HELM_SERVICE),
        ("configmap.yaml", HELM_CONFIGMAP),
        ("_helpers.tpl", HELM_HELPERS),
    ] {
        assert!(
            !template.contains("voiceService"),
            "{name} must not consume .Values.voiceService: `enabled` has no deployment template"
        );
    }
    assert!(
        HELM_README.contains("voiceService.enabled"),
        "Helm README must document that voiceService.enabled is sample-only"
    );
}

#[test]
fn stt_enabled_is_parsed_but_unused_by_stt_route() {
    assert!(
        !STT_ROUTE.contains("stt_enabled"),
        "the /stt route must not gate on stt_enabled (parsed-but-unused is documented, not fixed here)"
    );
    assert!(
        HELM_README.contains("stt_enabled"),
        "Helm README must document that stt_enabled is parsed but unused"
    );
}
