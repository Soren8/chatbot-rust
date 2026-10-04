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
//! that flavor resource through `ServerUrlResolver::resolveCanonical` or
//! `ServerUrlSettingStore` (which applies the persisted override).

use std::fs;
use std::path::Path;
use std::process::Command;

const RESOLVER: &str = include_str!(
    "../../android/app/src/main/java/com/chatbot/app/util/ServerUrlResolver.java"
);
const MAIN_ACTIVITY: &str =
    include_str!("../../android/app/src/main/java/com/chatbot/app/MainActivity.java");
const NATIVE_TTS: &str = include_str!(
    "../../android/app/src/main/java/com/chatbot/app/NativeVoiceTts/NativeVoiceTtsPlugin.java"
);
const SECURE_KEY_PLUGIN: &str = include_str!(
    "../../android/app/src/main/java/com/chatbot/app/NativeSecureKey/NativeSecureKeyPlugin.java"
);
const SERVER_URL_SETTING_STORE: &str = include_str!(
    "../../android/app/src/main/java/com/chatbot/app/util/ServerUrlSettingStore.java"
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

fn java_section<'a>(source: &'a str, start: &str, end: &str) -> &'a str {
    source.split_once(start).unwrap_or_else(|| panic!("missing Java section start: {start}"))
        .1.split_once(end).unwrap_or_else(|| panic!("missing Java section end: {end}"))
        .0
}

fn run_extracted_java(class_name: &str, fixture: &str, source_section: &str, extra_source: Option<&str>) {
    let output_dir = tempfile::tempdir().unwrap();
    let source = fixture.replace("/* SHIPPED_METHODS */", source_section);
    let path = output_dir.path().join(format!("{class_name}.java"));
    fs::write(&path, source).unwrap();
    let mut compile = Command::new("javac");
    compile.args(["-encoding", "UTF-8"]).arg("-d").arg(output_dir.path()).arg(&path);
    if let Some(extra_source) = extra_source {
        compile.arg(Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().join(extra_source));
    }
    let compile = compile.output().expect("javac available");
    assert!(compile.status.success(), "{class_name} compile: {}", String::from_utf8_lossy(&compile.stderr));
    let run = Command::new("java").arg("-cp").arg(output_dir.path()).arg(class_name)
        .output().expect("java available");
    assert!(run.status.success(), "{class_name} behavior: {}\n{}",
        String::from_utf8_lossy(&run.stderr), String::from_utf8_lossy(&run.stdout));
    print!("{}", String::from_utf8_lossy(&run.stdout));
}

#[test]
fn locked_switch_and_unlock_require_successful_shipped_biometric_callback() {
    let section = java_section(MAIN_ACTIVITY, "private void ensureLockOverlay() {",
        "private void updateWindowSecurity(boolean hasFocus) {");
    run_extracted_java("Phase4ResumeLockTest", include_str!("fixtures/Phase4ResumeLockTest.java"),
        &format!("private void ensureLockOverlay() {{{section}"),
        Some("android/app/src/main/java/com/chatbot/app/util/NativeUnlockGate.java"));
}

#[test]
fn native_tts_url_failures_do_not_log_throwable_content() {
    let section = java_section(NATIVE_TTS, "private void workerLoop(",
        "private AudioClip playUrlToTrackOnce(");
    run_extracted_java("Phase4TtsLogTest", include_str!("fixtures/Phase4TtsLogTest.java"),
        &format!("private void workerLoop({section}"),
        Some("android/app/src/main/java/com/chatbot/app/audio/TtsClipOutcome.java"));
}

#[test]
fn native_cached_key_is_not_exposed_to_page_js() {
    assert!(
        !SECURE_KEY_PLUGIN.contains("public void getKey(PluginCall"),
        "NativeSecureKey must not export getKey through the Capacitor bridge"
    );
    assert!(
        !SECURE_KEY_PLUGIN.contains("result.put(\"key\", cached)")
            && !SECURE_KEY_PLUGIN.contains("result.put(\"key\", key)"),
        "cached or unwrapped keys must not be returned to page JS"
    );
    let unlock = SECURE_KEY_PLUGIN
        .split("public void unlockCachedLogin(PluginCall call)")
        .nth(1)
        .expect("cached login must still be supported")
        .split("@PluginMethod")
        .next()
        .unwrap();
    let injection = SECURE_KEY_PLUGIN
        .split("private void setCookieValues(")
        .nth(1)
        .unwrap()
        .split("private void expireCookies(")
        .next()
        .unwrap();
    assert!(
        unlock.contains("CredentialCookies.injectCookieValue(name, rememberVal)")
            && unlock.contains("CredentialCookies.injectCookieValue(name, encKeyVal)")
            && unlock.contains("setCookieValues(cm, serverUrl, cookieValues")
            && injection.contains("cm.setCookie(origin, cookie, one)")
            && injection.contains("cm.flush()"),
        "cached login must acknowledge injection of the selected account's cookies"
    );
    assert!(
        !unlock.contains("result.put(\"key\""),
        "cached login must not return the unwrapped key to page JS"
    );
}

#[test]
fn native_cached_login_fails_closed_without_authentication_gate() {
    let unlock = SECURE_KEY_PLUGIN
        .split("public void unlockCachedLogin(PluginCall call)")
        .nth(1)
        .expect("cached login must still be supported")
        .split("@PluginMethod")
        .next()
        .unwrap();
    assert!(
        unlock.contains("if (!canPromptForBiometric()) {")
            && unlock.contains("call.reject(\"biometric or device credential unlock unavailable\")"),
        "cached login must reject rather than decrypt without a prompt"
    );
    assert!(
        !SECURE_KEY_PLUGIN.contains("generateWrapKey(false)"),
        "wrapping key creation must not fall back to a non-auth-bound key"
    );
    assert!(
        SECURE_KEY_PLUGIN.contains("NativeUnlockGate.canPrompt(")
            && SECURE_KEY_PLUGIN.contains("biometricManager.canAuthenticate(authenticators), BiometricManager.BIOMETRIC_SUCCESS"),
        "platform availability result must pass through the executed pure decision"
    );
    assert!(MAIN_ACTIVITY.contains("NativeUnlockGate.shouldLockEntry(")
        && MAIN_ACTIVITY.contains("setVisibility(View.INVISIBLE)")
        && MAIN_ACTIVITY.contains("VoiceModeForegroundSession.get().isConfirmed()"),
        "cold native entry must hide WebView content when jar or sealed credentials exist");
    let on_create = MAIN_ACTIVITY.split("protected void onCreate(Bundle savedInstanceState)")
        .nth(1).unwrap().split("private void installOfflineErrorHandler()").next().unwrap();
    let hide = on_create.find("hideProtectedWebView()").expect("cold gate must hide before first Activity draw");
    let prompt = on_create.find("lockApp()").expect("cold gate must prompt after hiding");
    assert!(hide < prompt, "authenticated WebView must be hidden before showing the unlock prompt");
    assert!(on_create.contains("PREF_NATIVE_UNLOCK_REQUIRED")
        && on_create.contains("getBoolean(PREF_NATIVE_UNLOCK_REQUIRED, false)")
        && on_create.contains("getLong(PREF_NATIVE_BACKGROUND_ELAPSED, 0)"),
        "lock state and resume age must survive same-process Activity recreation even without a saved Bundle");
    assert!(!on_create.contains("if (savedInstanceState != null)"),
        "resume timestamp restoration must not depend on a non-null Android saved Bundle");
    assert!(on_create.find("getLong(PREF_NATIVE_BACKGROUND_ELAPSED, 0)").unwrap()
        < on_create.find("super.onCreate(savedInstanceState)").unwrap(),
        "persisted resume age must be evaluated before Capacitor creates the first page");
    let load = MAIN_ACTIVITY.split("protected void load() {").nth(1).unwrap()
        .split("@Override\n    public void onStart()").next().unwrap();
    assert!(load.find("webView.setVisibility(View.INVISIBLE)").unwrap()
        < load.find("super.load();").unwrap(),
        "cold entry must hide the WebView before BridgeActivity starts its navigation");
    assert!(SECURE_KEY_PLUGIN.contains("public static boolean hasSealedCredentials(Context context)")
        && MAIN_ACTIVITY.contains("NativeSecureKeyPlugin.hasSealedCredentials(this)"),
        "cold gate must recognize origin-scoped sealed credentials after cookie purge");
    let seal = SECURE_KEY_PLUGIN.split("public void sealCachedCredentials(PluginCall call)")
        .nth(1).unwrap().split("@PluginMethod").next().unwrap();
    assert!(seal.contains("result.put(\"cookiesPurged\", false)")
        && !seal.contains("purgeCachedCookies") && !seal.contains("setCookie("),
        "sealing active credentials must preserve the live request cookies");
    assert!(SECURE_KEY_PLUGIN.contains("failed to purge cached credentials")
        && SECURE_KEY_PLUGIN.contains("accepted == null || !accepted"),
        "login-page credential purge must acknowledge CookieManager failures");
    assert!(SECURE_KEY_PLUGIN.contains("injectCookieValue(name, rememberVal)")
        && SECURE_KEY_PLUGIN.contains("injectCookieValue(name, encKeyVal)")
        && !SECURE_KEY_PLUGIN.contains("injectCookieValue(\"remember\"")
        && !SECURE_KEY_PLUGIN.contains("injectCookieValue(\"enc_key\""),
        "cached unlock must inject account-scoped values without clobbering generic cookies");
}

#[test]
fn native_tts_clip_consumption_reports_played_expired_or_failed() {
    let worker = NATIVE_TTS.split("private void workerLoop(").nth(1).unwrap()
        .split("private AudioClip playUrlToTrackOnce(").next().unwrap();
    let download = NATIVE_TTS.split("private AudioClip playUrlToTrackOnce(").nth(1).unwrap()
        .split("private AudioClip streamWavToTrack(").next().unwrap();
    assert!(worker.contains("event.put(\"type\", \"clipConsumed\")")
        && worker.contains("event.put(\"outcome\", outcome)"),
        "legacy slot-release event must carry the explicit terminal clip outcome");
    assert!(worker.contains("TtsClipOutcome.PLAYED")
        && worker.contains("TtsClipOutcome.FAILED")
        && worker.contains("TtsClipOutcome.forFailure(cause)")
        && worker.contains("if (!TtsClipOutcome.PLAYED.equals(outcome))"),
        "playback and download errors must not be indistinguishable consumed successes");
    assert!(download.contains("TtsClipOutcome.isExpiredHttpStatus(code)")
        && download.contains("throw new TtsClipOutcome.ExpiredToken()"),
        "expired token must cross retry plumbing as a distinct renewal outcome");
}

#[test]
fn resume_lock_unavailable_cannot_dismiss_overlay() {
    let prompt = MAIN_ACTIVITY
        .split("private void promptResumeUnlock() {")
        .nth(1)
        .expect("resume unlock entry point")
        .split("private void unlockApp() {")
        .next()
        .unwrap();
    assert!(
        prompt.contains("NativeUnlockGate.canPrompt(")
            && prompt.contains("biometricManager.canAuthenticate(authenticators), BiometricManager.BIOMETRIC_SUCCESS"),
        "resume availability must use the executed fail-closed decision"
    );
    let unavailable = prompt.split("if (!NativeUnlockGate.canPrompt(").nth(1)
        .expect("resume availability guard")
        .split("Executor executor =")
        .next()
        .unwrap();
    assert!(!unavailable.contains("unlockApp()"), "unavailable authentication must retain the lock overlay");
    assert!(unavailable.contains("Log.w(") && unavailable.contains("return;"),
        "unavailable authentication must log and leave retry available");
    assert!(MAIN_ACTIVITY.contains("unlockBtn.setOnClickListener(v -> promptResumeUnlock())"),
        "Unlock button must retry");
    assert!(prompt.contains("promptResumeUnlock(this::unlockApp)")
        && prompt.contains("public void onAuthenticationSucceeded(")
        && prompt.contains("onSuccess.run();"), "normal Unlock must dismiss only through successful authentication");
    let failure = prompt.split("public void onAuthenticationError(").nth(1).unwrap();
    assert!(!failure.split("public void onAuthenticationFailed(").next().unwrap().contains("unlockApp()"),
        "cancel must retain the lock");
    assert!(!failure.split("public void onAuthenticationFailed(").nth(1).unwrap().contains("unlockApp()"),
        "failed authentication must retain the lock");
}

#[test]
fn resume_lock_gate_runs_with_platform_statuses() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let output_dir = tempfile::tempdir().unwrap();
    let stub = output_dir.path().join("BiometricManager.java");
    fs::write(&stub, r#"package androidx.biometric;
public class BiometricManager {
    public static final int BIOMETRIC_SUCCESS = 0, BIOMETRIC_ERROR_NO_HARDWARE = 12;
    public static int status;
    public int canAuthenticate(int authenticators) { return status; }
}"#).unwrap();
    let compile = Command::new("javac")
        .args(["-encoding", "UTF-8"])
        .arg("-d").arg(output_dir.path())
        .arg(&stub)
        .arg(root.join("android/app/src/main/java/com/chatbot/app/util/NativeUnlockGate.java"))
        .arg(root.join("chatbot-server/tests/fixtures/ResumeUnlockGateTest.java"))
        .output().expect("test image must provide javac");
    assert!(compile.status.success(), "Java compilation: {}", String::from_utf8_lossy(&compile.stderr));
    let run = Command::new("java")
        .arg("-cp").arg(output_dir.path()).arg("ResumeUnlockGateTest")
        .output().expect("run resume unlock gate fixture");
    assert!(run.status.success(), "resume lock behavior: {}", String::from_utf8_lossy(&run.stderr));
    print!("{}", String::from_utf8_lossy(&run.stdout));
}

#[test]
fn native_tts_response_logs_never_contain_playback_url() {
    let request = NATIVE_TTS.split("private AudioClip playUrlToTrackOnce(").nth(1)
        .expect("native TTS downloader")
        .split("private AudioClip streamWavToTrack(").next().unwrap();
    for (line_number, line) in request.lines().enumerate() {
        if line.contains("Log.d(") || line.contains("Log.e(") {
            for sensitive in ["urlStr", "+ url", "+ token", "tts_stream/"] {
                assert!(!line.contains(sensitive),
                    "NativeVoiceTts downloader line {} leaks bearer URL ({sensitive}): {line}", line_number + 1);
            }
        }
    }
    assert!(request.contains("Log.d(TAG, \"GET code=\" + code)"),
        "successful response diagnostic must retain only status code");
    assert!(request.contains("Log.e(TAG, \"GET non-retryable code=\" + code)"),
        "non-retryable diagnostic must retain only status code");
}

#[test]
fn native_unlock_control_flow_runs_on_shipped_java() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let output_dir = tempfile::tempdir().unwrap();
    let fixtures = root.join("chatbot-server/tests/fixtures/unlock");
    let mut sources = Vec::new();
    for entry in fs::read_dir(&fixtures).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_some_and(|ext| ext == "java") {
            sources.push(path);
        }
    }
    assert!(!sources.is_empty());
    let stubs = [
        ("Context.java", r#"package android.content;
public abstract class Context {
 public static final int MODE_PRIVATE=0;
 public Context getApplicationContext(){return this;}
 public abstract String getString(int id);
 public abstract SharedPreferences getSharedPreferences(String name,int mode);
}"#),
        ("SharedPreferences.java", r#"package android.content;
import java.util.Map;
public interface SharedPreferences {
 String getString(String key,String fallback); Map<String,?> getAll(); Editor edit();
 interface Editor { Editor putString(String key,String value); Editor remove(String key); Editor clear(); void apply(); boolean commit(); }
}"#),
        ("Handler.java", r#"package android.os;
public class Handler { public Handler(Looper l){} public void post(Runnable r){r.run();} public void postDelayed(Runnable r,long d){} }"#),
        ("Looper.java", r#"package android.os; public class Looper { public static Looper getMainLooper(){return null;} }"#),
        ("Build.java", r#"package android.os; public class Build { public static class VERSION {public static int SDK_INT=30;} public static class VERSION_CODES {public static final int Q=29,R=30;} }"#),
        ("Base64.java", r#"package android.util;
public class Base64 {public static final int DEFAULT=0,NO_WRAP=2; public static String encodeToString(byte[] b,int flags){return java.util.Base64.getEncoder().encodeToString(b);} public static byte[] decode(String s,int flags){return java.util.Base64.getDecoder().decode(s);} }"#),
        ("Log.java", r#"package android.util; public class Log {public static int i(String t,String m){return 0;} public static int w(String t,String m){return 0;} public static int w(String t,String m,Throwable e){return 0;} public static int e(String t,String m,Throwable e){return 0;} }"#),
        ("ValueCallback.java", r#"package android.webkit; public interface ValueCallback<T>{void onReceiveValue(T value);}"#),
        ("CookieManager.java", r#"package android.webkit;
import java.util.*;
public class CookieManager {
 private static final CookieManager INSTANCE=new CookieManager();
 public final Map<String,String> jar=new LinkedHashMap<>(); public final List<String> injected=new ArrayList<>(); public int flushes; public boolean acknowledge=true;
 public static CookieManager getInstance(){return INSTANCE;}
 public String getCookie(String url){return String.join("; ",jar.entrySet().stream().map(e->e.getKey()+"="+e.getValue()).toList());}
 public void setCookie(String url,String cookie){setCookie(url,cookie,null);}
 public void setCookie(String url,String cookie,ValueCallback<Boolean> cb){injected.add(url+" "+cookie);if(acknowledge){String[] pair=cookie.split(";",2)[0].split("=",2); if(cookie.contains("Max-Age=0"))jar.remove(pair[0]);else jar.put(pair[0],pair[1]);}if(cb!=null)cb.onReceiveValue(acknowledge);}
 public void removeExpiredCookie(){} public void flush(){flushes++;}
}"#),
        ("R.java", r#"package com.chatbot.app; public class R {public static class string {public static final int server_url=1;} }"#),
        ("FragmentActivity.java", r#"package androidx.fragment.app; public class FragmentActivity {public void runOnUiThread(Runnable r){r.run();}}"#),
        ("BiometricManager.java", r#"package androidx.biometric;
import android.content.Context;
public class BiometricManager {public static final int BIOMETRIC_SUCCESS=0; public static int status=0; public static int checks;
 public static class Authenticators {public static final int BIOMETRIC_STRONG=1,BIOMETRIC_WEAK=2,DEVICE_CREDENTIAL=4;}
 public static BiometricManager from(Context c){return new BiometricManager();} public int canAuthenticate(int a){checks++;return status;}
}"#),
        ("BiometricPrompt.java", r#"package androidx.biometric;
import androidx.fragment.app.FragmentActivity; import java.util.concurrent.Executor;
public class BiometricPrompt {public static int mode=0, prompts=0;
 public static class AuthenticationResult {} public static class AuthenticationCallback {
  public void onAuthenticationSucceeded(AuthenticationResult r){} public void onAuthenticationError(int code,CharSequence message){} public void onAuthenticationFailed(){}
 }
 public static class PromptInfo { public static class Builder {public Builder setTitle(String s){return this;} public Builder setSubtitle(String s){return this;} public Builder setAllowedAuthenticators(int i){return this;} public Builder setDeviceCredentialAllowed(boolean b){return this;} public PromptInfo build(){return new PromptInfo();}} }
 private final AuthenticationCallback callback;
 public BiometricPrompt(FragmentActivity a,Executor e,AuthenticationCallback callback){this.callback=callback;}
 public void authenticate(PromptInfo p){prompts++;if(mode==0)callback.onAuthenticationSucceeded(new AuthenticationResult());else {if(mode==2)callback.onAuthenticationFailed();callback.onAuthenticationError(5,"cancelled");}}
}"#),
        ("ContextCompat.java", r#"package androidx.core.content; import android.content.Context; import java.util.concurrent.Executor; public class ContextCompat {public static Executor getMainExecutor(Context c){return Runnable::run;}}"#),
        ("Plugin.java", r#"package com.getcapacitor; import android.content.Context; import androidx.fragment.app.FragmentActivity; public class Plugin { public Context context; public FragmentActivity activity; public Context getContext(){return context;} public FragmentActivity getActivity(){return activity;} }"#),
        ("PluginCall.java", r#"package com.getcapacitor; import java.util.*;
public class PluginCall {public final Map<String,String> args=new HashMap<>();public JSObject result;public String error;public int resolutions,rejections;public boolean keepAlive;
 public String getString(String key){return args.get(key);}public void setKeepAlive(boolean v){keepAlive=v;}
 public void resolve(JSObject o){resolutions++;result=o;} public void reject(String s){rejections++;error=s;}public void reject(String s,Throwable t){reject(s);}
}"#),
        ("JSObject.java", r#"package com.getcapacitor; public class JSObject extends java.util.LinkedHashMap<String,Object>{}"#),
        ("PluginMethod.java", r#"package com.getcapacitor; public @interface PluginMethod {}"#),
        ("CapacitorPlugin.java", r#"package com.getcapacitor.annotation; public @interface CapacitorPlugin {String name();}"#),
        ("KeyProperties.java", r#"package android.security.keystore; public class KeyProperties {public static final String KEY_ALGORITHM_AES="AES",BLOCK_MODE_GCM="GCM",ENCRYPTION_PADDING_NONE="NoPadding";public static final int PURPOSE_ENCRYPT=1,PURPOSE_DECRYPT=2;}"#),
        ("KeyGenParameterSpec.java", r#"package android.security.keystore; public class KeyGenParameterSpec implements java.security.spec.AlgorithmParameterSpec {public final String alias;public boolean auth;private KeyGenParameterSpec(String a,boolean b){alias=a;auth=b;}
 public static class Builder {private final String alias;private boolean auth;public Builder(String a,int p){alias=a;}public Builder setBlockModes(String... s){return this;}public Builder setEncryptionPaddings(String... s){return this;}public Builder setUserAuthenticationRequired(boolean b){auth=b;return this;}public Builder setUserAuthenticationValidityDurationSeconds(int s){return this;}public KeyGenParameterSpec build(){return new KeyGenParameterSpec(alias,auth);}}
}"#),
        ("JSONObject.java", r#"package org.json;
import java.util.*;
// JVM-only flat string-map stand-in: org.json itself is not exercised by this harness.
public class JSONObject {private final Map<String,String> values=new LinkedHashMap<>();public JSONObject(){}
 public JSONObject(String json){int i=0;String s=json.trim();if(!s.startsWith("{")||!s.endsWith("}"))throw new IllegalArgumentException("JSON object");i=1;while(i<s.length()-1){while(i<s.length()-1&&(Character.isWhitespace(s.charAt(i))||s.charAt(i)==','))i++;if(i>=s.length()-1)break;StringBuilder k=new StringBuilder(),v=new StringBuilder();i=string(s,i,k);while(Character.isWhitespace(s.charAt(i)))i++;if(s.charAt(i++)!=':')throw new IllegalArgumentException();while(Character.isWhitespace(s.charAt(i)))i++;i=string(s,i,v);values.put(k.toString(),v.toString());}}
 private static int string(String s,int i,StringBuilder out){if(s.charAt(i++)!='\"')throw new IllegalArgumentException();while(i<s.length()){char c=s.charAt(i++);if(c=='\"')return i;if(c=='\\'){c=s.charAt(i++);if(c=='u'){c=(char)Integer.parseInt(s.substring(i,i+4),16);i+=4;}else if(c=='n')c='\n';else if(c=='r')c='\r';else if(c=='t')c='\t';}out.append(c);}throw new IllegalArgumentException();}
 public JSONObject put(String k,Object v){values.put(k,v==null?"":v.toString());return this;}public String optString(String k,String fallback){return values.getOrDefault(k,fallback);}
 private static String quote(String s){StringBuilder b=new StringBuilder("\"");for(char c:s.toCharArray()){if(c=='\"'||c=='\\')b.append('\\');if(c=='\n'){b.append("\\n");continue;}b.append(c);}return b.append('\"').toString();}
 public String toString(){StringJoiner j=new StringJoiner(",","{","}");values.forEach((k,v)->j.add(quote(k)+":"+quote(v)));return j.toString();}
}"#),
    ];
    for (name, source) in stubs {
        let path = output_dir.path().join(name);
        fs::write(&path, source).unwrap();
        sources.push(path);
    }
    let compile = Command::new("javac")
        .args(["-encoding", "UTF-8"])
        .arg("-d")
        .arg(output_dir.path())
        .args(&sources)
        .arg(root.join("android/app/src/main/java/com/chatbot/app/util/ServerUrlResolver.java"))
        .arg(root.join("android/app/src/main/java/com/chatbot/app/util/ServerUrlSetting.java"))
        .arg(root.join("android/app/src/main/java/com/chatbot/app/util/ServerUrlSettingStore.java"))
        .arg(root.join("android/app/src/main/java/com/chatbot/app/util/NativeUnlockGate.java"))
        .arg(root.join("android/app/src/main/java/com/chatbot/app/NativeSecureKey/NativeSecureKeyPlugin.java"))
        .arg(root.join("android/app/src/main/java/com/chatbot/app/NativeSecureKey/CredentialCookies.java"))
        .arg(root.join("android/app/src/main/java/com/chatbot/app/NativeSecureKey/SealedCredentialPayload.java"))
        .arg(root.join("chatbot-server/tests/fixtures/NativeUnlockGateTest.java"))
        .output()
        .expect("test image must provide javac");
    assert!(compile.status.success(), "Java compilation: {}", String::from_utf8_lossy(&compile.stderr));
    let run = Command::new("java")
        .arg("-cp")
        .arg(output_dir.path())
        .arg("NativeUnlockGateTest")
        .output()
        .expect("run native unlock behavior test");
    assert!(run.status.success(), "native unlock behavior: {}\n{}", String::from_utf8_lossy(&run.stderr), String::from_utf8_lossy(&run.stdout));
    print!("{}", String::from_utf8_lossy(&run.stdout));
}

#[test]
fn native_entry_gates_and_tts_outcomes_run_on_shipped_java() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let output_dir = tempfile::tempdir().unwrap();
    let compile = Command::new("javac")
        .args(["-encoding", "UTF-8"])
        .arg("-d").arg(output_dir.path())
        .arg(root.join("android/app/src/main/java/com/chatbot/app/util/NativeUnlockGate.java"))
        .arg(root.join("android/app/src/main/java/com/chatbot/app/audio/TtsClipOutcome.java"))
        .arg(root.join("chatbot-server/tests/fixtures/NativeBoundaryOutcomeTest.java"))
        .output().expect("test image must provide javac");
    assert!(compile.status.success(), "Java compilation: {}", String::from_utf8_lossy(&compile.stderr));
    let run = Command::new("java").arg("-cp").arg(output_dir.path())
        .arg("NativeBoundaryOutcomeTest").output().expect("run native boundary fixture");
    assert!(run.status.success(), "native boundaries: {}\n{}",
        String::from_utf8_lossy(&run.stderr), String::from_utf8_lossy(&run.stdout));
}

#[test]
fn advertised_api_24_has_no_unconditional_api_26_audio_focus_or_base64_calls() {
    let mic = include_str!("../../android/app/src/main/java/com/chatbot/app/NativeMic/NativeMicPlugin.java");
    let tts = include_str!("../../android/app/src/main/java/com/chatbot/app/NativeVoiceTts/NativeVoiceTtsPlugin.java");
    let car = include_str!("../../android/app/src/main/java/com/chatbot/app/car/VoiceScreen.java");
    let setting = include_str!("../../android/app/src/main/java/com/chatbot/app/util/ServerUrlSetting.java");
    let build = include_str!("../../android/variables.gradle");
    assert!(build.contains("minSdkVersion = 24"), "retain the advertised API 24 floor");
    for (name, source) in [("mic", mic), ("handheld TTS", tts), ("Android Auto", car)] {
        assert!(source.contains("AudioFocusCompat.request("), "{name} must use the API-gated focus adapter");
        assert!(!source.contains("new AudioFocusRequest.Builder"), "{name} must not construct API-26 focus requests directly");
        assert!(!source.contains("abandonAudioFocusRequest("), "{name} must not abandon API-26 focus directly");
    }
    assert!(!setting.contains("java.util.Base64") && !setting.contains("Base64.getUrlEncoder"),
        "origin slot encoding must remain available on API 24/25 without app desugaring");
}

#[test]
fn audio_focus_adapter_executes_legacy_and_api_26_platform_paths() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let output_dir = tempfile::tempdir().unwrap();
    let stubs = [
        ("Build.java", r#"package android.os; public class Build {
 public static class VERSION { public static int SDK_INT=25; }
 public static class VERSION_CODES { public static final int O=26; }
}"#),
        ("AudioAttributes.java", r#"package android.media; public class AudioAttributes {
 public static class Builder { public Builder setUsage(int i){return this;} public Builder setContentType(int i){return this;} public AudioAttributes build(){return new AudioAttributes();} }
}"#),
        ("AudioFocusRequest.java", r#"package android.media; public class AudioFocusRequest {
 public static class Builder { public Builder(int i){} public Builder setAudioAttributes(AudioAttributes a){return this;} public Builder setOnAudioFocusChangeListener(AudioManager.OnAudioFocusChangeListener l){return this;} public AudioFocusRequest build(){return new AudioFocusRequest();} }
}"#),
        ("AudioManager.java", r#"package android.media; public class AudioManager {
 public static final int AUDIOFOCUS_GAIN=1, AUDIOFOCUS_REQUEST_GRANTED=1, STREAM_MUSIC=3;
 public interface OnAudioFocusChangeListener { void onAudioFocusChange(int change); }
 public int legacyRequests, modernRequests, legacyAbandons, modernAbandons;
 public int requestAudioFocus(OnAudioFocusChangeListener l,int stream,int gain){legacyRequests++;return AUDIOFOCUS_REQUEST_GRANTED;}
 public int requestAudioFocus(AudioFocusRequest r){modernRequests++;return AUDIOFOCUS_REQUEST_GRANTED;}
 public int abandonAudioFocus(OnAudioFocusChangeListener l){legacyAbandons++;return 1;}
 public int abandonAudioFocusRequest(AudioFocusRequest r){modernAbandons++;return 1;}
}"#),
    ];
    let mut sources = Vec::new();
    for (name, source) in stubs {
        let path = output_dir.path().join(name);
        fs::write(&path, source).unwrap();
        sources.push(path);
    }
    let compile = Command::new("javac").args(["-encoding", "UTF-8"])
        .arg("-d").arg(output_dir.path()).args(&sources)
        .arg(root.join("android/app/src/main/java/com/chatbot/app/audio/AudioFocusCompat.java"))
        .arg(root.join("chatbot-server/tests/fixtures/NativeAudioFocusCompatTest.java"))
        .output().expect("test image must provide javac");
    assert!(compile.status.success(), "Java compilation: {}", String::from_utf8_lossy(&compile.stderr));
    let run = Command::new("java").arg("-cp").arg(output_dir.path())
        .arg("NativeAudioFocusCompatTest").output().expect("run API focus fixture");
    assert!(run.status.success(), "audio focus adapter: {}\n{}",
        String::from_utf8_lossy(&run.stderr), String::from_utf8_lossy(&run.stdout));
}

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
        ("ServerUrlSettingStore", SERVER_URL_SETTING_STORE),
    ] {
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
    for (name, src) in [
        ("ClientLogReporter", CLIENT_LOG_REPORTER),
        ("VoiceScreen", VOICE_SCREEN),
        ("ServerUrlSettingStore", SERVER_URL_SETTING_STORE),
    ] {
        assert!(src.contains("R.string.server_url"), "{name} must read the flavor server_url resource");
    }
    assert!(
        SERVER_URL_SETTING_STORE.contains("ServerUrlResolver.resolveCanonical(context.getString(R.string.server_url))"),
        "shared store must resolve the flavor resource through the canonical resolver"
    );
    assert!(
        SERVER_URL_SETTING_STORE.contains("ServerUrlSetting.selected(store(context), flavorDefault(context))"),
        "shared store must select the persisted override over the flavor default"
    );
    assert!(
        MAIN_ACTIVITY.contains("setServerUrl"),
        "MainActivity must pin the CapConfig WebView origin to the flavor resource"
    );
    for (name, src) in [
        ("MainActivity", MAIN_ACTIVITY),
        ("NativeSecureKeyPlugin", SECURE_KEY_PLUGIN),
    ] {
        assert!(
            src.contains("ServerUrlSettingStore.selected(")
                && src.contains("ServerUrlSettingStore.flavorDefault("),
            "{name} must select the validated override over the canonical flavor origin via the shared store"
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

#[test]
fn car_voice_logs_exclude_turn_content_and_tts_tokens() {
    // FileLogger persists these lines and the crash reporter can upload them.
    // Keep HTTP status and audio diagnostics, but never pass turn payloads.
    for (line_number, line) in VOICE_SCREEN.lines().enumerate() {
        if !line.contains("FileLogger.log(") {
            continue;
        }
        for sensitive in [
            "+ text", "+ response", "+ token", "+ body", "+ err",
            "+ lastTranscription", "text.substring", "response.substring",
            "token=", "body=", "error=",
        ] {
            assert!(
                !line.contains(sensitive),
                "VoiceScreen.java:{} logs turn content or a token ({sensitive}): {line}",
                line_number + 1
            );
        }
    }
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

/// Compile the real Android selection entry point against minimal framework
/// doubles so the flavor/resource and persisted-override contract is exercised.
#[test]
fn server_setting_store_selection_runs_on_shipped_java() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let output_dir = tempfile::tempdir().unwrap();
    let stubs = [
        ("Context.java", r#"package android.content;
public abstract class Context {
    public static final int MODE_PRIVATE = 0;
    public Context getApplicationContext() { return this; }
    public abstract String getString(int id);
    public abstract SharedPreferences getSharedPreferences(String name, int mode);
}"#),
        ("SharedPreferences.java", r#"package android.content;
import java.util.Map;
public interface SharedPreferences {
    String getString(String key, String defaultValue);
    Map<String, ?> getAll();
    Editor edit();
    interface Editor {
        Editor remove(String key);
        Editor putString(String key, String value);
        boolean commit();
    }
}"#),
        ("Handler.java", r#"package android.os;
public class Handler {
    public Handler(Looper looper) {}
    public void post(Runnable action) { action.run(); }
    public void postDelayed(Runnable action, long delay) {}
}"#),
        ("Looper.java", r#"package android.os;
public class Looper { public static Looper getMainLooper() { return null; } }"#),
        ("ValueCallback.java", r#"package android.webkit;
public interface ValueCallback<T> { void onReceiveValue(T value); }"#),
        ("CookieManager.java", r#"package android.webkit;
public class CookieManager {
    private static final CookieManager INSTANCE = new CookieManager();
    public String header;
    public final java.util.List<String> expired = new java.util.ArrayList<>();
    public boolean acknowledge = true;
    public int flushes;
    public static CookieManager getInstance() { return INSTANCE; }
    public String getCookie(String origin) { return header; }
    public void setCookie(String origin, String value, ValueCallback<Boolean> done) {
        expired.add(origin + " " + value);
        done.onReceiveValue(acknowledge);
    }
    public void removeExpiredCookie() {}
    public void flush() { flushes++; }
}"#),
        ("Log.java", r#"package android.util;
public class Log {
    public static int w(String tag, String text) { return 0; }
    public static int w(String tag, String text, Throwable error) { return 0; }
}"#),
        ("R.java", r#"package com.chatbot.app;
public class R { public static class string { public static final int server_url = 1; } }"#),
    ];
    let mut sources = Vec::new();
    for (name, source) in stubs {
        let path = output_dir.path().join(name);
        fs::write(&path, source).unwrap();
        sources.push(path);
    }
    let fixture = output_dir.path().join("ServerUrlSettingStoreSelectionTest.java");
    fs::write(&fixture, r#"import android.content.Context;
import android.content.SharedPreferences;
import android.webkit.CookieManager;
import com.chatbot.app.util.ServerUrlResolver;
import com.chatbot.app.util.ServerUrlSettingStore;

public class ServerUrlSettingStoreSelectionTest {
    static class TestContext extends Context {
        String resource, override;
        boolean missing;
        TestContext(String resource, String override) {
            this.resource = resource;
            this.override = override;
        }
        @Override public String getString(int id) {
            if (missing) throw new IllegalArgumentException("missing resource");
            return resource;
        }
        @Override public SharedPreferences getSharedPreferences(String name, int mode) {
            return new SharedPreferences() {
                @Override public String getString(String key, String fallback) { return override; }
                @Override public java.util.Map<String, ?> getAll() { return java.util.Map.of(); }
                @Override public Editor edit() { throw new AssertionError("selection must not write"); }
            };
        }
    }
    static void expect(String expected, String actual) {
        if (!expected.equals(actual)) throw new AssertionError(expected + " != " + actual);
    }
    public static void main(String[] args) {
        TestContext emulator = new TestContext("http://10.0.2.2:80", null);
        TestContext physical = new TestContext("https://physical.example", null);
        expect(emulator.resource, ServerUrlSettingStore.selected(emulator));
        expect(physical.resource, ServerUrlSettingStore.selected(physical));
        emulator.missing = true;
        expect(ServerUrlResolver.FALLBACK_URL, ServerUrlSettingStore.flavorDefault(emulator));
        expect(ServerUrlResolver.FALLBACK_URL, ServerUrlSettingStore.selected(emulator));
        physical.override = "http://invalid.example";
        expect(physical.resource, ServerUrlSettingStore.selected(physical));
        physical.override = "https://chosen.example:8443/";
        expect("https://chosen.example:8443", ServerUrlSettingStore.selected(physical));
        expect(ServerUrlResolver.FALLBACK_URL, ServerUrlSettingStore.selected(null));
        if (ServerUrlSettingStore.flavorDefault(null) != null) throw new AssertionError("null context default");

        CookieManager jar = CookieManager.getInstance();
        jar.header = "session=S; remember-alice=A; enc_key-alice=K; csrf=C; other=V; session=S";
        ServerUrlSettingStore.purgeSwitchCookiesAsync("https://old.example", ok -> {
            if (!ok) throw new AssertionError("acknowledged purge must succeed");
        });
        if (jar.expired.size() != 3) throw new AssertionError("only unique switch cookies expire: " + jar.expired);
        for (String name : new String[]{"session", "remember-alice", "enc_key-alice"}) {
            if (!jar.expired.contains("https://old.example "
                    + com.chatbot.app.CredentialCookies.expiredCookieValue(name))) {
                throw new AssertionError("missing expiry: " + name);
            }
        }
        if (jar.flushes != 1) throw new AssertionError("purge must flush");
        jar.expired.clear();
        jar.acknowledge = false;
        jar.header = "session=S";
        ServerUrlSettingStore.purgeSwitchCookiesAsync("https://old.example", ok -> {
            if (ok) throw new AssertionError("rejected expiry must fail closed");
        });
        jar.expired.clear();
        jar.header = "csrf=C";
        ServerUrlSettingStore.purgeSwitchCookiesAsync("https://old.example", ok -> {
            if (!ok) throw new AssertionError("no switch cookies must succeed");
        });
        if (!jar.expired.isEmpty()) throw new AssertionError("unrelated cookies must survive");
    }
}"#).unwrap();
    let compile = Command::new("javac")
        .args(["-encoding", "UTF-8"])
        .arg("-d")
        .arg(output_dir.path())
        .args(&sources)
        .arg(root.join("android/app/src/main/java/com/chatbot/app/util/ServerUrlResolver.java"))
        .arg(root.join("android/app/src/main/java/com/chatbot/app/util/ServerUrlSetting.java"))
        .arg(root.join("android/app/src/main/java/com/chatbot/app/util/ServerUrlSettingStore.java"))
        .arg(root.join("android/app/src/main/java/com/chatbot/app/NativeSecureKey/CredentialCookies.java"))
        .arg(fixture)
        .output()
        .expect("test image must provide javac");
    assert!(compile.status.success(), "Java compilation: {}", String::from_utf8_lossy(&compile.stderr));
    let run = Command::new("java")
        .arg("-cp")
        .arg(output_dir.path())
        .arg("ServerUrlSettingStoreSelectionTest")
        .output()
        .expect("run native selection behavior test");
    assert!(run.status.success(), "native selection behavior: {}", String::from_utf8_lossy(&run.stderr));
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

/// GHSA-w5hq-g745-h8pq: every installed uuid copy must be fixed stable >=11.1.1.
#[test]
fn installed_uuid_copies_are_fixed_stable() {
    let lock: serde_json::Value = serde_json::from_str(PACKAGE_LOCK_JSON).expect("lock must parse");
    let packages = lock
        .get("packages")
        .and_then(|p| p.as_object())
        .expect("lock must have packages");
    let mut found = 0;
    for (path, entry) in packages {
        if path != "node_modules/uuid" && !path.ends_with("/node_modules/uuid") {
            continue;
        }
        found += 1;
        let version = entry
            .get("version")
            .and_then(|v| v.as_str())
            .unwrap_or_else(|| panic!("{path} must carry a version"));
        assert!(
            stable_version(version) >= (11, 1, 1),
            "{path} must be fixed stable >=11.1.1; got `{version}`"
        );
    }
    assert!(found > 0, "lock must install at least one uuid copy");
}

fn stable_version(raw: &str) -> (u64, u64, u64) {
    assert!(
        !raw.contains('-') && !raw.contains('+'),
        "uuid must be stable, got `{raw}`"
    );
    let parts: Vec<&str> = raw.split('.').collect();
    assert!(
        parts.len() == 3
            && parts
                .iter()
                .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit())),
        "uuid must be strict X.Y.Z, got `{raw}`"
    );
    (
        parts[0].parse().unwrap(),
        parts[1].parse().unwrap(),
        parts[2].parse().unwrap(),
    )
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
