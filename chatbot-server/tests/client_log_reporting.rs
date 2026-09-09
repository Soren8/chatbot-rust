//! Contract tests for Android client log reporting (debug builds only) and
//! the JS error bridge that feeds it.

/// The Android reporter must be a no-op outside debug builds, must use the
/// session cookie (no CSRF available to native), and the crash handler must
/// upload synchronously before chaining to the previous handler.
#[test]
fn android_crash_and_error_reporting_is_debug_gated_and_cookie_authorized() {
    let reporter = include_str!(
        "../../android/app/src/main/java/com/chatbot/app/util/ClientLogReporter.java"
    );
    let activity = include_str!(
        "../../android/app/src/main/java/com/chatbot/app/MainActivity.java"
    );
    let logger = include_str!(
        "../../android/app/src/main/java/com/chatbot/app/Logger/LoggerPlugin.java"
    );
    let file_logger = include_str!(
        "../../android/app/src/main/java/com/chatbot/app/util/FileLogger.java"
    );

    assert!(
        reporter.contains("BuildConfig.DEBUG"),
        "reporting must be gated to debug builds; release stays silent"
    );
    assert!(
        reporter.contains("/client_logs"),
        "reports must target the /client_logs ingest endpoint"
    );
    assert!(
        reporter.contains("getCookie"),
        "the reporter must authorize via the session cookie (native has no CSRF token)"
    );
    assert!(
        reporter.contains("reportCrash") && reporter.contains("snapshotLines"),
        "crash reports must include the recent FileLogger ring history"
    );

    assert!(
        activity.contains("installCrashReporter")
            && activity.contains("setDefaultUncaughtExceptionHandler"),
        "MainActivity must install an uncaught exception reporter"
    );
    let handler_start = activity
        .find("private void installCrashReporter()")
        .expect("installCrashReporter must be declared");
    let handler_end = activity[handler_start..]
        .find("previous.uncaughtException(thread, throwable)")
        .map(|i| handler_start + i)
        .expect("crash handler must chain to the previous handler");
    let handler_body = &activity[handler_start..handler_end];
    assert!(
        handler_body.contains("ClientLogReporter.reportCrash"),
        "crash handler must upload via ClientLogReporter before chaining"
    );

    assert!(
        logger.contains("public void report(") && logger.contains("ClientLogReporter.report"),
        "Logger plugin must expose report() so JS errors reach the server"
    );
    assert!(
        file_logger.contains("snapshotLines") && file_logger.contains("ring.addLast"),
        "FileLogger must keep an in-memory ring for crash reports"
    );
}

/// JS global errors and unhandled rejections must reach the native reporter
/// (Android app only; the web build has no Logger plugin and stays silent).
#[test]
fn js_global_errors_bridge_to_native_reporter() {
    let chat_js = include_str!("../../static/chat.js");

    assert!(
        chat_js.contains("window.addEventListener('error'")
            && chat_js.contains("window.addEventListener('unhandledrejection'"),
        "chat.js must hook global error and unhandledrejection events"
    );
    assert!(
        chat_js.contains("'Logger', 'report'"),
        "errors must be forwarded through the Logger.report bridge call"
    );
    assert!(
        chat_js.contains("window.Capacitor.nativePromise"),
        "the bridge call must be Capacitor-gated so desktop browsers never invoke it"
    );
}
