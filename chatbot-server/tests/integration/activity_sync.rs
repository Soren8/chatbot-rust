use std::path::Path;
use std::process::Command;

#[test]
fn activity_sync_behavior() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let run = Command::new("node")
        .arg(root.join("chatbot-server/tests/fixtures/activity_sync_test.js"))
        .arg(root.join("static/activity-sync.js"))
        .arg(root.join("static/chat.js"))
        .output()
        .expect("test image must provide Node");
    assert!(run.status.success(), "{}\n{}", String::from_utf8_lossy(&run.stdout), String::from_utf8_lossy(&run.stderr));
}

#[test]
fn activity_sync_page_wiring() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let html = std::fs::read_to_string(root.join("static/templates/chat.html")).unwrap();
    assert!(html.find("/static/activity-sync.js").expect("activity sync script") < html.find("/static/chat.js").unwrap());
    let chat = std::fs::read_to_string(root.join("static/chat.js")).unwrap();
    assert!(chat.contains("ChatActivitySync.createActivitySync"));
    for path in ["/get_sets", "/load_set", "/history_pair", "/create_set", "/fork_set", "/delete_message", "/reset_chat", "/rename_set", "/delete_set", "/set_privacy", "/update_memory", "/update_system_prompt", "/update_preferences"] {
        assert!(!chat.contains(&format!("fetch('{path}'")), "direct fetch remains for {path}");
    }
    assert!(chat.contains("activitySync.generationResponse"));
    assert!(chat.contains("activitySync.stop()"));
    assert!(chat.contains("activitySync.navigate"));
    assert!(chat.contains("activitySync.recover"));
    assert!(chat.contains("discoverActivity(setId, loadGen)"), "discover after load");
    assert!(chat.contains("renderRecoveredActivity"), "recovered text renderer");
    assert!(chat.contains("loadHistoryImage"), "retrying history image loader");
    assert!(chat.contains("if (activitySync.interrupted()) paintFailedAiTurn($pendingUserMessage, errText);"), "interrupted generation must show Retry");
    assert!(!chat.contains("if (window.voiceModeActive) noteLocalVersionBumpAfterPersist();"), "all durable renderers must not double bump");
    let connections = std::fs::read_to_string(root.join("static/agent-connections.js")).unwrap();
    assert!(connections.contains("activitySync.request"));
}
