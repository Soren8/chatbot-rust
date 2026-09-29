use std::path::Path;
use std::process::Command;

fn run_case(case: &str) {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let run = Command::new("node")
        .arg(root.join("chatbot-server/tests/fixtures/sec008_browser_ui.js"))
        .arg(case)
        .arg(root.join("static/login.js"))
        .arg(root.join("static/chat.js"))
        .arg(root.join("static/templates/chat.html"))
        .output()
        .expect("test image must provide Node for browser behavior tests");
    assert!(run.status.success(), "{case}: {}", String::from_utf8_lossy(&run.stderr));
}

#[test]
fn fallback_after_prior_derived_login_does_not_submit_stale_storage_key() {
    run_case("login");
}

#[test]
fn forget_failure_preserves_cached_account_and_does_not_claim_removed() {
    run_case("forget");
}

#[test]
fn logout_this_computer_stays_put_when_forget_fails() {
    run_case("logout");
}

#[test]
fn privacy_selector_offers_three_modes_and_confirms_wider_access() {
    run_case("privacy");
}
