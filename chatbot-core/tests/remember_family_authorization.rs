use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chatbot_core::{account_service::AccountService, remember_store::ResumeOutcome};

fn forged_family_token(token: &str) -> String {
    let mut bytes = URL_SAFE_NO_PAD.decode(token).expect("issued token");
    bytes[16] ^= 1; // Preserve family ID, invalidate the bearer secret.
    URL_SAFE_NO_PAD.encode(bytes)
}

#[test]
fn forged_family_cookie_cannot_rotate_during_authenticated_password_login() {
    let root = tempfile::tempdir().unwrap();
    let accounts = AccountService::with_root_and_secret(root.path().to_path_buf(), "test-secret");
    let original = accounts.remember().unwrap().issue("alice").unwrap();
    let forged = forged_family_token(&original);

    // The password-login caller has authenticated alice, but the supplied
    // remember cookie belongs to an attacker who knows only the family ID.
    let new_cookie = accounts
        .remember()
        .unwrap()
        .issue_or_refresh("alice", Some(&forged))
        .unwrap();
    assert!(
        matches!(
            accounts
                .remember()
                .unwrap()
                .resume(Some(&original))
                .unwrap(),
            ResumeOutcome::Authenticated { .. }
        ),
        "forged cookie must not rotate the existing family"
    );
    assert!(matches!(
        accounts
            .remember()
            .unwrap()
            .resume(Some(&new_cookie))
            .unwrap(),
        ResumeOutcome::Authenticated { .. }
    ));
}

#[test]
fn forged_family_cookie_cannot_revoke_during_guest_forget() {
    let root = tempfile::tempdir().unwrap();
    let accounts = AccountService::with_root_and_secret(root.path().to_path_buf(), "test-secret");
    let original = accounts.remember().unwrap().issue("alice").unwrap();
    let forged = forged_family_token(&original);

    // /login/forget authenticates only the guest CSRF token and trusts this
    // cookie for family ownership; the caller supplies the requested username.
    assert_eq!(accounts.remember().unwrap().peek_username(Some(&forged)), None);
    assert!(!accounts
        .remember()
        .unwrap()
        .revoke_if_username(Some(&forged), "alice"));
    assert!(
        matches!(
            accounts
                .remember()
                .unwrap()
                .resume(Some(&original))
                .unwrap(),
            ResumeOutcome::Authenticated { .. }
        ),
        "forged cookie must not revoke another device's family"
    );
}

#[test]
fn forged_family_cookie_cannot_revoke_during_password_login_opt_out() {
    let root = tempfile::tempdir().unwrap();
    let accounts = AccountService::with_root_and_secret(root.path().to_path_buf(), "test-secret");
    let original = accounts.remember().unwrap().issue("alice").unwrap();
    let forged = forged_family_token(&original);
    // The unchecked-password-login caller revokes the supplied account cookie.
    accounts.remember().unwrap().revoke(Some(&forged));
    assert!(matches!(
        accounts
            .remember()
            .unwrap()
            .resume(Some(&original))
            .unwrap(),
        ResumeOutcome::Authenticated { .. }
    ));
}
