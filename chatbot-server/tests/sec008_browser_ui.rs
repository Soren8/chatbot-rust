const LOGIN: &str = include_str!("../../static/login.js");
const CHAT: &str = include_str!("../../static/chat.js");
const TEMPLATE: &str = include_str!("../../static/templates/chat.html");

#[test]
fn fallback_after_prior_derived_login_does_not_submit_stale_storage_key() {
    let submit = LOGIN.split("$('form').on('submit'").nth(1).expect("submit handler");
    let clear = submit.find("form.querySelector('input[name=\"storage_key\"]')?.remove()")
        .expect("clear prior attempt's key");
    let salt = submit.find("fetch(`/auth/salt/").expect("salt request");
    let fallback = submit.find("await postLogin(form);").expect("fallback POST");
    assert!(clear < fallback && clear < salt,
        "each attempt must clear a previous storage_key before fallback can POST");
}

#[test]
fn forget_failure_preserves_cached_account_and_does_not_claim_removed() {
    let forget = LOGIN.split("$('#forget-account').on('click'").nth(1).expect("forget handler");
    let revoke = forget.find("fetch('/login/forget'").expect("revoke request");
    let checked = forget[revoke..].find("resp.ok").expect("revoke status check") + revoke;
    let remove = forget.find("window.EncKey.removeSlot(username)").expect("slot removal");
    assert!(revoke < checked && checked < remove,
        "do not discard the cached account or report Removed until revoke succeeds");
}

#[test]
fn logout_this_computer_stays_put_when_forget_fails() {
    let logout = CHAT.split("function logoutThisComputer() {").nth(1).expect("logout handler")
        .split("// Settings panel behavior").next().unwrap();
    let revoke = logout.find("fetch('/login/forget'").expect("revoke request");
    let checked = logout[revoke..].find("response.ok").expect("revoke status check") + revoke;
    let remove = logout.find("window.EncKey.removeSlot(username)").expect("slot removal");
    let navigate = logout.rfind("window.location.href = '/logout'").expect("logout navigation");
    assert!(revoke < checked && checked < remove && remove < navigate,
        "failed revoke must retain recoverable slot and prevent logout navigation");
}

#[test]
fn privacy_selector_offers_only_implemented_modes_and_explains_non_private() {
    let options = TEMPLATE.split("<select id=\"privacy-select\"").nth(1).expect("privacy selector")
        .split("</select>").next().unwrap();
    assert!(options.contains("value=\"private\"") && options.contains("value=\"non_private\""));
    assert!(!options.contains("value=\"standard\""), "Standard is not selectable");
    assert!(TEMPLATE.contains("history encrypted"), "describe unchanged encrypted storage");
    assert!(!TEMPLATE.contains("Standard: reputable"), "do not present planned Standard as available");

    let change = CHAT.split("$('#privacy-select').on('change'").nth(1).expect("privacy change handler")
        .split("function loadSets(").next().unwrap();
    assert!(change.contains("SELECTABLE_PRIVACY_LEVELS.includes(requested)"),
        "a synthetic change must not submit planned Standard");
    assert!(change.contains("Non-private services may retain data or train on it")
        && change.contains("Earlier transmissions cannot be undone"),
        "confirmation must explain the actual transition and prior transmissions");
    assert!(!change.contains("Standard services have limited retention"));
}
