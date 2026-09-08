//! Pure snapshot transformations — no I/O, no crypto, no store access.
//!
//! All durable mutations should: load → pure op → CAS commit.

use super::types::{HistoryPair, PrepareCapture, SetSnapshot, SetVersion};

/// Maximum number of (user, assistant) pairs stored in one set.
pub const MAX_HISTORY_PAIRS: usize = 2_000;
/// Maximum characters per user or assistant message.
///
/// Must cover base64 `[IMAGE:data:...]` attachments that fit the `/chat` HTTP body
/// cap (`5 * 1024 * 1024` bytes). A 1M-char limit rejected typical photo data URLs
/// at history finalize even when the request body was accepted.
pub const MAX_MESSAGE_CHARS: usize = 5 * 1024 * 1024;
/// Maximum characters for set memory field (aligned under `/update_memory` 1MB body cap).
pub const MAX_MEMORY_CHARS: usize = 900_000;
/// Maximum characters for system prompt (same body cap as memory).
pub const MAX_PROMPT_CHARS: usize = 900_000;
/// Maximum characters for display name.
pub const MAX_DISPLAY_NAME_CHARS: usize = 200;

/// Errors from pure history operations (content/index validation only).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum OpsError {
    #[error("pair_index out of range")]
    PairIndexOutOfRange,
    #[error("content mismatch at pair_index")]
    ContentMismatch,
    #[error("empty user message")]
    EmptyUserMessage,
    #[error("empty set name")]
    EmptySetName,
    #[error("history too large")]
    HistoryTooLarge,
    #[error("message too large")]
    MessageTooLarge,
    #[error("memory too large")]
    MemoryTooLarge,
    #[error("system prompt too large")]
    PromptTooLarge,
    #[error("set name too large")]
    DisplayNameTooLarge,
}

fn check_message_sizes(user_msg: &str, assistant_msg: &str) -> Result<(), OpsError> {
    // Byte length is the right size proxy (base64 image tags are ASCII). Avoid
    // chars().count() which walks multi-megabyte messages on every append.
    if user_msg.len() > MAX_MESSAGE_CHARS || assistant_msg.len() > MAX_MESSAGE_CHARS {
        return Err(OpsError::MessageTooLarge);
    }
    Ok(())
}

fn check_history_capacity(current_len: usize) -> Result<(), OpsError> {
    if current_len >= MAX_HISTORY_PAIRS {
        return Err(OpsError::HistoryTooLarge);
    }
    Ok(())
}

/// Append a chat pair to a snapshot (does not bump version — store does that on commit).
pub fn append_pair(
    snapshot: &SetSnapshot,
    user_msg: &str,
    assistant_msg: &str,
) -> Result<SetSnapshot, OpsError> {
    if user_msg.trim().is_empty() {
        return Err(OpsError::EmptyUserMessage);
    }
    check_message_sizes(user_msg, assistant_msg)?;
    check_history_capacity(snapshot.history.len())?;
    let mut next = snapshot.clone();
    next.history
        .push((user_msg.to_owned(), assistant_msg.to_owned()));
    align_pair_ids_on_append(&mut next.pair_ids, snapshot.history.len(), snapshot.pair_ids.len());
    Ok(next)
}

/// Keep `pair_ids` aligned with history on append.
///
/// Format-2 snapshots (including empty sets) get a new `PairId`. Pre-chunk
/// fixtures with history but no ids stay without ids.
fn align_pair_ids_on_append(pair_ids: &mut Vec<crate::history::types::PairId>, history_len_before: usize, pair_ids_len_before: usize) {
    if pair_ids_len_before == history_len_before && (pair_ids_len_before > 0 || history_len_before == 0) {
        pair_ids.push(crate::history::types::PairId::new());
    }
}

/// Remove a history pair after verifying the user text matches.
///
/// Takes ownership so multi-MB histories are not cloned just to drop one pair.
pub fn delete_pair(
    mut snapshot: SetSnapshot,
    pair_index: usize,
    expected_user_msg: &str,
) -> Result<SetSnapshot, OpsError> {
    if pair_index >= snapshot.history.len() {
        return Err(OpsError::PairIndexOutOfRange);
    }
    let (stored_user, _) = &snapshot.history[pair_index];
    if !crate::chat_images::user_messages_match(stored_user, expected_user_msg) {
        return Err(OpsError::ContentMismatch);
    }
    snapshot.history.remove(pair_index);
    if pair_index < snapshot.pair_ids.len() {
        snapshot.pair_ids.remove(pair_index);
    }
    Ok(snapshot)
}

/// Clear chat history; keep memory, prompt, name, flags.
pub fn reset_history(mut snapshot: SetSnapshot) -> SetSnapshot {
    snapshot.history.clear();
    snapshot.pair_ids.clear();
    snapshot
}

pub fn update_memory(snapshot: &SetSnapshot, memory: &str) -> Result<SetSnapshot, OpsError> {
    if memory.len() > MAX_MEMORY_CHARS {
        return Err(OpsError::MemoryTooLarge);
    }
    let mut next = snapshot.clone();
    next.memory = memory.to_owned();
    Ok(next)
}

pub fn update_system_prompt(snapshot: &SetSnapshot, prompt: &str) -> Result<SetSnapshot, OpsError> {
    if prompt.len() > MAX_PROMPT_CHARS {
        return Err(OpsError::PromptTooLarge);
    }
    let mut next = snapshot.clone();
    next.system_prompt = prompt.to_owned();
    Ok(next)
}

pub fn rename(snapshot: &SetSnapshot, new_name: &str) -> Result<SetSnapshot, OpsError> {
    let trimmed = new_name.trim();
    if trimmed.is_empty() {
        return Err(OpsError::EmptySetName);
    }
    if trimmed.chars().count() > MAX_DISPLAY_NAME_CHARS {
        return Err(OpsError::DisplayNameTooLarge);
    }
    let mut next = snapshot.clone();
    next.display_name = trimmed.to_owned();
    Ok(next)
}

/// Placeholder prefix for low-friction new chats. The first successful chat
/// append replaces it with a contextual name; the user can rename anytime.
pub const AUTO_NEW_CHAT_PREFIX: &str = "New Chat";
/// Storage display names are limited by `SET_NAME_RE` to 64 chars.
pub const MAX_AUTO_NAME_CHARS: usize = 64;

/// True for auto placeholder names (`New Chat`, `New Chat 2`, ...).
pub fn is_auto_placeholder_name(name: &str) -> bool {
    let trimmed = name.trim();
    if trimmed == AUTO_NEW_CHAT_PREFIX {
        return true;
    }
    if let Some(rest) = trimmed.strip_prefix("New Chat ") {
        return !rest.is_empty() && rest.chars().all(|c| c.is_ascii_digit());
    }
    false
}

/// Sanitize a candidate into the `SET_NAME_RE` alphabet (`A-Za-z0-9 _-`, ≤64).
fn sanitize_name_candidate(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut last_space = false;
    for c in raw.chars() {
        let ok = c.is_ascii_alphanumeric() || c == ' ' || c == '_' || c == '-' || c == '\'';
        if c.is_whitespace() || !ok {
            if !out.is_empty() && !last_space {
                out.push(' ');
                last_space = true;
            }
            continue;
        }
        if c == '\'' {
            if !out.is_empty() && !last_space {
                out.push(' ');
                last_space = true;
            }
            continue;
        }
        out.push(c);
        last_space = false;
    }
    let trimmed = out.trim().to_string();
    if trimmed.chars().count() <= MAX_AUTO_NAME_CHARS {
        return trimmed;
    }
    trimmed.chars().take(MAX_AUTO_NAME_CHARS).collect::<String>().trim().to_string()
}

/// Derive a contextual chat name from the first user message.
///
/// Strips `[IMAGE:...]` payloads, collapses whitespace, keeps ~6 words / 48
/// chars so branch suffixes still fit. Falls back to `New Chat` when empty.
pub fn derive_chat_name_from_message(user_msg: &str) -> String {
    let stripped = crate::chat_images::strip_image_payloads(user_msg);
    let stripped = stripped.replace("[IMAGE:]", " ").replace("[IMAGE]", " ");
    let collapsed = stripped.split_whitespace().collect::<Vec<_>>().join(" ");
    let words: Vec<&str> = collapsed.split_whitespace().take(6).collect();
    let mut candidate = words.join(" ");
    if candidate.chars().count() > 48 {
        candidate = candidate.chars().take(48).collect::<String>();
        if let Some(pos) = candidate.rfind(' ') {
            candidate.truncate(pos);
        }
    }
    let clean = sanitize_name_candidate(&candidate);
    if clean.is_empty() || clean.eq_ignore_ascii_case("default") {
        return AUTO_NEW_CHAT_PREFIX.to_string();
    }
    clean
}

/// Candidate branch name for a fork (`<source> - branch`). Caller dedups.
pub fn branch_name_for(source: &str) -> String {
    let suffix = " - branch";
    let max_base = MAX_AUTO_NAME_CHARS.saturating_sub(suffix.len());
    let mut base = sanitize_name_candidate(source);
    if base.is_empty() {
        base = "Chat".to_string();
    }
    if base.chars().count() > max_base {
        base = base.chars().take(max_base).collect::<String>().trim().to_string();
    }
    format!("{base}{suffix}")
}

/// Append ` 2`, ` 3`, ... until `exists` is false. Truncates the base to fit.
pub fn dedup_name(base: &str, exists: impl Fn(&str) -> bool) -> String {
    let base = sanitize_name_candidate(base);
    let base = if base.is_empty() {
        AUTO_NEW_CHAT_PREFIX.to_string()
    } else {
        base
    };
    if !exists(&base) {
        return base;
    }
    for n in 2..10000 {
        let suffix = format!(" {n}");
        let max_base = MAX_AUTO_NAME_CHARS.saturating_sub(suffix.len());
        let mut stem = base.clone();
        if stem.chars().count() > max_base {
            stem = stem.chars().take(max_base).collect::<String>().trim().to_string();
        }
        let candidate = format!("{stem}{suffix}");
        if !exists(&candidate) {
            return candidate;
        }
    }
    base
}

/// Apply a successful regenerate/edit onto the **prepare capture** history.
///
/// Does not mutate shared state; caller commits the result via CAS.
pub fn apply_regenerate(
    capture: &PrepareCapture,
    assistant_response: &str,
) -> Result<SetSnapshot, OpsError> {
    let user_msg = capture
        .replace_user_message
        .as_deref()
        .filter(|s| !s.trim().is_empty())
        .ok_or(OpsError::EmptyUserMessage)?;

    check_message_sizes(user_msg, assistant_response)?;

    let mut history = capture.history.clone();
    let mut pair_ids = capture.pair_ids.clone();
    let pair: HistoryPair = (user_msg.to_owned(), assistant_response.to_owned());

    match capture.insertion_index {
        Some(idx) => {
            if idx > history.len() {
                return Err(OpsError::PairIndexOutOfRange);
            }
            // Capture still holds the original pair at idx (prepare is non-destructive).
            // Replace that pair; if idx == len (pop-last fallback), append.
            if idx < history.len() {
                history[idx] = pair;
            } else {
                check_history_capacity(history.len())?;
                history.push(pair);
                align_pair_ids_on_append(&mut pair_ids, capture.history.len(), capture.pair_ids.len());
            }
        }
        None => {
            // Treat as append (chat-style) if no index — unusual for regenerate.
            check_history_capacity(history.len())?;
            history.push(pair);
            align_pair_ids_on_append(&mut pair_ids, capture.history.len(), capture.pair_ids.len());
        }
    }

    Ok(SetSnapshot {
        set_id: capture.set_id,
        version: capture.version,
        display_name: capture.display_name.clone(),
        memory: capture.memory.clone(),
        system_prompt: capture.system_prompt.clone(),
        history,
        pair_ids,
        is_default: capture.is_default,
    })
}

/// Build the post-chat snapshot from an immutable prepare capture.
pub fn apply_chat_append(
    capture: &PrepareCapture,
    user_msg: &str,
    assistant_msg: &str,
) -> Result<SetSnapshot, OpsError> {
    if user_msg.trim().is_empty() {
        return Err(OpsError::EmptyUserMessage);
    }
    check_message_sizes(user_msg, assistant_msg)?;
    check_history_capacity(capture.history.len())?;
    let mut history = capture.history.clone();
    history.push((user_msg.to_owned(), assistant_msg.to_owned()));
    let mut pair_ids = capture.pair_ids.clone();
    align_pair_ids_on_append(&mut pair_ids, capture.history.len(), capture.pair_ids.len());
    Ok(SetSnapshot {
        set_id: capture.set_id,
        version: capture.version,
        display_name: capture.display_name.clone(),
        memory: capture.memory.clone(),
        system_prompt: capture.system_prompt.clone(),
        history,
        pair_ids,
        is_default: capture.is_default,
    })
}

/// Stamp a new version after a successful pure op (store layer also does this).
pub fn with_version(mut snapshot: SetSnapshot, version: SetVersion) -> SetSnapshot {
    snapshot.version = version;
    snapshot
}

/// Default number of most-recent pairs returned by `/load_set` when the client
/// asks for a page (not applied unless `limit` is present).
pub const DEFAULT_HISTORY_PAGE_SIZE: usize = 40;
/// Hard cap on a single history page so a client cannot request the entire set
/// of multi-MB image pairs in one JSON body.
pub const MAX_HISTORY_PAGE_SIZE: usize = 200;

/// Window into a history vec: `[start, end)` plus whether older pairs exist.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HistoryPage {
    pub start: usize,
    pub end: usize,
    pub total: usize,
    pub has_more: bool,
}

impl HistoryPage {
    pub fn slice<'a, T>(&self, history: &'a [T]) -> &'a [T] {
        let end = self.end.min(history.len());
        let start = self.start.min(end);
        &history[start..end]
    }
}

/// Select a chronological window of pairs.
///
/// * `limit = None` — whole history (legacy `/load_set` clients and tests).
/// * `before = None` — the most recent `limit` pairs (tail).
/// * `before = Some(i)` — pairs with index `< i` (older page).
pub fn page_history(total: usize, limit: Option<usize>, before: Option<usize>) -> HistoryPage {
    match limit {
        None => HistoryPage {
            start: 0,
            end: total,
            total,
            has_more: false,
        },
        Some(raw_limit) => {
            let limit = raw_limit.clamp(1, MAX_HISTORY_PAGE_SIZE);
            let end = before.unwrap_or(total).min(total);
            let start = end.saturating_sub(limit);
            HistoryPage {
                start,
                end,
                total,
                has_more: start > 0,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::history::types::SetId;

    fn sample() -> SetSnapshot {
        let mut s = SetSnapshot::empty(SetId::new(), "default", "You are helpful.", true);
        s.version = SetVersion(3);
        s.history = vec![
            ("u1".into(), "a1".into()),
            ("u2".into(), "a2".into()),
            ("u3".into(), "a3".into()),
        ];
        s
    }

    #[test]
    fn append_pair_extends_history() {
        let s = sample();
        let next = append_pair(&s, "u4", "a4").unwrap();
        assert_eq!(next.history.len(), 4);
        assert_eq!(next.history[3], ("u4".into(), "a4".into()));
        assert_eq!(next.version, SetVersion(3)); // version unchanged until commit
        assert!(next.pair_ids.is_empty());
    }

    #[test]
    fn append_and_delete_keep_pair_ids_aligned() {
        let mut s = sample();
        s.pair_ids = vec![
            crate::history::types::PairId::new(),
            crate::history::types::PairId::new(),
            crate::history::types::PairId::new(),
        ];
        let first = s.pair_ids[0];
        let third = s.pair_ids[2];
        let next = append_pair(&s, "u4", "a4").unwrap();
        assert_eq!(next.pair_ids.len(), 4);
        assert_eq!(next.pair_ids[0], first);
        let deleted = delete_pair(next, 1, "u2").unwrap();
        assert_eq!(deleted.history.len(), 3);
        assert_eq!(deleted.pair_ids.len(), 3);
        assert_eq!(deleted.pair_ids[0], first);
        assert_eq!(deleted.pair_ids[1], third);
    }

    #[test]
    fn append_rejects_empty_user() {
        let s = sample();
        assert!(matches!(
            append_pair(&s, "  ", "a"),
            Err(OpsError::EmptyUserMessage)
        ));
    }

    #[test]
    fn auto_placeholder_detection() {
        assert!(is_auto_placeholder_name("New Chat"));
        assert!(is_auto_placeholder_name("New Chat 2"));
        assert!(is_auto_placeholder_name("  New Chat 12  "));
        assert!(!is_auto_placeholder_name("New Chat X"));
        assert!(!is_auto_placeholder_name("My Chat"));
        assert!(!is_auto_placeholder_name("New Chatty"));
    }

    #[test]
    fn derive_name_from_first_message() {
        assert_eq!(
            derive_chat_name_from_message("Plan my trip to Tokyo please"),
            "Plan my trip to Tokyo please"
        );
        assert_eq!(
            derive_chat_name_from_message("What's the weather like today?"),
            "What s the weather like today"
        );
        assert_eq!(
            derive_chat_name_from_message("see this\n[IMAGE:data:image/jpeg;base64,AAAA]"),
            "see this"
        );
        assert_eq!(derive_chat_name_from_message("   "), "New Chat");
        assert_eq!(derive_chat_name_from_message("😀🎉"), "New Chat");
        let long = "word ".repeat(30);
        let derived = derive_chat_name_from_message(&long);
        assert!(derived.chars().count() <= MAX_AUTO_NAME_CHARS);
    }

    #[test]
    fn branch_and_dedup_names_fit_storage_alphabet() {
        let b = branch_name_for("Trip planning!!!");
        assert_eq!(b, "Trip planning - branch");
        let existing = vec!["New Chat".to_string()];
        assert_eq!(
            dedup_name("New Chat", |c| existing.iter().any(|e| e == c)),
            "New Chat 2"
        );
        let long_base = "x".repeat(100);
        let d = dedup_name(&long_base, |_| false);
        assert!(d.chars().count() <= MAX_AUTO_NAME_CHARS);
        let re = regex::Regex::new(r"^[A-Za-z0-9 _-]{1,64}$").unwrap();
        assert!(re.is_match(&b));
        assert!(re.is_match(&d));
        assert!(re.is_match(&derive_chat_name_from_message("Hello, world!")));
    }

    #[test]
    fn delete_pair_checks_content() {
        let s = sample();
        let next = delete_pair(s.clone(), 1, "u2").unwrap();
        assert_eq!(next.history.len(), 2);
        assert_eq!(next.history[1].0, "u3");

        assert!(matches!(
            delete_pair(s.clone(), 1, "wrong"),
            Err(OpsError::ContentMismatch)
        ));
        assert!(matches!(
            delete_pair(s, 9, "u1"),
            Err(OpsError::PairIndexOutOfRange)
        ));
    }

    #[test]
    fn delete_pair_matches_thumbnail_image_payload() {
        let mut s = sample();
        s.history[1].0 = "see\n[IMAGE:data:image/jpeg;base64,FULLRESOLUTIONPAYLOAD]".into();
        let next = delete_pair(
            s.clone(),
            1,
            "see\n[IMAGE:data:image/jpeg;base64,THUMB]",
        )
        .unwrap();
        assert_eq!(next.history.len(), 2);
        assert_eq!(next.history[1].0, "u3");
        assert!(matches!(
            delete_pair(s, 1, "other\n[IMAGE:data:image/jpeg;base64,THUMB]"),
            Err(OpsError::ContentMismatch)
        ));
    }

    #[test]
    fn page_history_none_limit_is_full_legacy() {
        let page = page_history(50, None, None);
        assert_eq!(
            page,
            HistoryPage {
                start: 0,
                end: 50,
                total: 50,
                has_more: false
            }
        );
    }

    #[test]
    fn page_history_tail_then_older() {
        let tail = page_history(50, Some(10), None);
        assert_eq!(tail.start, 40);
        assert_eq!(tail.end, 50);
        assert!(tail.has_more);
        let items: Vec<usize> = (0..50).collect();
        assert_eq!(tail.slice(&items), &items[40..50]);

        let older = page_history(50, Some(10), Some(40));
        assert_eq!(older.start, 30);
        assert_eq!(older.end, 40);
        assert!(older.has_more);

        let first = page_history(50, Some(10), Some(10));
        assert_eq!(first.start, 0);
        assert_eq!(first.end, 10);
        assert!(!first.has_more);
    }

    #[test]
    fn page_history_clamps_limit_and_before() {
        let page = page_history(5, Some(0), None);
        assert_eq!(page.start, 4);
        assert_eq!(page.end, 5);
        let overflow = page_history(8, Some(10), Some(99));
        assert_eq!(overflow.start, 0);
        assert_eq!(overflow.end, 8);
        assert!(!overflow.has_more);
    }

    #[test]
    fn reset_clears_history_only() {
        let mut s = sample();
        s.memory = "mem".into();
        let prompt = s.system_prompt.clone();
        let next = reset_history(s);
        assert!(next.history.is_empty());
        assert_eq!(next.memory, "mem");
        assert_eq!(next.system_prompt, prompt);
    }

    #[test]
    fn apply_chat_append_from_capture_ignores_later_mutations() {
        let s = sample();
        let capture = PrepareCapture::from_snapshot(&s);
        // Simulate wrong-set pollution: live snapshot diverged after prepare.
        let mut live = s.clone();
        live.history = vec![("other".into(), "set".into())];

        let committed = apply_chat_append(&capture, "new", "resp").unwrap();
        assert_eq!(committed.history.len(), 4);
        assert_eq!(committed.history[0].0, "u1");
        assert_eq!(committed.history[3], ("new".into(), "resp".into()));
        assert_ne!(committed.history, live.history);
    }

    #[test]
    fn apply_regenerate_replaces_pair_keeps_later() {
        let s = sample();
        let capture = PrepareCapture::from_snapshot(&s).with_regenerate(1, "u2-edited");
        assert_eq!(capture.context_history_for_model().len(), 1);
        assert_eq!(capture.context_history_for_model()[0].0, "u1");
        // Original capture history still has 3 pairs (non-destructive).
        assert_eq!(capture.history.len(), 3);

        let next = apply_regenerate(&capture, "new-a2").unwrap();
        assert_eq!(next.history.len(), 3);
        assert_eq!(next.history[1], ("u2-edited".into(), "new-a2".into()));
        assert_eq!(next.history[2].0, "u3");
    }

    #[test]
    fn rename_and_memory_ops() {
        let s = sample();
        let s2 = update_memory(&s, "note").unwrap();
        assert_eq!(s2.memory, "note");
        let s3 = rename(&s2, "  project  ").unwrap();
        assert_eq!(s3.display_name, "project");
    }

    #[test]
    fn rejects_oversized_history_and_messages() {
        let mut s = sample();
        s.history = (0..MAX_HISTORY_PAIRS)
            .map(|i| (format!("u{i}"), format!("a{i}")))
            .collect();
        assert!(matches!(
            append_pair(&s, "more", "x"),
            Err(OpsError::HistoryTooLarge)
        ));

        let s = sample();
        let huge = "x".repeat(MAX_MESSAGE_CHARS + 1);
        assert!(matches!(
            append_pair(&s, &huge, "a"),
            Err(OpsError::MessageTooLarge)
        ));
        assert!(matches!(
            update_memory(&s, &"m".repeat(MAX_MEMORY_CHARS + 1)),
            Err(OpsError::MemoryTooLarge)
        ));
        assert!(matches!(
            rename(&s, &"n".repeat(MAX_DISPLAY_NAME_CHARS + 1)),
            Err(OpsError::DisplayNameTooLarge)
        ));
        assert!(matches!(rename(&s, "  "), Err(OpsError::EmptySetName)));
    }

    #[test]
    fn accepts_image_sized_user_messages_under_chat_body_cap() {
        let s = sample();
        // ~1.5 MiB JPEG-like data URL: accepted by the 5 MiB `/chat` body limit but
        // previously rejected by a 1M-char history max at finalize.
        let image_msg = format!(
            "what is this?\n[IMAGE:data:image/jpeg;base64,{}]",
            "A".repeat(1_500_000)
        );
        assert!(image_msg.chars().count() < MAX_MESSAGE_CHARS);
        assert!(image_msg.chars().count() > 1_000_000);

        let next = append_pair(&s, &image_msg, "I see a photo.").unwrap();
        assert_eq!(next.history.len(), 4);
        assert!(next.history[3].0.contains("[IMAGE:data:image/jpeg;base64,"));
        assert_eq!(next.history[3].1, "I see a photo.");

        let capture = PrepareCapture::from_snapshot(&s);
        let from_capture = apply_chat_append(&capture, &image_msg, "ok").unwrap();
        assert_eq!(from_capture.history.last().unwrap().0, image_msg);
    }

    #[test]
    fn apply_regenerate_at_len_appends_in_flight_turn() {
        let s = sample();
        let capture = PrepareCapture::from_snapshot(&s).with_regenerate(3, "u4-joined");
        assert_eq!(capture.history.len(), 3);
        let next = apply_regenerate(&capture, "a4").unwrap();
        assert_eq!(next.history.len(), 4);
        assert_eq!(next.history[3], ("u4-joined".into(), "a4".into()));
        assert_eq!(next.history[2].0, "u3");
    }

    #[test]
    fn apply_regenerate_without_index_appends() {
        let s = sample();
        let capture = PrepareCapture::from_snapshot(&s);
        // no insertion_index — treat as append
        let mut cap = capture;
        cap.replace_user_message = Some("new-u".into());
        let next = apply_regenerate(&cap, "new-a").unwrap();
        assert_eq!(next.history.len(), 4);
        assert_eq!(next.history[3], ("new-u".into(), "new-a".into()));
    }

    #[test]
    fn context_history_for_model_is_prefix_only() {
        let s = sample();
        let cap = PrepareCapture::from_snapshot(&s).with_regenerate(2, "u3");
        let ctx = cap.context_history_for_model();
        assert_eq!(ctx.len(), 2);
        assert_eq!(ctx[0].0, "u1");
        assert_eq!(ctx[1].0, "u2");
        // full capture history unchanged
        assert_eq!(cap.history.len(), 3);
    }
}
