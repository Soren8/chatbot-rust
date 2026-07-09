//! Pure snapshot transformations — no I/O, no crypto, no store access.
//!
//! All durable mutations should: load → pure op → CAS commit.

use super::types::{HistoryPair, PrepareCapture, SetSnapshot, SetVersion};

/// Errors from pure history operations (content/index validation only).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum OpsError {
    #[error("pair_index out of range")]
    PairIndexOutOfRange,
    #[error("content mismatch at pair_index")]
    ContentMismatch,
    #[error("empty user message")]
    EmptyUserMessage,
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
    let mut next = snapshot.clone();
    next.history
        .push((user_msg.to_owned(), assistant_msg.to_owned()));
    Ok(next)
}

/// Remove a history pair after verifying the user text matches.
pub fn delete_pair(
    snapshot: &SetSnapshot,
    pair_index: usize,
    expected_user_msg: &str,
) -> Result<SetSnapshot, OpsError> {
    if pair_index >= snapshot.history.len() {
        return Err(OpsError::PairIndexOutOfRange);
    }
    let (stored_user, _) = &snapshot.history[pair_index];
    if stored_user.trim() != expected_user_msg.trim() {
        return Err(OpsError::ContentMismatch);
    }
    let mut next = snapshot.clone();
    next.history.remove(pair_index);
    Ok(next)
}

/// Clear chat history; keep memory, prompt, name, flags.
pub fn reset_history(snapshot: &SetSnapshot) -> SetSnapshot {
    let mut next = snapshot.clone();
    next.history.clear();
    next
}

pub fn update_memory(snapshot: &SetSnapshot, memory: &str) -> SetSnapshot {
    let mut next = snapshot.clone();
    next.memory = memory.to_owned();
    next
}

pub fn update_system_prompt(snapshot: &SetSnapshot, prompt: &str) -> SetSnapshot {
    let mut next = snapshot.clone();
    next.system_prompt = prompt.to_owned();
    next
}

pub fn rename(snapshot: &SetSnapshot, new_name: &str) -> Result<SetSnapshot, OpsError> {
    let trimmed = new_name.trim();
    if trimmed.is_empty() {
        return Err(OpsError::EmptyUserMessage);
    }
    let mut next = snapshot.clone();
    next.display_name = trimmed.to_owned();
    Ok(next)
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

    let mut history = capture.history.clone();
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
                history.push(pair);
            }
            // Drop any pairs after the regenerated one? Product today keeps later pairs
            // (regenerate middle keeps future). Match existing regenerate_finalize insert behavior:
            // when prepare removed the pair, finalize inserted at index — later pairs stayed.
            // With non-destructive prepare, replacing at idx preserves later pairs. Good.
        }
        None => {
            // Treat as append (chat-style) if no index — unusual for regenerate.
            history.push(pair);
        }
    }

    Ok(SetSnapshot {
        set_id: capture.set_id,
        version: capture.version,
        display_name: capture.display_name.clone(),
        memory: capture.memory.clone(),
        system_prompt: capture.system_prompt.clone(),
        history,
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
    let mut history = capture.history.clone();
    history.push((user_msg.to_owned(), assistant_msg.to_owned()));
    Ok(SetSnapshot {
        set_id: capture.set_id,
        version: capture.version,
        display_name: capture.display_name.clone(),
        memory: capture.memory.clone(),
        system_prompt: capture.system_prompt.clone(),
        history,
        is_default: capture.is_default,
    })
}

/// Stamp a new version after a successful pure op (store layer also does this).
pub fn with_version(mut snapshot: SetSnapshot, version: SetVersion) -> SetSnapshot {
    snapshot.version = version;
    snapshot
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
    fn delete_pair_checks_content() {
        let s = sample();
        let next = delete_pair(&s, 1, "u2").unwrap();
        assert_eq!(next.history.len(), 2);
        assert_eq!(next.history[1].0, "u3");

        assert!(matches!(
            delete_pair(&s, 1, "wrong"),
            Err(OpsError::ContentMismatch)
        ));
        assert!(matches!(
            delete_pair(&s, 9, "u1"),
            Err(OpsError::PairIndexOutOfRange)
        ));
    }

    #[test]
    fn reset_clears_history_only() {
        let mut s = sample();
        s.memory = "mem".into();
        let next = reset_history(&s);
        assert!(next.history.is_empty());
        assert_eq!(next.memory, "mem");
        assert_eq!(next.system_prompt, s.system_prompt);
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
        let s2 = update_memory(&s, "note");
        assert_eq!(s2.memory, "note");
        let s3 = rename(&s2, "  project  ").unwrap();
        assert_eq!(s3.display_name, "project");
    }
}
