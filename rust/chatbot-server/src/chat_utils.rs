use chatbot_core::bridge::chat_release_lock;
use once_cell::sync::Lazy;
use regex::Regex;
use tracing::error;

pub struct ChatLockGuard {
    session_id: String,
    released: bool,
}

impl ChatLockGuard {
    pub fn new(session_id: String) -> Self {
        Self {
            session_id,
            released: false,
        }
    }

    pub fn mark_released(&mut self) {
        self.released = true;
    }

    pub fn release_if_needed(&mut self) {
        if !self.released {
            if let Err(err) = chat_release_lock(&self.session_id) {
                error!(?err, "failed to release chat lock");
            }
            self.released = true;
        }
    }
}

impl Drop for ChatLockGuard {
    fn drop(&mut self) {
        self.release_if_needed();
    }
}

pub const SYSTEM_PROMPT_BUFFER: f64 = 0.2;
pub const DEFAULT_CONTEXT_SIZE: usize = 8_192;

static THINK_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"<think>.*?</think>").expect("valid think regex"));

pub fn calculate_available_history_tokens(
    context_size: usize,
    system_prompt: &str,
    memory_text: &str,
) -> usize {
    let system_tokens = system_prompt.len() / 4;
    let memory_tokens = memory_text.len() / 4;
    let reserved =
        system_tokens + memory_tokens + ((context_size as f64 * SYSTEM_PROMPT_BUFFER) as usize);
    context_size.saturating_sub(reserved)
}

pub fn truncate_history(
    history: &[(String, String)],
    available_tokens: usize,
) -> Vec<(String, String)> {
    let mut truncated = Vec::new();
    let mut total_tokens = 0usize;

    for (user, assistant) in history.iter().rev() {
        let user_tokens = user.len() / 4;
        let assistant_tokens = assistant.len() / 4;
        let combined = user_tokens + assistant_tokens;

        if total_tokens + combined > available_tokens {
            let remaining = available_tokens.saturating_sub(total_tokens);
            if remaining > 100 {
                let limit = remaining * 2;
                let user_part = user.chars().take(limit).collect::<String>();
                let assistant_part = assistant.chars().take(limit).collect::<String>();
                truncated.push((user_part, assistant_part));
            }
            break;
        }

        truncated.push((user.clone(), assistant.clone()));
        total_tokens += combined;
    }

    truncated.reverse();
    truncated
}

pub fn strip_think_tags(content: &str) -> String {
    THINK_REGEX.replace_all(content, "").into_owned()
}
