use crate::session::ChatContext;
use once_cell::sync::Lazy;
use regex::Regex;
use tracing::{debug, warn};

pub const SYSTEM_PROMPT_BUFFER: f64 = 0.2;
pub const DEFAULT_CONTEXT_SIZE: usize = 8_192;
const MIN_PARTIAL_HISTORY_TOKENS: f64 = 100.0;
const MEMORY_SNIPPET_CHAR_LIMIT: usize = 2_000;

static THINK_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?s)<think>.*?(?:</think>|\[BEGIN FINAL RESPONSE\])").expect("valid think regex"));

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChatMessageRole {
    System,
    User,
    Assistant,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChatMessage {
    pub role: ChatMessageRole,
    pub content: String,
}

impl ChatMessage {
    pub fn system(content: impl Into<String>) -> Self {
        Self {
            role: ChatMessageRole::System,
            content: content.into(),
        }
    }

    pub fn user(content: impl Into<String>) -> Self {
        Self {
            role: ChatMessageRole::User,
            content: content.into(),
        }
    }

    pub fn assistant(content: impl Into<String>) -> Self {
        Self {
            role: ChatMessageRole::Assistant,
            content: content.into(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct PreparedChatMessages {
    pub messages: Vec<ChatMessage>,
    pub truncated_history: Vec<(String, String)>,
    pub original_history_pairs: usize,
    pub truncated_history_pairs: usize,
    pub original_history_tokens: usize,
    pub truncated_history_tokens: usize,
}

impl PreparedChatMessages {
    pub fn was_truncated(&self) -> bool {
        self.truncated_history_pairs < self.original_history_pairs
    }
}

pub fn calculate_available_history_tokens(
    context_size: usize,
    system_prompt: &str,
    memory_text: &str,
) -> usize {
    let context_size_f = context_size as f64;
    let system_tokens = approximate_token_count(system_prompt);
    let memory_tokens = approximate_token_count(memory_text);
    let reserved = system_tokens + memory_tokens + (context_size_f * SYSTEM_PROMPT_BUFFER);
    let available = (context_size_f - reserved).floor();
    if available <= 0.0 {
        0
    } else {
        available as usize
    }
}

pub fn truncate_history(
    history: &[(String, String)],
    available_tokens: usize,
) -> Vec<(String, String)> {
    let mut truncated = Vec::new();
    let mut total_tokens = 0.0;
    let available = available_tokens as f64;

    for (user, assistant) in history.iter().rev() {
        let user_tokens = approximate_token_count(user);
        let assistant_tokens = approximate_token_count(assistant);
        let combined = user_tokens + assistant_tokens;

        if total_tokens + combined > available {
            let remaining = available - total_tokens;
            if remaining > MIN_PARTIAL_HISTORY_TOKENS {
                let limit = (remaining * 2.0).floor() as usize;
                truncated.push((take_chars(user, limit), take_chars(assistant, limit)));
            }
            break;
        }

        truncated.push((user.clone(), assistant.clone()));
        total_tokens += combined;
    }

    truncated.reverse();
    truncated
}

pub fn prepare_chat_messages(
    context: &ChatContext,
    new_user_message: &str,
) -> PreparedChatMessages {
    let context_size = context
        .provider
        .context_size
        .unwrap_or(DEFAULT_CONTEXT_SIZE as u32) as usize;
    let available_tokens = calculate_available_history_tokens(
        context_size,
        &context.system_prompt,
        &context.memory_text,
    );

    let history_processed: Vec<(String, String)> = if context.send_thoughts {
        context.history.clone()
    } else {
        context.history
            .iter()
            .map(|(u, a)| (u.clone(), strip_think_tags(a)))
            .collect()
    };

    let truncated_history = truncate_history(&history_processed, available_tokens);

    let original_pairs = context.history.len();
    let truncated_pairs = truncated_history.len();
    let original_tokens = approximate_history_tokens(&context.history);
    let truncated_tokens = approximate_history_tokens(&truncated_history);

    if truncated_pairs < original_pairs {
        warn!(
            original_pairs,
            truncated_pairs,
            original_tokens,
            truncated_tokens,
            "truncated chat history to fit context window"
        );
    }

    let mut messages = Vec::new();
    messages.push(ChatMessage::system(context.system_prompt.clone()));

    if !context.memory_text.trim().is_empty() {
        messages.push(ChatMessage::system(format!(
            "Memory:\n{}",
            memory_snippet(&context.memory_text)
        )));
    }

    for (user, assistant) in truncated_history.iter() {
        messages.push(ChatMessage::user(user.clone()));
        if !assistant.is_empty() {
            messages.push(ChatMessage::assistant(assistant.clone()));
        }
    }

    messages.push(ChatMessage::user(new_user_message.to_owned()));

    debug!(
        history_pairs = original_pairs,
        truncated_pairs = truncated_pairs,
        "prepared chat messages via Rust chat logic"
    );

    PreparedChatMessages {
        messages,
        truncated_history,
        original_history_pairs: original_pairs,
        truncated_history_pairs: truncated_pairs,
        original_history_tokens: original_tokens,
        truncated_history_tokens: truncated_tokens,
    }
}

pub fn strip_think_tags(content: &str) -> String {
    THINK_REGEX.replace_all(content, "").into_owned()
}

fn approximate_token_count(text: &str) -> f64 {
    text.len() as f64 / 4.0
}

fn approximate_history_tokens(history: &[(String, String)]) -> usize {
    history
        .iter()
        .map(|(user, assistant)| ((user.len() + assistant.len()) as f64 / 4.0).floor() as usize)
        .sum()
}

fn take_chars(text: &str, limit: usize) -> String {
    if limit == 0 {
        return String::new();
    }
    text.chars().take(limit).collect()
}

pub fn memory_snippet(memory: &str) -> String {
    memory.chars().take(MEMORY_SNIPPET_CHAR_LIMIT).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mock_context(history: Vec<(String, String)>, memory: &str) -> ChatContext {
        ChatContext {
            session_id: "session-1".into(),
            username: Some("user".into()),
            set_name: "default".into(),
            memory_text: memory.into(),
            system_prompt: "You are helpful.".into(),
            history,
            encrypted: false,
            model_name: "test-model".into(),
            provider: crate::config::ProviderConfig {
                provider_name: "default".into(),
                provider_type: "openai".into(),
                tier: None,
                model_name: "model".into(),
                context_size: Some(600),
                base_url: "https://api".into(),
                api_key: Some("key".into()),
                template: None,
                allowed_providers: Vec::new(),
                request_timeout: None,
                test_chunks: None,
            },
            encryption_key: None,
            test_chunks: None,
            send_thoughts: false,
        }
    }

    #[test]
    fn available_tokens_respects_buffer() {
        let available = calculate_available_history_tokens(1_000, "abcd", "efgh");
        assert_eq!(available, 798);
    }

    #[test]
    fn truncate_history_keeps_most_recent_entries() {
        let history = vec![
            ("u".repeat(1600), "v".repeat(1600)),
            ("new".repeat(400), "reply".repeat(400)),
        ];
        let truncated = truncate_history(&history, 300);
        assert_eq!(truncated.len(), 1);
        assert_eq!(truncated[0].0.len(), 600);
        assert_eq!(truncated[0].1.len(), 600);
        assert!(truncated[0].0.starts_with("new"));
        assert!(truncated[0].1.starts_with("reply"));
    }

    #[test]
    fn prepare_chat_messages_includes_memory_and_new_prompt() {
        let history = vec![("Hello".into(), "Hi".into())];
        let context = mock_context(history, "Remember this.");
        let prepared = prepare_chat_messages(&context, "How are you?");

        assert_eq!(prepared.messages.len(), 5);
        assert!(matches!(prepared.messages[0].role, ChatMessageRole::System));
        assert!(prepared.messages[1].content.starts_with("Memory:"));
        assert!(matches!(prepared.messages[2].role, ChatMessageRole::User));
        assert!(matches!(
            prepared.messages[3].role,
            ChatMessageRole::Assistant
        ));
        assert_eq!(prepared.messages.last().unwrap().content, "How are you?");
    }

    #[test]
    fn strip_think_tags_removes_sections() {
        let text = "Hello<think>secret</think>world";
        assert_eq!(strip_think_tags(text), "Helloworld");
    }

    #[test]
    fn strip_think_tags_removes_alt_sections() {
        let text = "Hello<think>secret[BEGIN FINAL RESPONSE]world";
        assert_eq!(strip_think_tags(text), "Helloworld");
    }

    #[test]
    fn strip_think_tags_removes_multiline() {
        let text = "Hello<think>\nsecret\n</think>world";
        assert_eq!(strip_think_tags(text), "Helloworld");
    }

    #[test]
    fn prepare_chat_messages_strips_thinking_when_disabled() {
        let history = vec![("User".into(), "Hello<think>thought</think>World".into())];
        let mut context = mock_context(history, "");
        context.send_thoughts = false;

        let prepared = prepare_chat_messages(&context, "Next");
        // User message is at index 1 (0 is system)
        // Assistant message is at index 2
        // Wait, mock_context adds system prompt.
        // messages[0] = system
        // messages[1] = user
        // messages[2] = assistant

        assert_eq!(prepared.messages[2].content, "HelloWorld");

        context.send_thoughts = true;
        let prepared_with_thoughts = prepare_chat_messages(&context, "Next");
        assert_eq!(prepared_with_thoughts.messages[2].content, "Hello<think>thought</think>World");
    }
}
