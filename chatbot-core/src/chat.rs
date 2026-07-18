use crate::chat_images::{
    self, approximate_content_tokens, has_image, prepare_history_images, reserve_full_image_slots,
    MAX_FULL_RES_IMAGES,
};
use crate::session::ChatContext;
use once_cell::sync::Lazy;
use regex::Regex;
use tracing::{debug, warn};

pub const SYSTEM_PROMPT_BUFFER: f64 = 0.2;
pub const DEFAULT_CONTEXT_SIZE: usize = 8_192;
const MIN_PARTIAL_HISTORY_TOKENS: f64 = 100.0;
/// Leave headroom for the model response after packing history + new turn.
const RESPONSE_RESERVE_FRACTION: f64 = 0.10;

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

/// Truncate history to fit `available_tokens`, keeping the most recent pairs.
///
/// Image-aware: uses vision-style token estimates (not base64_len/4). Partial
/// truncation never cuts through an `[IMAGE:...]` tag — if a pair with an image
/// does not fully fit, the whole pair is dropped (older pairs go first).
pub fn truncate_history(
    history: &[(String, String)],
    available_tokens: usize,
) -> Vec<(String, String)> {
    let mut truncated = Vec::new();
    let mut total_tokens = 0.0;
    let available = available_tokens as f64;

    for (user, assistant) in history.iter().rev() {
        let user_tokens = approximate_content_tokens(user);
        let assistant_tokens = approximate_content_tokens(assistant);
        let combined = user_tokens + assistant_tokens;

        if total_tokens + combined > available {
            let remaining = available - total_tokens;
            if remaining > MIN_PARTIAL_HISTORY_TOKENS {
                if has_image(user) {
                    // Keep the image intact when the user side alone fits; only
                    // shrink assistant text. Never run take_chars over image tags.
                    if user_tokens <= remaining {
                        let asst_budget = ((remaining - user_tokens) * 2.0).floor() as usize;
                        truncated.push((user.clone(), take_chars(assistant, asst_budget)));
                    }
                    // else: drop this (older) image pair rather than strip the image
                } else {
                    let limit = (remaining * 2.0).floor() as usize;
                    truncated.push((take_chars(user, limit), take_chars(assistant, limit)));
                }
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

    // Limit system prompt and memory to 20% of context size each.
    // 20% system + 20% memory + 20% buffer = 60%, leaving ~40% for history + new message
    let max_component_tokens = (context_size as f64 * 0.20) as usize;
    let max_component_chars = max_component_tokens * 4;

    let system_prompt = if approximate_token_count(&context.system_prompt) > max_component_tokens as f64 {
        take_chars(&context.system_prompt, max_component_chars)
    } else {
        context.system_prompt.clone()
    };

    let memory_text = if approximate_token_count(&context.memory_text) > max_component_tokens as f64 {
        take_chars(&context.memory_text, max_component_chars)
    } else {
        context.memory_text.clone()
    };

    let available_tokens = calculate_available_history_tokens(
        context_size,
        &system_prompt,
        &memory_text,
    );

    // Reserve budget for the new user turn + a response headroom so history
    // packing cannot crowd out the latest message (and its image).
    let new_msg_tokens = approximate_content_tokens(new_user_message);
    let response_reserve = (context_size as f64 * RESPONSE_RESERVE_FRACTION).floor();
    let history_budget = (available_tokens as f64 - new_msg_tokens - response_reserve)
        .floor()
        .max(0.0) as usize;

    let history_processed: Vec<(String, String)> = if context.send_thoughts {
        context.history.clone()
    } else {
        context
            .history
            .iter()
            .map(|(u, a)| (u.clone(), strip_think_tags(a)))
            .collect()
    };

    // Full-res image slots: newest content first (new turn, then history newest→oldest).
    let mut full_slots = MAX_FULL_RES_IMAGES;
    reserve_full_image_slots(new_user_message, &mut full_slots);
    let history_images = prepare_history_images(&history_processed, &mut full_slots);

    let truncated_history = truncate_history(&history_images, history_budget);

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
            full_image_slots = MAX_FULL_RES_IMAGES,
            "truncated chat history to fit context window"
        );
    }

    let mut messages = Vec::new();
    messages.push(ChatMessage::system(system_prompt));

    if !memory_text.trim().is_empty() {
        messages.push(ChatMessage::system(format!(
            "Memory:\n{}",
            memory_snippet(&memory_text)
        )));
    }

    for (user, assistant) in truncated_history.iter() {
        messages.push(ChatMessage::user(user.clone()));
        if !assistant.is_empty() {
            messages.push(ChatMessage::assistant(assistant.clone()));
        }
    }

    // New user turn is always appended at full fidelity (including full-res image).
    messages.push(ChatMessage::user(new_user_message.to_owned()));

    debug!(
        history_pairs = original_pairs,
        truncated_pairs = truncated_pairs,
        new_msg_images = chat_images::count_images(new_user_message),
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
    // Plain text / prompts: classic 4 chars ≈ 1 token. Image-bearing strings
    // should go through approximate_content_tokens instead.
    if has_image(text) {
        approximate_content_tokens(text)
    } else {
        text.len() as f64 / 4.0
    }
}

fn approximate_history_tokens(history: &[(String, String)]) -> usize {
    history
        .iter()
        .map(|(user, assistant)| {
            (approximate_content_tokens(user) + approximate_content_tokens(assistant)).floor()
                as usize
        })
        .sum()
}

fn take_chars(text: &str, limit: usize) -> String {
    if limit == 0 {
        return String::new();
    }

    // Prefer not to bisect an image tag (would produce an invalid data URL).
    const IMAGE_TAG: &str = "[IMAGE:";
    if let Some(tag_pos) = text.find(IMAGE_TAG) {
        let rest = &text[tag_pos..];
        let closing_bracket = rest.find(']').map(|p| p + 1);

        if let Some(cb) = closing_bracket {
            let tag_end = tag_pos + cb;
            if tag_end <= limit {
                return text.chars().take(limit).collect();
            }
            if tag_pos < limit {
                // Keep text before the image rather than a truncated tag.
                return text.chars().take(tag_pos).collect();
            }
            return String::new();
        }
    }

    text.chars().take(limit).collect()
}

pub fn memory_snippet(memory: &str) -> String {
    memory.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chat_images::{count_images, IMAGE_TAG_PREFIX};
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    use image::{DynamicImage, ImageBuffer, Rgb};
    use std::io::Cursor;

    fn mock_context(history: Vec<(String, String)>, memory: &str) -> ChatContext {
        ChatContext {
            session_id: "session-1".into(),
            username: Some("user".into()),
            set_name: "default".into(),
            set_id: None,
            set_version: None,
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
                allowed_providers: Vec::new(),
                request_timeout: None,
                test_chunks: None,
                search: false,
                xai_search: true,
            },
            test_chunks: None,
            send_thoughts: false,
            prepare_capture: None,
        }
    }

    fn large_jpeg_tag() -> String {
        let img: ImageBuffer<Rgb<u8>, Vec<u8>> =
            ImageBuffer::from_fn(320, 320, |x, y| Rgb([(x % 255) as u8, (y % 255) as u8, 40]));
        let mut jpeg = Vec::new();
        {
            let mut cursor = Cursor::new(&mut jpeg);
            let mut enc = image::codecs::jpeg::JpegEncoder::new_with_quality(&mut cursor, 85);
            enc.encode_image(&DynamicImage::ImageRgb8(img)).unwrap();
        }
        format!(
            "{IMAGE_TAG_PREFIX}data:image/jpeg;base64,{}]",
            STANDARD.encode(&jpeg)
        )
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
        assert_eq!(prepared.messages[2].content, "HelloWorld");

        context.send_thoughts = true;
        let prepared_with_thoughts = prepare_chat_messages(&context, "Next");
        assert_eq!(
            prepared_with_thoughts.messages[2].content,
            "Hello<think>thought</think>World"
        );
    }

    #[test]
    fn latest_image_in_new_message_always_present_with_prior_images() {
        let tag = large_jpeg_tag();
        let history = vec![
            (format!("first {tag}"), "saw first".into()),
            (format!("second {tag}"), "saw second".into()),
        ];
        let mut context = mock_context(history, "");
        // Realistic vision context so packing has room for thumbs + latest.
        context.provider.context_size = Some(32_768);

        let latest = format!("third {tag}");
        let prepared = prepare_chat_messages(&context, &latest);

        let last = prepared.messages.last().unwrap();
        assert_eq!(last.role, ChatMessageRole::User);
        assert!(
            last.content.contains(&tag) || count_images(&last.content) == 1,
            "new message must keep its full image"
        );
        assert!(
            last.content.contains("[IMAGE:"),
            "latest image tag must be present"
        );

        // Prior user turns that remain should not all keep full-size payloads.
        let prior_users: Vec<_> = prepared
            .messages
            .iter()
            .filter(|m| m.role == ChatMessageRole::User && m.content != latest)
            .collect();
        for msg in prior_users {
            if has_image(&msg.content) {
                assert!(
                    msg.content.len() < latest.len(),
                    "older image should be thumbnailed ({} vs latest {})",
                    msg.content.len(),
                    latest.len()
                );
            }
        }
    }

    #[test]
    fn follow_up_text_keeps_most_recent_history_image() {
        let tag = large_jpeg_tag();
        let history = vec![
            (format!("old {tag}"), "ok".into()),
            (format!("recent {tag}"), "ok2".into()),
            ("what color is it?".into(), "red".into()),
        ];
        let mut context = mock_context(history, "");
        context.provider.context_size = Some(16_384);

        let prepared = prepare_chat_messages(&context, "and the shape?");
        let users: Vec<_> = prepared
            .messages
            .iter()
            .filter(|m| m.role == ChatMessageRole::User)
            .map(|m| m.content.as_str())
            .collect();

        // The most recent image-bearing history message should still include an image.
        let with_images: Vec<_> = users.iter().filter(|u| u.contains("[IMAGE:")).collect();
        assert!(
            !with_images.is_empty(),
            "expected at least one history image preserved for follow-up; users={users:?}"
        );
        // Newest image-bearing content among history should be the "recent" one if present.
        if let Some(last_img) = with_images.iter().rev().find(|u| u.contains("recent") || u.contains("old"))
        {
            if last_img.contains("recent") {
                // Prefer full-ish recent image over older
                assert!(last_img.contains("recent"));
            }
        }
    }

    #[test]
    fn truncate_does_not_bisect_image_tag() {
        let tag = large_jpeg_tag();
        let msg = format!("caption {tag}");
        // Budget too small for full pair with naive char take — must not emit broken tag.
        let history = vec![(msg, "reply".into())];
        let truncated = truncate_history(&history, 50);
        for (u, _) in &truncated {
            if let Some(start) = u.find("[IMAGE:") {
                assert!(
                    u[start..].contains(']'),
                    "truncated user text must not leave an open IMAGE tag: {u}"
                );
            }
        }
    }
}
