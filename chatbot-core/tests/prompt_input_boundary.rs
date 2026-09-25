//! Boundary tests for prompt packing via borrowed [`PromptInput`].
//!
//! These exercise `prepare_prompt_messages` directly and check the wrapper
//! `prepare_chat_messages` only for delegation compatibility (provider
//! default resolution). Expectations describe observable message output.

use chatbot_core::chat::{
    ChatMessageRole, PromptInput, DEFAULT_CONTEXT_SIZE, prepare_chat_messages,
    prepare_prompt_messages,
};
use chatbot_core::chat_images::{count_images, fixture_jpeg_data_url};
use chatbot_core::config::ProviderConfig;
use chatbot_core::session::ChatContext;

fn test_provider(context_size: Option<u32>) -> ProviderConfig {
    ProviderConfig {
        privacy_level: chatbot_core::config::PrivacyLevel::default_destination(),
        search_privacy_level: chatbot_core::config::PrivacyLevel::default_destination(),
        provider_name: "default".into(),
        provider_type: "openai".into(),
        tier: None,
        model_name: "model".into(),
        context_size,
        base_url: "https://api".into(),
        api_key: Some("key".into()),
        allowed_providers: Vec::new(),
        request_timeout: None,
        rate_limit_retries: None,
        rate_limit_max_wait_secs: None,
        test_chunks: None,
        search: false,
        xai_search: true,
        xai_zdr: false,
    }
}

fn test_context(
    history: Vec<(String, String)>,
    memory: &str,
    system: &str,
    send_thoughts: bool,
    context_size: Option<u32>,
) -> ChatContext {
    ChatContext {
        session_id: "session-1".into(),
        username: Some("user".into()),
        set_name: "default".into(),
        set_id: None,
        set_version: None,
        memory_text: memory.to_owned(),
        system_prompt: system.to_owned(),
        history,
        encrypted: false,
        model_name: "test-model".into(),
        provider: test_provider(context_size),
        test_chunks: None,
        send_thoughts,
        prepare_capture: None,
    }
}

fn system_messages(prepared: &chatbot_core::chat::PreparedChatMessages) -> Vec<&str> {
    prepared
        .messages
        .iter()
        .filter(|m| matches!(m.role, ChatMessageRole::System))
        .map(|m| m.content.as_str())
        .collect()
}

#[test]
fn prompt_input_merges_system_and_memory_into_single_system_message() {
    let history = vec![("Hello".to_string(), "Hi".to_string())];
    let input = PromptInput {
        system_prompt: "You are helpful.",
        memory_text: "Remember this.",
        history: &history,
        send_thoughts: false,
        context_size: 8_192,
    };

    let prepared = prepare_prompt_messages(&input, "How are you?");

    // [system (prompt + memory), user (history), assistant (history), user (new)]
    assert_eq!(prepared.messages.len(), 4);
    let systems = system_messages(&prepared);
    assert_eq!(systems.len(), 1, "must send exactly one system message");
    assert!(systems[0].contains("You are helpful."));
    assert!(systems[0].contains("Remember this."));
    assert!(matches!(
        prepared.messages[1].role,
        ChatMessageRole::User
    ));
    assert!(matches!(
        prepared.messages[2].role,
        ChatMessageRole::Assistant
    ));
    assert_eq!(prepared.messages.last().unwrap().content, "How are you?");
}

#[test]
fn prompt_input_with_empty_memory_emits_bare_system_prompt() {
    let history = vec![("Hello".to_string(), "Hi".to_string())];
    let input = PromptInput {
        system_prompt: "You are helpful.",
        memory_text: "",
        history: &history,
        send_thoughts: false,
        context_size: 8_192,
    };

    let prepared = prepare_prompt_messages(&input, "How are you?");

    let systems = system_messages(&prepared);
    assert_eq!(systems.len(), 1, "must send exactly one system message");
    assert_eq!(systems[0], "You are helpful.");
}

#[test]
fn prompt_input_strips_think_tags_when_send_thoughts_disabled() {
    let history = vec![(
        "User".to_string(),
        "Hello<think>thought</think>World".to_string(),
    )];
    let input = PromptInput {
        system_prompt: "You are helpful.",
        memory_text: "",
        history: &history,
        send_thoughts: false,
        context_size: 8_192,
    };

    let prepared = prepare_prompt_messages(&input, "Next");

    assert_eq!(prepared.messages[2].content, "HelloWorld");
}

#[test]
fn prompt_input_keeps_think_tags_when_send_thoughts_enabled() {
    let history = vec![(
        "User".to_string(),
        "Hello<think>thought</think>World".to_string(),
    )];
    let input = PromptInput {
        system_prompt: "You are helpful.",
        memory_text: "",
        history: &history,
        send_thoughts: true,
        context_size: 8_192,
    };

    let prepared = prepare_prompt_messages(&input, "Next");

    assert_eq!(
        prepared.messages[2].content,
        "Hello<think>thought</think>World"
    );
}

#[test]
fn prompt_input_truncates_history_to_most_recent_under_small_budget() {
    let history = vec![
        ("u".repeat(1600), "v".repeat(1600)),
        ("new".repeat(400), "reply".repeat(400)),
    ];
    let input = PromptInput {
        system_prompt: "You are helpful.",
        memory_text: "",
        history: &history,
        send_thoughts: false,
        context_size: 600,
    };

    let prepared = prepare_prompt_messages(&input, "Next?");

    assert_eq!(prepared.original_history_pairs, 2);
    assert_eq!(prepared.truncated_history_pairs, 1);
    assert!(prepared.was_truncated());
    assert!(prepared.truncated_history[0].0.starts_with("new"));
    assert!(prepared.truncated_history[0].1.starts_with("reply"));
    assert!(prepared.original_history_tokens > prepared.truncated_history_tokens);
    // The new turn is never crowded out: still present verbatim at the end.
    assert_eq!(prepared.messages.last().unwrap().content, "Next?");

    // The compatibility wrapper with the same explicit size packs identically.
    let context = test_context(history, "", "You are helpful.", false, Some(600));
    let via_wrapper = prepare_chat_messages(&context, "Next?");
    assert_eq!(via_wrapper.messages, prepared.messages);
    assert_eq!(
        via_wrapper.truncated_history,
        prepared.truncated_history
    );
}

#[test]
fn prompt_input_keeps_new_image_full_while_history_thumbnails() {
    let payload = fixture_jpeg_data_url(400, 400);
    let tag = format!("[IMAGE:{payload}]");
    let history = vec![(format!("first {tag}"), "saw first".to_string())];
    let latest = format!("latest {tag}");
    let input = PromptInput {
        system_prompt: "You are helpful.",
        memory_text: "",
        history: &history,
        send_thoughts: false,
        context_size: 32_768,
    };

    let prepared = prepare_prompt_messages(&input, &latest);

    // New turn always appended at full fidelity, including its full-res image.
    let last = prepared.messages.last().unwrap();
    assert!(matches!(last.role, ChatMessageRole::User));
    assert_eq!(last.content, latest);
    assert_eq!(count_images(&last.content), 1);

    // Retained history keeps its image, thumbnailed to less than full payload.
    let prior_users: Vec<_> = prepared.messages[..prepared.messages.len() - 1]
        .iter()
        .filter(|m| matches!(m.role, ChatMessageRole::User))
        .collect();
    assert_eq!(prior_users.len(), 1);
    assert_eq!(count_images(&prior_users[0].content), 1);
    assert!(
        prior_users[0].content.len() < latest.len(),
        "older image should be thumbnailed ({} vs latest {})",
        prior_users[0].content.len(),
        latest.len()
    );
}

#[test]
fn wrapper_without_provider_size_packs_with_default_context_size() {
    // Two moderate pairs (~400 tokens each): they fit in the 8k default
    // budget but not in a 600-token window.
    let history = vec![
        ("a".repeat(800), "b".repeat(800)),
        ("c".repeat(800), "d".repeat(800)),
    ];
    let context = test_context(
        history.clone(),
        "Remember this.",
        "You are helpful.",
        false,
        None,
    );

    let via_wrapper = prepare_chat_messages(&context, "Next?");

    // Behaviorally: nothing truncated under the default budget.
    assert_eq!(via_wrapper.original_history_pairs, 2);
    assert_eq!(via_wrapper.truncated_history_pairs, 2);
    assert!(!via_wrapper.was_truncated());
    let systems = system_messages(&via_wrapper);
    assert_eq!(systems.len(), 1);
    assert!(systems[0].contains("Remember this."));
    assert_eq!(via_wrapper.messages.last().unwrap().content, "Next?");

    // Compatibility: the wrapper resolves a missing size to DEFAULT_CONTEXT_SIZE.
    let direct = prepare_prompt_messages(
        &PromptInput {
            system_prompt: "You are helpful.",
            memory_text: "Remember this.",
            history: &history,
            send_thoughts: false,
            context_size: DEFAULT_CONTEXT_SIZE,
        },
        "Next?",
    );
    assert_eq!(via_wrapper.messages, direct.messages);
    assert_eq!(via_wrapper.truncated_history, direct.truncated_history);

    // Sanity that the budget matters: the same content truncates at 600.
    let small = prepare_prompt_messages(
        &PromptInput {
            system_prompt: "You are helpful.",
            memory_text: "Remember this.",
            history: &history,
            send_thoughts: false,
            context_size: 600,
        },
        "Next?",
    );
    assert_eq!(small.truncated_history_pairs, 1);
    assert!(small.was_truncated());
}
