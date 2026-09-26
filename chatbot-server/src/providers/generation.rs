//! Shared generation dispatch.
//!
//! Both `/chat` and `/regenerate` construct the same closed provider set,
//! map core messages through the shared message DTO, and apply the
//! same search gating. Request validation, saved-turn rendering with
//! append-versus-replace semantics, stream guards and finalizers stay in the
//! handlers.

use std::{fmt, pin::Pin};

use anyhow::Result;
use chatbot_core::{
    chat::{ChatMessage, ChatMessageRole},
    config::ProviderConfig,
};
use futures_util::Stream;
use tracing::{error, warn};

use crate::generation_deps::GenerationDeps;
use crate::providers::message_utils::parse_message_content;
use crate::providers::messages::ChatMessagePayload;
use crate::providers::openai::OpenAiProvider;
use crate::providers::xai::XaiProvider;

/// Closed generation backend.
pub enum GenerationProvider {
    OpenAi(OpenAiProvider),
    Xai(XaiProvider),
}

#[derive(Debug)]
pub struct PrivacyRestrictedFallback;

impl fmt::Display for PrivacyRestrictedFallback {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("privacy policy forbids native search fallback")
    }
}

impl std::error::Error for PrivacyRestrictedFallback {}

/// Construct the concrete provider for `provider_type` (`"openai"` | `"xai"`).
///
/// Compatibility wrapper: constructs through the live globals with the
/// original env timing. Injected routers must use
/// [`build_provider_with_generation`] with their own handle instead.
///
/// Callers own lock release and saved-turn rendering. Call after session
/// preparation, before message mapping.
pub fn build_provider(
    provider_type: &str,
    provider_config: &ProviderConfig,
) -> Result<GenerationProvider> {
    build_provider_with_generation(
        provider_type,
        provider_config,
        &GenerationDeps::global(),
    )
}

/// Scoped variant: constructs through the router's [`GenerationDeps`] so
/// fake stream/search inputs resolve in that router only. The global handle
/// keeps the original `new` timing; owned handles use only explicit fakes
/// with no env reads.
pub fn build_provider_with_generation(
    provider_type: &str,
    provider_config: &ProviderConfig,
    generation: &GenerationDeps,
) -> Result<GenerationProvider> {
    match provider_type {
        "openai" => match generation.openai_provider(provider_config) {
            Ok(provider) => Ok(GenerationProvider::OpenAi(provider)),
            Err(err) => {
                error!(?err, "failed to construct OpenAI provider");
                Err(err)
            }
        },
        "xai" => match generation.xai_provider(provider_config) {
            Ok(provider) => Ok(GenerationProvider::Xai(provider)),
            Err(err) => {
                error!(?err, "failed to construct XAI provider");
                Err(err)
            }
        },
        _ => unreachable!("provider_type should be filtered earlier"),
    }
}

/// Map core chat messages to the shared OpenAI-compatible payload.
pub fn map_core_messages(messages: &[ChatMessage]) -> Vec<ChatMessagePayload> {
    messages
        .iter()
        .map(|message| match message.role {
            ChatMessageRole::System => ChatMessagePayload::system(message.content.clone()),
            ChatMessageRole::User => {
                let content = parse_message_content(&message.content);
                ChatMessagePayload::user_with_content(content)
            }
            ChatMessageRole::Assistant => ChatMessagePayload::assistant(message.content.clone()),
        })
        .collect()
}

/// Open the provider stream with shared search policy.
///
/// OpenAI uses Brave search when `web_search` is set and a client exists.
/// XAI uses Brave only when `web_search` is set and `xai_search` is off, via
/// the OpenAI-compatible search path, then falls back to native streaming on
/// setup errors only.
///
/// The generation handle supplies the Brave client only in the same gated
/// branches as before; no key or env read happens outside them.
pub async fn dispatch_stream(
    provider: &GenerationProvider,
    provider_config: &ProviderConfig,
    messages: Vec<ChatMessagePayload>,
    web_search: bool,
    allow_native_search_fallback: bool,
    generation: &GenerationDeps,
) -> Result<Pin<Box<dyn Stream<Item = Result<String>> + Send + 'static>>> {
    match provider {
        GenerationProvider::OpenAi(openai_provider) => {
            let brave = if web_search {
                generation.brave_client()
            } else {
                None
            };

            if let Some(ref brave) = brave {
                let tools = vec![crate::tools::brave_web_search_tool()];
                match crate::search::search_augmented_stream(
                    openai_provider,
                    messages.clone(),
                    brave,
                    &tools,
                )
                .await
                {
                    Ok(stream) => Ok(stream),
                    Err(err) => {
                        warn!(?err, "search augmentation failed, falling back to regular streaming");
                        openai_provider.stream_chat(messages.clone())
                    }
                }
            } else {
                openai_provider.stream_chat(messages.clone())
            }
        }
        GenerationProvider::Xai(xai_provider) => {
            let use_brave = web_search && !provider_config.xai_search;
            let brave = if use_brave {
                generation.brave_client()
            } else {
                None
            };

            if let Some(ref brave) = brave {
                // Use Brave search via XAI's OpenAI-compatible /chat/completions endpoint
                // through the same generation handle so owned fakes stay scoped.
                match generation.openai_provider(provider_config) {
                    Ok(openai_provider) => {
                        let tools = vec![crate::tools::brave_web_search_tool()];
                        match crate::search::search_augmented_stream(
                            &openai_provider,
                            messages.clone(),
                            brave,
                            &tools,
                        )
                        .await
                        {
                            Ok(stream) => Ok(stream),
                            Err(err) => {
                                warn!(?err, "XAI Brave search setup failed");
                                if allow_native_search_fallback {
                                    xai_provider.stream_chat(messages.clone(), web_search)
                                } else {
                                    Err(PrivacyRestrictedFallback.into())
                                }
                            }
                        }
                    }
                    Err(err) => {
                        warn!(?err, "failed to build OpenAI provider for XAI Brave search");
                        if allow_native_search_fallback {
                            xai_provider.stream_chat(messages.clone(), web_search)
                        } else {
                            Err(PrivacyRestrictedFallback.into())
                        }
                    }
                }
            } else if web_search && !provider_config.xai_search && !allow_native_search_fallback {
                Err(PrivacyRestrictedFallback.into())
            } else {
                xai_provider.stream_chat(messages.clone(), web_search)
            }
        }
    }
}
