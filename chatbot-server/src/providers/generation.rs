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

/// Native XAI streaming when Brave setup fails, or a fail-closed privacy
/// error when native fallback is not permitted. Setup failures never
/// silently fall through to an unrestricted path.
fn fallback_or_restricted(
    xai_provider: &XaiProvider,
    messages: Vec<ChatMessagePayload>,
    web_search: bool,
    allow_native_search_fallback: bool,
) -> Result<Pin<Box<dyn Stream<Item = Result<String>> + Send + 'static>>> {
    if allow_native_search_fallback {
        xai_provider.stream_chat(messages, web_search)
    } else {
        Err(PrivacyRestrictedFallback.into())
    }
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
            let Some(brave) = brave else {
                return if use_brave && !allow_native_search_fallback {
                    Err(PrivacyRestrictedFallback.into())
                } else {
                    xai_provider.stream_chat(messages, web_search)
                };
            };

            // Use Brave search via XAI's OpenAI-compatible /chat/completions endpoint
            // through the same generation handle so owned fakes stay scoped.
            // Both error arms below are defensive: provider construction only
            // fails on HTTP client setup, and search errors surface when the
            // returned stream is polled, not here. The fallback decision
            // itself is pinned by the helper tests below.
            let openai_provider = match generation.openai_provider(provider_config) {
                Ok(provider) => provider,
                Err(err) => {
                    warn!(?err, "failed to build OpenAI provider for XAI Brave search");
                    return fallback_or_restricted(
                        xai_provider,
                        messages,
                        web_search,
                        allow_native_search_fallback,
                    );
                }
            };
            let tools = vec![crate::tools::brave_web_search_tool()];
            match crate::search::search_augmented_stream(
                &openai_provider,
                messages.clone(),
                &brave,
                &tools,
            )
            .await
            {
                Ok(stream) => Ok(stream),
                Err(err) => {
                    warn!(?err, "XAI Brave search setup failed");
                    fallback_or_restricted(
                        xai_provider,
                        messages,
                        web_search,
                        allow_native_search_fallback,
                    )
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use chatbot_core::config::PrivacyLevel;

    use super::*;

    fn xai_config_without_native_search() -> ProviderConfig {
        ProviderConfig {
            privacy_level: PrivacyLevel::default_destination(),
            provider_name: "xai".to_owned(),
            provider_type: "xai".to_owned(),
            tier: None,
            model_name: "grok-test".to_owned(),
            context_size: None,
            base_url: "http://127.0.0.1:1".to_owned(),
            api_key: None,
            allowed_providers: Vec::new(),
            request_timeout: None,
            rate_limit_retries: None,
            rate_limit_max_wait_secs: None,
            test_chunks: None,
            search: true,
            xai_search: false,
            xai_zdr: false,
        }
    }

    #[tokio::test]
    async fn xai_search_without_brave_key_and_without_fallback_is_fail_closed() {
        let config = xai_config_without_native_search();
        let generation = GenerationDeps::new(HashMap::new(), "xai".to_owned(), false, false, None);
        let provider = generation
            .xai_provider(&config)
            .expect("xai provider builds");
        let err = match dispatch_stream(
            &GenerationProvider::Xai(provider),
            &config,
            Vec::new(),
            true,
            false,
            &generation,
        )
        .await
        {
            Err(err) => err,
            Ok(_) => panic!("fail-closed without native fallback"),
        };
        assert!(err.downcast_ref::<PrivacyRestrictedFallback>().is_some());
    }

    fn xai_provider_for_helper() -> (ProviderConfig, GenerationDeps, GenerationProvider) {
        let config = xai_config_without_native_search();
        let generation =
            GenerationDeps::new(HashMap::new(), "xai".to_owned(), false, false, None);
        let provider = generation
            .xai_provider(&config)
            .expect("xai provider builds");
        (config, generation, GenerationProvider::Xai(provider))
    }

    #[test]
    fn fallback_helper_streams_natively_when_allowed() {
        let (_, _, provider) = xai_provider_for_helper();
        let GenerationProvider::Xai(xai) = provider else {
            panic!("expected xai provider");
        };
        // Stream construction is lazy: no network happens here.
        let stream = fallback_or_restricted(&xai, Vec::new(), true, true);
        assert!(stream.is_ok(), "allowed fallback must yield a stream");
    }

    #[test]
    fn fallback_helper_is_fail_closed_when_native_denied() {
        let (_, _, provider) = xai_provider_for_helper();
        let GenerationProvider::Xai(xai) = provider else {
            panic!("expected xai provider");
        };
        let err = match fallback_or_restricted(&xai, Vec::new(), true, false) {
            Err(err) => err,
            Ok(_) => panic!("denied fallback must not yield a stream"),
        };
        assert!(err.downcast_ref::<PrivacyRestrictedFallback>().is_some());
    }
}
