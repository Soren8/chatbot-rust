use std::{pin::Pin, time::Duration};

use anyhow::{Context, Result};
use async_stream::try_stream;
use futures_util::Stream;
use futures_util::StreamExt;
use reqwest::Client;
use serde_json::Value;
use tracing::debug;

use chatbot_core::config::ProviderConfig;

use self::messages::ChatMessagePayload;
use self::payload::{ChatCompletionRequest, ProviderRoutingOptions};

pub mod messages {
    use serde::Serialize;

    #[derive(Clone, Serialize)]
    pub struct ChatMessagePayload {
        pub role: String,
        pub content: String,
    }

    impl ChatMessagePayload {
        pub fn system(content: String) -> Self {
            Self {
                role: "system".to_string(),
                content,
            }
        }

        pub fn user(content: String) -> Self {
            Self {
                role: "user".to_string(),
                content,
            }
        }

        pub fn assistant(content: String) -> Self {
            Self {
                role: "assistant".to_string(),
                content,
            }
        }
    }
}

mod payload {
    use serde::Serialize;

    #[derive(Serialize)]
    pub struct ProviderRoutingOptions {
        pub order: Vec<String>,
        #[serde(default)]
        pub allow_fallbacks: bool,
    }

    #[derive(Serialize)]
    pub struct ChatCompletionRequest {
        pub model: String,
        pub messages: Vec<crate::providers::openai::messages::ChatMessagePayload>,
        pub stream: bool,
        pub temperature: f32,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub provider: Option<ProviderRoutingOptions>,
    }
}

pub struct OpenAiProvider {
    client: Client,
    base_url: String,
    api_key: Option<String>,
    model: String,
    allowed_providers: Vec<String>,
    test_chunks: Option<Vec<String>>,
}

impl OpenAiProvider {
    pub fn new(config: &ProviderConfig) -> Result<Self> {
        let timeout = Duration::from_secs_f64(config.request_timeout.unwrap_or(300.0));
        let client = Client::builder()
            .timeout(timeout)
            .build()
            .context("failed to build reqwest client")?;

        // If the provider-level config does not include test chunks, allow overriding
        // via the `CHATBOT_TEST_OPENAI_CHUNKS` environment variable so tests can
        // stub out network calls without requiring the provider configuration to
        // be mutated.
        let mut test_chunks = config.test_chunks.clone();
        if test_chunks.is_none() {
            if let Ok(env_val) = std::env::var("CHATBOT_TEST_OPENAI_CHUNKS") {
                if let Ok(parsed) = serde_json::from_str::<Vec<String>>(&env_val) {
                    test_chunks = Some(parsed);
                }
            }
        }

        Ok(Self {
            client,
            base_url: config.base_url.clone(),
            api_key: config.api_key.clone(),
            model: config.model_name.clone(),
            allowed_providers: config.allowed_providers.clone(),
            test_chunks,
        })
    }

    pub fn stream_chat(
        &self,
        messages: Vec<ChatMessagePayload>,
    ) -> Result<Pin<Box<dyn Stream<Item = Result<String>> + Send + 'static>>> {
        if let Some(ref chunks) = self.test_chunks {
            let chunks = chunks.clone();
            let stream = tokio_stream::iter(chunks.into_iter().map(Ok));
            return Ok(Box::pin(stream));
        }

        let mut is_implicit_model = self.model.contains("nemotron-3-nano-30b-a3b")
            || self.model.contains("apriel-1.6-15b-thinker");
        let api_key = self
            .api_key
            .as_deref()
            .unwrap_or("no-key-required")
            .to_string();

        let provider = if self.allowed_providers.is_empty() {
            None
        } else {
            Some(ProviderRoutingOptions {
                order: self.allowed_providers.clone(),
                allow_fallbacks: false,
            })
        };

        let payload = ChatCompletionRequest {
            model: self.model.clone(),
            messages,
            stream: true,
            temperature: 0.7,
            provider,
        };

        let url = format!("{}/chat/completions", self.base_url.trim_end_matches('/'));
        let client = self.client.clone();

        let stream = try_stream! {
            let response = client
                .post(url)
                .bearer_auth(api_key)
                .json(&payload)
                .send()
                .await
                .context("failed to send OpenAI request")?
                .error_for_status()
                .context("OpenAI returned error status")?;

            let mut buffer = String::new();
            let mut body_stream = response.bytes_stream();

            let mut currently_thinking = false;
            let mut has_sent_any_content = false;

            while let Some(chunk) = body_stream.next().await {
                let bytes = chunk.context("OpenAI stream read error")?;
                let piece = String::from_utf8_lossy(&bytes);
                buffer.push_str(&piece);

                let outcome = extract_sse_payloads(
                    &mut buffer,
                    &mut currently_thinking,
                    &mut has_sent_any_content,
                    &mut is_implicit_model,
                )?;
                for chunk in outcome.chunks {
                    yield chunk;
                }
                if outcome.done {
                    if currently_thinking && !is_implicit_model {
                        yield "</think>".to_string();
                    }
                    debug!("OpenAI SSE stream marked [DONE]");
                    return;
                }
            }

            if !buffer.is_empty() {
                buffer.push('\n');
                let outcome = extract_sse_payloads(
                    &mut buffer,
                    &mut currently_thinking,
                    &mut has_sent_any_content,
                    &mut is_implicit_model,
                )?;
                for chunk in outcome.chunks {
                    yield chunk;
                }
                if currently_thinking && !is_implicit_model {
                    yield "</think>".to_string();
                }
            }
        };

        Ok(Box::pin(stream))
    }
}

struct ExtractionOutcome {
    chunks: Vec<String>,
    done: bool,
}

fn extract_sse_payloads(
    buffer: &mut String,
    currently_thinking: &mut bool,
    has_sent_any_content: &mut bool,
    is_implicit_model: &mut bool,
) -> Result<ExtractionOutcome> {
    let mut chunks = Vec::new();
    let mut done = false;

    loop {
        if let Some(pos) = buffer.find('\n') {
            let mut line = buffer[..pos].to_string();
            buffer.drain(..=pos);
            if line.ends_with('\r') {
                line.pop();
            }
            if line.is_empty() || !line.starts_with("data:") {
                continue;
            }

            let data = line[5..].trim_start();
            if data == "[DONE]" {
                done = true;
                buffer.clear();
                break;
            }

            let value: Value =
                serde_json::from_str(data).context("failed to decode OpenAI stream chunk")?;

            let model_response = value.get("model").and_then(Value::as_str).unwrap_or("");
            if !*is_implicit_model
                && (model_response.contains("nemotron-3-nano-30b-a3b")
                    || model_response.contains("apriel-1.6-15b-thinker"))
            {
                *is_implicit_model = true;
            }

            if *is_implicit_model && !*has_sent_any_content && !*currently_thinking {
                chunks.push("<think>".to_string());
                *currently_thinking = true;
            }

            let delta = value
                .get("choices")
                .and_then(|choices| choices.get(0))
                .and_then(|choice| choice.get("delta"));

            if let Some(delta) = delta {
                if let Some(reasoning) = delta
                    .get("reasoning_content")
                    .or_else(|| delta.get("reasoning"))
                    .and_then(Value::as_str)
                {
                    if !*currently_thinking {
                        chunks.push("<think>".to_string());
                        *currently_thinking = true;
                    }
                    if !reasoning.is_empty() {
                        chunks.push(reasoning.to_string());
                        *has_sent_any_content = true;
                    }
                }
                
                if let Some(content) = delta.get("content").and_then(Value::as_str) {
                    if *currently_thinking && !*is_implicit_model {
                        chunks.push("</think>".to_string());
                        *currently_thinking = false;
                    }
                    if !content.is_empty() {
                        chunks.push(content.to_string());
                        *has_sent_any_content = true;
                    }
                }
            }
        } else {
            break;
        }
    }

    Ok(ExtractionOutcome { chunks, done })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_openai_extract_sse_payloads_with_both_reasoning_and_content() {
        let mut buffer = String::new();
        let mut currently_thinking = false;
        let mut has_sent_any_content = false;
        let mut is_implicit_model = false;

        // Simulate a chunk that contains BOTH reasoning_content (transitioning out?) and content.
        // This simulates the race condition where both fields arrive in the same JSON delta.
        let json = serde_json::json!({
            "choices": [{
                "delta": {
                    "reasoning_content": "final thought",
                    "content": "Hello"
                }
            }]
        });
        
        buffer.push_str(&format!("data: {}\n\n", json.to_string()));

        let outcome = extract_sse_payloads(
            &mut buffer,
            &mut currently_thinking,
            &mut has_sent_any_content,
            &mut is_implicit_model,
        ).unwrap();

        // We expect:
        // 1. <think> (since we weren't thinking)
        // 2. "final thought"
        // 3. </think> (transition to content)
        // 4. "Hello"
        
        // With the bug, "Hello" (and </think>) will be missing because 'else if' prevents the second block from running.
        
        let combined = outcome.chunks.join("");
        assert!(combined.contains("final thought"), "Should contain reasoning");
        assert!(combined.contains("Hello"), "Should contain content but got: {}", combined);
    }
}
