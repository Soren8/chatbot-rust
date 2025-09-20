use std::{pin::Pin, time::Duration};

use anyhow::{anyhow, Context, Result};
use async_stream::try_stream;
use futures_util::Stream;
use futures_util::StreamExt;
use reqwest::Client;
use serde::Serialize;
use serde_json::Value;

use chatbot_core::bridge::ProviderConfig;

use self::messages::ChatMessagePayload;
use self::payload::{ChatCompletionRequest, ProviderRoutingOptions};

pub mod messages {
    use serde::Serialize;

    #[derive(Serialize)]
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
        // be mutated in Python.
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
    ) -> Result<Pin<Box<dyn Stream<Item = Result<String>> + Send>>> {
        if let Some(ref chunks) = self.test_chunks {
            let chunks = chunks.clone();
            let stream = tokio_stream::iter(chunks.into_iter().map(Ok));
            return Ok(Box::pin(stream));
        }

        let api_key = self
            .api_key
            .as_ref()
            .ok_or_else(|| anyhow!("OpenAI API key is not configured"))?
            .clone();

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

            while let Some(chunk) = body_stream.next().await {
                let bytes = chunk.context("OpenAI stream read error")?;
                let piece = String::from_utf8_lossy(&bytes);
                buffer.push_str(&piece);

                let outcome = extract_sse_payloads(&mut buffer)?;
                for chunk in outcome.chunks {
                    yield chunk;
                }
                if outcome.done {
                    return;
                }
            }

            if !buffer.is_empty() {
                buffer.push('\n');
                let outcome = extract_sse_payloads(&mut buffer)?;
                for chunk in outcome.chunks {
                    yield chunk;
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

fn extract_sse_payloads(buffer: &mut String) -> Result<ExtractionOutcome> {
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
            if let Some(content) = value
                .get("choices")
                .and_then(|choices| choices.get(0))
                .and_then(|choice| choice.get("delta"))
                .and_then(|delta| delta.get("content"))
                .and_then(Value::as_str)
            {
                chunks.push(content.to_string());
            }
        } else {
            break;
        }
    }

    Ok(ExtractionOutcome { chunks, done })
}
