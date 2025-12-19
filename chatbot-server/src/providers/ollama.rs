use std::{pin::Pin, time::Duration};

use anyhow::{anyhow, Context, Result};
use async_stream::try_stream;
use futures_util::{Stream, StreamExt};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tracing::debug;

use chatbot_core::{
    chat::{self, PreparedChatMessages},
    config::ProviderConfig,
    session::ChatContext,
};

#[derive(Clone)]
pub struct OllamaChatRequest {
    pub system_prompt: String,
    pub prompt: String,
    pub context_size: u32,
}

pub struct OllamaProvider {
    client: Client,
    base_url: String,
    model: String,
    template: Option<String>,
    test_chunks: Option<Vec<String>>,
}

impl OllamaProvider {
    pub fn new(config: &ProviderConfig) -> Result<Self> {
        let timeout = Duration::from_secs_f64(config.request_timeout.unwrap_or(300.0));
        let client = Client::builder()
            .timeout(timeout)
            .build()
            .context("failed to build reqwest client")?;

        let mut test_chunks = config.test_chunks.clone();
        if test_chunks.is_none() {
            if let Ok(env_val) = std::env::var("CHATBOT_TEST_OLLAMA_CHUNKS") {
                if let Ok(parsed) = serde_json::from_str::<Vec<String>>(&env_val) {
                    test_chunks = Some(parsed);
                }
            }
        }

        Ok(Self {
            client,
            base_url: config.base_url.trim_end_matches('/').to_string(),
            model: config.model_name.clone(),
            template: config.template.clone().filter(|tpl| !tpl.trim().is_empty()),
            test_chunks,
        })
    }

    pub fn build_request(
        &self,
        context: &ChatContext,
        prepared: &PreparedChatMessages,
        new_user_message: &str,
    ) -> OllamaChatRequest {
        let mut prompt = String::new();
        prompt.push_str(&context.system_prompt);
        prompt.push_str("\n\n");

        let memory_snippet = chat::memory_snippet(&context.memory_text);
        if !memory_snippet.trim().is_empty() {
            prompt.push_str("### Memory:\n");
            prompt.push_str(memory_snippet.trim());
            prompt.push_str("\n\n");
        }

        for (user, assistant) in prepared.truncated_history.iter() {
            prompt.push_str("### User:\n");
            prompt.push_str(user);
            prompt.push_str("\n\n### Assistant:\n");
            prompt.push_str(assistant);
            prompt.push_str("\n\n");
        }

        prompt.push_str("### User:\n");
        prompt.push_str(new_user_message);
        prompt.push_str("\n\n### Assistant:\n");

        let context_size = context
            .provider
            .context_size
            .unwrap_or(chat::DEFAULT_CONTEXT_SIZE as u32);

        OllamaChatRequest {
            system_prompt: context.system_prompt.clone(),
            prompt,
            context_size,
        }
    }

    pub fn stream_chat(
        &self,
        request: OllamaChatRequest,
    ) -> Result<Pin<Box<dyn Stream<Item = Result<String>> + Send>>> {
        if let Some(ref chunks) = self.test_chunks {
            let stream = tokio_stream::iter(chunks.clone().into_iter().map(Ok));
            return Ok(Box::pin(stream));
        }

        let url = format!("{}/api/generate", self.base_url);
        let client = self.client.clone();

        #[derive(Serialize)]
        struct Options {
            #[serde(skip_serializing_if = "Option::is_none")]
            num_ctx: Option<u32>,
        }

        #[derive(Serialize)]
        struct RequestBody {
            model: String,
            prompt: String,
            #[serde(skip_serializing_if = "Option::is_none")]
            system: Option<String>,
            stream: bool,
            #[serde(skip_serializing_if = "Option::is_none")]
            template: Option<String>,
            #[serde(skip_serializing_if = "Option::is_none")]
            options: Option<Options>,
        }

        let payload = RequestBody {
            model: self.model.clone(),
            prompt: request.prompt.clone(),
            system: Some(request.system_prompt.clone()),
            stream: true,
            template: self.template.clone(),
            options: Some(Options {
                num_ctx: Some(request.context_size),
            }),
        };

        let stream = try_stream! {
            let response = client
                .post(&url)
                .json(&payload)
                .send()
                .await
                .context("failed to send Ollama request")?
                .error_for_status()
                .context("Ollama returned error status")?;

            let mut buffer = Vec::new();
            let mut body_stream = response.bytes_stream();

            while let Some(chunk) = body_stream.next().await {
                let bytes = chunk.context("Ollama stream read error")?;
                buffer.extend_from_slice(&bytes);

                while let Some(pos) = buffer.iter().position(|b| *b == b'\n') {
                    let line = buffer.drain(..=pos).collect::<Vec<_>>();
                    let line = std::str::from_utf8(&line)
                        .map_err(|err| anyhow!("invalid UTF-8 from Ollama: {err}"))?
                        .trim();

                    if line.is_empty() {
                        continue;
                    }

                    match parse_chunk(line)? {
                        ChunkOutcome::Continue(piece) => {
                            yield piece;
                        }
                        ChunkOutcome::Done(piece) => {
                            if let Some(piece) = piece {
                                yield piece;
                            }
                            debug!("Ollama stream marked done");
                            return;
                        }
                    }
                }
            }

            if !buffer.is_empty() {
                let line = std::str::from_utf8(&buffer)
                    .map_err(|err| anyhow!("invalid UTF-8 from Ollama: {err}"))?
                    .trim();
                if !line.is_empty() {
                    match parse_chunk(line)? {
                        ChunkOutcome::Continue(piece) => {
                            yield piece;
                        }
                        ChunkOutcome::Done(piece) => {
                            if let Some(piece) = piece {
                                yield piece;
                            }
                        }
                    }
                }
            }
        };

        Ok(Box::pin(stream))
    }
}

#[derive(Deserialize)]
struct OllamaStreamChunk {
    response: Option<String>,
    done: Option<bool>,
    error: Option<String>,
}

enum ChunkOutcome {
    Continue(String),
    Done(Option<String>),
}

fn parse_chunk(line: &str) -> Result<ChunkOutcome> {
    let chunk: OllamaStreamChunk = serde_json::from_str(line)
        .with_context(|| format!("failed to decode Ollama stream chunk: {line}"))?;

    if let Some(error) = chunk.error {
        return Err(anyhow!("Ollama error: {error}"));
    }

    let response = chunk.response.unwrap_or_default();
    if chunk.done.unwrap_or(false) {
        if response.is_empty() {
            Ok(ChunkOutcome::Done(None))
        } else {
            Ok(ChunkOutcome::Done(Some(response)))
        }
    } else {
        Ok(ChunkOutcome::Continue(response))
    }
}
