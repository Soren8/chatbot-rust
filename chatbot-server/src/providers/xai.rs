use std::{pin::Pin, time::Duration};

use anyhow::{Context, Result};
use async_stream::try_stream;
use futures_util::Stream;
use futures_util::StreamExt;
use reqwest::Client;
use serde::Serialize;
use serde_json::{json, Value};
use tracing::{debug, error};

use chatbot_core::config::ProviderConfig;
use crate::providers::openai::messages::ChatMessagePayload;

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolType {
    WebSearch,
}

#[derive(Serialize)]
pub struct Tool {
    #[serde(rename = "type")]
    pub tool_type: ToolType,
}

#[derive(Serialize)]
pub struct ResponseRequest {
    pub model: String,
    #[serde(rename = "input")]
    pub messages: Vec<Value>,
    pub tools: Vec<Tool>,
    pub stream: bool,
}

pub struct XaiProvider {
    client: Client,
    base_url: String,
    api_key: Option<String>,
    model: String,
}

impl XaiProvider {
    pub fn new(config: &ProviderConfig) -> Result<Self> {
        let timeout = Duration::from_secs_f64(config.request_timeout.unwrap_or(300.0));
        let client = Client::builder()
            .timeout(timeout)
            .build()
            .context("failed to build reqwest client")?;

        Ok(Self {
            client,
            base_url: config.base_url.clone(),
            api_key: config.api_key.clone(),
            model: config.model_name.clone(),
        })
    }

    pub fn stream_chat(
        &self,
        messages: Vec<ChatMessagePayload>,
        web_search_enabled: bool,
    ) -> Result<Pin<Box<dyn Stream<Item = Result<String>> + Send + 'static>>> {
        let api_key = if let Some(key) = &self.api_key {
            key.clone()
        } else {
            std::env::var("XAI_API_KEY").unwrap_or_else(|_| "no-key-required".to_string())
        };

        let mapped_messages: Vec<Value> = messages
            .into_iter()
            .map(|msg| {
                let role = match msg.role.as_str() {
                    "system" => "system",
                    "user" => "user",
                    "assistant" => "assistant",
                    _ => "user",
                };
                json!({
                    "role": role,
                    "content": msg.content
                })
            })
            .collect();

        // Only include tools if web search is enabled
        let tools = if web_search_enabled {
            vec![Tool { tool_type: ToolType::WebSearch }]
        } else {
            vec![]
        };

        let payload = ResponseRequest {
            model: self.model.clone(),
            messages: mapped_messages,
            tools,
            stream: true,
        };

        let body_json = serde_json::to_string(&payload).unwrap_or_default();
        debug!(body = %body_json, "sending xAI request");

        // Ensure base_url is correct. If it's missing or empty, default to https://api.x.ai/v1
        let base = if self.base_url.is_empty() {
            "https://api.x.ai/v1"
        } else {
            self.base_url.trim_end_matches('/')
        };
        
        let url = format!("{}/responses", base);
        let client = self.client.clone();

        let stream = try_stream! {
            let response = client
                .post(url)
                .bearer_auth(api_key)
                .json(&payload)
                .send()
                .await
                .context("failed to send xAI request")?;

            if response.status().is_success() {
                let mut buffer = String::new();
                let mut body_stream = response.bytes_stream();

                while let Some(chunk) = body_stream.next().await {
                    let bytes = chunk.context("xAI stream read error")?;
                    let piece = String::from_utf8_lossy(&bytes);
                    debug!(chunk = %piece, "xAI raw stream chunk");
                    buffer.push_str(&piece);

                    let outcome = extract_sse_payloads(&mut buffer)?;
                    for chunk in outcome.chunks {
                        yield chunk;
                    }
                    if outcome.done {
                        debug!("xAI SSE stream marked [DONE]");
                        return;
                    }
                }
            } else {
                let status = response.status();
                let text = response.text().await.unwrap_or_default();
                debug!(status = ?status, body = %text, "xAI API response payload");
                error!(status = ?status, body_preview = %text.chars().take(200).collect::<String>(), "xAI error response");
                Err(anyhow::anyhow!("xAI returned error: {} - {}", status, text))?;
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
                // If line starts with "event:", we can optionally log it, but the data line contains the type too.
                continue;
            }

            let data = line[5..].trim_start();
            if data == "[DONE]" {
                done = true;
                buffer.clear();
                break;
            }

            let value: Value = serde_json::from_str(data).context("failed to decode xAI stream chunk")?;

            // xAI Responses API structure
            if let Some(msg_type) = value.get("type").and_then(Value::as_str) {
                match msg_type {
                    "response.output_text.delta" => {
                        if let Some(delta) = value.get("delta").and_then(Value::as_str) {
                            if !delta.is_empty() {
                                chunks.push(delta.to_string());
                            }
                        }
                    }
                    "response.completed" => {
                        done = true;
                    }
                    "response.output_item.added" => {
                        if let Some(item) = value.get("item") {
                            if item.get("type").and_then(Value::as_str) == Some("web_search_call") {
                                if let Some(action) = item.get("action") {
                                    if let Some(query) = action.get("query").and_then(Value::as_str) {
                                        if !query.is_empty() {
                                            chunks.push(format!("<think>Searching for: {}...\n</think>", query));
                                        } else {
                                            chunks.push("<think>Starting web search...\n</think>".to_string());
                                        }
                                    }
                                }
                            }
                        }
                    }
                    "response.output_item.done" => {
                        if let Some(item) = value.get("item") {
                            if item.get("type").and_then(Value::as_str) == Some("web_search_call") {
                                if let Some(action) = item.get("action") {
                                    if let Some(url) = action.get("url").and_then(Value::as_str) {
                                        chunks.push(format!("<think>Found source: {}\n</think>", url));
                                    }
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }

            // Fallback to OpenAI standard structure (just in case they support both or mixed)
            let delta = value
                .get("choices")
                .and_then(|choices| choices.get(0))
                .and_then(|choice| choice.get("delta"));

            if let Some(delta) = delta {
                 if let Some(content) = delta.get("content").and_then(Value::as_str) {
                    if !content.is_empty() {
                        chunks.push(content.to_string());
                    }
                }
            }
        } else {
            break;
        }
    }

    Ok(ExtractionOutcome { chunks, done })
}