use std::{pin::Pin, time::Duration};

use anyhow::{Context, Result};
use async_stream::try_stream;
use futures_util::Stream;
use futures_util::StreamExt;
use reqwest::Client;
use serde::Serialize;
use serde_json::{json, Value};
use tracing::{debug, error, warn};

use chatbot_core::config::ProviderConfig;
use crate::providers::messages::{ChatMessageContent, ChatMessagePayload, ContentPart};

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
    /// When `Some(false)`, disable Responses API server-side retention of this
    /// request/response (see xAI `store` on `/v1/responses`). Omitted when ZDR
    /// is not requested so the API default applies.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub store: Option<bool>,
}

pub struct XaiProvider {
    client: Client,
    base_url: String,
    api_key: Option<String>,
    model: String,
    /// When true, send `store: false` and expect team ZDR (`x-zero-data-retention`).
    xai_zdr: bool,
    /// Owned key fallback. `None` means live: read `XAI_API_KEY` at stream
    /// time. `Some` means owned: use the explicit key (or `"no-key-required"`
    /// when `None`) with no env read.
    fake_key: Option<Option<String>>,
}

impl XaiProvider {
    pub fn new(config: &ProviderConfig) -> Result<Self> {
        Self::with_fake_key(config, None)
    }

    /// Owned construction with an explicit key fallback and no env reads.
    /// Live routers keep using [`XaiProvider::new`].
    pub fn new_owned(config: &ProviderConfig, fake_key: Option<String>) -> Result<Self> {
        Self::with_fake_key(config, Some(fake_key))
    }

    fn with_fake_key(config: &ProviderConfig, fake_key: Option<Option<String>>) -> Result<Self> {
        let timeout = Duration::from_secs_f64(config.request_timeout.unwrap_or(300.0));
        let client = super::shared_client(timeout)?;

        Ok(Self {
            client,
            base_url: config.base_url.clone(),
            api_key: config.api_key.clone(),
            model: config.model_name.clone(),
            xai_zdr: config.xai_zdr,
            fake_key,
        })
    }

    fn resolve_api_key(&self) -> String {
        if let Some(key) = &self.api_key {
            return key.clone();
        }
        match &self.fake_key {
            Some(fake) => fake
                .clone()
                .unwrap_or_else(|| "no-key-required".to_string()),
            None => {
                std::env::var("XAI_API_KEY").unwrap_or_else(|_| "no-key-required".to_string())
            }
        }
    }

    pub fn stream_chat(
        &self,
        messages: Vec<ChatMessagePayload>,
        web_search_enabled: bool,
    ) -> Result<Pin<Box<dyn Stream<Item = Result<String>> + Send + 'static>>> {
        let api_key = self.resolve_api_key();

        let mapped_messages: Vec<Value> = messages
            .into_iter()
            .map(|msg| {
                let role = match msg.role.as_str() {
                    "system" => "system",
                    "user" => "user",
                    "assistant" => "assistant",
                    _ => "user",
                };
                let content = match msg.content {
                    Some(ChatMessageContent::Text(s)) => Value::String(s),
                    Some(ChatMessageContent::MultiModal(parts)) => {
                        let converted: Vec<Value> = parts
                            .into_iter()
                            .map(|part| match part {
                                ContentPart::Text { text } => json!({
                                    "type": "input_text",
                                    "text": text
                                }),
                                ContentPart::ImageUrl { image_url } => json!({
                                    "type": "input_image",
                                    "image_url": image_url.url
                                }),
                            })
                            .collect();
                        Value::Array(converted)
                    }
                    None => Value::String("".to_string()),
                };
                json!({
                    "type": "message",
                    "role": role,
                    "content": content
                })
            })
            .collect();

        // Only include tools if web search is enabled
        let tools = if web_search_enabled {
            vec![Tool { tool_type: ToolType::WebSearch }]
        } else {
            vec![]
        };

        // xAI Responses API: `store: false` opts out of server-side conversation
        // retention. Team-level ZDR (no audit logs) is configured in the Console.
        let store = if self.xai_zdr { Some(false) } else { None };

        let payload = ResponseRequest {
            model: self.model.clone(),
            messages: mapped_messages,
            tools,
            stream: true,
            store,
        };

        debug!(xai_zdr = self.xai_zdr, "sending xAI request");

        // Ensure base_url is correct. If it's missing or empty, default to https://api.x.ai/v1
        let base = if self.base_url.is_empty() {
            "https://api.x.ai/v1"
        } else {
            self.base_url.trim_end_matches('/')
        };
        
        let url = format!("{}/responses", base);
        let client = self.client.clone();
        let expect_zdr = self.xai_zdr;

        let stream = try_stream! {
            let response = client
                .post(url)
                .bearer_auth(api_key)
                .json(&payload)
                .send()
                .await
                .context("failed to send LLM request")?;

            if expect_zdr {
                log_zdr_response_header(response.headers());
            }

            if response.status().is_success() {
                let mut buffer = String::new();
                let mut pending_utf8 = Vec::new();
                let mut body_stream = response.bytes_stream();

                while let Some(chunk) = body_stream.next().await {
                    let bytes = chunk.context("LLM stream read error")?;
                    super::push_utf8(&mut buffer, &mut pending_utf8, &bytes);

                    let outcome = extract_sse_payloads(&mut buffer)?;
                    for chunk in outcome.chunks {
                        yield chunk;
                    }
                    if outcome.done {
                        debug!("xAI SSE stream marked [DONE]");
                        return;
                    }
                }
                super::flush_utf8(&mut buffer, &mut pending_utf8);
                if !buffer.is_empty() {
                    buffer.push('\n');
                    let outcome = extract_sse_payloads(&mut buffer)?;
                    for chunk in outcome.chunks {
                        yield chunk;
                    }
                    if outcome.done {
                        return;
                    }
                }
                Err(anyhow::anyhow!("xAI stream ended before a successful terminal event"))?;
            } else {
                let status = response.status();
                error!(status = ?status, "xAI error response");
                Err(anyhow::anyhow!("HTTP {}", status))?;
            }
        };

        Ok(Box::pin(stream))
    }
}

/// When `xai_zdr` is enabled, check the xAI `x-zero-data-retention` response header.
/// Team ZDR is console-only; `store: false` alone is not full ZDR.
fn log_zdr_response_header(headers: &reqwest::header::HeaderMap) {
    match headers
        .get("x-zero-data-retention")
        .and_then(|v| v.to_str().ok())
    {
        Some("true") => {
            debug!(header = "true", "xAI Zero Data Retention confirmed on response");
        }
        Some(other) => {
            warn!(
                header = %other,
                "xai_zdr is enabled but xAI response header x-zero-data-retention is not true; \
                 enable team ZDR in the xAI Console (Team Settings). store=false still applies \
                 for this request"
            );
        }
        None => {
            warn!(
                "xai_zdr is enabled but xAI response omitted x-zero-data-retention header; \
                 cannot confirm team-level Zero Data Retention"
            );
        }
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

            let value: Value = serde_json::from_str(data).context("failed to decode LLM stream chunk")?;

            // xAI Responses API structure
            if let Some(msg_type) = value.get("type").and_then(Value::as_str) {
                match msg_type {
                    "response.failed" | "response.incomplete" | "error" => {
                        Err(anyhow::anyhow!("xAI response failed"))?;
                    }
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
            if value.get("error").is_some() && value.get("type").and_then(Value::as_str).is_none() {
                Err(anyhow::anyhow!("xAI response failed"))?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::header::{HeaderMap, HeaderValue};
    use tokio::net::TcpListener;

    async fn stream_body(body: &'static str) -> Vec<Result<String>> {
        use axum::{body::Body, http::StatusCode, response::Response, routing::post, Router};
        use futures_util::StreamExt;

        let app = Router::new().route("/v1/responses", post(move || async move {
            Response::builder()
                .status(StatusCode::OK)
                .header("content-type", "text/event-stream")
                .body(Body::from(body))
                .unwrap()
        }));
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind mock");
        let address = listener.local_addr().expect("mock address");
        tokio::spawn(async move { axum::serve(listener, app).await.expect("mock server") });

        let provider = XaiProvider::new_owned(
            &ProviderConfig {
                privacy_level: chatbot_core::config::PrivacyLevel::default_destination(),
                provider_name: "test".into(),
                provider_type: "xai".into(),
                tier: None,
                model_name: "test-model".into(),
                context_size: Some(4096),
                base_url: format!("http://{address}/v1"),
                api_key: None,
                allowed_providers: vec![],
                request_timeout: Some(5.0),
                rate_limit_retries: None,
                rate_limit_max_wait_secs: None,
                test_chunks: None,
                search: false,
                xai_search: true,
                xai_zdr: false,
            },
            None,
        )
        .expect("provider");
        provider
            .stream_chat(vec![], false)
            .expect("stream setup")
            .collect()
            .await
    }

    #[test]
    fn response_request_omits_store_when_zdr_off() {
        let payload = ResponseRequest {
            model: "grok-3".to_string(),
            messages: vec![],
            tools: vec![],
            stream: true,
            store: None,
        };
        let json = serde_json::to_value(&payload).expect("serialize");
        assert!(json.get("store").is_none());
        assert_eq!(json.get("stream"), Some(&Value::Bool(true)));
    }

    #[test]
    fn response_request_sets_store_false_when_zdr_on() {
        let payload = ResponseRequest {
            model: "grok-3".to_string(),
            messages: vec![],
            tools: vec![],
            stream: true,
            store: Some(false),
        };
        let json = serde_json::to_value(&payload).expect("serialize");
        assert_eq!(json.get("store"), Some(&Value::Bool(false)));
    }

    #[test]
    fn log_zdr_header_accepts_true() {
        let mut headers = HeaderMap::new();
        headers.insert("x-zero-data-retention", HeaderValue::from_static("true"));
        // Should not panic; only logs.
        log_zdr_response_header(&headers);
    }

    #[test]
    fn log_zdr_header_handles_missing_and_false() {
        let empty = HeaderMap::new();
        log_zdr_response_header(&empty);

        let mut headers = HeaderMap::new();
        headers.insert("x-zero-data-retention", HeaderValue::from_static("false"));
        log_zdr_response_header(&headers);
    }

    #[test]
    fn in_band_terminal_failure_events_are_errors_without_upstream_details() {
        for event_type in ["response.failed", "response.incomplete", "error"] {
            let mut buffer = format!(
                "data: {}\n",
                json!({"type": event_type, "error": {"message": "PRIVATE_UPSTREAM_SENTINEL"}})
            );
            let result = extract_sse_payloads(&mut buffer);
            let error = match result {
                Ok(_) => panic!("terminal failure must not be treated as a successful chunk"),
                Err(error) => error,
            };
            let message = format!("{error:#}");
            assert!(!message.contains("PRIVATE_UPSTREAM_SENTINEL"), "upstream detail leaked: {message}");
        }
    }

    #[tokio::test]
    async fn http_200_terminal_failures_and_unterminated_eof_are_stream_errors() {
        for body in [
            "data: {\"type\":\"response.failed\",\"error\":{\"message\":\"PRIVATE_UPSTREAM_SENTINEL\"}}\n\n",
            "data: {\"type\":\"response.incomplete\",\"response\":{\"status\":\"incomplete\"}}\n\n",
            "data: {\"type\":\"error\",\"message\":\"PRIVATE_UPSTREAM_SENTINEL\"}\n\n",
            "data: {\"type\":\"response.output_text.delta\",\"delta\":\"partial\"}",
        ] {
            let items = stream_body(body).await;
            let error = items.into_iter().find_map(Result::err)
                .expect("failed/incomplete/error/EOF must not complete successfully");
            let message = format!("{error:#}");
            assert!(!message.contains("PRIVATE_UPSTREAM_SENTINEL"), "upstream detail leaked: {message}");
        }
    }

    #[tokio::test]
    async fn http_200_completed_response_remains_successful() {
        let items = stream_body("data: {\"type\":\"response.output_text.delta\",\"delta\":\"answer\"}\n\ndata: {\"type\":\"response.completed\"}")
            .await;
        assert_eq!(items.into_iter().collect::<Result<Vec<_>>>().expect("successful completion"), ["answer"]);
    }
}
