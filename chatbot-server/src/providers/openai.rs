use std::{collections::BTreeMap, pin::Pin, time::Duration};

use anyhow::{Context, Result};
use async_stream::try_stream;
use futures_util::Stream;
use futures_util::StreamExt;
use reqwest::{Client, Response};
use serde_json::Value;
use tracing::{debug, error, warn};

use chatbot_core::config::ProviderConfig;

use self::messages::ChatMessagePayload;
use self::payload::{ChatCompletionRequest, ProviderRoutingOptions};

/// Extra attempts after an upstream `429 Too Many Requests` when the provider
/// config omits `rate_limit_retries`. Providers rarely serve an immediate
/// retry — the limit window is still closed — so keep backing off
/// exponentially across several attempts. An impatient user can hit Stop at
/// any time: the response stream (and with it any pending retry wait) is
/// dropped on client disconnect.
const DEFAULT_RATE_LIMIT_RETRIES: u32 = 5;
/// Cap (seconds) on a single rate-limit retry wait, applied both to the
/// exponential backoff (1s, 2s, 4s, 8s, 16s — never truncated by this default)
/// and to any upstream `Retry-After` hint.
const DEFAULT_RATE_LIMIT_MAX_WAIT_SECS: f64 = 30.0;

pub struct ToolCall {
    pub name: String,
    pub arguments: Value,
}

pub enum ToolStreamChunk {
    Content(String),
    ToolCalls(Vec<ToolCall>),
}

pub mod messages {
    use serde::Serialize;
    use serde_json::Value;

    #[derive(Clone, Serialize)]
    #[serde(tag = "type", rename_all = "snake_case")]
    pub enum ContentPart {
        Text { text: String },
        ImageUrl { image_url: ImageUrlPart },
    }

    #[derive(Clone, Serialize)]
    pub struct ImageUrlPart {
        pub url: String,
    }

    #[derive(Clone, Serialize)]
    #[serde(untagged)]
    pub enum ChatMessageContent {
        Text(String),
        MultiModal(Vec<ContentPart>),
    }

    #[derive(Clone, Serialize)]
    pub struct ChatMessagePayload {
        pub role: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub content: Option<ChatMessageContent>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub tool_calls: Option<Vec<Value>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub tool_call_id: Option<String>,
    }

    impl ChatMessagePayload {
        pub fn system(content: String) -> Self {
            Self {
                role: "system".to_string(),
                content: Some(ChatMessageContent::Text(content)),
                tool_calls: None,
                tool_call_id: None,
            }
        }

        pub fn user(content: String) -> Self {
            Self {
                role: "user".to_string(),
                content: Some(ChatMessageContent::MultiModal(vec![
                    ContentPart::Text { text: content },
                ])),
                tool_calls: None,
                tool_call_id: None,
            }
        }

        pub fn user_with_content(content: ChatMessageContent) -> Self {
            Self {
                role: "user".to_string(),
                content: Some(content),
                tool_calls: None,
                tool_call_id: None,
            }
        }

        pub fn assistant(content: String) -> Self {
            Self {
                role: "assistant".to_string(),
                content: Some(ChatMessageContent::Text(content)),
                tool_calls: None,
                tool_call_id: None,
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
        #[serde(skip_serializing_if = "Option::is_none")]
        pub tools: Option<Vec<serde_json::Value>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub tool_choice: Option<String>,
    }
}

#[derive(Clone)]
pub struct OpenAiProvider {
    client: Client,
    base_url: String,
    api_key: Option<String>,
    model: String,
    allowed_providers: Vec<String>,
    test_chunks: Option<Vec<String>>,
    rate_limit_retries: u32,
    rate_limit_max_wait: Duration,
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
            rate_limit_retries: config
                .rate_limit_retries
                .unwrap_or(DEFAULT_RATE_LIMIT_RETRIES),
            rate_limit_max_wait: Duration::from_secs_f64(
                config
                    .rate_limit_max_wait_secs
                    .unwrap_or(DEFAULT_RATE_LIMIT_MAX_WAIT_SECS),
            ),
        })
    }

    pub fn stream_chat(
        &self,
        messages: Vec<ChatMessagePayload>,
    ) -> Result<Pin<Box<dyn Stream<Item = Result<String>> + Send + 'static>>> {
        if let Some(ref chunks) = self.test_chunks {
            let chunks = chunks.clone();
            // Optional per-chunk delay so tests can abort mid-stream (client Stop).
            let delay_ms: u64 = std::env::var("CHATBOT_TEST_OPENAI_CHUNK_DELAY_MS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
            if delay_ms == 0 {
                // Special token for tests: emit a stream error instead of a text chunk.
                let stream = tokio_stream::iter(chunks.into_iter().map(|chunk| {
                    if chunk == "__STREAM_ERROR__" {
                        Err(anyhow::anyhow!("injected test stream error").context("provider stream failed"))
                    } else {
                        Ok(chunk)
                    }
                }));
                return Ok(Box::pin(stream));
            }
            let stream = async_stream::stream! {
                for chunk in chunks {
                    tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
                    if chunk == "__STREAM_ERROR__" {
                        yield Err(anyhow::anyhow!("injected test stream error").context("provider stream failed"));
                    } else {
                        yield Ok(chunk);
                    }
                }
            };
            return Ok(Box::pin(stream));
        }

        let mut is_implicit_model = self.model.contains("nemotron-3-nano-30b-a3b")
            || self.model.contains("apriel-1.6-15b-thinker")
            || self.model.contains("glm-4");
        
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
            tools: None,
            tool_choice: None,
        };

        let url = format!("{}/chat/completions", self.base_url.trim_end_matches('/'));
        let client = self.client.clone();
        let rate_limit_retries = self.rate_limit_retries;
        let rate_limit_max_wait = self.rate_limit_max_wait;

        let stream = try_stream! {
            let response = send_with_rate_limit_retry(
                &client,
                &url,
                &api_key,
                &payload,
                rate_limit_retries,
                rate_limit_max_wait,
                "OpenAI request",
            )
            .await?;
            let response = check_openai_response(response).await?;

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
                    if currently_thinking {
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
                if currently_thinking {
                    yield "</think>".to_string();
                }
            }
        };

        Ok(Box::pin(stream))
    }

    pub fn stream_chat_with_tools(
        &self,
        messages: Vec<ChatMessagePayload>,
        tools: &[Value],
    ) -> Result<Pin<Box<dyn Stream<Item = Result<ToolStreamChunk>> + Send + 'static>>> {
        if let Ok(query) = std::env::var("CHATBOT_TEST_OPENAI_TOOL_CALL_QUERY") {
            if !query.is_empty() {
                let stream = tokio_stream::iter(vec![Ok(ToolStreamChunk::ToolCalls(vec![
                    ToolCall {
                        name: "brave_web_search".to_string(),
                        arguments: serde_json::json!({ "query": query }),
                    },
                ]))]);
                return Ok(Box::pin(stream));
            }
        }

        if let Some(ref chunks) = self.test_chunks {
            let chunks = chunks.clone();
            let delay_ms: u64 = std::env::var("CHATBOT_TEST_OPENAI_CHUNK_DELAY_MS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
            let stream = async_stream::try_stream! {
                for chunk in chunks {
                    if delay_ms > 0 {
                        tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                    }
                    if chunk == "__STREAM_ERROR__" {
                        Err(anyhow::anyhow!("injected test stream error").context("provider stream failed"))?;
                    }
                    yield ToolStreamChunk::Content(chunk);
                }
            };
            return Ok(Box::pin(stream));
        }

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
            tools: Some(tools.to_vec()),
            tool_choice: Some("auto".to_string()),
        };

        let url = format!("{}/chat/completions", self.base_url.trim_end_matches('/'));

        let client = self.client.clone();
        let rate_limit_retries = self.rate_limit_retries;
        let rate_limit_max_wait = self.rate_limit_max_wait;
        let stream = try_stream! {
            let response = send_with_rate_limit_retry(
                &client,
                &url,
                &api_key,
                &payload,
                rate_limit_retries,
                rate_limit_max_wait,
                "tool-aware OpenAI request",
            )
            .await?;
            let response = check_openai_response(response).await?;

            let mut buffer = String::new();
            let mut body_stream = response.bytes_stream();
            let mut currently_thinking = false;
            let mut has_sent_any_content = false;
            let mut is_implicit_model = false;
            let mut tool_call_builders: BTreeMap<usize, ToolCallBuilder> = BTreeMap::new();

            while let Some(chunk) = body_stream.next().await {
                let bytes = chunk.context("OpenAI tool-aware stream read error")?;
                buffer.push_str(&String::from_utf8_lossy(&bytes));

                let outcome = extract_sse_payloads(
                    &mut buffer,
                    &mut currently_thinking,
                    &mut has_sent_any_content,
                    &mut is_implicit_model,
                )?;
                for chunk in outcome.chunks {
                    yield ToolStreamChunk::Content(chunk);
                }
                collect_tool_call_deltas(&mut tool_call_builders, outcome.tool_call_deltas);

                if outcome.done {
                    if currently_thinking {
                        yield ToolStreamChunk::Content("</think>".to_string());
                    }
                    let tool_calls = finish_tool_calls(tool_call_builders);
                    if !tool_calls.is_empty() {
                        yield ToolStreamChunk::ToolCalls(tool_calls);
                    }
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
                    yield ToolStreamChunk::Content(chunk);
                }
                collect_tool_call_deltas(&mut tool_call_builders, outcome.tool_call_deltas);
            }
            if currently_thinking {
                yield ToolStreamChunk::Content("</think>".to_string());
            }
            let tool_calls = finish_tool_calls(tool_call_builders);
            if !tool_calls.is_empty() {
                yield ToolStreamChunk::ToolCalls(tool_calls);
            }
        };

        Ok(Box::pin(stream))
    }
}

struct ToolCallBuilder {
    name: String,
    arguments: String,
}

struct ToolCallDelta {
    index: usize,
    name: Option<String>,
    arguments: String,
}

fn collect_tool_call_deltas(
    builders: &mut BTreeMap<usize, ToolCallBuilder>,
    deltas: Vec<ToolCallDelta>,
) {
    for delta in deltas {
        let builder = builders.entry(delta.index).or_insert_with(|| ToolCallBuilder {
            name: String::new(),
            arguments: String::new(),
        });
        if let Some(name) = delta.name {
            builder.name.push_str(&name);
        }
        builder.arguments.push_str(&delta.arguments);
    }
}

fn finish_tool_calls(builders: BTreeMap<usize, ToolCallBuilder>) -> Vec<ToolCall> {
    builders
        .into_values()
        .filter(|builder| !builder.name.is_empty())
        .map(|builder| ToolCall {
            name: builder.name,
            arguments: serde_json::from_str(&builder.arguments)
                .unwrap_or_else(|_| serde_json::json!({})),
        })
        .collect()
}

struct ExtractionOutcome {
    chunks: Vec<String>,
    tool_call_deltas: Vec<ToolCallDelta>,
    done: bool,
}

const PROVIDER_ERROR_BODY_MAX_CHARS: usize = 512;

fn truncate_for_error(body: &str) -> String {
    if body.chars().count() <= PROVIDER_ERROR_BODY_MAX_CHARS {
        return body.to_string();
    }
    let mut truncated: String = body.chars().take(PROVIDER_ERROR_BODY_MAX_CHARS).collect();
    truncated.push('…');
    truncated
}

/// Send the chat-completions request, retrying `429 Too Many Requests` up to
/// `retries` extra times. Waits honor the upstream `Retry-After` header when
/// present, capped at `max_wait`; without it, a short exponential backoff
/// (1s, 2s, …) applies, capped the same way. Retries only happen before the
/// stream starts, so no content has been yielded or persisted for the turn.
async fn send_with_rate_limit_retry(
    client: &Client,
    url: &str,
    api_key: &str,
    payload: &ChatCompletionRequest,
    retries: u32,
    max_wait: Duration,
    context: &'static str,
) -> Result<Response> {
    let mut attempt = 0u32;
    loop {
        let response = client
            .post(url)
            .bearer_auth(api_key)
            .json(payload)
            .send()
            .await
            .with_context(|| format!("failed to send {context}"))?;

        if response.status() != reqwest::StatusCode::TOO_MANY_REQUESTS || attempt >= retries {
            return Ok(response);
        }

        let wait = rate_limit_wait(response.headers(), max_wait, attempt);
        warn!(
            attempt = attempt + 1,
            retries,
            wait_ms = u64::try_from(wait.as_millis()).unwrap_or(u64::MAX),
            "{context} rate limited (429); waiting before retry"
        );
        tokio::time::sleep(wait).await;
        attempt += 1;
    }
}

/// Pick the wait before a rate-limit retry: `Retry-After` seconds when the
/// upstream provides a usable hint, otherwise exponential backoff — always
/// capped at `max_wait`.
fn rate_limit_wait(
    headers: &reqwest::header::HeaderMap,
    max_wait: Duration,
    attempt: u32,
) -> Duration {
    let retry_after = headers
        .get(reqwest::header::RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.trim().parse::<f64>().ok())
        .filter(|secs| secs.is_finite() && *secs >= 0.0)
        .map(Duration::from_secs_f64);
    let backoff = Duration::from_secs_f64(2f64.powi(attempt as i32));
    retry_after.unwrap_or(backoff).min(max_wait)
}

/// Surface HTTP error statuses with the provider's error body instead of
/// discarding it via `error_for_status` (quota/auth/model errors live there).
async fn check_openai_response(response: Response) -> Result<Response> {
    let status = response.status();
    if status.is_success() {
        return Ok(response);
    }
    let body = response.text().await.unwrap_or_default();
    error!(
        status = ?status,
        body_preview = %body.chars().take(200).collect::<String>(),
        "OpenAI error response"
    );
    Err(anyhow::anyhow!(
        "OpenAI returned error: {} - {}",
        status,
        truncate_for_error(&body)
    ))
}

fn extract_sse_payloads(
    buffer: &mut String,
    currently_thinking: &mut bool,
    has_sent_any_content: &mut bool,
    is_implicit_model: &mut bool,
) -> Result<ExtractionOutcome> {
    let mut chunks = Vec::new();
    let mut tool_call_deltas = Vec::new();
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

            // In-band error events (e.g. OpenRouter mid-stream failures) carry no
            // "choices"; without this check the stream would end silently and look
            // like a successful empty response.
            if let Some(err_val) = value.get("error").filter(|v| !v.is_null()) {
                return Err(anyhow::anyhow!("OpenAI stream error event: {err_val}"));
            }

            let model_response = value.get("model").and_then(Value::as_str).unwrap_or("");
            if !*is_implicit_model
                && (model_response.contains("nemotron-3-nano-30b-a3b")
                    || model_response.contains("apriel-1.6-15b-thinker")
                    || model_response.contains("glm-4"))
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
                if let Some(raw_tool_calls) = delta.get("tool_calls").and_then(Value::as_array) {
                    for raw_tool_call in raw_tool_calls {
                        let index = raw_tool_call
                            .get("index")
                            .and_then(Value::as_u64)
                            .unwrap_or(0) as usize;
                        let function = raw_tool_call.get("function");
                        let name = function
                            .and_then(|function| function.get("name"))
                            .and_then(Value::as_str)
                            .map(str::to_string);
                        let arguments = function
                            .and_then(|function| function.get("arguments"))
                            .and_then(Value::as_str)
                            .unwrap_or("")
                            .to_string();
                        tool_call_deltas.push(ToolCallDelta {
                            index,
                            name,
                            arguments,
                        });
                    }
                }

                let reasoning_field = delta.get("reasoning_content").or_else(|| delta.get("reasoning"));
                let content_field = delta.get("content");
                
                if let Some(r) = reasoning_field.and_then(Value::as_str) {
                    if !*currently_thinking {
                        chunks.push("<think>".to_string());
                        *currently_thinking = true;
                    }
                    if !r.is_empty() {
                        chunks.push(r.to_string());
                        *has_sent_any_content = true;
                    }
                    if r.contains("</think>") {
                        *currently_thinking = false;
                    }
                }                
                if let Some(c) = content_field.and_then(Value::as_str) {
                    // If we see an explicit closing tag in the content stream, 
                    // we must respect it and stop thinking, even for "implicit" models.
                    let has_explicit_close = c.contains("</think>");
                    
                    if *currently_thinking && !c.trim().is_empty() {
                        if !*is_implicit_model || has_explicit_close {
                             // For implicit models, we only close if we see the tag or if we want to transition to content.
                             // But if the model SENT </think>, we definitely stop thinking.
                             if has_explicit_close {
                                 // We don't push another </think> because c contains it.
                                 *currently_thinking = false;
                             } else if !*is_implicit_model {
                                 chunks.push("</think>".to_string());
                                 *currently_thinking = false;
                             }
                        }
                    }
                    
                    if !c.is_empty() {
                        chunks.push(c.to_string());
                        *has_sent_any_content = true;
                    }
                }
            }
        } else {
            break;
        }
    }

    Ok(ExtractionOutcome {
        chunks,
        tool_call_deltas,
        done,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::StreamExt;

    fn test_provider(test_chunks: Vec<String>) -> OpenAiProvider {
        OpenAiProvider::new(&ProviderConfig {
            provider_name: "test".to_string(),
            provider_type: "openai".to_string(),
            tier: None,
            model_name: "test-model".to_string(),
            context_size: Some(4096),
            base_url: "https://example.test/v1".to_string(),
            api_key: None,
            allowed_providers: vec![],
            request_timeout: Some(1.0),
            rate_limit_retries: None,
            rate_limit_max_wait_secs: None,
            test_chunks: Some(test_chunks),
            search: false,
            xai_search: true,
            xai_zdr: false,
        })
        .expect("test provider")
    }

    #[tokio::test]
    async fn tool_aware_stream_passes_through_direct_content() {
        let provider = test_provider(vec!["first".to_string(), " second".to_string()]);
        let mut stream = provider
            .stream_chat_with_tools(vec![], &[])
            .expect("tool-aware stream");
        let mut content = String::new();

        while let Some(event) = stream.next().await {
            match event.expect("stream event") {
                ToolStreamChunk::Content(chunk) => content.push_str(&chunk),
                ToolStreamChunk::ToolCalls(_) => {
                    panic!("direct response unexpectedly called a tool")
                }
            }
        }

        assert_eq!(content, "first second");
    }

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

    #[test]
    fn test_openai_extract_sse_payloads_collects_tool_call_deltas() {
        let mut buffer = String::new();
        let mut currently_thinking = false;
        let mut has_sent_any_content = false;
        let mut is_implicit_model = false;
        let json = serde_json::json!({
            "choices": [{
                "delta": {
                    "tool_calls": [{
                        "index": 0,
                        "function": {
                            "name": "brave_web_search",
                            "arguments": r#"{"query":"weather"#
                        }
                    }]
                }
            }]
        });

        buffer.push_str(&format!("data: {}\n\n", json));
        let outcome = extract_sse_payloads(
            &mut buffer,
            &mut currently_thinking,
            &mut has_sent_any_content,
            &mut is_implicit_model,
        )
        .expect("tool call delta");

        assert!(outcome.chunks.is_empty());
        assert_eq!(outcome.tool_call_deltas.len(), 1);
        assert_eq!(outcome.tool_call_deltas[0].index, 0);
        assert_eq!(
            outcome.tool_call_deltas[0].name.as_deref(),
            Some("brave_web_search")
        );
        assert_eq!(outcome.tool_call_deltas[0].arguments, "{\"query\":\"weather");
    }

    #[test]
    fn test_interleaved_thinking_coalescence() {
        let mut buffer = String::new();
        let mut currently_thinking = false;
        let mut has_sent_any_content = false;
        let mut is_implicit_model = false;

        // Chunk 1: Thought
        buffer.push_str("data: {\"choices\": [{\"delta\": {\"reasoning_content\": \"thought 1\"}}]}\n\n");
        let outcome1 = extract_sse_payloads(&mut buffer, &mut currently_thinking, &mut has_sent_any_content, &mut is_implicit_model).unwrap();
        
        // Chunk 2: Just a space in content (this triggers the bug: closing thinking prematurely)
        buffer.push_str("data: {\"choices\": [{\"delta\": {\"content\": \" \"}}]}\n\n");
        let outcome2 = extract_sse_payloads(&mut buffer, &mut currently_thinking, &mut has_sent_any_content, &mut is_implicit_model).unwrap();

        // Chunk 3: More thought
        buffer.push_str("data: {\"choices\": [{\"delta\": {\"reasoning_content\": \"thought 2\"}}]}\n\n");
        let outcome3 = extract_sse_payloads(&mut buffer, &mut currently_thinking, &mut has_sent_any_content, &mut is_implicit_model).unwrap();

        let all_chunks: Vec<String> = outcome1.chunks.into_iter()
            .chain(outcome2.chunks)
            .chain(outcome3.chunks)
            .collect();
            
        let combined = all_chunks.join("");
        // Desired behavior: "<think>thought 1 thought 2"
        assert_eq!(combined.matches("<think>").count(), 1, "Should have coalesced thinking blocks. Got: {}", combined);
        assert!(!combined.contains("</think>"), "Should not have closed thinking block prematurely. Got: {}", combined);
    }

    #[test]
    fn extract_sse_payloads_surfaces_in_band_error_events() {
        let mut buffer = String::from(
            "data: {\"error\": {\"message\": \"Provider is overloaded\", \"code\": 502}}\n\n",
        );
        let mut currently_thinking = false;
        let mut has_sent_any_content = false;
        let mut is_implicit_model = false;

        let outcome = extract_sse_payloads(
            &mut buffer,
            &mut currently_thinking,
            &mut has_sent_any_content,
            &mut is_implicit_model,
        );

        let err = match outcome {
            Err(err) => err,
            Ok(outcome) => panic!(
                "in-band SSE error event must surface as an error, got chunks: {:?}",
                outcome.chunks
            ),
        };
        assert!(
            err.to_string().contains("Provider is overloaded"),
            "error must include the provider's error payload, got: {err:#}"
        );
    }

    #[test]
    fn extract_sse_payloads_tolerates_null_error_fields() {
        let mut buffer = String::from("data: {\"error\": null, \"choices\": [{\"delta\": {\"content\": \"ok\"}}]}\n\n");
        let mut currently_thinking = false;
        let mut has_sent_any_content = false;
        let mut is_implicit_model = false;

        let outcome = extract_sse_payloads(
            &mut buffer,
            &mut currently_thinking,
            &mut has_sent_any_content,
            &mut is_implicit_model,
        )
        .expect("null error field must not be treated as an error");

        assert_eq!(outcome.chunks.join(""), "ok");
    }

    #[tokio::test]
    async fn stream_chat_includes_status_and_body_on_http_error() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock listener");
        let addr = listener.local_addr().expect("mock addr");
        let hits = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let route_hits = hits.clone();
        let app = axum::Router::new().route(
            "/v1/chat/completions",
            axum::routing::post(move || {
                let hits = route_hits.clone();
                async move {
                    hits.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    (
                        axum::http::StatusCode::TOO_MANY_REQUESTS,
                        axum::Json(serde_json::json!({
                            "error": { "message": "Rate limit exceeded, quota reached" }
                        })),
                    )
                }
            }),
        );
        tokio::spawn(async move {
            axum::serve(listener, app).await.expect("mock server");
        });

        let provider = OpenAiProvider::new(&ProviderConfig {
            provider_name: "test".to_string(),
            provider_type: "openai".to_string(),
            tier: None,
            model_name: "test-model".to_string(),
            context_size: Some(4096),
            base_url: format!("http://{addr}/v1"),
            api_key: None,
            allowed_providers: vec![],
            request_timeout: Some(5.0),
            // Retry disabled: this test pins single-attempt error surfacing.
            rate_limit_retries: Some(0),
            rate_limit_max_wait_secs: None,
            test_chunks: None,
            search: false,
            xai_search: true,
            xai_zdr: false,
        })
        .expect("provider");

        let stream = provider
            .stream_chat(vec![ChatMessagePayload::user("hello".to_string())])
            .expect("stream setup");
        let mut stream = stream;

        let first = stream.next().await.expect("stream item");
        let err = first.expect_err("HTTP error status must surface as a stream error");
        let message = format!("{err:#}");
        assert!(
            message.contains("429"),
            "error must include the HTTP status, got: {message}"
        );
        assert!(
            message.contains("Rate limit exceeded, quota reached"),
            "error must include the provider error body, got: {message}"
        );
        assert_eq!(
            hits.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "retries disabled must mean exactly one request"
        );
    }

    const RETRY_429_TEST_RETRIES: u32 = 2;

    #[test]
    fn default_rate_limit_settings_back_off_five_times_with_30s_cap() {
        let provider = OpenAiProvider::new(&ProviderConfig {
            provider_name: "test".to_string(),
            provider_type: "openai".to_string(),
            tier: None,
            model_name: "test-model".to_string(),
            context_size: Some(4096),
            base_url: "https://example.test/v1".to_string(),
            api_key: None,
            allowed_providers: vec![],
            request_timeout: Some(5.0),
            rate_limit_retries: None,
            rate_limit_max_wait_secs: None,
            test_chunks: None,
            search: false,
            xai_search: true,
            xai_zdr: false,
        })
        .expect("provider");
        assert_eq!(provider.rate_limit_retries, 5);
        assert_eq!(provider.rate_limit_max_wait, Duration::from_secs(30));
    }

    fn retry_test_provider(base_url: String) -> OpenAiProvider {
        OpenAiProvider::new(&ProviderConfig {
            provider_name: "test".to_string(),
            provider_type: "openai".to_string(),
            tier: None,
            model_name: "test-model".to_string(),
            context_size: Some(4096),
            base_url,
            api_key: None,
            allowed_providers: vec![],
            request_timeout: Some(5.0),
            rate_limit_retries: Some(RETRY_429_TEST_RETRIES),
            // Tiny cap keeps the suite fast; Retry-After: 0 needs no wait anyway.
            rate_limit_max_wait_secs: Some(0.02),
            test_chunks: None,
            search: false,
            xai_search: true,
            xai_zdr: false,
        })
        .expect("retry test provider")
    }

    fn rate_limited_mock_app(
        hits: std::sync::Arc<std::sync::atomic::AtomicUsize>,
        limit: Option<usize>,
    ) -> axum::Router {
        use axum::response::IntoResponse;
        const SSE_OK_BODY: &str =
            "data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\ndata: [DONE]\n\n";
        axum::Router::new().route(
            "/v1/chat/completions",
            axum::routing::post(move || {
                let hits = hits.clone();
                async move {
                    let hit = hits.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    let limited = match limit {
                        Some(max) => hit < max,
                        None => true,
                    };
                    if limited {
                        (
                            axum::http::StatusCode::TOO_MANY_REQUESTS,
                            [("retry-after", "0")],
                            axum::Json(serde_json::json!({
                                "error": { "message": "Rate limit exceeded" }
                            })),
                        )
                            .into_response()
                    } else {
                        (
                            axum::http::StatusCode::OK,
                            [("content-type", "text/event-stream")],
                            SSE_OK_BODY,
                        )
                            .into_response()
                    }
                }
            }),
        )
    }

    async fn spawn_rate_limited_mock(limit: Option<usize>) -> (String, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock listener");
        let addr = listener.local_addr().expect("mock addr");
        let hits = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let app = rate_limited_mock_app(hits.clone(), limit);
        tokio::spawn(async move {
            axum::serve(listener, app).await.expect("mock server");
        });
        (format!("http://{addr}/v1"), hits)
    }

    #[test]
    fn rate_limit_wait_honors_retry_after_and_caps_wait() {
        use std::time::Duration;
        let mut headers = reqwest::header::HeaderMap::new();

        // No header: exponential backoff 1s, 2s, 4s.
        headers.clear();
        assert_eq!(rate_limit_wait(&headers, Duration::from_secs(5), 0), Duration::from_secs(1));
        assert_eq!(rate_limit_wait(&headers, Duration::from_secs(5), 1), Duration::from_secs(2));

        // Backoff is capped by max_wait.
        assert_eq!(rate_limit_wait(&headers, Duration::from_millis(200), 3), Duration::from_millis(200));

        // Usable Retry-After wins over backoff; capped when larger than max_wait.
        headers.insert(
            reqwest::header::RETRY_AFTER,
            reqwest::header::HeaderValue::from_static("0.25"),
        );
        assert_eq!(rate_limit_wait(&headers, Duration::from_secs(5), 0), Duration::from_millis(250));
        headers.insert(
            reqwest::header::RETRY_AFTER,
            reqwest::header::HeaderValue::from_static("120"),
        );
        assert_eq!(rate_limit_wait(&headers, Duration::from_secs(5), 0), Duration::from_secs(5));

        // Garbage hint (HTTP-date or junk) falls back to backoff.
        headers.insert(
            reqwest::header::RETRY_AFTER,
            reqwest::header::HeaderValue::from_static("Wed, 21 Oct 2026 07:28:00 GMT"),
        );
        assert_eq!(rate_limit_wait(&headers, Duration::from_secs(5), 0), Duration::from_secs(1));
    }

    #[tokio::test]
    async fn stream_chat_retries_429_and_succeeds() {
        let (base_url, hits) = spawn_rate_limited_mock(Some(1)).await;
        let provider = retry_test_provider(base_url);

        let mut stream = provider
            .stream_chat(vec![ChatMessagePayload::user("hello".to_string())])
            .expect("stream setup");

        let mut content = String::new();
        while let Some(item) = stream.next().await {
            content.push_str(&item.expect("stream item must not error after retry"));
        }
        assert_eq!(content, "hi");
        assert_eq!(
            hits.load(std::sync::atomic::Ordering::SeqCst),
            2,
            "retry stops at the first non-429 response: one 429, then success"
        );
    }

    #[tokio::test]
    async fn tool_aware_stream_retries_429_and_succeeds() {
        let (base_url, hits) = spawn_rate_limited_mock(Some(1)).await;
        let provider = retry_test_provider(base_url);

        let mut stream = provider
            .stream_chat_with_tools(vec![ChatMessagePayload::user("hello".to_string())], &[])
            .expect("tool-aware stream setup");

        let mut content = String::new();
        while let Some(item) = stream.next().await {
            match item.expect("stream item must not error after retry") {
                ToolStreamChunk::Content(chunk) => content.push_str(&chunk),
                ToolStreamChunk::ToolCalls(_) => panic!("unexpected tool call"),
            }
        }
        assert_eq!(content, "hi");
        assert_eq!(hits.load(std::sync::atomic::Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn stream_chat_429_retries_are_bounded_then_error_surfaces() {
        let (base_url, hits) = spawn_rate_limited_mock(None).await;
        let provider = retry_test_provider(base_url);

        let mut stream = provider
            .stream_chat(vec![ChatMessagePayload::user("hello".to_string())])
            .expect("stream setup");

        let first = stream.next().await.expect("stream item");
        let err = first.expect_err("exhausted retries must surface the 429");
        let message = format!("{err:#}");
        assert!(message.contains("429"), "error must keep status, got: {message}");
        assert!(
            message.contains("Rate limit exceeded"),
            "error must keep provider body, got: {message}"
        );
        assert_eq!(
            hits.load(std::sync::atomic::Ordering::SeqCst),
            RETRY_429_TEST_RETRIES as usize + 1,
            "initial attempt plus exactly `retries` extra attempts"
        );
    }
}
