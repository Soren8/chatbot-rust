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

pub struct ToolCall {
    pub id: String,
    pub name: String,
    pub arguments: Value,
    pub raw: Value,
}

pub enum ToolCallResponse {
    Content(String),
    ToolCalls(Vec<ToolCall>),
}

pub mod messages {
    use serde::Serialize;
    use serde_json::Value;

    #[derive(Clone, Serialize)]
    pub struct ChatMessagePayload {
        pub role: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub content: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub tool_calls: Option<Vec<Value>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub tool_call_id: Option<String>,
    }

    impl ChatMessagePayload {
        pub fn system(content: String) -> Self {
            Self {
                role: "system".to_string(),
                content: Some(content),
                tool_calls: None,
                tool_call_id: None,
            }
        }

        pub fn user(content: String) -> Self {
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
                content: Some(content),
                tool_calls: None,
                tool_call_id: None,
            }
        }

        pub fn assistant_with_tool_calls(tool_calls: Vec<Value>) -> Self {
            Self {
                role: "assistant".to_string(),
                content: None,
                tool_calls: Some(tool_calls),
                tool_call_id: None,
            }
        }

        pub fn tool(tool_call_id: String, content: String) -> Self {
            Self {
                role: "tool".to_string(),
                content: Some(content),
                tool_calls: None,
                tool_call_id: Some(tool_call_id),
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

    pub async fn call_with_tools(
        &self,
        messages: &[ChatMessagePayload],
        tools: &[Value],
    ) -> Result<ToolCallResponse> {
        if let Ok(query) = std::env::var("CHATBOT_TEST_OPENAI_TOOL_CALL_QUERY") {
            if !query.is_empty() {
                let raw = serde_json::json!({
                    "id": "test_call_1",
                    "type": "function",
                    "function": {
                        "name": "brave_web_search",
                        "arguments": format!("{{\"query\":\"{}\"}}", query)
                    }
                });
                return Ok(ToolCallResponse::ToolCalls(vec![ToolCall {
                    id: "test_call_1".to_string(),
                    name: "brave_web_search".to_string(),
                    arguments: serde_json::json!({ "query": query }),
                    raw,
                }]));
            }
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
            messages: messages.to_vec(),
            stream: false,
            temperature: 0.7,
            provider,
            tools: Some(tools.to_vec()),
            tool_choice: Some("auto".to_string()),
        };

        let url = format!("{}/chat/completions", self.base_url.trim_end_matches('/'));

        let response: Value = self
            .client
            .post(url)
            .bearer_auth(api_key)
            .json(&payload)
            .send()
            .await
            .context("failed to send tool call request")?
            .error_for_status()
            .context("tool call request returned error status")?
            .json()
            .await
            .context("failed to parse tool call response")?;

        let message = &response["choices"][0]["message"];

        if let Some(raw_tool_calls) = message.get("tool_calls").and_then(|v| v.as_array()) {
            if !raw_tool_calls.is_empty() {
                let calls = raw_tool_calls
                    .iter()
                    .filter_map(|tc| {
                        let id = tc["id"].as_str()?.to_string();
                        let name = tc["function"]["name"].as_str()?.to_string();
                        let args_str = tc["function"]["arguments"].as_str().unwrap_or("{}");
                        let arguments =
                            serde_json::from_str(args_str).unwrap_or(serde_json::json!({}));
                        Some(ToolCall {
                            id,
                            name,
                            arguments,
                            raw: tc.clone(),
                        })
                    })
                    .collect::<Vec<_>>();

                if !calls.is_empty() {
                    return Ok(ToolCallResponse::ToolCalls(calls));
                }
            }
        }

        let content = message
            .get("content")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        Ok(ToolCallResponse::Content(content))
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
}
