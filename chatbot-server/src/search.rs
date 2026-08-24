use std::pin::Pin;

use anyhow::Result;
use async_stream::try_stream;
use futures_util::Stream;
use futures_util::StreamExt;
use serde_json::Value;
use tracing::{debug, warn};

use crate::brave::BraveClient;
use crate::providers::openai::messages::ChatMessagePayload;
use crate::providers::openai::{OpenAiProvider, ToolStreamChunk};

const MAX_SEARCH_RESULT_LEN: usize = 8_000;

pub async fn search_augmented_stream(
    provider: &OpenAiProvider,
    messages: Vec<ChatMessagePayload>,
    brave: &BraveClient,
    tools: &[Value],
) -> Result<Pin<Box<dyn Stream<Item = Result<String>> + Send + 'static>>> {
    let mut initial_stream = provider.stream_chat_with_tools(messages.clone(), tools)?;
    let mut fallback_stream = provider.stream_chat(messages.clone())?;
    let final_provider = provider.clone();
    let brave = brave.clone();

    let stream = try_stream! {
        let mut sent_content = false;
        let mut tool_calls = None;

        while let Some(event) = initial_stream.next().await {
            match event {
                Ok(ToolStreamChunk::Content(chunk)) => {
                    sent_content = true;
                    yield chunk;
                }
                Ok(ToolStreamChunk::ToolCalls(calls)) => {
                    tool_calls = Some(calls);
                    break;
                }
                Err(err) => {
                    if sent_content {
                        Err(err)?;
                    } else {
                        warn!(?err, "tool-aware stream failed; falling back to regular streaming");
                        while let Some(chunk) = fallback_stream.next().await {
                            yield chunk?;
                        }
                        return;
                    }
                }
            }
        }

        let Some(tool_calls) = tool_calls else {
            return;
        };

        let mut prefix_chunks = Vec::new();
        let mut augmented = messages;
        let mut any_results = false;

        for tool_call in tool_calls {
            if tool_call.name != "brave_web_search" {
                continue;
            }

            let query = tool_call
                .arguments
                .get("query")
                .and_then(Value::as_str)
                .unwrap_or("");

            prefix_chunks.push(format!("<think>Searching for: {}...</think>", query));
            debug!(query = %query, "executing brave_web_search");

            let result = brave.search(query).await.unwrap_or_else(|e| {
                warn!(?e, "Brave Search request failed");
                format!("Search failed: {e}")
            });

            let truncated = if result.len() > MAX_SEARCH_RESULT_LEN {
                format!("{}...[truncated]", &result[..MAX_SEARCH_RESULT_LEN])
            } else {
                result
            };

            // Inject results as a user message — universally compatible with all
            // models, unlike the OpenAI tool-role format which many local models
            // don't handle correctly and causes them to loop on tool calls.
            augmented.push(ChatMessagePayload::user(format!(
                "[Web search results for \"{}\"]\n\n{}",
                query, truncated
            )));
            any_results = true;
        }

        if any_results {
            prefix_chunks.push("<think>Search complete.</think>".to_string());
        }

        for chunk in prefix_chunks {
            yield chunk;
        }

        let mut final_stream = final_provider.stream_chat(augmented)?;
        while let Some(chunk) = final_stream.next().await {
            yield chunk?;
        }
    };

    Ok(Box::pin(stream))
}
