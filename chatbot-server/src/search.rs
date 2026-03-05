use std::pin::Pin;

use anyhow::Result;
use futures_util::Stream;
use futures_util::StreamExt;
use serde_json::Value;
use tracing::{debug, warn};

use crate::brave::BraveClient;
use crate::providers::openai::messages::ChatMessagePayload;
use crate::providers::openai::{OpenAiProvider, ToolCallResponse};

const MAX_SEARCH_RESULT_LEN: usize = 8_000;

pub async fn search_augmented_stream(
    provider: &OpenAiProvider,
    messages: Vec<ChatMessagePayload>,
    brave: &BraveClient,
    tools: &[Value],
) -> Result<Pin<Box<dyn Stream<Item = Result<String>> + Send + 'static>>> {
    match provider.call_with_tools(&messages, tools).await {
        Ok(ToolCallResponse::ToolCalls(tool_calls)) => {
            let mut prefix_chunks: Vec<String> = Vec::new();
            let mut augmented = messages.clone();

            let raw_tool_calls: Vec<Value> = tool_calls.iter().map(|tc| tc.raw.clone()).collect();
            augmented.push(ChatMessagePayload::assistant_with_tool_calls(raw_tool_calls));

            for tc in &tool_calls {
                if tc.name == "brave_web_search" {
                    let query = tc
                        .arguments
                        .get("query")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let count = tc
                        .arguments
                        .get("count")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(10) as usize;

                    prefix_chunks
                        .push(format!("<think>Searching for: {}...</think>", query));
                    debug!(query = %query, "executing brave_web_search");

                    let result = brave.search(query, count).await.unwrap_or_else(|e| {
                        warn!(?e, "Brave Search request failed");
                        format!("Search failed: {e}")
                    });

                    let truncated = if result.len() > MAX_SEARCH_RESULT_LEN {
                        format!("{}...[truncated]", &result[..MAX_SEARCH_RESULT_LEN])
                    } else {
                        result
                    };

                    augmented.push(ChatMessagePayload::tool(tc.id.clone(), truncated));
                }
            }

            prefix_chunks.push("<think>Search complete.</think>".to_string());

            let final_stream = provider.stream_chat(augmented)?;
            let prefix_stream =
                tokio_stream::iter(prefix_chunks.into_iter().map(Ok::<String, anyhow::Error>));
            let combined = prefix_stream.chain(final_stream);
            Ok(Box::pin(combined))
        }
        Ok(ToolCallResponse::Content(text)) => {
            debug!("model returned content directly (no tool calls)");
            let stream = tokio_stream::iter(vec![Ok(text)]);
            Ok(Box::pin(stream))
        }
        Err(err) => {
            warn!(?err, "call_with_tools failed; falling back to regular streaming");
            provider.stream_chat(messages)
        }
    }
}
