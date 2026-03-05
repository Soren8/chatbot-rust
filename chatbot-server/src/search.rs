use std::pin::Pin;

use anyhow::Result;
use futures_util::Stream;
use futures_util::StreamExt;
use serde_json::Value;
use tracing::{debug, warn};

use crate::mcp::McpClient;
use crate::providers::openai::messages::ChatMessagePayload;
use crate::providers::openai::{OpenAiProvider, ToolCallResponse};

const MAX_TOOL_RESULT_LEN: usize = 8_000;

pub async fn search_augmented_stream(
    provider: &OpenAiProvider,
    messages: Vec<ChatMessagePayload>,
    mcp_client: &McpClient,
    tools: &[Value],
) -> Result<Pin<Box<dyn Stream<Item = Result<String>> + Send + 'static>>> {
    match provider.call_with_tools(&messages, tools).await {
        Ok(ToolCallResponse::ToolCalls(tool_calls)) => {
            let mut prefix_chunks: Vec<String> = Vec::new();
            let mut augmented = messages.clone();

            // Build the assistant message that echoes the tool_calls back
            let raw_tool_calls: Vec<Value> = tool_calls.iter().map(|tc| tc.raw.clone()).collect();
            augmented.push(ChatMessagePayload::assistant_with_tool_calls(raw_tool_calls));

            for tc in &tool_calls {
                if tc.name == "brave_web_search" {
                    let query = tc
                        .arguments
                        .get("query")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    prefix_chunks.push(format!(
                        "<think>Searching for: {}...</think>",
                        query
                    ));
                    debug!(query = %query, "executing brave_web_search via MCP");

                    let result = mcp_client
                        .call_tool(&tc.name, tc.arguments.clone())
                        .await
                        .unwrap_or_else(|e| {
                            warn!(?e, "MCP tool call failed");
                            format!("Search failed: {e}")
                        });

                    let truncated = if result.len() > MAX_TOOL_RESULT_LEN {
                        format!("{}...[truncated]", &result[..MAX_TOOL_RESULT_LEN])
                    } else {
                        result
                    };

                    augmented.push(ChatMessagePayload::tool(tc.id.clone(), truncated));
                }
            }

            prefix_chunks.push("<think>Search complete.</think>".to_string());

            // Stream final answer without tools to prevent loops
            let final_stream = provider.stream_chat(augmented)?;
            let prefix_stream =
                tokio_stream::iter(prefix_chunks.into_iter().map(Ok::<String, anyhow::Error>));
            let combined = prefix_stream.chain(final_stream);
            Ok(Box::pin(combined))
        }
        Ok(ToolCallResponse::Content(text)) => {
            // Model answered directly without invoking any tool
            debug!("model returned content directly (no tool calls)");
            let stream = tokio_stream::iter(vec![Ok(text)]);
            Ok(Box::pin(stream))
        }
        Err(err) => {
            // Fall back to regular streaming on any error
            warn!(?err, "call_with_tools failed; falling back to regular streaming");
            provider.stream_chat(messages)
        }
    }
}
