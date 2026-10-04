use std::pin::Pin;

use anyhow::Result;
use async_stream::try_stream;
use futures_util::Stream;
use futures_util::StreamExt;
use serde_json::Value;
use tracing::{debug, warn};

use crate::brave::BraveClient;
use crate::providers::messages::ChatMessagePayload;
use crate::providers::openai::{OpenAiProvider, ToolStreamChunk};

const MAX_SEARCH_RESULT_LEN: usize = 8_000;

fn truncate_search_result(result: String) -> String {
    if result.len() > MAX_SEARCH_RESULT_LEN {
        let mut boundary = MAX_SEARCH_RESULT_LEN;
        while !result.is_char_boundary(boundary) {
            boundary -= 1;
        }
        format!("{}...[truncated]", &result[..boundary])
    } else {
        result
    }
}

#[cfg(test)]
mod tests {
    use super::{search_augmented_stream, truncate_search_result};
    use crate::{brave::brave_client_with_key_and_fake, providers::{messages::ChatMessagePayload, openai::OpenAiProvider}};
    use std::{io::Write, sync::{Arc, Mutex}};

    #[derive(Clone)]
    struct CapturedLogs(Arc<Mutex<Vec<u8>>>);

    impl Write for CapturedLogs {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> { Ok(()) }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for CapturedLogs {
        type Writer = CapturedLogs;
        fn make_writer(&'a self) -> Self::Writer { self.clone() }
    }

    #[tokio::test]
    async fn brave_status_failure_logs_and_followup_omit_private_upstream_details() {
        use axum::{routing::{get, post}, Json, Router};
        use serde_json::Value;

        let query = "BRAVE_PRIVATE_QUERY_TRACE_7431";
        let upstream_detail = "BRAVE_PRIVATE_UPSTREAM_BODY_8842";
        let requests = Arc::new(Mutex::new(Vec::<Value>::new()));
        let captured_requests = requests.clone();
        let mock = Router::new()
            .route("/context", get(move || async move {
                (axum::http::StatusCode::BAD_GATEWAY, upstream_detail)
            }))
            .route("/v1/chat/completions", post(move |Json(request): Json<Value>| {
            let captured_requests = captured_requests.clone();
            async move {
                let mut requests = captured_requests.lock().unwrap();
                requests.push(request);
                let response = if requests.len() == 1 {
                    format!(
                        "data: {{\"choices\":[{{\"delta\":{{\"tool_calls\":[{{\"index\":0,\"function\":{{\"name\":\"brave_web_search\",\"arguments\":\"{{\\\"query\\\":\\\"{query}\\\"}}\"}}}}]}}}}]}}\n\ndata: [DONE]\n\n"
                    )
                } else {
                    "data: {\"choices\":[{\"delta\":{\"content\":\"safe final answer\"}}]}\n\ndata: [DONE]\n\n".to_string()
                };
                ([(axum::http::header::CONTENT_TYPE, "text/event-stream")], response)
            }
        }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, mock).await.unwrap() });

        let provider = OpenAiProvider::new_owned(
            &chatbot_core::config::ProviderConfig {
                privacy_level: chatbot_core::config::PrivacyLevel::default_destination(),
                provider_name: "test".into(),
                provider_type: "openai".into(),
                tier: None,
                model_name: "test-model".into(),
                context_size: Some(4096),
                base_url: format!("http://{address}/v1"),
                api_key: None,
                allowed_providers: vec![],
                request_timeout: Some(5.0),
                rate_limit_retries: Some(0),
                rate_limit_max_wait_secs: None,
                test_chunks: None,
                search: true,
                xai_search: false,
                xai_zdr: false,
            },
            None,
            0,
            None,
        ).unwrap();
        let brave = brave_client_with_key_and_fake(Some("mock-key"), None, true)
            .unwrap()
            .with_endpoint(format!("http://{address}/context"));

        let logs = CapturedLogs(Arc::new(Mutex::new(Vec::new())));
        let subscriber = tracing_subscriber::fmt().with_max_level(tracing::Level::DEBUG)
            .with_ansi(false).with_writer(logs.clone()).finish();
        let _guard = tracing::subscriber::set_default(subscriber);
        tracing::callsite::rebuild_interest_cache();

        let mut stream = search_augmented_stream(
            &provider,
            vec![ChatMessagePayload::user("hello".into())],
            &brave,
            &[],
        ).await.unwrap();
        use futures_util::StreamExt;
        let mut output = String::new();
        while let Some(chunk) = stream.next().await {
            output.push_str(&chunk.unwrap());
        }
        let captured = String::from_utf8(logs.0.lock().unwrap().clone()).unwrap();
        let requests = requests.lock().unwrap();
        assert_eq!(requests.len(), 2, "expected the tool request and follow-up");
        let followup = &requests[1];
        let followup_text = serde_json::to_string(&followup["messages"]).unwrap();
        assert!(followup_text.contains("Search failed: upstream request unavailable"), "sanitized failure was not injected into follow-up: {followup_text}");
        assert!(followup_text.contains(query), "search query missing from follow-up: {followup_text}");
        assert!(!followup_text.contains(upstream_detail), "upstream response body leaked into follow-up: {followup_text}");
        assert!(!followup_text.contains(&format!("http://{address}")), "upstream URL leaked into follow-up: {followup_text}");
        for text in [&captured, &output] {
            assert!(!text.contains(upstream_detail), "upstream response body leaked: {text}");
        }
        assert!(!captured.contains(query), "private query entered logs: {captured}");
        assert!(captured.contains("upstream_request"), "bounded failure category missing: {captured}");
        assert!(output.contains(query), "the requested query may remain visible in its stream");
    }

    #[test]
    fn truncating_multibyte_results_preserves_characters_and_marks_clipping() {
        let result = format!("{}{}", "a".repeat(7_999), "é".repeat(10));
        let truncated = truncate_search_result(result);
        assert!(truncated.starts_with(&"a".repeat(7_999)));
        assert!(truncated.ends_with("...[truncated]"));
    }

    #[test]
    fn long_ascii_results_include_truncation_marker() {
        assert!(truncate_search_result("a".repeat(8_010)).ends_with("...[truncated]"));
    }
}

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
            debug!("executing brave_web_search");

            let result = brave.search(query).await.unwrap_or_else(|_| {
                warn!(failure = "upstream_request", "Brave Search request failed");
                "Search failed: upstream request unavailable".to_string()
            });

            let truncated = truncate_search_result(result);

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
