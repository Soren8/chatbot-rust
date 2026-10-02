use anyhow::{Context, Result};
use once_cell::sync::OnceCell;
use reqwest::Client;
use serde::Deserialize;
use tracing::{info, warn};

#[derive(Deserialize)]
struct LlmContextResponse {
    grounding: Option<Grounding>,
}

#[derive(Deserialize)]
struct Grounding {
    generic: Vec<GroundingItem>,
}

#[derive(Deserialize)]
struct GroundingItem {
    url: String,
    title: Option<String>,
    snippets: Vec<String>,
}

const LLM_CONTEXT_URL: &str = "https://api.search.brave.com/res/v1/llm/context";

static HTTP_CLIENT: OnceCell<Client> = OnceCell::new();

fn http_client() -> &'static Client {
    HTTP_CLIENT.get_or_init(Client::new)
}

#[derive(Clone)]
pub struct BraveClient {
    api_key: String,
    /// Explicit fake results for owned routers. `Some` returns without any
    /// env read or HTTP; `None` on an owned client means real HTTP with no
    /// env stub. Live clients (`None` + `is_owned=false`) keep the original
    /// env-stub-first ordering.
    fake_results: Option<String>,
    is_owned: bool,
    endpoint: String,
}

impl BraveClient {
    fn new(api_key: String) -> Self {
        Self {
            api_key,
            fake_results: None,
            is_owned: false,
            endpoint: LLM_CONTEXT_URL.to_owned(),
        }
    }

    fn new_owned(api_key: String, fake_results: Option<String>) -> Self {
        Self {
            api_key,
            fake_results,
            is_owned: true,
            endpoint: LLM_CONTEXT_URL.to_owned(),
        }
    }

    #[cfg(test)]
    fn with_endpoint(mut self, endpoint: String) -> Self {
        self.endpoint = endpoint;
        self
    }

    pub async fn search(&self, query: &str) -> Result<String> {
        if self.is_owned {
            if let Some(ref fake) = self.fake_results {
                return Ok(fake.clone());
            }
            // Owned without fake: real HTTP, never the ambient stub.
        } else if let Ok(stub) = std::env::var("CHATBOT_TEST_BRAVE_RESULTS") {
            return Ok(stub);
        }

        let resp: LlmContextResponse = http_client()
            .get(&self.endpoint)
            .query(&[("q", query)])
            .header("X-Subscription-Token", &self.api_key)
            .header("Accept", "application/json")
            .send()
            .await
            .context("Brave LLM Context request failed")?
            .error_for_status()
            .context("Brave LLM Context returned error status")?
            .json()
            .await
            .context("failed to parse Brave LLM Context response")?;

        let items = resp.grounding.map(|g| g.generic).unwrap_or_default();
        if items.is_empty() {
            return Ok("No results found.".to_string());
        }

        Ok(items
            .iter()
            .filter(|item| !item.snippets.is_empty())
            .map(|item| {
                let header = match &item.title {
                    Some(title) => format!("## {}\n{}", title, item.url),
                    None => item.url.clone(),
                };
                format!("{}\n{}", header, item.snippets.join("\n"))
            })
            .collect::<Vec<_>>()
            .join("\n\n"))
    }
}

/// Returns a `BraveClient` for an explicit key, otherwise `None`.
/// Same messages as [`brave_client`]; dispatch calls this only in the gated
/// search branches so explicit router keys stay isolated.
pub fn brave_client_with_key(key: Option<&str>) -> Option<BraveClient> {
    brave_client_with_key_and_fake(key, None, false)
}

/// Owned variant: explicit key plus optional fake results, never reading
/// ambient env. `fake_results` `Some` short-circuits `search` without HTTP;
/// `None` means real HTTP with no env stub.
pub fn brave_client_with_key_and_fake(
    key: Option<&str>,
    fake_results: Option<String>,
    owned: bool,
) -> Option<BraveClient> {
    match key {
        Some(key) if !key.is_empty() => {
            info!("Brave Search client initialized");
            Some(if owned {
                BraveClient::new_owned(key.to_owned(), fake_results)
            } else {
                BraveClient::new(key.to_owned())
            })
        }
        _ => {
            warn!("BRAVE_API_KEY not set; Brave Search disabled");
            None
        }
    }
}

/// Returns a `BraveClient` if `BRAVE_API_KEY` is set, otherwise `None`.
/// Reads the env var on each call — cheap, and avoids singleton issues in tests.
/// The underlying HTTP connection pool (`http_client()`) is still a singleton.
pub fn brave_client() -> Option<BraveClient> {
    brave_client_with_key(std::env::var("BRAVE_API_KEY").ok().as_deref())
}

#[cfg(test)]
mod tests {
    use super::BraveClient;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
        sync::oneshot,
    };

    async fn spawn_mock(status: &str, body: &'static str) -> (String, oneshot::Receiver<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind mock");
        let addr = listener.local_addr().expect("mock address");
        let (request_tx, request_rx) = oneshot::channel();
        let status = status.to_owned();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept request");
            let mut bytes = Vec::new();
            loop {
                let mut chunk = [0; 1024];
                let count = stream.read(&mut chunk).await.expect("read request");
                assert_ne!(count, 0, "request ended before headers");
                bytes.extend_from_slice(&chunk[..count]);
                if bytes.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            let request = String::from_utf8(bytes).expect("request headers are UTF-8");
            let _ = request_tx.send(request);
            let response = format!(
                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            stream.write_all(response.as_bytes()).await.expect("write response");
        });
        (format!("http://{addr}/res/v1/llm/context"), request_rx)
    }

    fn client(endpoint: String) -> BraveClient {
        BraveClient::new_owned("test-key".into(), None).with_endpoint(endpoint)
    }

    #[tokio::test]
    async fn formats_grounding_and_sends_expected_request() {
        let body = r#"{"grounding":{"generic":[{"title":"First","url":"https://one.test","snippets":["alpha","beta"]},{"title":"Second","url":"https://two.test","snippets":["gamma"]},{"title":null,"url":"https://three.test","snippets":["delta"]},{"title":"Empty","url":"https://empty.test","snippets":[]}]}}"#;
        let (endpoint, request_rx) = spawn_mock("200 OK", body).await;
        let result = client(endpoint).search("cats & dogs").await.unwrap();
        assert_eq!(
            result,
            "## First\nhttps://one.test\nalpha\nbeta\n\n## Second\nhttps://two.test\ngamma\n\nhttps://three.test\ndelta"
        );

        let request = request_rx.await.expect("mock captured request");
        let request_line = request.lines().next().expect("request line");
        assert!(request_line.contains("q=cats+%26+dogs"), "{request_line}");
        let headers = request.split("\r\n\r\n").next().unwrap();
        assert!(headers.lines().skip(1).any(|line| {
            line.split_once(':').is_some_and(|(name, value)| {
                name.eq_ignore_ascii_case("x-subscription-token") && value.trim() == "test-key"
            })
        }));
        assert!(headers.lines().skip(1).any(|line| {
            line.split_once(':').is_some_and(|(name, value)| {
                name.eq_ignore_ascii_case("accept") && value.trim() == "application/json"
            })
        }));
    }

    #[tokio::test]
    async fn empty_and_missing_grounding_return_no_results() {
        for body in [r#"{"grounding":{"generic":[]}}"#, "{}"] {
            let (endpoint, _) = spawn_mock("200 OK", body).await;
            assert_eq!(client(endpoint).search("query").await.unwrap(), "No results found.");
        }
    }

    #[tokio::test]
    async fn non_success_status_returns_contextual_error() {
        let (endpoint, _) = spawn_mock("500 Internal Server Error", "{}").await;
        let error = client(endpoint).search("query").await.unwrap_err();
        assert!(format!("{error:#}").contains("Brave LLM Context returned error status"));
    }

    #[tokio::test]
    async fn malformed_json_returns_contextual_error() {
        let (endpoint, _) = spawn_mock("200 OK", "not json").await;
        let error = client(endpoint).search("query").await.unwrap_err();
        assert!(format!("{error:#}").contains("failed to parse Brave LLM Context response"));
    }
}
