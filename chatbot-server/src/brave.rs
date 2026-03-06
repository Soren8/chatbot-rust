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

static HTTP_CLIENT: OnceCell<Client> = OnceCell::new();

fn http_client() -> &'static Client {
    HTTP_CLIENT.get_or_init(Client::new)
}

pub struct BraveClient {
    api_key: String,
}

impl BraveClient {
    fn new(api_key: String) -> Self {
        Self { api_key }
    }

    pub async fn search(&self, query: &str) -> Result<String> {
        if let Ok(stub) = std::env::var("CHATBOT_TEST_BRAVE_RESULTS") {
            return Ok(stub);
        }

        let resp: LlmContextResponse = http_client()
            .get("https://api.search.brave.com/res/v1/llm/context")
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

/// Returns a `BraveClient` if `BRAVE_API_KEY` is set, otherwise `None`.
/// Reads the env var on each call — cheap, and avoids singleton issues in tests.
/// The underlying HTTP connection pool (`http_client()`) is still a singleton.
pub fn brave_client() -> Option<BraveClient> {
    match std::env::var("BRAVE_API_KEY") {
        Ok(key) if !key.is_empty() => {
            info!("Brave Search client initialized");
            Some(BraveClient::new(key))
        }
        _ => {
            warn!("BRAVE_API_KEY not set; Brave Search disabled");
            None
        }
    }
}
