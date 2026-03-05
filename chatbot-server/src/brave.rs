use anyhow::{Context, Result};
use once_cell::sync::OnceCell;
use reqwest::Client;
use serde::Deserialize;
use tracing::{info, warn};

#[derive(Deserialize)]
struct SearchResponse {
    web: Option<WebResults>,
}

#[derive(Deserialize)]
struct WebResults {
    results: Vec<SearchResult>,
}

#[derive(Deserialize)]
struct SearchResult {
    title: String,
    url: String,
    description: Option<String>,
}

pub struct BraveClient {
    api_key: String,
    client: Client,
}

impl BraveClient {
    fn new(api_key: String) -> Self {
        Self {
            api_key,
            client: Client::new(),
        }
    }

    pub async fn search(&self, query: &str, count: usize) -> Result<String> {
        let count = count.clamp(1, 20);

        let resp: SearchResponse = self
            .client
            .get("https://api.search.brave.com/res/v1/web/search")
            .query(&[("q", query), ("count", &count.to_string())])
            .header("X-Subscription-Token", &self.api_key)
            .header("Accept", "application/json")
            .send()
            .await
            .context("Brave Search request failed")?
            .error_for_status()
            .context("Brave Search returned error status")?
            .json()
            .await
            .context("failed to parse Brave Search response")?;

        let results = resp.web.map(|w| w.results).unwrap_or_default();
        if results.is_empty() {
            return Ok("No results found.".to_string());
        }

        Ok(results
            .iter()
            .map(|r| {
                let mut parts = vec![r.title.as_str(), r.url.as_str()];
                if let Some(desc) = &r.description {
                    parts.push(desc.as_str());
                }
                parts.join("\n")
            })
            .collect::<Vec<_>>()
            .join("\n\n"))
    }
}

static BRAVE_CLIENT: OnceCell<Option<BraveClient>> = OnceCell::new();

pub fn brave_client() -> Option<&'static BraveClient> {
    BRAVE_CLIENT
        .get_or_init(|| match std::env::var("BRAVE_API_KEY") {
            Ok(key) if !key.is_empty() => {
                info!("Brave Search client initialized");
                Some(BraveClient::new(key))
            }
            _ => {
                warn!("BRAVE_API_KEY not set; Brave Search disabled");
                None
            }
        })
        .as_ref()
}
