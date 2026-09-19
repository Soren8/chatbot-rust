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

#[derive(Clone)]
pub struct BraveClient {
    api_key: String,
    /// Explicit fake results for owned routers. `Some` returns without any
    /// env read or HTTP; `None` on an owned client means real HTTP with no
    /// env stub. Live clients (`None` + `is_owned=false`) keep the original
    /// env-stub-first ordering.
    fake_results: Option<String>,
    is_owned: bool,
}

impl BraveClient {
    fn new(api_key: String) -> Self {
        Self {
            api_key,
            fake_results: None,
            is_owned: false,
        }
    }

    fn new_owned(api_key: String, fake_results: Option<String>) -> Self {
        Self {
            api_key,
            fake_results,
            is_owned: true,
        }
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
