use anyhow::{Context, Result};
use once_cell::sync::OnceCell;
use reqwest::Client;
use serde_json::{json, Value};
use tracing::{info, warn};

pub struct McpToolDef {
    pub name: String,
    pub description: String,
    pub input_schema: Value,
}

pub struct McpClient {
    pub base_url: String,
    client: Client,
}

impl McpClient {
    pub fn new(base_url: String) -> Self {
        Self {
            base_url,
            client: Client::new(),
        }
    }

    pub async fn list_tools(&self) -> Result<Vec<McpToolDef>> {
        let payload = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list",
            "params": {}
        });

        let resp: Value = self
            .client
            .post(&self.base_url)
            .json(&payload)
            .send()
            .await
            .context("MCP tools/list request failed")?
            .json()
            .await
            .context("MCP tools/list response parse failed")?;

        let tools = resp["result"]["tools"]
            .as_array()
            .cloned()
            .unwrap_or_default();

        Ok(tools
            .into_iter()
            .filter_map(|t| {
                let name = t["name"].as_str()?.to_string();
                let description = t["description"].as_str().unwrap_or("").to_string();
                let input_schema = t["inputSchema"].clone();
                Some(McpToolDef {
                    name,
                    description,
                    input_schema,
                })
            })
            .collect())
    }

    pub async fn call_tool(&self, name: &str, arguments: Value) -> Result<String> {
        let payload = json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": name,
                "arguments": arguments
            }
        });

        let resp: Value = self
            .client
            .post(&self.base_url)
            .json(&payload)
            .send()
            .await
            .context("MCP tools/call request failed")?
            .json()
            .await
            .context("MCP tools/call response parse failed")?;

        let content = &resp["result"]["content"];
        if let Some(arr) = content.as_array() {
            let text = arr
                .iter()
                .filter_map(|item| {
                    if item["type"].as_str() == Some("text") {
                        item["text"].as_str().map(|s| s.to_string())
                    } else {
                        None
                    }
                })
                .collect::<Vec<_>>()
                .join("\n");
            Ok(text)
        } else if let Some(text) = content.as_str() {
            Ok(text.to_string())
        } else {
            Ok(resp["result"].to_string())
        }
    }
}

static MCP_CLIENT: OnceCell<Option<McpClient>> = OnceCell::new();

pub fn mcp_client() -> Option<&'static McpClient> {
    MCP_CLIENT
        .get_or_init(|| match std::env::var("BRAVE_MCP_URL") {
            Ok(url) if !url.is_empty() => {
                info!(url = %url, "Brave Search MCP client initialized");
                Some(McpClient::new(url))
            }
            _ => {
                warn!("BRAVE_MCP_URL not set; Brave Search MCP disabled");
                None
            }
        })
        .as_ref()
}

pub async fn init_mcp() {
    if let Some(client) = mcp_client() {
        match client.list_tools().await {
            Ok(tools) => {
                let names: Vec<&str> = tools.iter().map(|t| t.name.as_str()).collect();
                info!(tools = ?names, "MCP tool discovery successful");
            }
            Err(err) => {
                warn!(?err, "MCP tool discovery failed; search will still be attempted at runtime");
            }
        }
    }
}
