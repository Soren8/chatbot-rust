use std::{collections::HashMap, sync::Mutex, time::Duration};

use anyhow::{Context, Result};
use once_cell::sync::Lazy;
use reqwest::Client;

pub mod generation;
pub mod message_utils;
pub mod messages;
pub mod openai;
pub mod xai;

/// Provider HTTP clients shared across turns, keyed by the only builder
/// input (`request_timeout`), so each turn reuses the pooled connections
/// instead of paying DNS + TCP + TLS before the first token.
static PROVIDER_CLIENTS: Lazy<Mutex<HashMap<Duration, Client>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

pub(crate) fn shared_client(timeout: Duration) -> Result<Client> {
    let mut clients = PROVIDER_CLIENTS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(client) = clients.get(&timeout) {
        return Ok(client.clone());
    }
    let client = Client::builder()
        .timeout(timeout)
        .build()
        .context("failed to build reqwest client")?;
    clients.insert(timeout, client.clone());
    Ok(client)
}
