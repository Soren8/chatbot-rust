use std::{collections::HashMap, sync::Mutex, time::Duration};

use anyhow::{Context, Result};
use once_cell::sync::Lazy;
use reqwest::Client;

pub mod generation;
pub mod message_utils;
pub mod messages;
pub mod openai;
pub mod xai;

pub(crate) fn push_utf8(buffer: &mut String, pending: &mut Vec<u8>, bytes: &[u8]) {
    pending.extend_from_slice(bytes);
    loop {
        match std::str::from_utf8(pending) {
            Ok(valid) => {
                buffer.push_str(valid);
                pending.clear();
                break;
            }
            Err(error) => {
                let valid_len = error.valid_up_to();
                if valid_len > 0 {
                    buffer.push_str(std::str::from_utf8(&pending[..valid_len]).expect("valid prefix"));
                    pending.drain(..valid_len);
                }
                match error.error_len() {
                    Some(invalid_len) => {
                        buffer.push_str(&String::from_utf8_lossy(&pending[..invalid_len]));
                        pending.drain(..invalid_len);
                    }
                    None => break,
                }
            }
        }
    }
}

pub(crate) fn flush_utf8(buffer: &mut String, pending: &mut Vec<u8>) {
    buffer.push_str(&String::from_utf8_lossy(pending));
    pending.clear();
}

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

#[cfg(test)]
mod tests {
    use super::{flush_utf8, push_utf8};

    #[test]
    fn push_utf8_preserves_split_two_byte_character() {
        let mut output = String::new();
        let mut pending = Vec::new();
        push_utf8(&mut output, &mut pending, b"caf\xC3");
        assert_eq!(output, "caf");
        assert_eq!(pending, [0xC3]);
        push_utf8(&mut output, &mut pending, b"\xA9");
        assert_eq!(output, "café");
        assert!(pending.is_empty());
    }

    #[test]
    fn push_utf8_preserves_split_four_byte_character() {
        let mut output = String::new();
        let mut pending = Vec::new();
        push_utf8(&mut output, &mut pending, b"\xF0\x9F");
        push_utf8(&mut output, &mut pending, b"\x8D\x95");
        assert_eq!(output, "🍕");
        assert!(pending.is_empty());
    }

    #[test]
    fn push_utf8_replaces_invalid_bytes_lossily() {
        let mut output = String::new();
        let mut pending = Vec::new();
        push_utf8(&mut output, &mut pending, b"a\xFFb");
        assert_eq!(output, "a�b");
        assert!(pending.is_empty());
    }

    #[test]
    fn flush_utf8_replaces_trailing_incomplete_sequence() {
        let mut output = String::new();
        let mut pending = Vec::new();
        push_utf8(&mut output, &mut pending, b"ok\xE2\x98");
        assert_eq!(output, "ok");
        flush_utf8(&mut output, &mut pending);
        assert_eq!(output, "ok�");
        assert!(pending.is_empty());
    }
}
