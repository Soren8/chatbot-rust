//! Shared provider message DTO.
//!
//! The OpenAI adapter, the XAI adapter, the search fallback and the shared
//! generation dispatch all exchange this one message shape. Serialization
//! uses the OpenAI-compatible wire format.

use serde::Serialize;
use serde_json::Value;

#[derive(Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ContentPart {
    Text { text: String },
    ImageUrl { image_url: ImageUrlPart },
}

#[derive(Clone, Serialize)]
pub struct ImageUrlPart {
    pub url: String,
}

#[derive(Clone, Serialize)]
#[serde(untagged)]
pub enum ChatMessageContent {
    Text(String),
    MultiModal(Vec<ContentPart>),
}

#[derive(Clone, Serialize)]
pub struct ChatMessagePayload {
    pub role: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<ChatMessageContent>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_calls: Option<Vec<Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_call_id: Option<String>,
}

impl ChatMessagePayload {
    pub fn system(content: String) -> Self {
        Self {
            role: "system".to_string(),
            content: Some(ChatMessageContent::Text(content)),
            tool_calls: None,
            tool_call_id: None,
        }
    }

    pub fn user(content: String) -> Self {
        Self {
            role: "user".to_string(),
            content: Some(ChatMessageContent::MultiModal(vec![
                ContentPart::Text { text: content },
            ])),
            tool_calls: None,
            tool_call_id: None,
        }
    }

    pub fn user_with_content(content: ChatMessageContent) -> Self {
        Self {
            role: "user".to_string(),
            content: Some(content),
            tool_calls: None,
            tool_call_id: None,
        }
    }

    pub fn assistant(content: String) -> Self {
        Self {
            role: "assistant".to_string(),
            content: Some(ChatMessageContent::Text(content)),
            tool_calls: None,
            tool_call_id: None,
        }
    }
}
