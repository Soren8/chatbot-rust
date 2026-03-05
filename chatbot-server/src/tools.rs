use serde_json::{json, Value};

/// Returns the OpenAI function-calling definition for `brave_web_search`.
pub fn brave_web_search_tool() -> Value {
    json!({
        "type": "function",
        "function": {
            "name": "brave_web_search",
            "description": "Performs a web search using Brave Search. Use this for current events, recent facts, or any information that requires up-to-date web content.",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "The search query"
                    },
                    "count": {
                        "type": "integer",
                        "description": "Number of results to return (1-20, default 10)",
                        "default": 10
                    }
                },
                "required": ["query"]
            }
        }
    })
}
