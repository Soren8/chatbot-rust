use serde_json::{json, Value};

/// Returns the OpenAI function-calling definition for `brave_web_search`.
pub fn brave_web_search_tool() -> Value {
    json!({
        "type": "function",
        "function": {
            "name": "brave_web_search",
            "description": "Searches the web using Brave Search and returns extracted page content optimised for LLM use. Use this for current events, recent facts, or any information requiring up-to-date web content.",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "The search query"
                    }
                },
                "required": ["query"]
            }
        }
    })
}
