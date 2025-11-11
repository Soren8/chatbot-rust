use crate::config::ProviderConfig;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use pyo3::prelude::*;
use pyo3::types::PyAnyMethods;
use pyo3::types::{PyBytes, PyDict, PyList};
use pyo3::Py;
use serde::Deserialize;

pub struct PythonResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct SessionContext {
    pub session_id: String,
    pub username: Option<String>,
    pub encryption_key: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub struct HomeBootstrap {
    pub session_id: String,
    pub username: Option<String>,
    pub csrf_token: String,
    pub set_cookie: Option<String>,
}

/// Initializes the embedded Python interpreter and imports core application modules.
#[allow(deprecated)]
pub fn initialize_python() -> PyResult<()> {
    // For now we simply ensure the interpreter spins up.
    Python::attach(|_py| Ok(()))
}

/// Placeholder helper illustrating how Rust will invoke Python callables.
#[allow(deprecated)]
pub fn call_python_function(module: &str, function: &str) -> PyResult<Py<PyAny>> {
    Python::attach(|py| {
        let module = py.import(module)?;
        let callable = module.getattr(function)?;
        let result = callable.call0()?;
        Ok(result.unbind())
    })
}

/// Proxy a request into the Flask app and return the raw HTTP artifacts.
pub fn proxy_request(
    method: &str,
    path: &str,
    query_string: Option<&str>,
    headers: &[(String, String)],
    cookie_header: Option<&str>,
    body: Option<&[u8]>,
) -> PyResult<PythonResponse> {
    Python::attach(|py| {
        let bridge = py.import("app.rust_bridge")?;

        let kwargs = PyDict::new(py);

        if let Some(query) = query_string {
            kwargs.set_item("query_string", query)?;
        }

        if !headers.is_empty() {
            let header_map = PyDict::new(py);
            for (name, value) in headers {
                header_map.set_item(name, value)?;
            }
            kwargs.set_item("headers", header_map)?;
        }

        if let Some(cookie) = cookie_header {
            kwargs.set_item("cookie_header", cookie)?;
        }

        if let Some(body_bytes) = body {
            let py_body = PyBytes::new(py, body_bytes);
            kwargs.set_item("body", py_body)?;
        }

        let result = bridge.call_method("handle_request", (method, path), Some(&kwargs))?;
        let (status, header_items, body_bytes): (u16, Vec<(String, String)>, Vec<u8>) =
            result.extract()?;

        Ok(PythonResponse {
            status,
            headers: header_items,
            body: body_bytes,
        })
    })
}

/// Validate a CSRF token against the Flask session state.
pub fn validate_csrf_token(cookie_header: Option<&str>, token: &str) -> PyResult<bool> {
    Python::attach(|py| {
        let bridge = py.import("app.rust_bridge")?;
        let result = bridge.call_method("validate_csrf_token", (cookie_header, token), None)?;
        result.extract()
    })
}

/// Finalize login by deferring to Flask session handling.
pub fn finalize_login(
    cookie_header: Option<&str>,
    username: &str,
    encryption_key: &[u8],
) -> PyResult<PythonResponse> {
    Python::attach(|py| {
        let bridge = py.import("app.rust_bridge")?;
        let key = PyBytes::new(py, encryption_key);
        let result = bridge.call_method("finalize_login", (cookie_header, username, key), None)?;
        let (status, header_items, body_bytes): (u16, Vec<(String, String)>, Vec<u8>) =
            result.extract()?;

        Ok(PythonResponse {
            status,
            headers: header_items,
            body: body_bytes,
        })
    })
}

/// Clear Flask session state and redirect back to the home page.
pub fn logout_user(cookie_header: Option<&str>) -> PyResult<PythonResponse> {
    Python::attach(|py| {
        let bridge = py.import("app.rust_bridge")?;
        let result = bridge.call_method("logout_user", (cookie_header,), None)?;
        let (status, header_items, body_bytes): (u16, Vec<(String, String)>, Vec<u8>) =
            result.extract()?;

        Ok(PythonResponse {
            status,
            headers: header_items,
            body: body_bytes,
        })
    })
}

pub fn session_context(cookie_header: Option<&str>) -> PyResult<SessionContext> {
    Python::attach(|py| {
        let bridge = py.import("app.rust_bridge")?;
        let result = bridge.call_method("get_session_context", (cookie_header,), None)?;
        let (session_id, username, encryption_key): (String, Option<String>, Option<Vec<u8>>) =
            result.extract()?;
        Ok(SessionContext {
            session_id,
            username,
            encryption_key,
        })
    })
}

pub fn session_set_memory(session_id: &str, memory: &str) -> PyResult<()> {
    Python::attach(|py| {
        let bridge = py.import("app.rust_bridge")?;
        bridge.call_method("set_session_memory", (session_id, memory), None)?;
        Ok(())
    })
}

pub fn session_set_system_prompt(session_id: &str, prompt: &str) -> PyResult<()> {
    Python::attach(|py| {
        let bridge = py.import("app.rust_bridge")?;
        bridge.call_method("set_session_system_prompt", (session_id, prompt), None)?;
        Ok(())
    })
}

pub fn session_set_history(session_id: &str, history: &[(String, String)]) -> PyResult<()> {
    Python::attach(|py| {
        let bridge = py.import("app.rust_bridge")?;
        let py_history = PyList::new(py, history.iter().map(|(u, a)| (u.as_str(), a.as_str())))?;
        bridge.call_method("set_session_history", (session_id, py_history), None)?;
        Ok(())
    })
}

pub fn session_get_history(session_id: &str) -> PyResult<Vec<(String, String)>> {
    Python::attach(|py| {
        let bridge = py.import("app.rust_bridge")?;
        let result = bridge.call_method("get_session_history", (session_id,), None)?;
        result.extract()
    })
}

/// Render the home page via Flask and return the complete response.
pub fn render_home(cookie_header: Option<&str>) -> PyResult<PythonResponse> {
    Python::attach(|py| {
        let bridge = py.import("app.rust_bridge")?;
        let result = bridge.call_method("render_home", (cookie_header,), None)?;
        let (status, header_items, body_bytes): (u16, Vec<(String, String)>, Vec<u8>) =
            result.extract()?;

        Ok(PythonResponse {
            status,
            headers: header_items,
            body: body_bytes,
        })
    })
}

pub fn prepare_home_context(cookie_header: Option<&str>) -> PyResult<HomeBootstrap> {
    Python::attach(|py| {
        let bridge = py.import("app.rust_bridge")?;
        let result = bridge.call_method("prepare_home_context", (cookie_header,), None)?;
        let (session_id, username, csrf_token, set_cookie): (
            String,
            Option<String>,
            String,
            Option<String>,
        ) = result.extract()?;

        Ok(HomeBootstrap {
            session_id,
            username,
            csrf_token,
            set_cookie,
        })
    })
}

#[derive(Debug, Clone)]
pub struct ChatContext {
    pub session_id: String,
    pub username: Option<String>,
    pub set_name: String,
    pub memory_text: String,
    pub system_prompt: String,
    pub history: Vec<(String, String)>,
    pub encrypted: bool,
    pub model_name: String,
    pub provider: ProviderConfig,
    pub encryption_key: Option<Vec<u8>>,
    pub test_chunks: Option<Vec<String>>,
}

pub struct ChatPrepareResult {
    pub context: Option<ChatContext>,
    pub error: Option<PythonResponse>,
}

pub struct ChatRequestData<'a> {
    pub message: &'a str,
    pub system_prompt: Option<&'a str>,
    pub set_name: Option<&'a str>,
    pub model_name: Option<&'a str>,
    pub encrypted: bool,
}

pub struct RegeneratePrepareResult {
    pub context: Option<ChatContext>,
    pub insertion_index: Option<usize>,
    pub error: Option<PythonResponse>,
}

pub struct RegenerateRequestData<'a> {
    pub message: &'a str,
    pub system_prompt: Option<&'a str>,
    pub set_name: Option<&'a str>,
    pub model_name: Option<&'a str>,
    pub encrypted: bool,
    pub pair_index: Option<i32>,
}

#[derive(Deserialize)]
struct ChatContextJson {
    session_id: String,
    username: Option<String>,
    set_name: String,
    memory_text: String,
    system_prompt: String,
    history: Vec<Vec<String>>,
    encrypted: bool,
    model_name: String,
    provider_config: ProviderConfig,
    encryption_key: Option<String>,
    test_chunks: Option<Vec<String>>,
}

impl TryFrom<ChatContextJson> for ChatContext {
    type Error = PyErr;

    fn try_from(value: ChatContextJson) -> PyResult<Self> {
        let history = value
            .history
            .into_iter()
            .filter_map(|pair| {
                if pair.len() == 2 {
                    Some((pair[0].clone(), pair[1].clone()))
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();

        let encryption_key = match value.encryption_key {
            Some(encoded) => {
                let decoded = STANDARD.decode(encoded.as_bytes()).map_err(|err| {
                    PyErr::new::<pyo3::exceptions::PyValueError, _>(err.to_string())
                })?;
                Some(decoded)
            }
            None => None,
        };

        let mut provider = value.provider_config;
        // If the top-level context provided test chunks (via CHATBOT_TEST_OPENAI_CHUNKS),
        // prefer those over an absent provider-level test_chunks value so tests can stub
        // provider streaming without modifying provider config dicts.
        if provider.test_chunks.is_none() {
            provider.test_chunks = value.test_chunks.clone();
        }

        Ok(Self {
            session_id: value.session_id,
            username: value.username,
            set_name: value.set_name,
            memory_text: value.memory_text,
            system_prompt: value.system_prompt,
            history,
            encrypted: value.encrypted,
            model_name: value.model_name,
            provider,
            encryption_key,
            test_chunks: value.test_chunks,
        })
    }
}

pub fn chat_prepare(
    cookie_header: Option<&str>,
    payload: &ChatRequestData<'_>,
) -> PyResult<ChatPrepareResult> {
    Python::attach(|py| {
        let bridge = py.import("app.rust_bridge")?;
        let py_payload = PyDict::new(py);
        py_payload.set_item("message", payload.message)?;
        if let Some(system_prompt) = payload.system_prompt {
            py_payload.set_item("system_prompt", system_prompt)?;
        }
        if let Some(set_name) = payload.set_name {
            py_payload.set_item("set_name", set_name)?;
        }
        if let Some(model_name) = payload.model_name {
            py_payload.set_item("model_name", model_name)?;
        }
        py_payload.set_item("encrypted", payload.encrypted)?;

        let result_any = bridge.call_method("chat_prepare", (cookie_header, py_payload), None)?;
        let result_dict = result_any.downcast::<PyDict>()?;

        let ok = result_dict
            .get_item("ok")?
            .and_then(|flag| flag.extract().ok())
            .unwrap_or(false);
        if !ok {
            let response_obj = result_dict.get_item("response")?.ok_or_else(|| {
                PyErr::new::<pyo3::exceptions::PyValueError, _>("response missing")
            })?;
            let (status, headers, body_bytes): (u16, Vec<(String, String)>, Vec<u8>) =
                response_obj.extract()?;
            return Ok(ChatPrepareResult {
                context: None,
                error: Some(PythonResponse {
                    status,
                    headers,
                    body: body_bytes,
                }),
            });
        }

        let context_obj = result_dict
            .get_item("context")?
            .ok_or_else(|| PyErr::new::<pyo3::exceptions::PyValueError, _>("context missing"))?;
        let context_json: String = context_obj.extract()?;
        let parsed: ChatContextJson = serde_json::from_str(&context_json)
            .map_err(|err| PyErr::new::<pyo3::exceptions::PyValueError, _>(err.to_string()))?;
        let context = ChatContext::try_from(parsed)?;

        Ok(ChatPrepareResult {
            context: Some(context),
            error: None,
        })
    })
}

pub fn chat_finalize(
    cookie_header: Option<&str>,
    session_id: &str,
    set_name: &str,
    user_message: &str,
    assistant_response: &str,
    encryption_key: Option<&[u8]>,
) -> PyResult<Vec<String>> {
    Python::attach(|py| {
        let bridge = py.import("app.rust_bridge")?;
        let result = bridge.call_method(
            "chat_finalize",
            (
                cookie_header,
                session_id,
                set_name,
                user_message,
                assistant_response,
                encryption_key,
            ),
            None,
        )?;
        result.extract()
    })
}

pub fn chat_release_lock(session_id: &str) -> PyResult<()> {
    Python::attach(|py| {
        let bridge = py.import("app.rust_bridge")?;
        bridge.call_method("chat_release_lock", (session_id,), None)?;
        Ok(())
    })
}

pub fn regenerate_prepare(
    cookie_header: Option<&str>,
    payload: &RegenerateRequestData<'_>,
) -> PyResult<RegeneratePrepareResult> {
    Python::attach(|py| {
        let bridge = py.import("app.rust_bridge")?;
        let py_payload = PyDict::new(py);
        py_payload.set_item("message", payload.message)?;
        if let Some(system_prompt) = payload.system_prompt {
            py_payload.set_item("system_prompt", system_prompt)?;
        }
        if let Some(set_name) = payload.set_name {
            py_payload.set_item("set_name", set_name)?;
        }
        if let Some(model_name) = payload.model_name {
            py_payload.set_item("model_name", model_name)?;
        }
        if let Some(pair_index) = payload.pair_index {
            py_payload.set_item("pair_index", pair_index)?;
        }
        py_payload.set_item("encrypted", payload.encrypted)?;

        let result_any =
            bridge.call_method("regenerate_prepare", (cookie_header, py_payload), None)?;
        let result_dict = result_any.downcast::<PyDict>()?;

        let ok = result_dict
            .get_item("ok")?
            .and_then(|flag| flag.extract().ok())
            .unwrap_or(false);
        if !ok {
            let response_obj = result_dict.get_item("response")?.ok_or_else(|| {
                PyErr::new::<pyo3::exceptions::PyValueError, _>("response missing")
            })?;
            let (status, headers, body_bytes): (u16, Vec<(String, String)>, Vec<u8>) =
                response_obj.extract()?;
            return Ok(RegeneratePrepareResult {
                context: None,
                insertion_index: None,
                error: Some(PythonResponse {
                    status,
                    headers,
                    body: body_bytes,
                }),
            });
        }

        let context_obj = result_dict
            .get_item("context")?
            .ok_or_else(|| PyErr::new::<pyo3::exceptions::PyValueError, _>("context missing"))?;
        let context_json: String = context_obj.extract()?;
        let parsed: ChatContextJson = serde_json::from_str(&context_json)
            .map_err(|err| PyErr::new::<pyo3::exceptions::PyValueError, _>(err.to_string()))?;
        let context = ChatContext::try_from(parsed)?;

        let insertion_index = match result_dict.get_item("insertion_index")? {
            Some(value) if !value.is_none() => {
                let idx: i64 = value.extract().map_err(|err| {
                    PyErr::new::<pyo3::exceptions::PyValueError, _>(err.to_string())
                })?;
                if idx < 0 {
                    None
                } else {
                    Some(idx as usize)
                }
            }
            _ => None,
        };

        Ok(RegeneratePrepareResult {
            context: Some(context),
            insertion_index,
            error: None,
        })
    })
}

pub fn regenerate_finalize(
    cookie_header: Option<&str>,
    session_id: &str,
    set_name: &str,
    user_message: &str,
    assistant_response: &str,
    insertion_index: Option<usize>,
    encryption_key: Option<&[u8]>,
) -> PyResult<Vec<String>> {
    Python::attach(|py| {
        let bridge = py.import("app.rust_bridge")?;
        let idx = insertion_index.map(|value| value as i64);
        let result = bridge.call_method(
            "regenerate_finalize",
            (
                cookie_header,
                session_id,
                set_name,
                user_message,
                assistant_response,
                idx,
                encryption_key,
            ),
            None,
        )?;
        result.extract()
    })
}

pub fn generate_tts(
    cookie_header: Option<&str>,
    csrf_token: &str,
    content_type: Option<&str>,
    body: Option<&[u8]>,
) -> PyResult<PythonResponse> {
    Python::attach(|py| {
        let bridge = py.import("app.rust_bridge")?;
        let kwargs = PyDict::new(py);
        kwargs.set_item("csrf_token", csrf_token)?;
        if let Some(content_type) = content_type {
            kwargs.set_item("content_type", content_type)?;
        }
        if let Some(body_bytes) = body {
            let py_body = PyBytes::new(py, body_bytes);
            kwargs.set_item("body", py_body)?;
        }

        let result = bridge.call_method("generate_tts", (cookie_header,), Some(&kwargs))?;
        let (status, header_items, body_bytes): (u16, Vec<(String, String)>, Vec<u8>) =
            result.extract()?;

        Ok(PythonResponse {
            status,
            headers: header_items,
            body: body_bytes,
        })
    })
}

pub fn reset_chat(cookie_header: Option<&str>, set_name: Option<&str>) -> PyResult<PythonResponse> {
    Python::attach(|py| {
        let bridge = py.import("app.rust_bridge")?;
        let payload = PyDict::new(py);
        if let Some(set_name) = set_name {
            payload.set_item("set_name", set_name)?;
        }

        let result = bridge.call_method("reset_chat", (cookie_header, payload), None)?;
        let (status, headers, body_bytes): (u16, Vec<(String, String)>, Vec<u8>) =
            result.extract()?;

        Ok(PythonResponse {
            status,
            headers,
            body: body_bytes,
        })
    })
}

pub fn get_sets(cookie_header: Option<&str>) -> PyResult<PythonResponse> {
    Python::attach(|py| {
        let bridge = py.import("app.rust_bridge")?;
        let result = bridge.call_method("get_sets", (cookie_header,), None)?;
        let (status, headers, body_bytes): (u16, Vec<(String, String)>, Vec<u8>) =
            result.extract()?;

        Ok(PythonResponse {
            status,
            headers,
            body: body_bytes,
        })
    })
}

pub fn create_set(
    cookie_header: Option<&str>,
    csrf_token: &str,
    set_name: Option<&str>,
) -> PyResult<PythonResponse> {
    Python::attach(|py| {
        let bridge = py.import("app.rust_bridge")?;
        let payload = PyDict::new(py);
        if let Some(set_name) = set_name {
            payload.set_item("set_name", set_name)?;
        }

        let kwargs = PyDict::new(py);
        kwargs.set_item("csrf_token", csrf_token)?;

        let result = bridge.call_method("create_set", (cookie_header, payload), Some(&kwargs))?;
        let (status, headers, body_bytes): (u16, Vec<(String, String)>, Vec<u8>) =
            result.extract()?;

        Ok(PythonResponse {
            status,
            headers,
            body: body_bytes,
        })
    })
}

pub fn delete_set(
    cookie_header: Option<&str>,
    csrf_token: &str,
    set_name: Option<&str>,
) -> PyResult<PythonResponse> {
    Python::attach(|py| {
        let bridge = py.import("app.rust_bridge")?;
        let payload = PyDict::new(py);
        if let Some(set_name) = set_name {
            payload.set_item("set_name", set_name)?;
        }

        let kwargs = PyDict::new(py);
        kwargs.set_item("csrf_token", csrf_token)?;

        let result = bridge.call_method("delete_set", (cookie_header, payload), Some(&kwargs))?;
        let (status, headers, body_bytes): (u16, Vec<(String, String)>, Vec<u8>) =
            result.extract()?;

        Ok(PythonResponse {
            status,
            headers,
            body: body_bytes,
        })
    })
}

pub fn load_set(
    cookie_header: Option<&str>,
    csrf_token: &str,
    set_name: Option<&str>,
) -> PyResult<PythonResponse> {
    Python::attach(|py| {
        let bridge = py.import("app.rust_bridge")?;
        let payload = PyDict::new(py);
        if let Some(set_name) = set_name {
            payload.set_item("set_name", set_name)?;
        }

        let kwargs = PyDict::new(py);
        kwargs.set_item("csrf_token", csrf_token)?;

        let result = bridge.call_method("load_set", (cookie_header, payload), Some(&kwargs))?;
        let (status, headers, body_bytes): (u16, Vec<(String, String)>, Vec<u8>) =
            result.extract()?;

        Ok(PythonResponse {
            status,
            headers,
            body: body_bytes,
        })
    })
}

pub fn update_memory(
    cookie_header: Option<&str>,
    csrf_token: &str,
    memory: Option<&str>,
    set_name: Option<&str>,
    encrypted: Option<bool>,
) -> PyResult<PythonResponse> {
    Python::attach(|py| {
        let bridge = py.import("app.rust_bridge")?;
        let payload = PyDict::new(py);
        if let Some(memory) = memory {
            payload.set_item("memory", memory)?;
        }
        if let Some(set_name) = set_name {
            payload.set_item("set_name", set_name)?;
        }
        if let Some(encrypted) = encrypted {
            payload.set_item("encrypted", encrypted)?;
        }

        let kwargs = PyDict::new(py);
        kwargs.set_item("csrf_token", csrf_token)?;

        let result =
            bridge.call_method("update_memory", (cookie_header, payload), Some(&kwargs))?;
        let (status, headers, body_bytes): (u16, Vec<(String, String)>, Vec<u8>) =
            result.extract()?;

        Ok(PythonResponse {
            status,
            headers,
            body: body_bytes,
        })
    })
}

pub fn update_system_prompt(
    cookie_header: Option<&str>,
    csrf_token: &str,
    system_prompt: Option<&str>,
    set_name: Option<&str>,
    encrypted: Option<bool>,
) -> PyResult<PythonResponse> {
    Python::attach(|py| {
        let bridge = py.import("app.rust_bridge")?;
        let payload = PyDict::new(py);
        if let Some(system_prompt) = system_prompt {
            payload.set_item("system_prompt", system_prompt)?;
        }
        if let Some(set_name) = set_name {
            payload.set_item("set_name", set_name)?;
        }
        if let Some(encrypted) = encrypted {
            payload.set_item("encrypted", encrypted)?;
        }

        let kwargs = PyDict::new(py);
        kwargs.set_item("csrf_token", csrf_token)?;

        let result = bridge.call_method(
            "update_system_prompt",
            (cookie_header, payload),
            Some(&kwargs),
        )?;
        let (status, headers, body_bytes): (u16, Vec<(String, String)>, Vec<u8>) =
            result.extract()?;

        Ok(PythonResponse {
            status,
            headers,
            body: body_bytes,
        })
    })
}

pub fn delete_message(
    cookie_header: Option<&str>,
    csrf_token: &str,
    user_message: Option<&str>,
    ai_message: Option<&str>,
    set_name: Option<&str>,
) -> PyResult<PythonResponse> {
    Python::attach(|py| {
        let bridge = py.import("app.rust_bridge")?;
        let payload = PyDict::new(py);
        if let Some(user_message) = user_message {
            payload.set_item("user_message", user_message)?;
        }
        if let Some(ai_message) = ai_message {
            payload.set_item("ai_message", ai_message)?;
        }
        if let Some(set_name) = set_name {
            payload.set_item("set_name", set_name)?;
        }

        let kwargs = PyDict::new(py);
        kwargs.set_item("csrf_token", csrf_token)?;

        let result =
            bridge.call_method("delete_message", (cookie_header, payload), Some(&kwargs))?;
        let (status, headers, body_bytes): (u16, Vec<(String, String)>, Vec<u8>) =
            result.extract()?;

        Ok(PythonResponse {
            status,
            headers,
            body: body_bytes,
        })
    })
}
