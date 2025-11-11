pub use crate::session::{
    ChatContext, ChatPrepareResult, ChatRequestData, HomeBootstrap, LoginFinalize, LogoutFinalize,
    PythonResponse, RegeneratePrepareResult, RegenerateRequestData, SessionContext,
};
use pyo3::prelude::*;
use pyo3::types::PyAnyMethods;
use pyo3::types::{PyBytes, PyDict};
use pyo3::Py;
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
