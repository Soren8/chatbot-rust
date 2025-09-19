use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict};
use pyo3::Py;

pub struct PythonResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// Initializes the embedded Python interpreter and imports core application modules.
#[allow(deprecated)]
pub fn initialize_python() -> PyResult<()> {
    // For now we simply ensure the interpreter spins up.
    Python::with_gil(|_py| Ok(()))
}

/// Placeholder helper illustrating how Rust will invoke Python callables.
#[allow(deprecated)]
pub fn call_python_function(module: &str, function: &str) -> PyResult<Py<PyAny>> {
    Python::with_gil(|py| {
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
    Python::with_gil(|py| {
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
    Python::with_gil(|py| {
        let bridge = py.import("app.rust_bridge")?;
        let result = bridge.call_method("validate_csrf_token", (cookie_header, token), None)?;
        result.extract()
    })
}
