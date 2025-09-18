use pyo3::prelude::*;

/// Initializes the embedded Python interpreter and imports core application modules.
pub fn initialize_python() -> PyResult<()> {
    // For now we simply ensure the interpreter spins up.
    Python::with_gil(|_py| Ok(()))
}

/// Placeholder helper illustrating how Rust will invoke Python callables.
pub fn call_python_function(module: &str, function: &str) -> PyResult<PyObject> {
    Python::with_gil(|py| {
        let module = py.import(module)?;
        let callable = module.getattr(function)?;
        callable.call0()
    })
}
