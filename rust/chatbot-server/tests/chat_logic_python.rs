use once_cell::sync::Lazy;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use std::ffi::CString;
use std::sync::Mutex;

mod common;

static PY_TEST_GUARD: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

#[test]
fn python_chat_logic_helpers_match_expected_behavior() {
    if !common::ensure_flask_available() {
        eprintln!(
            "skipping python_chat_logic_helpers_match_expected_behavior: flask not available"
        );
        return;
    }

    let _guard = PY_TEST_GUARD.lock().unwrap();
    common::ensure_pythonpath();

    Python::attach(|py| -> PyResult<()> {
        let chat_logic = py.import("app.chat_logic")?;

        let calc_tokens = chat_logic.getattr("calculate_available_history_tokens")?;
        let available: i32 = calc_tokens.call1((1000, "abcd", "efgh"))?.extract()?;
        assert_eq!(available, 798);

        let truncate = chat_logic.getattr("truncate_history")?;
        let history = vec![
            ("u".repeat(1600), "v".repeat(1600)),
            ("new".repeat(400), "reply".repeat(400)),
        ];
        let py_history = PyList::new(py, &history)?;
        let truncated: Vec<(String, String)> = truncate.call1((&py_history, 300))?.extract()?;

        assert_eq!(truncated.len(), 1);

        let expected_user = "new".repeat(400);
        let expected_ai = "reply".repeat(400);

        assert!(expected_user.starts_with(&truncated[0].0));
        assert!(expected_ai.starts_with(&truncated[0].1));
        assert_eq!(truncated[0].0.len(), 600);
        assert_eq!(truncated[0].1.len(), 600);

        Ok(())
    })
    .expect("python chat logic helpers invocation");
}

#[test]
fn python_generate_text_stream_truncates_history_for_provider() {
    if !common::ensure_flask_available() {
        eprintln!(
            "skipping python_generate_text_stream_truncates_history_for_provider: flask not available"
        );
        return;
    }

    let _guard = PY_TEST_GUARD.lock().unwrap();
    common::ensure_pythonpath();
    std::env::set_var("SECRET_KEY", "integration_test_secret");
    let _workspace = common::TestWorkspace::with_openai_provider();

    Python::attach(|py| -> PyResult<()> {
        let locals = PyDict::new(py);
        let code = CString::new(
            r#"
class RecordingProvider:
    last_call = None

    def __init__(self, config):
        self.config = config

    def generate_text_stream(self, prompt, system_prompt, session_history, memory_text, context_size):
        RecordingProvider.last_call = {
            "prompt": prompt,
            "system_prompt": system_prompt,
            "session_history": list(session_history),
            "memory_text": memory_text,
            "context_size": context_size,
        }
        yield "[chunk-1]"
        yield "[chunk-2]"
"#,
        )
        .expect("valid stub provider python code");
        py.run(code.as_c_str(), Some(&locals), Some(&locals))?;

        let recording_provider = locals
            .get_item("RecordingProvider")?
            .expect("RecordingProvider defined");

        let openai_module = py.import("app.llm.openai_provider")?;
        let original_provider = openai_module.getattr("OpenaiProvider")?.unbind();
        openai_module.setattr("OpenaiProvider", &recording_provider)?;

        let restore = scopeguard::guard(original_provider, |original| {
            Python::attach(|py_inner| {
                if let Ok(openai_mod) = py_inner.import("app.llm.openai_provider") {
                    let _ = openai_mod.setattr("OpenaiProvider", original.bind(py_inner));
                }
            });
        });

        recording_provider.setattr("last_call", py.None())?;

        let config_module = py.import("app.config")?;
        let config_class = config_module.getattr("Config")?;
        let providers_any = config_class.getattr("LLM_PROVIDERS")?;
        let providers = providers_any.downcast::<PyList>()?;
        let provider_entry = providers.get_item(0)?;
        let provider_dict = provider_entry.downcast::<PyDict>()?;
        provider_dict.set_item("context_size", 600)?;
        provider_dict.set_item("provider_name", "default")?;
        provider_dict.set_item("type", "openai")?;
        provider_dict.set_item("api_key", "test-key")?;
        config_class.setattr("DEFAULT_LLM", &provider_dict)?;

        let chat_logic = py.import("app.chat_logic")?;
        let history = vec![
            ("a".repeat(50), "b".repeat(50)),
            ("m".repeat(1000), "n".repeat(1000)),
            ("p".repeat(800), "q".repeat(400)),
        ];
        let py_history = PyList::new(py, &history)?;

        let generator = chat_logic.getattr("generate_text_stream")?.call1((
            "New prompt",
            "",
            "default",
            &py_history,
            "",
        ))?;

        let iterator = generator.call_method0("__iter__")?;
        let mut chunks = Vec::new();
        loop {
            match iterator.call_method0("__next__") {
                Ok(item) => {
                    let chunk: String = item.extract()?;
                    chunks.push(chunk);
                }
                Err(err) => {
                    if err.is_instance_of::<pyo3::exceptions::PyStopIteration>(py) {
                        break;
                    }
                    return Err(err);
                }
            }
        }

        assert_eq!(chunks, vec!["[chunk-1]".to_string(), "[chunk-2]".to_string()]);

        let last_call = recording_provider.getattr("last_call")?;
        let last_call = last_call.downcast::<PyDict>()?;

        let session_history_any = last_call
            .get_item("session_history")?
            .expect("session_history recorded");
        let session_history: Vec<(String, String)> = session_history_any.extract()?;

        assert_eq!(session_history.len(), 2);
        assert_eq!(session_history[0].0.len(), 360);
        assert_eq!(session_history[0].1.len(), 360);
        assert!(session_history[0].0.chars().all(|c| c == 'm'));
        assert!(session_history[0].1.chars().all(|c| c == 'n'));
        assert_eq!(session_history[1].0, "p".repeat(800));
        assert_eq!(session_history[1].1, "q".repeat(400));

        let context_size_any = last_call
            .get_item("context_size")?
            .expect("context_size recorded");
        let context_size: i32 = context_size_any.extract()?;
        assert_eq!(context_size, 600);

        drop(restore);

        Ok(())
    })
    .expect("python chat logic generate_text_stream invocation");
}
