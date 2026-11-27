//! Shared integration-test binary for `chatbot-core`. Run one former test file
//! with `--test integration --filter <module>::`.
//!
//! Every module here leaves process-global state alone: no environment or
//! current-directory changes, no `config::reset`, and no assertions on global
//! counters or first initialisation. Files that need their own process stay
//! as top-level `tests/<file>.rs` targets:
//! - `account_service_isolation`, `account_store_inputs`, `user_store_atomicity`:
//!   set `SECRET_KEY`/`HOST_DATA_DIR` and reset the global config.
//! - `chat_service_test_chunks_isolation`: `TestWorkspace` (cwd, `HOST_DATA_DIR`)
//!   and `CHATBOT_TEST_OPENAI_CHUNKS`.
//! - `http_identity_lazy_init`: changes cwd and env and asserts first
//!   initialisation of the global session store.
//! - `agent_connection_service`: compiles `src/agent_connections.rs` via
//!   `#[path]` as a crate-root module beside crate-root shims.

mod agent_egress;
mod chat_service_isolation;
mod chat_service_lazy_history;
mod chat_session_isolation;
mod crypto_buffer_literals;
mod finalize_outcome_boundary;
mod generation_lease_ownership;
mod history_cache_key;
mod history_snapshot_boundary;
mod http_identity_isolation;
mod live_helper_contracts;
mod model_image_bounds;
mod mutation_mirror_boundary;
mod privacy_policy;
mod prompt_input_boundary;
mod remember_family_authorization;
mod session_operation_errors;
mod user_store_concurrency;
mod user_store_first_enrollment;
