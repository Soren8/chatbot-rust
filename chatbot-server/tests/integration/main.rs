//! Shared integration-test binary for `chatbot-server`. Run one former test
//! file with `--test integration --filter <module>::`.
//!
//! Every module here leaves process-global state alone: no `TestWorkspace`,
//! no environment or current-directory changes, no `config`/`rate_limit`
//! resets, and no assertions on the global error counter or captured logs.
//!
//! Every remaining top-level `tests/<file>.rs` target uses `TestWorkspace`,
//! which changes the process cwd, sets `HOST_DATA_DIR`/`OPENAI_API_KEY` and
//! resets the global config and rate limiter; each file serialises its own
//! tests with a file-local lock only, so two such files cannot share a
//! process. Most also set provider env vars (`SECRET_KEY`,
//! `CHATBOT_TEST_OPENAI_CHUNKS`, `XAI_API_KEY`, `RATE_LIMIT_*`, ...), and some
//! assert on the global error counter or install log-capture subscribers.

#[path = "../common/mod.rs"]
mod common;

mod activity_sync;
mod android_unit_tests;
mod android_volume;
mod audio_perf;
mod browser_glue;
mod car_voice_failure_modes;
mod chat_renderer_boundary;
mod client_log_reporting;
mod conversation_request_application;
mod conversation_request_binding;
mod conversation_state;
mod credential_crypto;
mod credential_metadata;
mod credential_sealed_storage;
mod desktop_playback_cancellation;
mod desktop_playback_cancellation_vm;
mod distribution;
mod dns_sidecar_unit;
mod docker_build;
mod file_logger_cap;
mod finalize_stream_boundary;
mod fork_operation_boundaries;
mod fork_receipt_parity;
mod generate_connection_recovery;
mod health;
mod history_mutation_resend;
mod http_errors;
mod image_safety;
mod ip_extraction;
mod js_syntax;
mod native_audio_wav;
mod native_foreground_stop;
mod native_mic_capture;
mod native_tts_communication;
mod native_vad_speech_like;
mod native_voice_coordinator;
mod operation_receipts;
mod phase3_client_characterization;
mod playback_source_boundary;
mod playback_source_characterization;
mod sec008_browser_ui;
mod server_settings_entry;
mod session_client;
mod static_assets;
mod stream_decoder;
mod tts_download_queue;
mod tts_sentence_boundaries;
mod voice_capture_boundary;
mod voice_events;
mod voice_lifecycle;
mod voice_mode_reliability;
mod voice_service_lifecycle;
mod voice_text_boundary;
mod voice_text_sanitize_html;
