pub use chatbot_test_support::*;

use std::path::PathBuf;

use axum::Router;
use chatbot_server::{build_router_with_services, compose_services, services::AppServices};

pub fn workspace_router(static_root: PathBuf) -> (Router, AppServices) {
    let services = compose_services(&chatbot_core::config::app_config())
        .expect("compose workspace services");
    let router = build_router_with_services(static_root, services.clone());
    (router, services)
}
