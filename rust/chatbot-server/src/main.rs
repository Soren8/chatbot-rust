use anyhow::Error;
use axum::{routing::get, Router};
use chatbot_core::bridge;
use tokio::net::TcpListener;
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::from_default_env())
        .with(tracing_subscriber::fmt::layer())
        .init();

    bridge::initialize_python().map_err(Error::from)?;

    let app = Router::new()
        .route("/health", get(health_check))
        .route("/", get(ui_placeholder));

    let listener = TcpListener::bind("0.0.0.0:8000").await?;
    let addr = listener.local_addr()?;
    info!("listening on http://{addr}");

    axum::serve(listener, app).await?;
    Ok(())
}

async fn health_check() -> &'static str {
    "ok"
}

async fn ui_placeholder() -> &'static str {
    "web ui placeholder"
}
