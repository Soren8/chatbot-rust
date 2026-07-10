use std::env;

use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogFormat {
    Plain,
    Json,
}

fn parse_log_format() -> LogFormat {
    match env::var("LOG_FORMAT")
        .unwrap_or_default()
        .to_ascii_lowercase()
        .as_str()
    {
        "json" => LogFormat::Json,
        _ => LogFormat::Plain,
    }
}

fn parse_ansi_enabled() -> bool {
    !matches!(
        env::var("LOG_ANSI")
            .unwrap_or_default()
            .to_ascii_lowercase()
            .as_str(),
        "0" | "false" | "no" | "off"
    )
}

fn env_filter() -> EnvFilter {
    EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        let level = env::var("LOG_LEVEL").unwrap_or_else(|_| "info".to_string());
        EnvFilter::new(level)
    })
}

/// Initialise tracing for server processes. Idempotent only when called once at startup.
pub fn init_logging() {
    let filter = env_filter();
    let format = parse_log_format();
    let ansi = parse_ansi_enabled();
    let registry = tracing_subscriber::registry().with(filter);

    match format {
        LogFormat::Json => {
            registry
                .with(
                    fmt::layer()
                        .json()
                        .with_current_span(false)
                        .with_ansi(ansi),
                )
                .init();
        }
        LogFormat::Plain => registry.with(fmt::layer().with_ansi(ansi)).init(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_log_format_defaults_to_plain() {
        let previous = env::var("LOG_FORMAT").ok();
        env::remove_var("LOG_FORMAT");
        assert_eq!(parse_log_format(), LogFormat::Plain);
        if let Some(value) = previous {
            env::set_var("LOG_FORMAT", value);
        }
    }

    #[test]
    fn parse_log_format_accepts_json() {
        let previous = env::var("LOG_FORMAT").ok();
        env::set_var("LOG_FORMAT", "JSON");
        assert_eq!(parse_log_format(), LogFormat::Json);
        match previous {
            Some(value) => env::set_var("LOG_FORMAT", value),
            None => env::remove_var("LOG_FORMAT"),
        }
    }
}