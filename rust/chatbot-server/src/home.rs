use std::collections::HashMap;

use axum::{
    body::Body,
    http::{header, HeaderValue, Request, Response, StatusCode},
};
use chatbot_core::{
    bridge::{self, HomeBootstrap},
    config,
};
use minijinja::{context, AutoEscape, Environment};
use std::sync::OnceLock;
use serde::Serialize;
use tracing::{error, warn};

use crate::user_store::UserStore;

const SECURITY_CSP: &str = "default-src 'self'; base-uri 'self'; frame-ancestors 'none'; connect-src 'self'; img-src 'self' data:; font-src 'self' https://cdn.jsdelivr.net data:; style-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'; script-src 'self' https://code.jquery.com https://cdn.jsdelivr.net; media-src 'self' blob: data:";
const FREE_TIER: &str = "free";

#[derive(Serialize)]
struct FrontendModel {
    provider_name: String,
    tier: String,
}

pub async fn handle_home(request: Request<Body>) -> Result<Response<Body>, (StatusCode, String)> {
    let cookie_header = request
        .headers()
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.to_owned());

    let bootstrap = bridge::prepare_home_context(cookie_header.as_deref()).map_err(|err| {
        error!(?err, "failed to prepare home context via python bridge");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "bridge error".to_string(),
        )
    })?;

    let logged_in = bootstrap.username.is_some();
    let user_tier = resolve_user_tier(bootstrap.username.as_deref());

    let config = config::app_config();
    let default_prompt = config.default_system_prompt.clone();
    let sri = config.cdn_sri.clone();
    let available_models = build_available_models(config.provider_names(), &user_tier, &config);

    let html = render_template(
        logged_in,
        &user_tier,
        &available_models,
        &default_prompt,
        &bootstrap.csrf_token,
        sri,
    )
    .map_err(|err| {
        error!(?err, "failed to render home template");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "template error".to_string(),
        )
    })?;

    build_response(html, bootstrap)
}

fn resolve_user_tier(username: Option<&str>) -> String {
    match username {
        Some(name) => {
            let store = match UserStore::new() {
                Ok(store) => store,
                Err(err) => {
                    warn!(?err, "failed to open user store when resolving tier");
                    return FREE_TIER.to_string();
                }
            };

            match store.user_tier(name) {
                Ok(tier) => tier,
                Err(err) => {
                    warn!(?err, "failed to load user tier; defaulting to free");
                    FREE_TIER.to_string()
                }
            }
        }
        None => FREE_TIER.to_string(),
    }
}

fn build_available_models(
    provider_names: &[String],
    user_tier: &str,
    config: &std::sync::Arc<config::AppConfig>,
) -> Vec<FrontendModel> {
    let mut models = Vec::new();
    for name in provider_names {
        let Some(provider) = config.provider(name) else {
            continue;
        };
        let tier = provider
            .tier
            .clone()
            .unwrap_or_else(|| FREE_TIER.to_string());
        if tier.eq_ignore_ascii_case("premium") && !user_tier.eq_ignore_ascii_case("premium") {
            continue;
        }
        models.push(FrontendModel {
            provider_name: provider.provider_name.clone(),
            tier,
        });
    }
    models
}

fn render_template(
    logged_in: bool,
    user_tier: &str,
    available_models: &[FrontendModel],
    default_prompt: &str,
    csrf_token: &str,
    sri: HashMap<String, String>,
) -> Result<String, minijinja::Error> {
    let env = template_env();
    let template = env.get_template("chat.html")?;
    template.render(context! {
        logged_in => logged_in,
        user_tier => user_tier,
        available_llms => available_models,
        default_system_prompt => default_prompt,
        csrf_token => csrf_token,
        sri => sri,
    })
}

fn template_env() -> &'static Environment<'static> {
    static ENV: OnceLock<Environment<'static>> = OnceLock::new();
    ENV.get_or_init(|| {
        let mut env = Environment::new();
        env.set_auto_escape_callback(|name| {
            if name.ends_with(".html") {
                AutoEscape::Html
            } else {
                AutoEscape::None
            }
        });
        env.add_template(
            "chat.html",
            include_str!("../../../app/templates/chat.html"),
        )
        .expect("chat.html template");
        env
    })
}

fn build_response(
    body: String,
    bootstrap: HomeBootstrap,
) -> Result<Response<Body>, (StatusCode, String)> {
    let mut builder = Response::builder()
        .status(StatusCode::OK)
        .header(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/html; charset=utf-8"),
        )
        .header("Content-Security-Policy", SECURITY_CSP);

    builder = builder
        .header("X-Content-Type-Options", "nosniff")
        .header("Referrer-Policy", "no-referrer")
        .header("X-Frame-Options", "DENY");

    if let Some(cookie) = bootstrap.set_cookie.as_deref() {
        if let Ok(value) = HeaderValue::from_str(cookie) {
            builder = builder.header(header::SET_COOKIE, value);
        } else {
            warn!("discarding invalid Set-Cookie header from python bridge");
        }
    }

    builder.body(Body::from(body)).map_err(|err| {
        error!(?err, "failed to build home response body");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "response build error".to_string(),
        )
    })
}
