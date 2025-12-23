use std::collections::HashMap;

use axum::{
    body::Body,
    http::{header, HeaderValue, Request, Response, StatusCode},
};
use chatbot_core::{config, session, user_store::UserStore};
use minijinja::{context, AutoEscape, Environment};
use serde::Serialize;
use std::sync::OnceLock;
use tracing::{error, warn};

pub const SECURITY_CSP: &str = "default-src 'self'; base-uri 'self'; frame-ancestors 'none'; connect-src 'self' https://cdn.jsdelivr.net; img-src 'self' data: blob:; font-src 'self' https://cdn.jsdelivr.net data:; style-src 'self' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com 'unsafe-inline'; script-src 'self' https://code.jquery.com https://cdn.jsdelivr.net https://cdnjs.cloudflare.com blob:; media-src 'self' blob: data:";
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

    let bootstrap = session::prepare_home_context(cookie_header.as_deref()).map_err(|err| {
        error!(?err, "failed to prepare home context");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "session error".to_string(),
        )
    })?;

    let logged_in = bootstrap.username.is_some();
    let user_details = resolve_user_details(bootstrap.username.as_deref());

    let config = config::app_config();
    let default_prompt = config.default_system_prompt.clone();
    let save_thoughts = config.save_thoughts;
    let send_thoughts = config.send_thoughts;
    
    tracing::debug!(
        save_thoughts,
        send_thoughts,
        "rendering home template with config"
    );

    let sri = config.cdn_sri.clone();
    let available_models = build_available_models(config.provider_names(), &user_details.tier, &config);

    let html = render_template(
        logged_in,
        &user_details,
        &available_models,
        &default_prompt,
        &bootstrap.csrf_token,
        sri,
        save_thoughts,
        send_thoughts,
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

struct UserDetails {
    tier: String,
    last_set: Option<String>,
    last_model: Option<String>,
    render_markdown: bool,
    autoplay_tts: bool,
}

fn resolve_user_details(username: Option<&str>) -> UserDetails {
    match username {
        Some(name) => {
            let store = match UserStore::new() {
                Ok(store) => store,
                Err(err) => {
                    warn!(?err, "failed to open user store when resolving details");
                    return UserDetails { tier: FREE_TIER.to_string(), last_set: None, last_model: None, render_markdown: true, autoplay_tts: false };
                }
            };

            let tier = store.user_tier(name).unwrap_or_else(|err| {
                warn!(?err, "failed to load user tier; defaulting to free");
                FREE_TIER.to_string()
            });

            let (last_set, last_model, render_markdown, autoplay_tts) = store.user_preferences(name).unwrap_or_else(|err| {
                 warn!(?err, "failed to load user preferences");
                 (None, None, true, false)
            });

            UserDetails { tier, last_set, last_model, render_markdown, autoplay_tts }
        }
        None => UserDetails { tier: FREE_TIER.to_string(), last_set: None, last_model: None, render_markdown: true, autoplay_tts: false },
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
    user_details: &UserDetails,
    available_models: &[FrontendModel],
    default_prompt: &str,
    csrf_token: &str,
    sri: HashMap<String, String>,
    save_thoughts: bool,
    send_thoughts: bool,
) -> Result<String, minijinja::Error> {
    let env = template_env();
    let template = env.get_template("chat.html")?;
    template.render(context! {
        logged_in => logged_in,
        user_tier => user_details.tier,
        last_set => user_details.last_set,
        last_model => user_details.last_model,
        render_markdown => user_details.render_markdown,
        autoplay_tts => user_details.autoplay_tts,
        available_llms => available_models,
        default_system_prompt => default_prompt,
        csrf_token => csrf_token,
        sri => sri,
        save_thoughts => save_thoughts,
        send_thoughts => send_thoughts,
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
            include_str!("../../static/templates/chat.html"),
        )
        .expect("chat.html template");
        env
    })
}

fn build_response(
    body: String,
    bootstrap: session::HomeBootstrap,
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

    if let Ok(value) = HeaderValue::from_str(&bootstrap.set_cookie) {
        builder = builder.header(header::SET_COOKIE, value);
    } else {
        warn!("discarding invalid Set-Cookie header from session manager");
    }

    builder.body(Body::from(body)).map_err(|err| {
        error!(?err, "failed to build home response body");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "response build error".to_string(),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_template_with_config() {
        let logged_in = true;
        let user_details = UserDetails {
            tier: "free".to_string(),
            last_set: None,
            last_model: None,
            render_markdown: true,
            autoplay_tts: false,
        };
        let available_models = vec![FrontendModel {
            provider_name: "test-model".to_string(),
            tier: "free".to_string(),
        }];
        let default_prompt = "system prompt";
        let csrf_token = "csrf";
        let sri = HashMap::new();
        let save_thoughts = true;
        let send_thoughts = true;

        let rendered = render_template(
            logged_in,
            &user_details,
            &available_models,
            default_prompt,
            csrf_token,
            sri,
            save_thoughts,
            send_thoughts,
        )
        .expect("render template");

        assert!(rendered.contains(r#""saveThoughts": true"#));
        assert!(rendered.contains(r#""sendThoughts": true"#));
    }
}
