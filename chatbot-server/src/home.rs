use std::collections::HashMap;

use axum::{
    body::Body,
    http::{header, HeaderValue, Request, Response, StatusCode},
};
use chatbot_core::{config, remember_store, session, user_store::UserStore};
use minijinja::{context, AutoEscape, Environment};
use serde::Serialize;
use std::sync::OnceLock;
use tracing::warn;

use crate::http_error::{
    log_and_api_error, map_response_build_err, map_session_err, HttpError,
};

pub const SECURITY_CSP: &str = "default-src 'self'; base-uri 'self'; frame-ancestors 'none'; connect-src 'self' https://cdn.jsdelivr.net; img-src 'self' data: blob:; font-src 'self' https://cdn.jsdelivr.net data:; style-src 'self' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com 'unsafe-inline'; script-src 'self' https://code.jquery.com https://cdn.jsdelivr.net https://cdnjs.cloudflare.com blob: 'wasm-unsafe-eval'; media-src 'self' blob: data:";
const FREE_TIER: &str = "free";

#[derive(Serialize)]
struct FrontendModel {
    provider_name: String,
    tier: String,
    search: bool,
}

struct RestoredSession {
    /// Cookie pair ("session=...") of the freshly minted session.
    session_cookie: String,
    /// Full Set-Cookie value for the rotated remember token.
    remember_set_cookie: String,
}

/// Silent resume of a remembered session on app entry (`GET /`). After a
/// server restart the in-memory session store is empty; a valid remember
/// cookie restores the authenticated session so the user lands logged in.
/// Only runs for guest sessions — an authenticated visit never rotates the
/// token. `/login` deliberately does NOT auto-restore: that page is the
/// account-selection surface.
fn try_auto_restore(cookie_header: Option<&str>, ip: &str) -> Option<RestoredSession> {
    let token = remember_store::extract_token(cookie_header)?;
    if session::session_context(cookie_header)
        .ok()
        .and_then(|ctx| ctx.username)
        .is_some()
    {
        return None;
    }

    let store = remember_store::RememberStore::new().ok()?;
    match store.resume(Some(&token)) {
        Ok(remember_store::ResumeOutcome::Authenticated {
            username,
            replacement_token,
        }) => {
            let finalize = session::finalize_login(cookie_header, &username).ok()?;
            let session_cookie = finalize
                .set_cookie
                .split(';')
                .next()
                .unwrap_or("")
                .trim()
                .to_owned();
            if session_cookie.is_empty() {
                return None;
            }
            tracing::info!(username = %username, ip = %ip, "Session restored via remember token on app entry");
            Some(RestoredSession {
                session_cookie,
                remember_set_cookie: remember_store::build_set_cookie(&replacement_token),
            })
        }
        Ok(remember_store::ResumeOutcome::Invalid) => {
            tracing::info!(
                "remember token presented but not valid (expired, revoked, or replayed)"
            );
            None
        }
        Err(err) => {
            warn!(?err, "remember token auto-restore failed");
            None
        }
    }
}

pub async fn handle_home(request: Request<Body>) -> Result<Response<Body>, HttpError> {
    let headers = request.headers();
    let ip = crate::chat_utils::get_ip(headers, request.extensions());
    let cookie_header = headers
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.to_owned());

    let mut restored_cookies: Vec<String> = Vec::new();
    let mut cookie_header = cookie_header;
    if let Some(restored) = try_auto_restore(cookie_header.as_deref(), &ip) {
        cookie_header = Some(restored.session_cookie);
        restored_cookies.push(restored.remember_set_cookie);
    }

    let bootstrap = session::prepare_home_context(cookie_header.as_deref())
        .map_err(|err| map_session_err(err, "home::get"))?;

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
        log_and_api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "template error",
            "home::get::render",
            err,
        )
    })?;

    build_response(html, bootstrap, restored_cookies)
}

struct UserDetails {
    username: Option<String>,
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
                    return UserDetails {
                        username: Some(name.to_string()),
                        tier: FREE_TIER.to_string(),
                        last_set: None,
                        last_model: None,
                        render_markdown: true,
                        autoplay_tts: false,
                    };
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

            UserDetails {
                username: Some(name.to_string()),
                tier,
                last_set,
                last_model,
                render_markdown,
                autoplay_tts,
            }
        }
        None => UserDetails {
            username: None,
            tier: FREE_TIER.to_string(),
            last_set: None,
            last_model: None,
            render_markdown: true,
            autoplay_tts: false,
        },
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
            search: provider.search,
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
        username => user_details.username,
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
    restored_cookies: Vec<String>,
) -> Result<Response<Body>, HttpError> {
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

    for set_cookie in restored_cookies {
        if let Ok(value) = HeaderValue::from_str(&set_cookie) {
            builder = builder.header(header::SET_COOKIE, value);
        } else {
            warn!("discarding invalid remember Set-Cookie header");
        }
    }

    if let Ok(value) = HeaderValue::from_str(&bootstrap.set_cookie) {
        builder = builder.header(header::SET_COOKIE, value);
    } else {
        warn!("discarding invalid Set-Cookie header from session manager");
    }

    builder
        .body(Body::from(body))
        .map_err(|err| map_response_build_err(err, "home::get::response"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_template_with_config() {
        let logged_in = true;
        let user_details = UserDetails {
            username: Some("tester".to_string()),
            tier: "free".to_string(),
            last_set: None,
            last_model: None,
            render_markdown: true,
            autoplay_tts: false,
        };
        let available_models = vec![FrontendModel {
            provider_name: "test-model".to_string(),
            tier: "free".to_string(),
            search: false,
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
