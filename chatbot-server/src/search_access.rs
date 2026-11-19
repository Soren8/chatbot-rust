//! Account-tier gate for `search_providers.<name>.tier`.

use axum::http::StatusCode;
use chatbot_core::config_source::DestinationPolicy;

use crate::{
    http_error::{api_error, map_user_store_err, HttpError},
    services::AppServices,
};

const PREMIUM_REQUIRED: &str = "Web search requires a Premium account";

/// True when an account of `user_tier` may search through the provider a
/// model uses (`native` selects XAI native search, otherwise Brave).
pub fn search_allowed_for_tier(
    policy: Option<&DestinationPolicy>,
    native: bool,
    user_tier: &str,
) -> bool {
    let premium_only = policy.is_some_and(|policy| {
        if native {
            policy.xai_native_search_premium
        } else {
            policy.brave_search_premium
        }
    });
    !premium_only || user_tier.eq_ignore_ascii_case("premium")
}

/// Enforce the search provider tier for a `/chat` or `/regenerate` request.
/// Returns whether XAI native-search fallback stays permitted for this user.
pub fn check_search_tier(
    services: &AppServices,
    username: Option<&str>,
    provider_type: &str,
    xai_search: bool,
    web_search: bool,
) -> Result<bool, HttpError> {
    if !web_search {
        return Ok(true);
    }
    let policy = services.config_source().destination_policy();
    let policy = policy.as_deref();
    if !policy.is_some_and(|p| p.brave_search_premium || p.xai_native_search_premium) {
        return Ok(true);
    }
    let user_tier = match username {
        Some(name) => {
            let store = services.accounts().users().map_err(|err| {
                map_user_store_err(err, "search::access::open_store", "Unable to check search access")
            })?;
            store.user_tier(name).map_err(|err| {
                map_user_store_err(err, "search::access::user_tier", "Unable to check search access")
            })?
        }
        None => "free".to_string(),
    };
    let native = provider_type == "xai" && xai_search;
    if !search_allowed_for_tier(policy, native, &user_tier) {
        return Err(api_error(StatusCode::FORBIDDEN, PREMIUM_REQUIRED));
    }
    Ok(search_allowed_for_tier(policy, true, &user_tier))
}

#[cfg(test)]
mod tests {
    use chatbot_core::config::{PrivacyLevel, SearchProviderConfig, SearchProvidersConfig};

    use super::*;

    fn policy(brave: Option<&str>, xai_native: Option<&str>) -> DestinationPolicy {
        let provider = |tier: Option<&str>| SearchProviderConfig {
            tier: tier.map(str::to_owned),
            ..SearchProviderConfig::default()
        };
        DestinationPolicy::from_providers(
            &[],
            &SearchProvidersConfig {
                brave: provider(brave),
                xai_native: provider(xai_native),
            },
            PrivacyLevel::NonPrivate,
            PrivacyLevel::NonPrivate,
        )
    }

    #[test]
    fn premium_search_provider_admits_only_premium_accounts() {
        let policy = policy(Some("premium"), None);
        assert!(!search_allowed_for_tier(Some(&policy), false, "free"));
        assert!(search_allowed_for_tier(Some(&policy), false, "Premium"));
        assert!(search_allowed_for_tier(Some(&policy), true, "free"));
    }

    #[test]
    fn unset_tier_admits_every_account() {
        let policy = policy(None, Some("free"));
        assert!(search_allowed_for_tier(Some(&policy), false, "free"));
        assert!(search_allowed_for_tier(Some(&policy), true, "free"));
        assert!(search_allowed_for_tier(None, true, "free"));
    }
}
