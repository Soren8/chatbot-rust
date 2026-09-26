use chatbot_core::config::{destination_is_eligible, fallback_provider, PrivacyLevel, ProviderConfig, SearchProvidersConfig};
use chatbot_core::config_source::{ConfigSource, DestinationPolicy};

#[test]
fn eligibility_respects_all_three_privacy_levels() {
    for (task, destination, allowed) in [
        (PrivacyLevel::Private, PrivacyLevel::Private, true),
        (PrivacyLevel::Private, PrivacyLevel::Standard, false),
        (PrivacyLevel::Private, PrivacyLevel::NonPrivate, false),
        (PrivacyLevel::Standard, PrivacyLevel::Private, true),
        (PrivacyLevel::Standard, PrivacyLevel::Standard, true),
        (PrivacyLevel::Standard, PrivacyLevel::NonPrivate, false),
        (PrivacyLevel::NonPrivate, PrivacyLevel::Private, true),
        (PrivacyLevel::NonPrivate, PrivacyLevel::Standard, true),
        (PrivacyLevel::NonPrivate, PrivacyLevel::NonPrivate, true),
    ] {
        assert_eq!(destination_is_eligible(task, destination), allowed, "task={task:?}, destination={destination:?}");
    }
}

#[test]
fn privacy_levels_use_distinct_defaults_and_closed_serialization() {
    assert_eq!(PrivacyLevel::default_chat(), PrivacyLevel::Private);
    assert_eq!(PrivacyLevel::default_destination(), PrivacyLevel::NonPrivate);
    assert_eq!(serde_yaml::from_str::<PrivacyLevel>("private").unwrap(), PrivacyLevel::Private);
    assert_eq!(serde_yaml::from_str::<PrivacyLevel>("standard").unwrap(), PrivacyLevel::Standard);
    assert_eq!(serde_yaml::from_str::<PrivacyLevel>("non_private").unwrap(), PrivacyLevel::NonPrivate);
    assert_eq!(serde_yaml::to_string(&PrivacyLevel::Standard).unwrap().trim(), "standard");
    assert!(serde_yaml::from_str::<PrivacyLevel>("recoverable").is_err());
    assert!(serde_yaml::from_str::<PrivacyLevel>("unknown").is_err());
}

#[test]
fn provider_omissions_are_non_private() {
    let provider: ProviderConfig = serde_yaml::from_str(
        "provider_name: local\ntype: openai\nmodel_name: model\n",
    ).unwrap();
    assert_eq!(provider.privacy_level, PrivacyLevel::NonPrivate);
}

#[test]
fn model_and_search_classifications_are_independent() {
    let provider: ProviderConfig = serde_yaml::from_str(
        "provider_name: local\ntype: openai\nmodel_name: model\nprivacy_level: standard\n",
    ).unwrap();
    let search: SearchProvidersConfig = serde_yaml::from_str(
        "brave:\n  privacy_level: private\nxai_native:\n  privacy_level: non_private\n",
    ).unwrap();
    let policy = DestinationPolicy::from_providers(&[provider], &search, PrivacyLevel::NonPrivate, PrivacyLevel::NonPrivate);

    assert_eq!(policy.provider("local"), Some(PrivacyLevel::Standard));
    assert_eq!(policy.brave_search, PrivacyLevel::Private);
    assert_eq!(policy.xai_native_search, PrivacyLevel::NonPrivate);
}

#[test]
fn missing_search_section_and_fields_are_non_private() {
    let missing: SearchProvidersConfig = serde_yaml::from_str("{}").unwrap();
    let partial: SearchProvidersConfig = serde_yaml::from_str("brave:\n  privacy_level: standard\n").unwrap();

    assert_eq!(missing.brave.privacy_level, PrivacyLevel::NonPrivate);
    assert_eq!(missing.xai_native.privacy_level, PrivacyLevel::NonPrivate);
    assert_eq!(partial.brave.privacy_level, PrivacyLevel::Standard);
    assert_eq!(partial.xai_native.privacy_level, PrivacyLevel::NonPrivate);
    assert_eq!(SearchProvidersConfig::default().xai_native.privacy_level, PrivacyLevel::NonPrivate);
}

#[test]
fn search_provider_levels_reject_unknown_values() {
    assert!(serde_yaml::from_str::<SearchProvidersConfig>("brave:\n  privacy_level: secret\n").is_err());
    assert!(serde_yaml::from_str::<SearchProvidersConfig>("xai_native:\n  privacy_level: secret\n").is_err());
}

#[test]
fn fallback_provider_does_not_gain_private_status_from_its_local_url() {
    let fallback = fallback_provider();
    assert_eq!(fallback.privacy_level, PrivacyLevel::NonPrivate);
}

#[test]
fn model_tier_does_not_change_privacy_and_search_selection_remains_independent() {
    let mut provider: ProviderConfig = serde_yaml::from_str(
        "provider_name: premium\ntype: xai\nmodel_name: grok\ntier: premium\nprivacy_level: private\nsearch: true\nxai_search: false\n",
    ).unwrap();
    let search: SearchProvidersConfig = serde_yaml::from_str("brave:\n  privacy_level: standard\nxai_native:\n  privacy_level: private\n").unwrap();
    let policy = DestinationPolicy::from_providers(&[provider.clone()], &search, PrivacyLevel::NonPrivate, PrivacyLevel::NonPrivate);
    assert_eq!(policy.provider("premium"), Some(PrivacyLevel::Private));
    assert!(destination_is_eligible(PrivacyLevel::Private, provider.privacy_level));
    assert!(!destination_is_eligible(PrivacyLevel::Private, policy.brave_search));
    assert!(provider.search);
    assert!(!provider.xai_search);
    provider.tier = Some("free".to_string());
    assert_eq!(provider.privacy_level, PrivacyLevel::Private);
    assert_eq!(DestinationPolicy::from_providers(&[provider], &search, PrivacyLevel::NonPrivate, PrivacyLevel::NonPrivate).xai_native_search, PrivacyLevel::Private);
}

#[test]
fn xai_search_selection_defaults_to_native_independently_of_classification() {
    let provider: ProviderConfig = serde_yaml::from_str(
        "provider_name: grok\ntype: xai\nmodel_name: grok\nsearch: true\n",
    ).unwrap();
    let search = SearchProvidersConfig::default();

    assert!(provider.search);
    assert!(provider.xai_search);
    assert_eq!(DestinationPolicy::from_providers(&[provider], &search, PrivacyLevel::NonPrivate, PrivacyLevel::NonPrivate).xai_native_search, PrivacyLevel::NonPrivate);
}

#[test]
fn owned_config_source_uses_its_destination_policy() {
    let provider: ProviderConfig = serde_yaml::from_str(
        "provider_name: local\ntype: openai\nmodel_name: model\nprivacy_level: private\n",
    ).unwrap();
    let source = ConfigSource::new(false, 60, "prompt".into(), "http://voice".into())
        .with_destination_policy(DestinationPolicy::from_providers(
            &[provider], &SearchProvidersConfig::default(), PrivacyLevel::Private, PrivacyLevel::NonPrivate,
        ));
    let policy = source.destination_policy().expect("owned policy");
    assert_eq!(policy.provider("local"), Some(PrivacyLevel::Private));
    assert_eq!(policy.brave_search, PrivacyLevel::NonPrivate);
    assert_eq!(policy.xai_native_search, PrivacyLevel::NonPrivate);
    assert_eq!(policy.stt, PrivacyLevel::Private);
    assert_eq!(policy.tts, PrivacyLevel::NonPrivate);
}
