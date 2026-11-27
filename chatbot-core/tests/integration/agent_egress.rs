use std::cell::{Cell, RefCell};
use std::net::{IpAddr, SocketAddr};

use chatbot_core::config::{agent_egress::{CanonicalBase, EgressError, OpenCodeClient, Resolver, Transport, validate_endpoint}, ExternalConnectionsConfig};
use url::Url;

struct FakeResolver { answers: RefCell<Vec<IpAddr>>, calls: Cell<usize> }
impl FakeResolver {
    fn new(answers: &[&str]) -> Self {
        Self { answers: RefCell::new(answers.iter().map(|v| v.parse().unwrap()).collect()), calls: Cell::new(0) }
    }
}
impl Resolver for &FakeResolver {
    fn resolve(&self, _: &str, _: u16) -> Result<Vec<IpAddr>, EgressError> {
        self.calls.set(self.calls.get() + 1);
        Ok(self.answers.borrow().clone())
    }
}

#[derive(Default)]
struct FakeTransport { calls: RefCell<Vec<(String, Vec<SocketAddr>)>> }
impl Transport for &FakeTransport {
    type Response = ();
    fn get_health(&self, url: &Url, pins: &[SocketAddr], _: &str, _: &str) -> Result<(), EgressError> {
        self.calls.borrow_mut().push((url.as_str().to_owned(), pins.to_vec()));
        Ok(())
    }
}

fn policy(yaml: &str) -> ExternalConnectionsConfig {
    serde_yaml::from_str::<ExternalConnectionsConfig>(yaml).unwrap().validate().unwrap()
}
const PUBLIC: &str = "enabled: true\nallowed_users: [alice]\nallow_public_https: true\n";
const RESTRICTED: &str = "enabled: true\nallowed_users: [alice, bob]\nallow_public_https: true\ntargets:\n  - id: tunnel\n    base_url: http://127.0.0.1:14096\n    allowed_users: [alice]\n    allowed_ips: [127.0.0.1]\n    allow_tunneled_http: true\n";

#[test]
fn offline_validation_and_canonical_safe_base_join() {
    let p = policy(PUBLIC);
    let endpoint = validate_endpoint(&p, "alice", "https://EXAMPLE.org:443/proxy/").unwrap();
    assert_eq!(endpoint.as_str(), "https://example.org/proxy");
    assert_eq!(endpoint.health_url().as_str(), "https://example.org/proxy/global/health");
    for bad in ["http://example.org", "https://example.org:8443", "file:///tmp/x", "https://a@b.com", "https://b.com?x=1", "https://b.com#x", "https://b.com/%2e%2e/admin", "https://b.com/a%2fb", "https://b.com/a\\b", "https://b.com/%252e%252e"] {
        assert!(validate_endpoint(&p, "alice", bad).is_err(), "{bad}");
    }
    assert_eq!(validate_endpoint(&p, "bob", "https://example.org"), Err(EgressError::Blocked));
    assert!(CanonicalBase::parse("https://example.org").is_ok());
}

#[test]
fn rebind_mixed_dns_and_reserved_alias_fail_without_connecting() {
    let p = policy(RESTRICTED);
    let resolver = FakeResolver::new(&["8.8.8.8"]);
    let transport = FakeTransport::default();
    let client = OpenCodeClient::new(&resolver, &transport);
    client.check(&p, "bob", "https://public.example", "user", "pw").unwrap();
    assert_eq!(transport.calls.borrow().len(), 1);
    *resolver.answers.borrow_mut() = vec!["8.8.8.8".parse().unwrap(), "127.0.0.1".parse().unwrap()];
    assert_eq!(client.check(&p, "bob", "https://public.example", "user", "pw"), Err(EgressError::Blocked));
    *resolver.answers.borrow_mut() = vec!["127.0.0.1".parse().unwrap()];
    assert_eq!(client.check(&p, "bob", "https://other.example:14096", "user", "pw"), Err(EgressError::Blocked));
    assert_eq!(client.check(&p, "alice", "http://127.0.0.1:14096", "user", "pw"), Ok(()));
    assert_eq!(client.check(&p, "bob", "http://127.0.0.1:14096", "user", "pw"), Err(EgressError::Blocked));
    assert_eq!(transport.calls.borrow().len(), 2);
    assert_eq!(resolver.calls.get(), 3);
}

#[test]
fn addresses_are_checked_and_pinned_per_request() {
    let p = policy(PUBLIC);
    let resolver = FakeResolver::new(&["8.8.8.8", "8.8.4.4"]);
    let transport = FakeTransport::default();
    let client = OpenCodeClient::new(&resolver, &transport);
    client.check(&p, "alice", "https://service.example/app", "u", "p").unwrap();
    assert_eq!(transport.calls.borrow()[0].0, "https://service.example/app/global/health");
    assert_eq!(transport.calls.borrow()[0].1, vec!["8.8.8.8:443".parse().unwrap(), "8.8.4.4:443".parse().unwrap()]);
    for denied in ["::ffff:127.0.0.1", "fe80::1", "fd00::1", "2001:db8::1", "169.254.169.254", "10.0.0.1", "100.64.0.1", "224.0.0.1", "0.0.0.0"] {
        *resolver.answers.borrow_mut() = vec![denied.parse().unwrap()];
        assert_eq!(client.check(&p, "alice", "https://service.example/app", "u", "p"), Err(EgressError::Blocked), "{denied}");
    }
    assert_eq!(transport.calls.borrow().len(), 1);
    *resolver.answers.borrow_mut() = vec!["8.8.8.8".parse().unwrap()];
    assert_eq!(client.check(&p, "alice", "https://127.0.0.1", "u", "p"), Err(EgressError::Blocked));
}

#[test]
fn defaults_are_disabled_and_public_rule_never_allows_http_or_nonstandard_port() {
    let defaults = policy("{}");
    assert!(!defaults.enabled);
    assert!(!defaults.allow_public_https);
    assert!(defaults.allowed_users.is_empty());
    assert!(defaults.targets.is_empty());
    let p = policy(PUBLIC);
    for url in ["http://8.8.8.8", "https://example.org:8443"] {
        assert_eq!(validate_endpoint(&p, "alice", url), Err(EgressError::Blocked));
    }
}

#[test]
fn rejects_bad_operator_rules() {
    for yaml in [
        "enabled: true\nallowed_users: [alice]\ntargets:\n - {id: a, base_url: 'http://127.0.0.1:1234', allowed_users: [bob], allowed_ips: [127.0.0.1], allow_tunneled_http: true}",
        "enabled: true\nallowed_users: [alice]\ntargets:\n - {id: a, base_url: 'http://127.0.0.1:1234', allowed_users: [alice], allowed_ips: [127.0.0.1]}",
        "enabled: true\nallowed_users: [alice]\ntargets:\n - {id: a, base_url: 'https://x.test', allowed_users: [alice], allowed_ips: []}",
        "enabled: true\nallowed_users: [alice, bob]\ntargets:\n - {id: a, base_url: 'https://x.test:444', allowed_users: [alice], allowed_ips: [8.8.8.8]}\n - {id: b, base_url: 'https://y.test:444', allowed_users: [bob], allowed_ips: [8.8.8.8]}",
    ] {
        assert!(serde_yaml::from_str::<ExternalConnectionsConfig>(yaml).unwrap().validate().is_err());
    }
}
