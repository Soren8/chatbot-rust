//! Outbound OpenCode destination gate. No socket is opened during endpoint validation.
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::net::ToSocketAddrs;
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
use std::time::{Duration, Instant};

use serde::Deserialize;

use thiserror::Error;
use url::{Host, Url};

use super::ExternalConnectionsConfig;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum EgressError {
    #[error("invalid connection URL")]
    InvalidUrl,
    #[error("connection blocked by deployment policy")]
    Blocked,
    #[error("connection resolution failed")]
    Resolve,
    #[error("connection transport failed")]
    Transport,
    #[error("connection timed out")]
    Timeout,
    #[error("remote authentication failed")]
    Authentication,
    #[error("remote health response invalid")]
    InvalidHealth,
    #[error("remote service unhealthy")]
    Unhealthy,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalBase {
    url: Url,
    host: String,
    port: u16,
}

impl CanonicalBase {
    pub fn parse(input: &str) -> Result<Self, EgressError> {
        if input.len() > 2048 || input.trim() != input || input.contains('\\') || input.chars().any(char::is_control) {
            return Err(EgressError::InvalidUrl);
        }
        let mut url = Url::parse(input).map_err(|_| EgressError::InvalidUrl)?;
        if !matches!(url.scheme(), "http" | "https") || url.cannot_be_a_base()
            || !url.username().is_empty() || url.password().is_some()
            || url.query().is_some() || url.fragment().is_some()
            || url.host().is_none()
        {
            return Err(EgressError::InvalidUrl);
        }
        let authority = input.split_once("://").ok_or(EgressError::InvalidUrl)?.1.split('/').next().unwrap_or("");
        if authority.contains('@') || authority.contains('%') || authority.is_empty() {
            return Err(EgressError::InvalidUrl);
        }
        let path = input.split_once("://").unwrap().1.split_once('/').map(|(_, p)| p).unwrap_or("");
        if path.split('/').any(|s| {
            let decoded = percent_decode(s);
            decoded.is_none_or(|d| d == "." || d == ".." || d.contains('/') || d.contains('\\') || d.contains('%') || d.chars().any(char::is_control))
        }) {
            return Err(EgressError::InvalidUrl);
        }
        let host = match url.host().ok_or(EgressError::InvalidUrl)? {
            Host::Domain(d) => d.to_ascii_lowercase(),
            Host::Ipv4(ip) => ip.to_string(),
            Host::Ipv6(ip) => ip.to_string(),
        };
        let port = url.port_or_known_default().ok_or(EgressError::InvalidUrl)?;
        // Remove trailing slash for stable policy matching; safe path joining is adapter-owned.
        let clean_path = url.path().trim_end_matches('/').to_owned();
        url.set_path(if clean_path.is_empty() { "/" } else { &clean_path });
        if url.port() == Some(if url.scheme() == "https" { 443 } else { 80 }) {
            url.set_port(None).map_err(|_| EgressError::InvalidUrl)?;
        }
        Ok(Self { url, host, port })
    }

    pub fn as_str(&self) -> &str { self.url.as_str() }
    pub fn host(&self) -> &str { &self.host }
    pub fn port(&self) -> u16 { self.port }
    pub fn is_https(&self) -> bool { self.url.scheme() == "https" }

    pub fn health_url(&self) -> Url {
        let mut url = self.url.clone();
        let base = self.url.path().trim_end_matches('/');
        url.set_path(&format!("{base}/global/health"));
        url
    }
}

fn percent_decode(segment: &str) -> Option<String> {
    let mut bytes = Vec::new();
    let mut iter = segment.bytes();
    while let Some(c) = iter.next() {
        if c == b'%' {
            let hi = (iter.next()? as char).to_digit(16)?;
            let lo = (iter.next()? as char).to_digit(16)?;
            bytes.push(((hi << 4) | lo) as u8);
        } else { bytes.push(c); }
    }
    String::from_utf8(bytes).ok()
}

fn normalized_ip(ip: IpAddr) -> IpAddr {
    match ip { IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip), _ => ip }
}

fn forbidden_even_for_target(ip: IpAddr) -> bool {
    match normalized_ip(ip) {
        IpAddr::V4(v) => v.is_link_local() || v == Ipv4Addr::new(169, 254, 169, 254) || v.is_unspecified() || v.is_multicast(),
        IpAddr::V6(v) => v.is_unicast_link_local() || v.is_unspecified() || v.is_multicast(),
    }
}

fn public_ip(ip: IpAddr) -> bool {
    match normalized_ip(ip) {
        IpAddr::V4(v) => {
            let [a,b,c,_] = v.octets();
            !matches!(a, 0 | 10 | 127 | 224..=255)
                && !(a == 100 && (64..=127).contains(&b))
                && !(a == 169 && b == 254)
                && !(a == 172 && (16..=31).contains(&b))
                && !(a == 192 && ((b == 0 && (c == 0 || c == 2)) || (b == 88 && c == 99) || b == 168))
                && !(a == 198 && (b == 18 || b == 19))
                && !(a == 198 && b == 51 && c == 100)
                && !(a == 203 && b == 0 && c == 113)
        }
        IpAddr::V6(v) => {
            let s = v.segments();
            (s[0] & 0xe000) == 0x2000 && s[0] != 0x2002
                && !(s[0] == 0x2001 && s[1] == 0)
                && !(s[0] == 0x2001 && s[1] == 0x0db8)
        }
    }
}

/// Only the HTTPS 443 public rule or an exact target may authorize a URL.
pub fn validate_endpoint(policy: &ExternalConnectionsConfig, user: &str, input: &str) -> Result<CanonicalBase, EgressError> {
    let base = CanonicalBase::parse(input)?;
    if !policy.enabled || !policy.allowed_users.iter().any(|u| u == user) {
        return Err(EgressError::Blocked);
    }
    let target = policy.targets.iter().find(|t| t.canonical_base_url() == base.as_str());
    if let Some(t) = target {
        if !t.allowed_users.iter().any(|u| u == user) || (!base.is_https() && !t.allow_tunneled_http) { return Err(EgressError::Blocked); }
    } else if !policy.allow_public_https || !base.is_https() || base.port != 443 {
        return Err(EgressError::Blocked);
    }
    Ok(base)
}

/// Resolver is invoked for *every operation*, including literal-IP destinations.
pub trait Resolver {
    fn resolve(&self, host: &str, port: u16) -> Result<Vec<IpAddr>, EgressError>;
}

/// Transport must connect ONLY to `pins`, preserve the URL hostname for Host/SNI,
/// verify TLS, ignore ambient proxies, disable redirects, and not reuse pooled sockets.
/// Implementations must not forward any caller-supplied headers.
pub trait Transport {
    type Response;
    fn get_health(&self, url: &Url, pins: &[SocketAddr], basic_user: &str, basic_password: &str) -> Result<Self::Response, EgressError>;
}

pub struct OpenCodeClient<R, T> {
    resolver: R,
    transport: T,
}

impl<R: Resolver, T: Transport> OpenCodeClient<R, T> {
    pub fn new(resolver: R, transport: T) -> Self { Self { resolver, transport } }

    pub fn check(&self, policy: &ExternalConnectionsConfig, user: &str, base_url: &str, basic_user: &str, basic_password: &str) -> Result<T::Response, EgressError> {
        let base = validate_endpoint(policy, user, base_url)?;
        let answers = self.resolver.resolve(base.host(), base.port())?;
        if answers.is_empty() { return Err(EgressError::Blocked); }
        let literal = base.host().parse::<IpAddr>().ok().map(normalized_ip);
        let target = policy.targets.iter().find(|t| t.canonical_base_url() == base.as_str());
        let mut pins = Vec::new();
        let mut seen = HashSet::new();
        for answer in answers {
            let ip = normalized_ip(answer);
            if forbidden_even_for_target(ip) || literal.is_some_and(|address| address != ip) { return Err(EgressError::Blocked); }
            // Reserve private/restricted destinations against alternate hostnames.
            if policy.targets.iter().any(|t| t.port() == base.port() && t.allowed_ips.iter().any(|v| normalized_ip(*v) == ip) && Some(t.id.as_str()) != target.map(|t| t.id.as_str())) {
                return Err(EgressError::Blocked);
            }
            if let Some(t) = target {
                if !t.allowed_ips.iter().any(|v| normalized_ip(*v) == ip) { return Err(EgressError::Blocked); }
            } else if !public_ip(ip) { return Err(EgressError::Blocked); }
            if seen.insert(ip) { pins.push(SocketAddr::new(ip, base.port())); }
        }
        self.transport.get_health(&base.health_url(), &pins, basic_user, basic_password)
    }
}

/// No DNS cache: each operation resolves again, and the transport pins only
/// addresses authorized for that operation.
#[derive(Clone, Copy, Default)]
pub struct SystemResolver;

impl Resolver for SystemResolver {
    fn resolve(&self, host: &str, port: u16) -> Result<Vec<IpAddr>, EgressError> {
        (host, port).to_socket_addrs()
            .map(|answers| answers.map(|address| address.ip()).collect())
            .map_err(|_| EgressError::Resolve)
    }
}

pub struct DeadlineResolver {
    deadline: Instant,
    cancelled: Arc<AtomicBool>,
}

impl DeadlineResolver {
    pub fn new(deadline: Instant, cancelled: Arc<AtomicBool>) -> Self {
        Self { deadline, cancelled }
    }
}

impl Resolver for DeadlineResolver {
    fn resolve(&self, host: &str, port: u16) -> Result<Vec<IpAddr>, EgressError> {
        let answers = SystemResolver.resolve(host, port)?;
        if self.cancelled.load(Ordering::Acquire) || Instant::now() >= self.deadline {
            return Err(EgressError::Timeout);
        }
        Ok(answers)
    }
}

pub struct HealthTransport {
    deadline: Instant,
    cancelled: Arc<AtomicBool>,
}

impl HealthTransport {
    pub fn new(deadline: Instant, cancelled: Arc<AtomicBool>) -> Self {
        Self { deadline, cancelled }
    }
}

#[derive(Deserialize)]
struct HealthPayload {
    healthy: bool,
    version: String,
}

impl Transport for HealthTransport {
    type Response = String;

    fn get_health(&self, url: &Url, pins: &[SocketAddr], basic_user: &str, basic_password: &str) -> Result<String, EgressError> {
        if self.cancelled.load(Ordering::Acquire) { return Err(EgressError::Timeout); }
        let remaining = self.deadline.checked_duration_since(Instant::now()).ok_or(EgressError::Timeout)?;
        let builder = reqwest::blocking::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .pool_max_idle_per_host(0)
            .connect_timeout(Duration::from_secs(3))
            .timeout(remaining);
        let host = url.host_str().ok_or(EgressError::InvalidUrl)?;
        let client = builder.resolve_to_addrs(host, pins).build().map_err(|_| EgressError::Transport)?;
        if self.cancelled.load(Ordering::Acquire) || Instant::now() >= self.deadline { return Err(EgressError::Timeout); }
        let response = client.get(url.clone())
            .basic_auth(basic_user, Some(basic_password))
            .header(reqwest::header::ACCEPT, "application/json")
            .send().map_err(transport_error)?;
        match response.status().as_u16() {
            401 | 403 => return Err(EgressError::Authentication),
            200 => {},
            _ => return Err(EgressError::Unhealthy),
        }
        let mut bytes = Vec::new();
        use std::io::Read;
        response.take(65_537).read_to_end(&mut bytes).map_err(|err| {
            if err.kind() == std::io::ErrorKind::TimedOut || Instant::now() >= self.deadline {
                EgressError::Timeout
            } else {
                EgressError::Transport
            }
        })?;
        if bytes.len() > 65_536 { return Err(EgressError::InvalidHealth); }
        let health: HealthPayload = serde_json::from_slice(&bytes).map_err(|_| EgressError::InvalidHealth)?;
        if !health.healthy { return Err(EgressError::Unhealthy); }
        if health.version.is_empty() || health.version.len() > 128 || health.version.chars().any(char::is_control) {
            return Err(EgressError::InvalidHealth);
        }
        Ok(health.version)
    }
}

fn transport_error(err: reqwest::Error) -> EgressError {
    if err.is_timeout() { EgressError::Timeout } else { EgressError::Transport }
}
