use axum::{extract::ConnectInfo, http::{Extensions, HeaderMap}};
use chatbot_server::chat_utils::get_ip;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

#[test]
fn test_get_ip_prefers_x_forwarded_for() {
    let mut headers = HeaderMap::new();
    headers.insert("X-Forwarded-For", "10.0.0.1, 10.0.0.2".parse().unwrap());
    
    let extensions = Extensions::new();
    
    let ip = get_ip(&headers, &extensions);
    assert_eq!(ip, "10.0.0.1");
}

#[test]
fn test_get_ip_falls_back_to_x_real_ip() {
    let mut headers = HeaderMap::new();
    headers.insert("X-Real-IP", "10.0.0.2".parse().unwrap());
    
    let extensions = Extensions::new();
    
    let ip = get_ip(&headers, &extensions);
    assert_eq!(ip, "10.0.0.2");
}

#[test]
fn test_get_ip_falls_back_to_connect_info() {
    let headers = HeaderMap::new();
    let mut extensions = Extensions::new();
    
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 12345);
    extensions.insert(ConnectInfo(addr));
    
    let ip = get_ip(&headers, &extensions);
    assert_eq!(ip, "127.0.0.1");
}

#[test]
fn test_get_ip_returns_unknown_when_no_info() {
    let headers = HeaderMap::new();
    let extensions = Extensions::new();
    
    let ip = get_ip(&headers, &extensions);
    assert_eq!(ip, "unknown");
}
