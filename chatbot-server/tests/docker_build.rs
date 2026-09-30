//! Guards the image build recipe against cargo's mtime-based freshness check.
//!
//! Docker `COPY` preserves the source files' mtimes, while the `rust-build`
//! stage compiles into a cache-mounted `CARGO_TARGET_DIR` that survives across
//! builds. An artifact from a previous build can therefore be newer than a
//! freshly copied source file, and cargo silently reuses the stale crate
//! instead of recompiling a moved API (rust-lang/cargo#9312). That surfaced as
//! "no method/field found" errors from `chatbot-server` while `chatbot-core`
//! linked from an old rlib. The build must advance workspace source mtimes
//! past any warm cache entry before cargo reads them.

#[test]
fn webserver_uses_host_network_with_sidecar_resolver() {
    let compose: serde_yaml::Value = serde_yaml::from_str(include_str!("../../docker-compose.yml")).unwrap();
    let web = &compose["services"]["webserver"];
    assert_eq!(web["network_mode"].as_str(), Some("host"));
    for key in ["ports", "dns", "networks", "extra_hosts"] {
        assert!(!web.as_mapping().unwrap().contains_key(serde_yaml::Value::from(key)), "host webserver must not use {key}");
    }
    let resolver = web["volumes"].as_sequence().unwrap().iter()
        .find(|mount| mount["target"].as_str() == Some("/etc/resolv.conf"))
        .expect("host webserver needs a sidecar resolver bind");
    assert_eq!(resolver["source"].as_str(), Some("${WEB_RESOLV_CONF:-./dns/host-resolv.conf}"));
    assert_eq!(resolver["read_only"].as_bool(), Some(true));
    assert_eq!(include_str!("../../dns/host-resolv.conf"), "nameserver 172.29.0.53\n");
    assert_eq!(compose["services"]["voice-service"]["ports"], serde_yaml::to_value(["127.0.0.1:5100:5100"]).unwrap());
}

const DOCKERFILE: &str = include_str!("../../Dockerfile");

fn stage_body<'a>(dockerfile: &'a str, name: &str) -> &'a str {
    let marker = format!("AS {name}\n");
    let start = dockerfile
        .find(&marker)
        .unwrap_or_else(|| panic!("Dockerfile has no stage `{name}`"))
        + marker.len();
    let rest = &dockerfile[start..];
    match rest.find("\nFROM ") {
        Some(end) => &rest[..end],
        None => rest,
    }
}

#[test]
fn rust_build_forces_source_freshness_before_cargo() {
    let build = stage_body(DOCKERFILE, "rust-build");
    // Join Dockerfile line continuations so each shell command is one string.
    let commands = build.replace("\\\n", " ");
    let freshness = commands
        .lines()
        .find(|line| line.contains("find") && line.contains("touch"))
        .unwrap_or_else(|| {
            panic!(
                "rust-build must advance workspace source mtimes before cargo build; \
                 Docker COPY preserves mtimes and the cache-mounted target dir can \
                 otherwise make cargo reuse a stale crate (rust-lang/cargo#9312)"
            )
        });
    for tree in ["chatbot-core", "chatbot-server", "chatbot-test-support"] {
        assert!(
            freshness.contains(tree),
            "freshness command must cover `{tree}`: {freshness}"
        );
    }
    assert!(
        build.contains("cargo build"),
        "rust-build still compiles the server"
    );
    let freshness_at = commands
        .find(freshness)
        .expect("freshness command is part of the stage body");
    let build_at = commands
        .find("cargo build")
        .expect("rust-build still compiles the server");
    assert!(
        freshness_at < build_at,
        "source mtimes must be advanced before cargo build, otherwise cargo \
         reuses the stale cached crate (rust-lang/cargo#9312)"
    );
}
