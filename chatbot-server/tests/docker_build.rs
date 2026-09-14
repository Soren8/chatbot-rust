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
