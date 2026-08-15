//! Parse first-party browser JS with oxc (Rust). No Node/npm.
//! Vendor files under static/deps/ are not checked here.

use oxc_allocator::Allocator;
use oxc_parser::Parser;
use oxc_span::SourceType;

fn assert_script_parses(name: &str, source: &str) {
    let allocator = Allocator::default();
    let source_type = SourceType::default().with_module(false).with_jsx(false);
    let ret = Parser::new(&allocator, source, source_type).parse();
    let errors: Vec<String> = ret.errors.iter().map(ToString::to_string).collect();
    assert!(
        errors.is_empty(),
        "{name} failed to parse ({} error(s)):\n{}",
        errors.len(),
        errors.join("\n")
    );
}

#[test]
fn first_party_static_js_parses() {
    assert_script_parses("static/chat.js", include_str!("../../static/chat.js"));
    assert_script_parses("static/login.js", include_str!("../../static/login.js"));
    assert_script_parses(
        "static/native-audio.js",
        include_str!("../../static/native-audio.js"),
    );
    assert_script_parses(
        "static/native-bridge.js",
        include_str!("../../static/native-bridge.js"),
    );
    assert_script_parses("static/enc-key.js", include_str!("../../static/enc-key.js"));
}
