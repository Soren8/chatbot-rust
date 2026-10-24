//! Key, salt and nonce buffers in crypto code start as `<[u8; N]>::default()`,
//! never a `[0u8; N]` literal: CodeQL rust/hard-coded-cryptographic-value
//! reports zero literals as hard-coded keys even when they are overwritten.

#[test]
fn crypto_sources_have_no_zero_array_literals() {
    for (name, source) in [
        ("user_store.rs", include_str!("../src/user_store.rs")),
        ("agent_connections.rs", include_str!("../src/agent_connections.rs")),
        ("operation_receipt.rs", include_str!("../src/operation_receipt.rs")),
        ("history/crypto.rs", include_str!("../src/history/crypto.rs")),
        ("enc_key.rs", include_str!("../src/enc_key.rs")),
    ] {
        assert!(
            !source.contains("[0u8;"),
            "{name} contains a `[0u8; N]` literal; use `<[u8; N]>::default()`"
        );
    }
}
