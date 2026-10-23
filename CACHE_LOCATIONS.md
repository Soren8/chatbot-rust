# Cargo cache locations

Operator notice before recreating the devcontainer: runtime Cargo downloads use
`/mnt/linux-data/.cargo/home` and intermediate builds use
`/mnt/linux-data/.cargo/target/{workspace-path-hash}`. Both prepared host
directories are bound at identical container paths. Missing sources fail the
mount; launchers do not provision them or create Cargo named volumes.

`CARGO_HOME_OVERRIDE` follows the shared home. Installed tools remain under
`/home/agent/.cargo` via `CARGO_INSTALL_ROOT`, with Rustup under
`/home/agent/.rustup`. Existing final-output `CARGO_TARGET_DIR` paths remain
local for scripts and rust-analyzer; they are separate from intermediate caches.
New repository templates use these same shared mounts and settings. Do not add
local download or intermediate-cache overrides.

Docker image-build and test-service caches are unchanged. Existing caches are
not moved or deleted. Storage provisioning, migration and pruning remain
operator-managed; no size limit is enabled by this configuration.

## TODO: build cache size (deferred, 2026-10-19)

The old `/mnt/linux-data/cache/chatbot-rust-target` reached 476 GB (last
written 2026-10-10): 443 GB of 2,436 debug executables for 226 targets, about
11 stale hash copies each. Every `tests/*.rs` file (129 in `chatbot-server`, 24
in `chatbot-core`, 8 in `chatbot-cuda`, 3 in `dns`) links its own binary with
full debug info, and Cargo never prunes superseded copies. Planned fixes:

1. Merge each crate's integration tests into one binary (`tests/main.rs` with
   modules).
2. Add `[profile.dev.package."*"] debug = false` so dependencies drop debug info;
   workspace crates keep full debug info.
3. Schedule pruning of the shared target cache (for example `cargo sweep --time
   14` from a weekly timer), approved by the operator.
