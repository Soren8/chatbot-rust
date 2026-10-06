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
