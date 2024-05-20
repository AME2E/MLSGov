# Baseline

For benchmarking purposes, we provide a baseline version of our messaging
platform that does not include the following governance related features:
reporting signatures, RBAC, and the policy engine.

## Enabling the baseline

To turn on the baseline, modify the `default` feature of `corelib/Cargo.toml` to include just `"baseline"`. To enable governance, this default feature
should include just `"gov"`. For example:

```toml
[features]
default = ["gov"] # Enable governance by default
baseline = [] 
gov = []
```

With this, running `cargo build` or `cargo run` will use the governance mode, while `cargo build --no-default-features --features baseline` will use the baseline mode.

In the client code (`client/src/main.rs`), the feature flags are checked to conditionally call the governance or baseline versions of functions. For example:

```rust
#[cfg(feature = "gov")]
use corelib::client_api::check_action_msg_and_get_mls;
#[cfg(feature = "baseline")]
use corelib::client_api::baseline::check_action_msg_and_get_mls;
```

This allows the client binary to adapt its behavior based on the compiled mode.

## Details and Usage

The baseline feature flag is used to conditionally compile governance-related code. When enabled, it:

- Removes the signature field from `Action` and related authentication logic in `corelib/src/client_api/actions/mod.rs`
- Stubs out the RBAC check in `check_action_msg_and_get_mls` to always return true (`corelib/src/client_api/baseline/mod.rs`)
- Disables the policy engine integration in `check_action_msg_and_get_mls` and `parse_incoming_onwire_msgs` (`corelib/src/client_api/baseline/mod.rs`)

With these changes, actions are no longer authenticated, authorized or governed by policies. The system becomes a basic encrypted group messaging platform without any governance layer.

This baseline mode is useful for:

1. Performance benchmarking: To measure the overhead added by the governance features, we can compare the performance with and without those features.
2. Feature development: Developers can disable governance to focus on testing core messaging functionality changes without potential interference from policies.
3. Simplified deployment: For use cases that don't require governance, the baseline mode offers a simpler, lighter-weight deployment option.

Note that the core security guarantees of end-to-end encryption, group key management with MLS, server authentication etc are preserved in the baseline mode. Only the governance layer is removed.