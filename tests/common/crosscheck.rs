//! The application's debug test builds must run with the engine's revocation
//! cross-check (CRL-T011); the root dev-dependency on `rssig-engine` enables
//! it. Without the feature the engine has no `REVOCATION_CROSSCHECK`, so the
//! including test crate fails to compile. Every application test crate
//! includes this, since `cargo test --test <name>` builds no other target; the
//! engine's test crates have their own copy (engine/tests/common). Release
//! test runs compile the cross-check out by design.

#[cfg(debug_assertions)]
const _: () = assert!(
    rssig_engine::REVOCATION_CROSSCHECK,
    "the rssig-engine dev-dependency in Cargo.toml must enable `revocation-crosscheck` for debug tests"
);
