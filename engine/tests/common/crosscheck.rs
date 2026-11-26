//! Debug test builds must run with the engine's revocation cross-check
//! (CRL-T011); the engine's self dev-dependency enables it. Without the
//! feature the engine has no `REVOCATION_CROSSCHECK`, so the including test
//! crate fails to compile. Every engine integration test crate includes this,
//! since `cargo test --test <name>` builds no other target. Release test runs
//! compile the cross-check out by design.

#[cfg(debug_assertions)]
const _: () = assert!(
    rssig_engine::REVOCATION_CROSSCHECK,
    "the self dev-dependency in engine/Cargo.toml must enable `revocation-crosscheck` for debug tests"
);
