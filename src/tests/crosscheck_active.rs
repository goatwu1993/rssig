//! The test-only revocation cross-check (CRL-T00011) must be compiled into debug
//! test builds: a silently missing oracle would leave revocation without a
//! backstop. Release test runs compile it out by design.

#[cfg(all(debug_assertions, not(feature = "revocation-crosscheck")))]
compile_error!(
    "the self dev-dependency in Cargo.toml must enable `revocation-crosscheck` for debug tests"
);
