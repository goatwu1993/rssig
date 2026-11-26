//! The rssig verification engine: untrusted container, script, RDP and CMS
//! parsing, and explicit Authenticode and RDP signature verification.
//!
//! The engine is pure logic over what its caller supplies: input bytes, a
//! `TrustStore`, a validation time and a `VerifyOptions` policy. It reads no
//! files, clock, environment or network and enumerates no OS roots.
//! Collaborators are injected: a `retrieval::CrlSource` for CRLs (feature
//! `retrieval`) and a `log::Logger` for diagnostics (`verify-core`). The
//! `rssig` application package supplies the defaults (the CLI, its HTTP CRL
//! source and OS root enumeration).
//!
//! Disable default features for a `no_std + alloc` parser. Enable `verify` for
//! all format verifiers, `verify-core` for the `no_std + alloc` shared verifier
//! and `retrieval` for CRL retrieval through an injected source. The `msi` and
//! `appx` features expose structural adapters requiring `std`, without
//! verification.
#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;
#[cfg(all(test, not(feature = "std")))]
extern crate std;

/// Error formatting contract: `{}` is the summary, `source()` walks the causes,
/// and `{:#}` is exactly the summary followed by each cause once.
#[cfg(test)]
pub(crate) fn assert_causes_once(error: &dyn core::error::Error, alternate: &str) {
    use alloc::string::ToString;
    let mut walked = error.to_string();
    let mut cause = error.source();
    while let Some(next) = cause {
        walked.push_str(&alloc::format!(": {next}"));
        cause = next.source();
    }
    assert_eq!(walked, alternate);
}

#[cfg(all(feature = "verify-core", feature = "appx"))]
mod appx;
#[cfg(feature = "verify-core")]
mod cab;
#[cfg(feature = "verify-core")]
mod cms;
#[cfg(feature = "verify-core")]
mod crypto;
mod der;
#[cfg(feature = "verify-core")]
pub mod domain;
#[cfg(feature = "verify-core")]
pub mod format;
#[cfg(feature = "verify-core")]
pub mod inspect;
#[cfg(feature = "verify-core")]
pub mod log;
#[cfg(all(feature = "verify-core", feature = "msi"))]
mod msi;
#[cfg(feature = "verify-core")]
mod navx;
pub mod parse;
#[cfg(feature = "verify-core")]
mod pe;
#[cfg(feature = "verify-core")]
mod powershell;
#[cfg(feature = "verify-core")]
mod rdp;
#[cfg(feature = "verify-core")]
mod report;
#[cfg(feature = "retrieval")]
pub mod retrieval;
#[cfg(feature = "verify-core")]
mod trust;
#[cfg(feature = "verify-core")]
pub mod verify;
#[cfg(feature = "verify-core")]
mod wsh;
#[cfg(feature = "verify-core")]
pub use domain::{SignatureReport, VerificationBundle, VerificationError};
#[cfg(feature = "verify-core")]
pub use trust::{TrustLoadError, TrustLoadErrorCode, TrustLoadErrorKind, TrustStore};
#[cfg(feature = "verify-core")]
pub use verify::{
    RevocationPolicy, Verifier, VerifyOptions, verify, verify_cab, verify_navx, verify_parsed_cab,
    verify_parsed_navx, verify_parsed_pe, verify_pe, verify_powershell, verify_powershell_xml,
    verify_rdp, verify_wsh,
};
#[cfg(all(test, feature = "verify"))]
mod tests;
// With `verify-core` alone the unit tests already evaluate CRLs, so the guard
// is declared here and not inside `tests`, which needs `verify`.
#[cfg(all(test, feature = "verify-core"))]
#[path = "tests/crosscheck_active.rs"]
mod crosscheck_active;

/// Whether this build runs the test-only revocation cross-check (CRL-T011).
/// Exists only with the test-only `revocation-crosscheck` feature, so product
/// builds never export it; both packages' tests assert it, and fail to
/// compile without it. Not a supported interface.
#[cfg(feature = "revocation-crosscheck")]
#[doc(hidden)]
pub const REVOCATION_CROSSCHECK: bool = cfg!(debug_assertions);

#[cfg(all(feature = "verify-core", feature = "appx"))]
pub use verify::{verify_appx, verify_parsed_appx};
#[cfg(all(feature = "verify-core", feature = "msi"))]
pub use verify::{verify_msi, verify_parsed_msi};

// Older RustCrypto errors implement Error only with std. Keep host causal
// diagnostics; preserve their Display diagnostic at the alloc-only boundary.
#[cfg(all(feature = "verify-core", feature = "std"))]
fn compat_error<E: Into<anyhow::Error>>(error: E) -> anyhow::Error {
    error.into()
}
#[cfg(all(feature = "verify-core", not(feature = "std")))]
fn compat_error<E: core::fmt::Display>(error: E) -> anyhow::Error {
    anyhow::anyhow!("{error}")
}
