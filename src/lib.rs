//! Untrusted container, script, RDP and CMS parsing and explicit Authenticode verification.
//!
//! Disable default features for a `no_std + alloc` parser. Enable `verify` for
//! all format verifiers, `verify-core` for the `no_std + alloc` shared verifier,
//! `system-roots` for native root enumeration, and
//! `cli` for the command-line adapter. The `msi` and `appx` features expose
//! structural adapters requiring `std`, without verification. Defaults retain the complete CLI.
#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;
#[cfg(all(test, not(feature = "std")))]
extern crate std;

#[cfg(all(feature = "verify-core", feature = "appx"))]
mod appx;
#[cfg(feature = "verify-core")]
mod cab;
#[cfg(feature = "cli")]
pub mod cli;
#[cfg(feature = "verify-core")]
mod cms;
#[cfg(feature = "verify-core")]
mod crypto;
mod der;
#[cfg(feature = "verify-core")]
pub mod domain;
#[cfg(feature = "verify-core")]
pub mod format;
#[cfg(feature = "cli")]
mod inspection;
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
#[cfg(feature = "verify-core")]
mod trust;
#[cfg(feature = "verify-core")]
pub mod verify;
#[cfg(feature = "verify-core")]
mod wsh;
#[cfg(feature = "verify-core")]
pub use domain::{SignatureReport, VerificationBundle, VerificationError};
#[cfg(feature = "verify-core")]
pub use trust::{TrustLoadError, TrustLoadErrorKind, TrustStore};
#[cfg(feature = "verify-core")]
pub use verify::{
    RevocationPolicy, VerifyOptions, verify, verify_cab, verify_navx, verify_parsed_cab,
    verify_parsed_navx, verify_parsed_pe, verify_pe, verify_powershell, verify_powershell_xml,
    verify_rdp, verify_wsh,
};
#[cfg(all(test, feature = "verify"))]
mod tests;

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
