//! Untrusted container, script, RDP and CMS parsing and explicit Authenticode verification.
//!
//! Disable default features for a `no_std + alloc` parser. Enable `verify` for
//! the RustCrypto verifier, `system-roots` for native root enumeration, and
//! `cli` for the command-line adapter. The `msi` and `appx` features expose
//! structural adapters requiring `std`, without verification. Defaults retain the complete CLI.
#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

#[cfg(feature = "verify")]
mod appx;
#[cfg(feature = "verify")]
mod cab;
#[cfg(feature = "cli")]
pub mod cli;
#[cfg(feature = "verify")]
mod cms;
#[cfg(feature = "verify")]
mod crypto;
mod der;
#[cfg(feature = "verify")]
pub mod domain;
#[cfg(feature = "verify")]
pub mod format;
#[cfg(feature = "cli")]
mod inspection;
#[cfg(feature = "verify")]
mod msi;
#[cfg(feature = "verify")]
mod navx;
pub mod parse;
#[cfg(feature = "verify")]
mod pe;
#[cfg(feature = "verify")]
mod powershell;
#[cfg(feature = "verify")]
mod rdp;
#[cfg(feature = "verify")]
mod report;
#[cfg(feature = "verify")]
mod trust;
#[cfg(feature = "verify")]
pub mod verify;
#[cfg(feature = "verify")]
mod wsh;
#[cfg(feature = "verify")]
pub use domain::{SignatureReport, VerificationBundle, VerificationError};
#[cfg(feature = "verify")]
pub use trust::{TrustLoadError, TrustLoadErrorKind, TrustStore};
#[cfg(feature = "verify")]
pub use verify::{
    RevocationPolicy, VerifyOptions, verify, verify_appx, verify_cab, verify_msi, verify_navx,
    verify_parsed_appx, verify_parsed_cab, verify_parsed_msi, verify_parsed_navx, verify_parsed_pe,
    verify_pe, verify_powershell, verify_powershell_xml, verify_rdp, verify_wsh,
};
#[cfg(all(test, feature = "verify"))]
mod tests;
