mod cab;
pub mod cli;
mod cms;
mod crypto;
mod der;
pub mod domain;
mod msi;
mod pe;
mod powershell;
mod trust;
mod verify;
pub use domain::{SignatureReport, VerificationBundle, VerificationError};
pub use trust::TrustStore;
pub use verify::{VerifyOptions, verify, verify_cab, verify_msi, verify_pe, verify_powershell};
#[cfg(test)]
mod tests;
