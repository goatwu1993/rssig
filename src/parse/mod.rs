//! Parse untrusted signature structures without cryptography, trust, clocks, or I/O.
//!
//! This initial API covers signed PE containers and attached/detached CMS
//! envelopes. Parsing success is not a verification result. Unknown algorithm
//! identifiers and opaque certificate choices retain their original DER.
//! Format policy, hashes, signature checks, timestamps, and certificate trust
//! belong to [`mod@crate::verify`]. This module currently requires `std`.
//!
//! ```
//! use rssig::parse::{Pe, SignedData};
//! use rssig::verify::{VerifyOptions, verify_parsed_pe};
//! # let bytes = include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/good-pe64.exe"));
//! let pe = Pe::parse(bytes)?;
//! for signature in pe.signatures()? {
//!     let cms = SignedData::parse(signature)?;
//!     assert!(!cms.certificate_choices().is_empty()); // Still untrusted.
//! }
//! // Explicit integrity-only verification; callers can supply a TrustStore.
//! let options = VerifyOptions {
//!     trust: None, check_revocation: false, allow_sha1: false, now: 1800000000,
//! };
//! let result = verify_parsed_pe(pe, &options)?;
//! assert!(!result.signatures[0].chain_trusted);
//! # Ok::<(), rssig::VerificationError>(())
//! ```

pub(crate) mod cms;
mod pe;

pub use cms::{AlgorithmIdentifier, CertificateChoice, SignedData};
pub use pe::Pe;
