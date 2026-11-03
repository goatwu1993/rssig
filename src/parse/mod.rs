//! Parse untrusted signature structures without cryptography, trust, clocks, or I/O.
//!
//! This initial API covers signed PE containers and attached/detached CMS
//! envelopes. Parsing success is not a verification result. Unknown algorithm
//! identifiers and opaque certificate choices retain their original DER.
//! Format policy, hashes, signature checks, timestamps, and certificate trust
//! belong to the optional `verify` module. Parsing requires only `core + alloc`.
//!
//! ```
//! use rssig::parse::{Pe, SignedData};
//! # let bytes = include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/good-pe64.exe"));
//! let pe = Pe::parse(bytes)?;
//! for signature in pe.signatures()? {
//!     let cms = SignedData::parse(signature)?;
//!     assert!(!cms.certificate_choices().is_empty()); // Still untrusted.
//! }
//! # Ok::<(), rssig::parse::Error>(())
//! ```

pub(crate) mod cms;
mod error;
mod pe;

pub use cms::{AlgorithmIdentifier, CertificateChoice, SignedData};
pub use error::{Error, ErrorKind};
pub use pe::Pe;
