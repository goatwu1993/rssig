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
pub use pe::{Pe, PeOffsetError, PeOffsets, PeTrait};

/// Stream an Authenticode image digest into any RustCrypto `digest::Update` sink.
///
/// Uses the same bounded layout policy as [`Pe`]: nonempty sections may be
/// supplied in any order, but must not overlap headers, each other, or the
/// certificate table. Only a gap before the first section is supported. That
/// gap and any overlay before the certificate table are hashed exactly once.
/// A present certificate table must be nonempty, eight-byte aligned, and end
/// at EOF. An absent table permits hashing unsigned images supplied by a view.
///
/// All ranges are validated before updating the sink; an error leaves it
/// unchanged. The view must derive its offsets from the actual PE headers:
/// this function validates the supplied layout, not the PE encoding itself.
/// It does not parse CMS, authenticate a signer, or establish trust.
pub fn authenticode_digest(
    pe: &impl PeTrait,
    digest: &mut impl digest::Update,
) -> Result<(), PeOffsetError> {
    for chunk in pe::validated_digest_chunks(pe)? {
        digest.update(chunk);
    }
    Ok(())
}
