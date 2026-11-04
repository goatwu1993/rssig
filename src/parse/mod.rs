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
pub use pe::{Pe, PeOffsets, PeTrait};

/// Stream an Authenticode image digest into any RustCrypto `digest::Update` sink.
///
/// This hashes the bytes selected by the supplied PE view. It does not parse the
/// embedded CMS, compare the signed digest, authenticate a signer, or establish trust.
pub fn authenticode_digest(
    pe: &impl PeTrait,
    digest: &mut impl digest::Update,
) -> Result<(), Error> {
    let offsets = pe
        .offsets()
        .map_err(|e| Error::new(ErrorKind::InvalidPe, anyhow::Error::new(e)))?;
    let bytes = pe.data();
    for range in [
        0..offsets.check_sum,
        offsets.after_check_sum..offsets.security_data_dir,
        offsets.after_security_data_dir..offsets.after_header,
    ] {
        let chunk = bytes.get(range).ok_or_else(|| {
            Error::new(
                ErrorKind::InvalidPe,
                anyhow::anyhow!("PE digest range exceeds input"),
            )
        })?;
        digest.update(chunk);
    }
    for range in pe.sections() {
        let chunk = bytes.get(range.clone()).ok_or_else(|| {
            Error::new(
                ErrorKind::InvalidPe,
                anyhow::anyhow!("PE section range exceeds input"),
            )
        })?;
        digest.update(chunk);
    }
    Ok(())
}
