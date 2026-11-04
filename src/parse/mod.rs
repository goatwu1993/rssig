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
/// This hashes the bytes selected by the supplied PE view. It does not parse the
/// embedded CMS, compare the signed digest, authenticate a signer, or establish trust.
pub fn authenticode_digest(
    pe: &impl PeTrait,
    digest: &mut impl digest::Update,
) -> Result<(), PeOffsetError> {
    let offsets = pe.offsets()?;
    let bytes = pe.data();
    for range in [
        0..offsets.check_sum,
        offsets.after_check_sum..offsets.security_data_dir,
        offsets.after_security_data_dir..offsets.after_header,
    ] {
        let chunk = bytes.get(range).ok_or(PeOffsetError)?;
        digest.update(chunk);
    }
    let mut sections = (1..=pe.num_sections())
        .map(|i| pe.section_data_range(i))
        .collect::<Result<alloc::vec::Vec<_>, _>>()?;
    sections.sort_unstable_by_key(|range| range.start);
    let mut hashed = offsets.after_header;
    for range in sections {
        let chunk = bytes.get(range.clone()).ok_or(PeOffsetError)?;
        digest.update(chunk);
        hashed = hashed.checked_add(chunk.len()).ok_or(PeOffsetError)?;
    }
    let mut trailing = bytes.len().checked_sub(hashed).ok_or(PeOffsetError)?;
    if let Some(cert) = pe.certificate_table_range()? {
        let cert_len = cert.end.checked_sub(cert.start).ok_or(PeOffsetError)?;
        trailing = trailing.checked_sub(cert_len).ok_or(PeOffsetError)?;
    }
    let end = hashed.checked_add(trailing).ok_or(PeOffsetError)?;
    digest.update(bytes.get(hashed..end).ok_or(PeOffsetError)?);
    Ok(())
}
