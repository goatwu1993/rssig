//! Parse untrusted signature structures without cryptography, trust, clocks, or I/O.
//!
//! This API covers signed PE, CAB, NAVX containers and attached/detached CMS
//! envelopes, PowerShell/XML comments, WSH scripts, and scoped RDP settings.
//! WSF XML validation requires the `xml` feature, which also uses `core + alloc`.
//! MSI/MSP and AppX adapters are available with `msi` and `appx` respectively;
//! those explicitly require `std`, without enabling verification or reports.
//! Parsing success is not a verification result. Unknown algorithm
//! identifiers and opaque certificate choices retain their original DER.
//! Signature algorithm policy, hashes, signature checks, timestamp authentication, and certificate trust
//! belong to the optional `verify` module. The base parsers require only `core + alloc`.
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

pub(crate) mod cab;
pub(crate) mod cms;
mod error;
pub(crate) mod navx;
mod nested;
mod pe;
pub(crate) mod signer;

pub use cab::Cab;
pub use cms::{AlgorithmIdentifier, CertificateChoice, SignedData};
pub use error::{Error, ErrorKind};
pub use navx::Navx;
pub use nested::{
    InspectedChild, InspectedCms, InspectedSigner, InspectionBudget, InspectionKind,
    InspectionLimits, ParsedTime, TstInfo,
};
pub use pe::{Pe, PeOffsetError, PeOffsets, PeTrait};
pub use signer::{Attribute, Attributes, Content, SignerIdentifier, SignerInfo};

pub(crate) mod powershell;
pub(crate) mod rdp;
mod text;
pub(crate) mod wsh;
pub use powershell::Powershell;
pub use rdp::{Rdp, RdpSetting, RdpValueType};
pub use text::TextEncoding;
pub use wsh::{Kind as WshKind, Wsh};

#[cfg(feature = "xml")]
mod wsf_xml;

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

#[cfg(feature = "msi")]
pub(crate) mod msi;
#[cfg(feature = "msi")]
pub use msi::Msi;
#[cfg(feature = "appx")]
pub(crate) mod appx;
#[cfg(feature = "appx")]
pub use appx::{
    Appx, AppxDigestInput, AppxIdentity, AppxPart, BlockMap, BlockMapBlock, BlockMapFile,
    BundlePackage,
};
