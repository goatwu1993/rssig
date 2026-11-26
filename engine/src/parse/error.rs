use core::{error, fmt};

/// The structure that could not be parsed; independent of verification policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ErrorKind {
    /// Invalid or unsupported MSI/MSP CFB structure.
    InvalidMsi,
    /// No embedded MSI/MSP signature stream.
    UnsignedMsi,
    /// Invalid MSIX/AppX archive or package XML.
    InvalidAppx,
    /// Unsupported MSIX/AppX archive profile.
    UnsupportedAppx,
    /// No embedded MSIX/AppX signature part.
    UnsignedAppx,
    /// Invalid or unsupported PE layout.
    InvalidPe,
    /// Malformed PowerShell text encoding or hash/XML signature block.
    InvalidPowershell,
    /// The PowerShell text has no signature block.
    UnsignedPowershell,
    /// Malformed or mismatched WSH text/signature framing.
    InvalidWsh,
    /// The WSH text has no signature block.
    UnsignedWsh,
    /// WSF XML validation requires the optional xml feature.
    UnsupportedWsfXml,
    /// Malformed RDP text, settings, scope, or signature blob.
    InvalidRdp,
    /// The RDP text has no signature.
    UnsignedRdp,
    /// An RDP signscope entry is outside the supported scope table.
    UnsupportedRdpScope,
    /// The PE has no embedded signature.
    Unsigned,
    /// Invalid or unsupported CAB layout.
    InvalidCab,
    /// The CAB has no embedded signature.
    UnsignedCab,
    /// Invalid or unsupported NAVX layout.
    InvalidNavx,
    /// The NAVX has no embedded signature.
    UnsignedNavx,
    /// Invalid WIN_CERTIFICATE framing or padding.
    InvalidCertificateTable,
    /// Invalid CMS/PKCS#7 structure.
    MalformedCms,
    /// Shared recursive inspection depth or work budget exhausted.
    InspectionLimit,
}

/// A structural parsing failure, with a typed kind and causal diagnostics.
///
/// Implements `core::error::Error`; no verifier, Serde, or `std` is required.
#[derive(Debug)]
pub struct Error {
    kind: ErrorKind,
    pub(crate) inner: anyhow::Error,
}

impl Error {
    pub(crate) fn new(kind: ErrorKind, inner: anyhow::Error) -> Self {
        match inner.downcast::<Self>() {
            Ok(error) => error,
            Err(inner) => Self { kind, inner },
        }
    }

    /// The unsupported RDP signscope entry, when that caused this error.
    pub fn rdp_scope_entry(&self) -> Option<&str> {
        self.inner
            .downcast_ref::<super::rdp::UnsupportedScope>()
            .map(|e| e.entry.as_str())
    }

    /// Stable classification; callers should not match diagnostic prose.
    pub fn kind(&self) -> ErrorKind {
        self.kind
    }
}

impl ErrorKind {
    fn summary(self) -> &'static str {
        match self {
            Self::InvalidMsi => "invalid MSI/MSP structure",
            Self::UnsignedMsi => "unsigned MSI/MSP",
            Self::InvalidAppx => "invalid MSIX/AppX package",
            Self::UnsupportedAppx => "unsupported MSIX/AppX package",
            Self::UnsignedAppx => "unsigned MSIX/AppX package",
            Self::InvalidPe => "invalid PE",
            Self::InvalidPowershell => "invalid PowerShell script",
            Self::UnsignedPowershell => "unsigned PowerShell script",
            Self::InvalidWsh => "invalid WSH script",
            Self::UnsignedWsh => "unsigned WSH script",
            Self::UnsupportedWsfXml => "unsupported WSF XML",
            Self::InvalidRdp => "invalid RDP file",
            Self::UnsignedRdp => "unsigned RDP file",
            Self::UnsupportedRdpScope => "unsupported RDP signscope",
            Self::Unsigned => "unsigned PE",
            Self::InvalidCab => "invalid CAB",
            Self::UnsignedCab => "unsigned CAB",
            Self::InvalidNavx => "invalid NAVX",
            Self::UnsignedNavx => "unsigned NAVX",
            Self::InvalidCertificateTable => "invalid certificate table",
            Self::MalformedCms => "malformed CMS",
            Self::InspectionLimit => "inspection limit exceeded",
        }
    }
}

/// `{}` names what failed from the typed kind; `{:#}` adds the whole causal
/// chain. `source()` is that chain, so a reporter walking sources prints each
/// cause once.
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.kind.summary())?;
        if f.alternate() {
            write!(f, ": {:#}", self.inner)?;
        }
        Ok(())
    }
}

impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        Some(self.inner.as_ref())
    }
}

// der 0.7 only implements std::error::Error with its std feature. This
// adapter preserves the same diagnostic on both std and core-only targets.
#[derive(Debug)]
pub(crate) struct DecodeError(pub ::der::Error);

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl error::Error for DecodeError {}

#[cfg(test)]
mod tests {
    use super::{Error, ErrorKind};
    use alloc::{format, string::ToString};

    // One list generates both an exhaustive match and the rows it tests, so a
    // new ErrorKind variant fails to compile until it is listed here.
    macro_rules! summaries {
        ($($kind:ident => $summary:literal,)*) => {
            #[allow(dead_code)]
            fn exhaustive(kind: ErrorKind) {
                match kind {
                    $(ErrorKind::$kind => {})*
                }
            }
            const ROWS: &[(ErrorKind, &str)] = &[$((ErrorKind::$kind, $summary)),*];
        };
    }
    summaries! {
        InvalidMsi => "invalid MSI/MSP structure",
        UnsignedMsi => "unsigned MSI/MSP",
        InvalidAppx => "invalid MSIX/AppX package",
        UnsupportedAppx => "unsupported MSIX/AppX package",
        UnsignedAppx => "unsigned MSIX/AppX package",
        InvalidPe => "invalid PE",
        InvalidPowershell => "invalid PowerShell script",
        UnsignedPowershell => "unsigned PowerShell script",
        InvalidWsh => "invalid WSH script",
        UnsignedWsh => "unsigned WSH script",
        UnsupportedWsfXml => "unsupported WSF XML",
        InvalidRdp => "invalid RDP file",
        UnsignedRdp => "unsigned RDP file",
        UnsupportedRdpScope => "unsupported RDP signscope",
        Unsigned => "unsigned PE",
        InvalidCab => "invalid CAB",
        UnsignedCab => "unsigned CAB",
        InvalidNavx => "invalid NAVX",
        UnsignedNavx => "unsigned NAVX",
        InvalidCertificateTable => "invalid certificate table",
        MalformedCms => "malformed CMS",
        InspectionLimit => "inspection limit exceeded",
    }

    #[test]
    fn every_kind_has_a_distinct_summary_and_prints_each_cause_once() {
        for (index, (kind, summary)) in ROWS.iter().enumerate() {
            assert!(
                ROWS[..index].iter().all(|(k, s)| k != kind && s != summary),
                "duplicate row for {kind:?}"
            );
            let error = Error::new(
                *kind,
                anyhow::anyhow!("leaf cause").context("outer context"),
            );
            assert_eq!(error.kind(), *kind);
            assert_eq!(error.to_string(), *summary);
            let chain = format!("{error:#}");
            assert_eq!(chain, format!("{summary}: outer context: leaf cause"));
            crate::assert_causes_once(&error, &chain);
        }
    }
}
