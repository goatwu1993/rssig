use core::{error, fmt};

/// The structure that could not be parsed; independent of verification policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ErrorKind {
    /// Invalid or unsupported PE layout.
    InvalidPe,
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

    /// Stable classification; callers should not match diagnostic prose.
    pub fn kind(&self) -> ErrorKind {
        self.kind
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#}", self.inner)
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
