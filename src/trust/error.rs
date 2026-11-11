//! Map path-validation errors at the webpki adapter boundary.
use crate::domain::{ErrorCode, Stage, VerificationError};
use serde_json::{Value, json};

pub(crate) fn webpki_error(error: webpki::Error) -> VerificationError {
    use webpki::Error as W;
    let (code, stage, details) = match &error {
        W::CertExpired { time, not_after } => (
            ErrorCode::CertificateExpired,
            Stage::CertificateChain,
            json!({"validation_time":time.as_secs(),"not_after":not_after.as_secs()}),
        ),
        W::CertNotValidYet { time, not_before } => (
            ErrorCode::CertificateNotYetValid,
            Stage::CertificateChain,
            json!({"validation_time":time.as_secs(),"not_before":not_before.as_secs()}),
        ),
        W::UnknownIssuer => (ErrorCode::UntrustedRoot, Stage::CertificateChain, json!({})),
        W::CertRevoked => (ErrorCode::CertificateRevoked, Stage::Revocation, json!({})),
        W::CrlExpired { time, next_update } => (
            ErrorCode::CrlExpired,
            Stage::Revocation,
            json!({"validation_time":time.as_secs(),"next_update":next_update.as_secs()}),
        ),
        W::InvalidCrlSignatureForPublicKey => {
            (ErrorCode::InvalidCrlSignature, Stage::Revocation, json!({}))
        }
        W::UnknownRevocationStatus => (ErrorCode::RevocationUnknown, Stage::Revocation, json!({})),
        W::RequiredEkuNotFoundContext(_) | W::EmptyEkuExtension => {
            (ErrorCode::InvalidEku, Stage::CertificateChain, json!({}))
        }
        W::IssuerNotCrlSigner => (ErrorCode::InvalidKeyUsage, Stage::Revocation, json!({})),
        _ => (
            ErrorCode::CertificateChainInvalid,
            Stage::CertificateChain,
            json!({}),
        ),
    };
    let mut result = VerificationError::new(
        code,
        stage,
        format!("certificate chain validation failed: {error:?}"),
    );
    if let Value::Object(map) = details {
        result.details.extend(map);
    }
    result
}

/// Stable input category for a trust-store loading failure, not a trust verdict.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum TrustLoadErrorKind {
    Roots,
    Crl,
    SystemRoots,
}

/// Loading diagnostics with a typed category and the original causal chain.
#[derive(Debug)]
pub struct TrustLoadError {
    kind: TrustLoadErrorKind,
    inner: anyhow::Error,
}
impl TrustLoadError {
    pub(crate) fn new(kind: TrustLoadErrorKind, inner: anyhow::Error) -> Self {
        Self { kind, inner }
    }
    pub fn kind(&self) -> TrustLoadErrorKind {
        self.kind
    }
}
impl core::fmt::Display for TrustLoadError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.inner.fmt(f)
    }
}
impl std::error::Error for TrustLoadError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.inner.as_ref())
    }
}
