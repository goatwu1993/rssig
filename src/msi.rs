//! Verification policy and reports over the shared MSI/MSP structural adapter.
use crate::crypto::DigestSink;
pub(crate) use crate::parse::Msi;
pub(crate) use crate::parse::msi::MAGIC;
use crate::{crypto::Hash, domain::*};
use anyhow::Result;

pub(crate) fn digests(msi: &mut Msi<'_>, hash: Hash) -> Result<(Vec<u8>, Option<DigestReport>)> {
    let mut digest = hash.hasher();
    let extended = if let Some(expected) = msi.extended_digest().map(<[u8]>::to_vec) {
        let mut metadata = hash.hasher();
        msi.update_metadata(&mut DigestSink(&mut *metadata))
            .map_err(VerificationError::from)?;
        let computed = metadata.finalize().to_vec();
        let report = DigestReport {
            algorithm: format!("{hash:?}"),
            expected: hex(&expected),
            computed: hex(&computed),
        };
        if expected != computed {
            return Err(VerificationError::new(
                ErrorCode::ExtendedDigestMismatch,
                Stage::PackageDigest,
                "MSI extended digest mismatch",
            )
            .detail("extended_digest", &report)
            .into());
        }
        digest.update(&computed);
        Some(report)
    } else {
        None
    };
    msi.update_content(&mut DigestSink(&mut *digest))
        .map_err(VerificationError::from)?;
    Ok((digest.finalize().to_vec(), extended))
}
