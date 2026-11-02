//! Bind Authenticode content to container bytes before authenticating signers.
use super::{container::Container, tagged};
use crate::{cms::SignedData, crypto::Hash, domain::*};
use anyhow::Result;

pub(super) struct Integrity {
    pub hash: Hash,
    pub image_digest: Option<DigestReport>,
    pub package_digest: Option<DigestReport>,
    pub script_digest: Option<DigestReport>,
    pub extended_digest: Option<DigestReport>,
    pub page_hashes: Option<DigestReport>,
}

pub(super) fn verify(
    container: &mut Container<'_>,
    sd: &SignedData<'_>,
    allow_sha1: bool,
) -> Result<Integrity> {
    let is_msi = matches!(container, Container::Msi(_));
    let is_navx = matches!(container, Container::Navx(_));
    let is_cab = matches!(container, Container::Cab(_));
    let is_script = matches!(container, Container::Powershell(_) | Container::Wsh(_));
    let is_appx = matches!(container, Container::Appx(_));
    let is_package = is_msi || is_cab || is_appx || is_navx;
    let stage = if is_script {
        Stage::ScriptDigest
    } else if is_package {
        Stage::PackageDigest
    } else {
        Stage::ImageDigest
    };
    let (hash, expected, appx_kind) = if let Container::Appx(appx) = container {
        let (hash, expected, signed_bundle) =
            tagged(sd.appx_digest(), ErrorCode::MalformedCms, Stage::Cms)?;
        (hash, expected, Some((signed_bundle, appx.is_bundle())))
    } else {
        let (hash, expected) = tagged(
            if let Container::Wsh(script) = container {
                sd.wsh_digest(script.kind)
            } else if is_script {
                sd.script_digest()
            } else if is_navx {
                sd.navx_digest()
            } else if is_cab {
                sd.cab_digest()
            } else if is_msi {
                sd.package_digest()
            } else {
                sd.image_digest()
            },
            ErrorCode::MalformedCms,
            Stage::Cms,
        )?;
        (hash, expected, None)
    };
    if let Some((signed_bundle, package_is_bundle)) = appx_kind
        && signed_bundle != package_is_bundle
    {
        return Err(VerificationError::new(
            ErrorCode::MalformedCms,
            Stage::Cms,
            "MSIX/AppX SIP UUID does not match the package kind",
        )
        .into());
    }
    if !allow_sha1 && hash == Hash::Sha1 {
        return Err(VerificationError::new(
            ErrorCode::WeakAlgorithm,
            stage,
            "SHA-1 image/package/script digest requires --allow-sha1",
        )
        .into());
    }
    let (computed, extended_digest) = match container {
        Container::Pe(pe) => (pe.digest(hash)?, None),
        Container::Msi(msi) => msi.digests(hash)?,
        Container::Appx(appx) => (
            tagged(appx.digests(hash), ErrorCode::InvalidAppx, Stage::Appx)?,
            None,
        ),
        Container::Cab(cab) => (cab.digest(hash), None),
        Container::Navx(navx) => (navx.digest(hash), None),
        Container::Powershell(script) => (script.digest(hash), None),
        Container::Wsh(script) => (script.digest(hash), None),
    };
    let image_digest = DigestReport {
        algorithm: format!("{hash:?}"),
        expected: hex(expected),
        computed: hex(&computed),
    };
    if computed != expected {
        if let Container::Appx(appx) = container {
            return Err(appx.mismatch(expected, &computed, hash).into());
        }
        return Err(VerificationError::new(
            if is_script {
                ErrorCode::ScriptDigestMismatch
            } else if is_navx {
                ErrorCode::NavxDigestMismatch
            } else if is_cab {
                ErrorCode::CabDigestMismatch
            } else if is_msi {
                ErrorCode::PackageDigestMismatch
            } else {
                ErrorCode::ImageDigestMismatch
            },
            stage,
            if is_script {
                "Script digest mismatch (file was modified)"
            } else if is_navx {
                "NAVX digest mismatch (file was modified)"
            } else if is_cab {
                "CAB digest mismatch (file was modified)"
            } else if is_msi {
                "MSI package digest mismatch (file was modified)"
            } else {
                "PE image digest mismatch (file was modified)"
            },
        )
        .detail("digest", &image_digest)
        .into());
    }
    if let Container::Appx(appx) = container {
        tagged(appx.validate(hash), ErrorCode::InvalidAppx, Stage::Appx)?;
    }
    let mut page_hashes = None;
    if let Container::Pe(pe) = container
        && let Some((hash, expected)) =
            tagged(sd.page_hashes(), ErrorCode::MalformedCms, Stage::PageHashes)?
    {
        if !allow_sha1 && hash == Hash::Sha1 {
            return Err(VerificationError::new(
                ErrorCode::WeakAlgorithm,
                Stage::PageHashes,
                "SHA-1 page hashes require --allow-sha1",
            )
            .into());
        }
        let computed = pe.page_hashes(hash)?;
        let report = DigestReport {
            algorithm: format!("{hash:?}"),
            expected: hex(expected),
            computed: hex(&computed),
        };
        if computed != expected {
            return Err(VerificationError::new(
                ErrorCode::PageHashMismatch,
                Stage::PageHashes,
                "PE page hash mismatch",
            )
            .detail("page_hashes", &report)
            .into());
        }
        page_hashes = Some(report);
    }
    Ok(Integrity {
        hash,
        image_digest: (!is_package && !is_script).then(|| image_digest.clone()),
        package_digest: is_package.then(|| image_digest.clone()),
        script_digest: is_script.then_some(image_digest),
        extended_digest,
        page_hashes,
    })
}
