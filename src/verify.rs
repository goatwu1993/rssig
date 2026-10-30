//! Authenticate parsed containers using explicit time, trust, and revocation policy.
//!
//! Parsing alone never establishes integrity or trust. Existing byte-oriented
//! entry points remain available; [`verify_parsed_pe`] reuses a parsed PE layout.

use crate::domain::*;
use crate::{
    appx::Appx,
    cab::Cab,
    cms::{self, SignedData},
    crypto::Hash,
    der::{self, Node},
    msi::Msi,
    navx::Navx,
    pe::Pe,
    powershell::Powershell,
    trust::{self, TrustStore},
    wsh::{Kind, Wsh},
};
use ::der::Decode;
use anyhow::{Context, Result, ensure};

pub struct VerifyOptions<'a> {
    pub trust: Option<&'a TrustStore>,
    pub check_revocation: bool,
    pub allow_sha1: bool,
    pub now: u64,
}

pub fn verify_pe(
    bytes: &[u8],
    options: &VerifyOptions<'_>,
) -> std::result::Result<VerificationBundle, VerificationError> {
    verify_inner(bytes, options, Format::Pe).map_err(|e| {
        VerificationError::from_internal(e, ErrorCode::InvalidCertificate, Stage::Certificate)
    })
}

/// Detect the signed container from its bytes; file extensions are not trusted.
pub fn verify(
    bytes: &[u8],
    options: &VerifyOptions<'_>,
) -> std::result::Result<VerificationBundle, VerificationError> {
    if bytes.starts_with(crate::msi::MAGIC) {
        verify_msi(bytes, options)
    } else if bytes.starts_with(crate::navx::MAGIC) {
        verify_navx(bytes, options)
    } else if bytes.starts_with(crate::cab::MAGIC) {
        verify_cab(bytes, options)
    } else if bytes.starts_with(b"PK\x03\x04") {
        verify_appx(bytes, options)
    } else if !bytes.starts_with(b"MZ") && crate::wsh::looks_like(bytes) {
        verify_wsh(bytes, options)
    } else if !bytes.starts_with(b"MZ") && crate::powershell::looks_like(bytes) {
        verify_powershell(bytes, options)
    } else if !bytes.starts_with(b"MZ") && crate::powershell::looks_like_xml(bytes) {
        verify_powershell_xml(bytes, options)
    } else if !bytes.starts_with(b"MZ") && crate::rdp::looks_like(bytes) {
        verify_rdp(bytes, options)
    } else {
        verify_pe(bytes, options)
    }
}

/// Verify an MSI installer or MSP patch's embedded Authenticode signature.
///
/// Both use the MSI SIP and report `msi_authenticode`. An MSP is verified on its
/// own; this does not check applicability to an installation or apply the patch.
pub fn verify_msi(
    bytes: &[u8],
    options: &VerifyOptions<'_>,
) -> std::result::Result<VerificationBundle, VerificationError> {
    verify_inner(bytes, options, Format::Msi).map_err(|e| {
        VerificationError::from_internal(e, ErrorCode::InvalidCertificate, Stage::Certificate)
    })
}

/// Verify a Microsoft Dynamics NAVX package with an embedded Authenticode signature.
pub fn verify_navx(
    bytes: &[u8],
    options: &VerifyOptions<'_>,
) -> std::result::Result<VerificationBundle, VerificationError> {
    verify_inner(bytes, options, Format::Navx).map_err(|e| {
        VerificationError::from_internal(e, ErrorCode::InvalidCertificate, Stage::Certificate)
    })
}

pub fn verify_cab(
    bytes: &[u8],
    options: &VerifyOptions<'_>,
) -> std::result::Result<VerificationBundle, VerificationError> {
    verify_inner(bytes, options, Format::Cab).map_err(|e| {
        VerificationError::from_internal(e, ErrorCode::InvalidCertificate, Stage::Certificate)
    })
}

/// Verify a hash-comment PowerShell script with an embedded Authenticode block.
pub fn verify_powershell(
    bytes: &[u8],
    options: &VerifyOptions<'_>,
) -> std::result::Result<VerificationBundle, VerificationError> {
    verify_inner(bytes, options, Format::Powershell).map_err(|e| {
        VerificationError::from_internal(e, ErrorCode::InvalidCertificate, Stage::Certificate)
    })
}

/// Verify XML-comment PowerShell Authenticode (.ps1xml), not XMLDSig.
pub fn verify_powershell_xml(
    bytes: &[u8],
    options: &VerifyOptions<'_>,
) -> std::result::Result<VerificationBundle, VerificationError> {
    verify_inner(bytes, options, Format::PowershellXml).map_err(|e| {
        VerificationError::from_internal(e, ErrorCode::InvalidCertificate, Stage::Certificate)
    })
}

/// Verify a detached CMS signature over the explicitly scoped RDP settings.
pub fn verify_rdp(
    bytes: &[u8],
    options: &VerifyOptions<'_>,
) -> std::result::Result<VerificationBundle, VerificationError> {
    crate::rdp::verify(bytes, options).map_err(|e| {
        VerificationError::from_internal(e, ErrorCode::InvalidCertificate, Stage::Certificate)
    })
}

/// Verify an embedded-signature MSIX/AppX package or bundle and its embedded packages.
pub fn verify_appx(
    bytes: &[u8],
    options: &VerifyOptions<'_>,
) -> std::result::Result<VerificationBundle, VerificationError> {
    verify_inner(bytes, options, Format::Appx).map_err(|e| {
        VerificationError::from_internal(e, ErrorCode::InvalidCertificate, Stage::Certificate)
    })
}

/// Verify Windows Script Host Authenticode, detecting the signature comment style.
pub fn verify_wsh(
    bytes: &[u8],
    options: &VerifyOptions<'_>,
) -> std::result::Result<VerificationBundle, VerificationError> {
    let kind = crate::wsh::detect(bytes)
        .map_err(|e| VerificationError::from_internal(e, ErrorCode::InvalidWsh, Stage::Wsh))?;
    verify_wsh_as(bytes, kind, options)
}
pub(crate) fn verify_wsh_as(
    bytes: &[u8],
    kind: Kind,
    options: &VerifyOptions<'_>,
) -> std::result::Result<VerificationBundle, VerificationError> {
    verify_inner(bytes, options, Format::Wsh(kind)).map_err(|e| {
        VerificationError::from_internal(e, ErrorCode::InvalidCertificate, Stage::Certificate)
    })
}

pub(crate) fn is_binary(bytes: &[u8]) -> bool {
    bytes.starts_with(b"MZ")
        || bytes.starts_with(crate::msi::MAGIC)
        || bytes.starts_with(crate::navx::MAGIC)
        || bytes.starts_with(crate::cab::MAGIC)
        || bytes.starts_with(b"PK\x03\x04")
}

enum Format {
    Pe,
    Msi,
    Cab,
    Navx,
    Powershell,
    PowershellXml,
    Wsh(Kind),
    Appx,
}

enum Container<'a> {
    Pe(Pe<'a>),
    Appx(Box<Appx<'a>>),
    Cab(Cab<'a>),
    Navx(Navx<'a>),
    Powershell(Powershell),
    Wsh(Wsh),
    Msi(Box<Msi<'a>>),
}

fn tagged<T>(result: Result<T>, code: ErrorCode, stage: Stage) -> Result<T> {
    result.map_err(|e| VerificationError::from_internal(e, code, stage).into())
}

fn verify_inner(
    bytes: &[u8],
    options: &VerifyOptions<'_>,
    format: Format,
) -> Result<VerificationBundle> {
    let container = match format {
        Format::Wsh(kind) => Container::Wsh(tagged(
            Wsh::parse(bytes, kind),
            ErrorCode::InvalidWsh,
            Stage::Wsh,
        )?),
        Format::Appx => Container::Appx(Box::new(tagged(
            Appx::parse(bytes),
            ErrorCode::InvalidAppx,
            Stage::Appx,
        )?)),
        Format::PowershellXml => Container::Powershell(tagged(
            Powershell::parse_xml(bytes),
            ErrorCode::InvalidPowershell,
            Stage::Powershell,
        )?),
        Format::Powershell => Container::Powershell(tagged(
            Powershell::parse(bytes),
            ErrorCode::InvalidPowershell,
            Stage::Powershell,
        )?),
        Format::Msi => Container::Msi(Box::new(Msi::parse(bytes)?)),
        Format::Pe => Container::Pe(Pe::parse(bytes)?),
        Format::Navx => Container::Navx(tagged(
            Navx::parse(bytes),
            ErrorCode::InvalidNavx,
            Stage::Navx,
        )?),
        Format::Cab => Container::Cab(tagged(
            Cab::parse(bytes),
            ErrorCode::InvalidCab,
            Stage::Cab,
        )?),
    };
    verify_container(bytes, options, format, container)
}

/// Verify a parsed PE without reparsing its headers. All hashes, CMS signatures,
/// timestamps, trust chains, and configured CRLs are still checked.
///
/// The parsed value has private fields and borrows immutable bytes, so it
/// cannot substitute altered bytes or caller-supplied verification assertions.
pub fn verify_parsed_pe(
    pe: crate::parse::Pe<'_>,
    options: &VerifyOptions<'_>,
) -> std::result::Result<VerificationBundle, VerificationError> {
    verify_container(pe.data, options, Format::Pe, Container::Pe(pe)).map_err(|e| {
        VerificationError::from_internal(e, ErrorCode::InvalidCertificate, Stage::Certificate)
    })
}

fn verify_container(
    bytes: &[u8],
    options: &VerifyOptions<'_>,
    format: Format,
    mut container: Container<'_>,
) -> Result<VerificationBundle> {
    let mut reports = Vec::new();
    let certificates: Vec<Vec<u8>> = match &container {
        Container::Pe(pe) => tagged(
            pe.certificates(),
            ErrorCode::InvalidCertificateTable,
            Stage::CertificateTable,
        )?
        .iter()
        .map(|c| c.to_vec())
        .collect(),
        Container::Msi(msi) => vec![msi.signature().to_vec()],
        Container::Appx(appx) => vec![appx.signature().to_vec()],
        Container::Navx(navx) => vec![navx.signature().to_vec()],
        Container::Cab(cab) => vec![cab.signature().to_vec()],
        Container::Powershell(script) => vec![script.signature().to_vec()],
        Container::Wsh(script) => vec![script.signature().to_vec()],
    };
    for certificate in &certificates {
        // Some signers count zero padding inside dwLength. Only permit zeroes
        // after one complete DER object, never arbitrary unsigned payloads.
        let mut rest = certificate.as_slice();
        let node = tagged(der::take(&mut rest), ErrorCode::MalformedCms, Stage::Cms)?;
        if matches!(
            format,
            Format::Powershell
                | Format::PowershellXml
                | Format::Wsh(_)
                | Format::Appx
                | Format::Navx
        ) && !rest.is_empty()
        {
            return Err(VerificationError::new(
                ErrorCode::MalformedCms,
                Stage::Cms,
                "trailing data in embedded CMS signature",
            )
            .into());
        }
        if matches!(format, Format::Msi) && !rest.is_empty() {
            return Err(VerificationError::new(
                ErrorCode::MalformedCms,
                Stage::Cms,
                "trailing data in MSI signature stream",
            )
            .into());
        }
        if matches!(format, Format::Cab) && (rest.len() > 7 || !rest.iter().all(|b| *b == 0)) {
            return Err(VerificationError::new(
                ErrorCode::MalformedCms,
                Stage::Cms,
                "invalid trailing data in CAB signature",
            )
            .into());
        }
        if !rest.iter().all(|b| *b == 0) {
            return Err(VerificationError::new(
                ErrorCode::InvalidCertificateTable,
                Stage::CertificateTable,
                "nonzero trailing data in WIN_CERTIFICATE",
            )
            .detail("trailing_bytes", rest.len())
            .into());
        }
        verify_signature(node.full, &mut container, options, 0, &mut reports)?;
    }
    let mut verification = VerificationBundle {
        format: match format {
            Format::Wsh(kind) => kind.format(),
            Format::Msi => "msi_authenticode",
            Format::Pe => "pe_authenticode",
            Format::Cab => "cab_authenticode",
            Format::Navx => "navx_authenticode",
            Format::Powershell => "powershell_authenticode",
            Format::PowershellXml => "powershell_xml_authenticode",
            Format::Appx => "appx_authenticode",
        }
        .into(),
        validation_time: options.now,
        file_sha256: hex(&Hash::Sha256.digest(bytes)),
        signatures: reports,
        rdp: None,
        appx: match &container {
            Container::Appx(appx) => appx.report.clone(),
            _ => None,
        },
    };
    if let Container::Appx(appx) = &container
        && appx.is_bundle()
    {
        let bundle_signer = verification
            .signatures
            .first()
            .context("bundle has no verified signing certificate")?
            .certificate_sha256
            .clone();
        let mut package_reports = Vec::with_capacity(appx.bundle_packages().len());
        for package in appx.bundle_packages() {
            let nested = tagged(
                Appx::parse(package.bytes),
                ErrorCode::InvalidAppx,
                Stage::Appx,
            )?;
            if nested.is_bundle() {
                return Err(VerificationError::new(
                    ErrorCode::UnsupportedAppx,
                    Stage::Appx,
                    "nested MSIX/AppX bundles are unsupported",
                )
                .detail("file_name", &package.file_name)
                .into());
            }
            let package_verification =
                verify_inner(package.bytes, options, Format::Appx).map_err(|error| {
                    VerificationError::from_internal(error, ErrorCode::InvalidAppx, Stage::Appx)
                        .detail("bundle_package", &package.file_name)
                })?;
            let package_report = package_verification
                .appx
                .as_ref()
                .context("verified bundle package has no AppX report")?;
            if !(package_report.kind == AppxKind::Package
                && package_report.identity.name == appx.report.as_ref().unwrap().identity.name
                && package_report.identity.version == package.version
                && package_report.identity.resource_id == package.resource_id
                && (package.package_type == "resource")
                    == tagged(
                        nested.resource_package(),
                        ErrorCode::InvalidAppx,
                        Stage::Appx,
                    )?
                && package.architecture.as_ref().is_none_or(|architecture| {
                    package_report
                        .identity
                        .processor_architecture
                        .as_deref()
                        .unwrap_or("neutral")
                        == architecture
                }))
            {
                return Err(VerificationError::new(
                    ErrorCode::InvalidAppx,
                    Stage::Appx,
                    "bundle package identity differs from its manifest entry",
                )
                .detail("bundle_package", &package.file_name)
                .into());
            }
            let package_signer = package_verification
                .signatures
                .first()
                .context("bundle package has no verified signing certificate")?;
            if package_signer.certificate_sha256 != bundle_signer {
                return Err(VerificationError::new(
                    ErrorCode::AppxPublisherMismatch,
                    Stage::Appx,
                    "bundle package and bundle use different signing certificates",
                )
                .detail("file_name", &package.file_name)
                .detail("bundle_certificate_sha256", &bundle_signer)
                .detail(
                    "package_certificate_sha256",
                    &package_signer.certificate_sha256,
                )
                .into());
            }
            package_reports.push(AppxBundlePackageReport {
                file_name: package.file_name.clone(),
                package_type: package.package_type.clone(),
                architecture: package.architecture.clone(),
                resource_id: package.resource_id.clone(),
                version: package.version.clone(),
                offset: package.offset,
                size: package.size,
                verification: Box::new(package_verification),
            });
        }
        verification
            .appx
            .as_mut()
            .context("verified bundle has no AppX report")?
            .bundle_packages = Some(package_reports);
    }
    Ok(verification)
}

fn verify_signature(
    bytes: &[u8],
    container: &mut Container<'_>,
    options: &VerifyOptions<'_>,
    depth: usize,
    reports: &mut Vec<SignatureReport>,
) -> Result<()> {
    if depth > 8 || reports.len() >= 64 {
        return Err(VerificationError::new(
            ErrorCode::MalformedCms,
            Stage::Cms,
            "too many nested signatures",
        )
        .into());
    }
    let sd = tagged(
        SignedData::parse(bytes),
        ErrorCode::MalformedCms,
        Stage::Cms,
    )?;
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
    if !options.allow_sha1 && hash == Hash::Sha1 {
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
        if !options.allow_sha1 && hash == Hash::Sha1 {
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
    for si in &sd.signers {
        let signer = tagged(
            sd.verify(*si, options.allow_sha1)
                .context("CMS signature verification"),
            ErrorCode::InvalidSignature,
            Stage::Cms,
        )?;
        if let Container::Appx(appx) = container {
            tagged(
                appx.publisher(&signer.cert),
                ErrorCode::AppxPublisherMismatch,
                Stage::Appx,
            )?;
        }
        let timestamp_verification = tagged(
            verify_timestamp(&sd.certs, &signer, options),
            ErrorCode::InvalidTimestamp,
            Stage::Timestamp,
        )?;
        let timestamp = timestamp_verification.as_ref().map(|t| t.signing_time);
        let trust_report = if let Some(trust) = options.trust {
            Some(tagged(
                trust.verify(
                    &signer.cert,
                    &sd.certs,
                    trust::CODE_SIGNING,
                    timestamp.unwrap_or(options.now),
                    options.now,
                    options.check_revocation,
                ),
                ErrorCode::CertificateChainInvalid,
                Stage::CertificateChain,
            )?)
        } else {
            None
        };
        let certificate = CertificateReport::parse(&signer.cert)?;
        if let Some(timestamp) = &timestamp_verification {
            check_fractional_validity(
                trust_report.as_ref(),
                timestamp.signing_time,
                timestamp.fractional_seconds.as_deref(),
            )?;
        }
        reports.push(SignatureReport {
            unverified_certificate_choices: sd.unverified_certificate_choices.clone(),
            subject: certificate.subject.display.clone(),
            digest_algorithm: format!("{hash:?}"),
            certificate_sha256: certificate.sha256.clone(),
            timestamp,
            chain_trusted: options.trust.is_some(),
            revocation_checked: options.trust.is_some() && options.check_revocation,
            nested_depth: depth,
            certificate,
            embedded_certificates: sd
                .certs
                .iter()
                .map(CertificateReport::parse)
                .collect::<Result<_>>()?,
            image_digest: (!is_package && !is_script).then(|| image_digest.clone()),
            package_digest: is_package.then(|| image_digest.clone()),
            script_digest: is_script.then(|| image_digest.clone()),
            extended_digest: extended_digest.clone(),
            page_hashes: page_hashes.clone(),
            trust: trust_report,
            timestamp_verification,
        });
        for (oid, values) in &signer.unsigned {
            if oid == cms::NESTED {
                for value in values {
                    verify_signature(value.full, container, options, depth + 1, reports)?;
                }
            }
        }
    }
    Ok(())
}

pub(crate) fn verify_timestamp(
    certificates: &[x509_cert::Certificate],
    signer: &cms::Signer<'_>,
    options: &VerifyOptions<'_>,
) -> Result<Option<TimestampReport>> {
    let mut timestamp = None;
    for (oid, values) in &signer.unsigned {
        if oid.as_slice() == cms::RFC3161 || oid.as_slice() == cms::CMS_TIMESTAMP {
            ensure!(
                values.len() == 1 && timestamp.is_none(),
                "multiple timestamps are unsupported"
            );
            let mut token = SignedData::parse(values[0].full)?;
            token.certs.extend(certificates.iter().cloned());
            ensure!(
                token.content_type == cms::TST_INFO && token.signers.len() == 1,
                "invalid RFC3161 token"
            );
            let info = token.content.children()?;
            ensure!(info.len() >= 5, "truncated TSTInfo");
            let imprint = der::fields(info[2].expect(0x30)?, 2)?;
            let hash = cms::algorithm(imprint[0])?;
            ensure!(
                options.allow_sha1 || hash != Hash::Sha1,
                "SHA-1 timestamp requires --allow-sha1"
            );
            let expected = imprint[1].expect(4)?.body;
            let computed = hash.digest(signer.signature);
            if expected != computed {
                return Err(VerificationError::new(
                    ErrorCode::TimestampImprintMismatch,
                    Stage::Timestamp,
                    "timestamp imprint mismatch",
                )
                .detail("expected", hex(expected))
                .detail("computed", hex(&computed))
                .into());
            }
            let (at, fractional_seconds) = parse_time(info[4])?;
            if at > options.now || (at == options.now && fractional_seconds.is_some()) {
                return Err(VerificationError::new(
                    ErrorCode::TimestampInFuture,
                    Stage::Timestamp,
                    "timestamp is in the future",
                )
                .detail("signing_time", at)
                .detail("fractional_seconds", &fractional_seconds)
                .detail("validation_time", options.now)
                .into());
            }
            let tsa = token.verify(token.signers[0], options.allow_sha1)?;
            let trust_report = if let Some(trust) = options.trust {
                Some(trust.verify(
                    &tsa.cert,
                    &token.certs,
                    trust::TIME_STAMPING,
                    at,
                    options.now,
                    options.check_revocation,
                )?)
            } else {
                None
            };
            check_fractional_validity(trust_report.as_ref(), at, fractional_seconds.as_deref())?;
            timestamp = Some(TimestampReport {
                fractional_seconds,
                kind: "rfc3161".into(),
                unverified_certificate_choices: token.unverified_certificate_choices,
                signing_time: at,
                certificate: CertificateReport::parse(&tsa.cert)?,
                trust: trust_report,
            });
        } else if oid.as_slice() == cms::COUNTERSIGN {
            ensure!(
                values.len() == 1 && timestamp.is_none(),
                "multiple timestamps are unsupported"
            );
            let tsa = cms::verify_countersigner(
                certificates,
                values[0],
                signer.signature,
                options.allow_sha1,
            )?;
            let time = cms::attribute(&tsa.signed, &[42, 134, 72, 134, 247, 13, 1, 9, 5])?
                .context("countersignature lacks signingTime")?;
            let (at, fractional_seconds) = parse_time(time)?;
            if at > options.now || (at == options.now && fractional_seconds.is_some()) {
                return Err(VerificationError::new(
                    ErrorCode::TimestampInFuture,
                    Stage::Timestamp,
                    "timestamp is in the future",
                )
                .detail("signing_time", at)
                .detail("fractional_seconds", &fractional_seconds)
                .detail("validation_time", options.now)
                .into());
            }
            let trust_report = if let Some(trust) = options.trust {
                Some(trust.verify(
                    &tsa.cert,
                    certificates,
                    trust::TIME_STAMPING,
                    at,
                    options.now,
                    options.check_revocation,
                )?)
            } else {
                None
            };
            check_fractional_validity(trust_report.as_ref(), at, fractional_seconds.as_deref())?;
            timestamp = Some(TimestampReport {
                fractional_seconds,
                kind: "pkcs9_countersignature".into(),
                unverified_certificate_choices: Vec::new(),
                signing_time: at,
                certificate: CertificateReport::parse(&tsa.cert)?,
                trust: trust_report,
            });
        }
    }
    Ok(timestamp)
}

pub(crate) fn check_fractional_validity(
    trust: Option<&TrustReport>,
    seconds: u64,
    fraction: Option<&str>,
) -> Result<()> {
    if let (Some(trust), Some(fraction)) = (trust, fraction) {
        // webpki checks notBefore and notAfter at whole seconds. Also check the
        // nonzero fraction against leaf/intermediate expiry. Trust anchors are
        // configured keys and retain webpki's validity policy.
        for cert in trust.chain.iter().take(trust.chain.len().saturating_sub(1)) {
            if cert.not_after <= seconds {
                return Err(VerificationError::new(
                    ErrorCode::CertificateExpired,
                    Stage::CertificateChain,
                    "fractional timestamp exceeds certificate validity",
                )
                .detail("certificate", cert)
                .detail("validation_time", seconds)
                .detail("fractional_seconds", fraction)
                .into());
            }
        }
    }
    Ok(())
}

fn parse_time(node: Node<'_>) -> Result<(u64, Option<String>)> {
    match node.tag {
        0x17 => Ok((
            ::der::asn1::UtcTime::from_der(node.full)?
                .to_unix_duration()
                .as_secs(),
            None,
        )),
        0x18 if node.body.len() > 15 => {
            let body = node.body;
            ensure!(
                body.len() <= 80 && body[14] == b'.' && body.last() == Some(&b'Z'),
                "noncanonical fractional GeneralizedTime"
            );
            let fraction = &body[15..body.len() - 1];
            ensure!(
                !fraction.is_empty()
                    && fraction.iter().all(u8::is_ascii_digit)
                    && fraction.last() != Some(&b'0'),
                "noncanonical fractional GeneralizedTime"
            );
            let mut whole = vec![0x18, 15];
            whole.extend_from_slice(&body[..14]);
            whole.push(b'Z');
            let seconds = ::der::asn1::GeneralizedTime::from_der(&whole)?
                .to_unix_duration()
                .as_secs();
            Ok((seconds, Some(std::str::from_utf8(fraction)?.into())))
        }
        0x18 => Ok((
            ::der::asn1::GeneralizedTime::from_der(node.full)?
                .to_unix_duration()
                .as_secs(),
            None,
        )),
        _ => anyhow::bail!("invalid timestamp time encoding"),
    }
}

#[cfg(test)]
mod time_tests {
    use super::*;

    fn time(text: &str) -> Result<(u64, Option<String>)> {
        let mut bytes = vec![0x18, text.len() as u8];
        bytes.extend_from_slice(text.as_bytes());
        parse_time(der::one(&bytes, 0x18)?)
    }

    #[test]
    fn generalized_time_preserves_fraction_and_requires_canonical_bounded_precision() {
        assert_eq!(time("20270115080000Z").unwrap(), (1800000000, None));
        assert_eq!(
            time("20270115080000.009Z").unwrap(),
            (1800000000, Some("009".into()))
        );
        assert!(time(&format!("20270115080000.{}1Z", "0".repeat(63))).is_ok());
        assert!(time(&format!("20270115080000.{}1Z", "0".repeat(64))).is_err());
        for text in [
            "20270115080000.Z",
            "20270115080000.0Z",
            "20270115080000.50Z",
            "20270115080000,5Z",
            "20270115080000.5+0000",
            "20270115080000.aZ",
            "20270230080000.5Z",
            "20270115086000.5Z",
        ] {
            assert!(time(text).is_err(), "{text}");
        }
    }

    #[test]
    fn fractional_expiry_checks_leaf_and_intermediates_but_not_configured_anchor() {
        let bytes = include_bytes!("../tests/fixtures/good-intermediate.exe");
        let mut store = TrustStore::default();
        store
            .add_roots(include_bytes!("../tests/fixtures/root.der"))
            .unwrap();
        let options = VerifyOptions {
            trust: Some(&store),
            check_revocation: false,
            allow_sha1: false,
            now: 1800000000,
        };
        let verified = verify_pe(bytes, &options).unwrap();
        let trust = verified.signatures[0].trust.as_ref().unwrap();
        assert_eq!(trust.chain.len(), 3);
        for index in 0..trust.chain.len() {
            let mut trust = trust.clone();
            trust.chain[index].not_after = options.now;
            assert!(check_fractional_validity(Some(&trust), options.now, None).is_ok());
            let result = check_fractional_validity(Some(&trust), options.now, Some("001"));
            if index < 2 {
                assert!(result.is_err());
            } else {
                assert!(result.is_ok());
            }
        }
    }
}
