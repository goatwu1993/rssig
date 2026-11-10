//! Integrity policy and reports over immutable MSIX/AppX structural views.
pub(crate) use crate::parse::Appx;
use crate::{
    crypto::Hash,
    domain::*,
    parse::{BlockMap, BundlePackage},
};
use anyhow::{Result, ensure};
#[cfg(test)]
use std::path::Path;
use std::str::FromStr;
use x509_cert::{Certificate, name::Name};
#[cfg(test)]
pub(crate) fn has_extension(path: &Path) -> bool {
    path.extension().and_then(|s| s.to_str()).is_some_and(|s| {
        ["appx", "msix", "appxbundle", "msixbundle"]
            .iter()
            .any(|v| s.eq_ignore_ascii_case(v))
    })
}
fn tagged<T>(r: Result<T>, stage: Stage) -> Result<T> {
    r.map_err(|e| VerificationError::from_internal(e, ErrorCode::InvalidAppx, stage).into())
}
pub(crate) fn digests(appx: &Appx<'_>, hash: Hash) -> Result<(Vec<u8>, Vec<AppxComponentReport>)> {
    let values = appx.digest_inputs().map_err(VerificationError::from)?;
    let mut bundle = b"APPX".to_vec();
    let mut components = Vec::with_capacity(values.len());
    for input in values {
        let tag = input.tag;
        let value = hash.digest(&input.bytes);
        bundle.extend(tag.as_bytes());
        bundle.extend(&value);
        components.push(AppxComponentReport {
            component: tag.into(),
            digest: DigestReport {
                algorithm: format!("{hash:?}"),
                expected: hex(&value),
                computed: hex(&value),
            },
        });
    }
    Ok((bundle, components))
}
pub(crate) fn mismatch(expected: &[u8], computed: &[u8], hash: Hash) -> VerificationError {
    let size = hash.digest(b"").len();
    let component = expected
        .get(4..)
        .and_then(|b| {
            b.chunks_exact(4 + size).enumerate().find(|(i, v)| {
                computed.get(4 + i * (4 + size)..4 + (i + 1) * (4 + size)) != Some(*v)
            })
        })
        .map(|(_, v)| String::from_utf8_lossy(&v[..4]).into_owned())
        .unwrap_or_else(|| "digest_bundle".into());
    VerificationError::new(
        ErrorCode::AppxDigestMismatch,
        Stage::PackageDigest,
        "MSIX/AppX signed package digest mismatch",
    )
    .detail("component", component)
    .detail(
        "digest",
        DigestReport {
            algorithm: format!("{hash:?}"),
            expected: hex(expected),
            computed: hex(computed),
        },
    )
}
pub(crate) fn validate(
    appx: &Appx<'_>,
    hash: Hash,
    components: Vec<AppxComponentReport>,
) -> Result<Box<AppxReport>> {
    appx.content_types().map_err(VerificationError::from)?;
    let (identity, packages) = if appx.is_bundle() {
        appx.bundle_identity().map_err(VerificationError::from)?
    } else {
        (
            appx.identity().map_err(VerificationError::from)?,
            Vec::new(),
        )
    };
    let block_map = tagged(block_map(appx, hash, &packages), Stage::BlockMap)?;
    let catalog = appx
        .code_integrity_catalog()
        .map_err(VerificationError::from)?
        .map(|b| AppxCatalogReport {
            sha256: hex(&Hash::Sha256.digest(&b)),
            signature_verified: false,
        });
    Ok(Box::new(AppxReport {
        kind: if appx.is_bundle() {
            AppxKind::Bundle
        } else {
            AppxKind::Package
        },
        identity: AppxIdentity {
            name: identity.name,
            publisher: identity.publisher,
            version: identity.version,
            processor_architecture: identity.processor_architecture,
            resource_id: identity.resource_id,
        },
        block_map,
        components,
        code_integrity_catalog: catalog,
        bundle_packages: None,
    }))
}
pub(crate) fn publisher(report: &AppxReport, cert: &Certificate) -> Result<()> {
    let publisher = &report.identity.publisher;
    let name = Name::from_str(publisher)?;
    fn canonical(name: &Name) -> Vec<Vec<(String, String)>> {
        DistinguishedName::parse(name)
            .rdns
            .into_iter()
            .map(|rdn| {
                let mut v: Vec<_> = rdn
                    .into_iter()
                    .map(|a| {
                        (
                            a.oid,
                            a.value
                                .unwrap_or_else(|| format!("{}:{}", a.asn1_tag, a.raw_value_hex)),
                        )
                    })
                    .collect();
                v.sort();
                v
            })
            .collect()
    }
    if canonical(&name) != canonical(&cert.tbs_certificate.subject) {
        return Err(VerificationError::new(
            ErrorCode::AppxPublisherMismatch,
            Stage::Appx,
            "manifest Publisher does not match the signing certificate subject",
        )
        .detail("publisher", publisher)
        .detail(
            "certificate_subject",
            DistinguishedName::parse(&cert.tbs_certificate.subject),
        )
        .into());
    }
    Ok(())
}
fn block_map(
    appx: &Appx<'_>,
    signature_hash: Hash,
    packages: &[BundlePackage<'_>],
) -> Result<AppxBlockMapReport> {
    let bytes = appx.block_map_bytes().map_err(|e| e.inner)?;
    let map = BlockMap::parse(&bytes).map_err(|e| e.inner)?;
    let hash = match map.hash_method().map_err(|e| e.inner)? {
        "http://www.w3.org/2001/04/xmlenc#sha256" => Hash::Sha256,
        "http://www.w3.org/2001/04/xmldsig-more#sha384" => Hash::Sha384,
        "http://www.w3.org/2001/04/xmlenc#sha512" => Hash::Sha512,
        _ => {
            return Err(VerificationError::new(
                ErrorCode::UnsupportedAlgorithm,
                Stage::BlockMap,
                "unsupported block-map hash method",
            )
            .into());
        }
    };
    ensure!(
        hash == signature_hash,
        "block-map and signed package digest algorithms differ"
    );
    let expected = appx.payload_parts(packages);
    let files = map.files();
    ensure!(
        files.len() == expected.len(),
        "block map must cover every payload part exactly once"
    );
    let mut blocks_verified = 0;
    let mut total = 0;
    for (file, e) in files.into_iter().zip(&expected) {
        let blocks = file.check_part(e)?;
        let data = e.read(64 * 1024 * 1024)?;
        let mut compressed_sizes = Vec::new();
        for (index, (block, content)) in blocks.into_iter().zip(data.chunks(65536)).enumerate() {
            let expected = block.hash().map_err(|e| e.inner)?;
            ensure!(
                expected.len() == hash.digest(b"").len(),
                "block-map digest length mismatch"
            );
            let computed = hash.digest(content);
            if expected != computed {
                return Err(VerificationError::new(
                    ErrorCode::BlockHashMismatch,
                    Stage::BlockMap,
                    "package payload block does not match the signed block map",
                )
                .detail("file", &e.name)
                .detail("block", index)
                .detail(
                    "digest",
                    DigestReport {
                        algorithm: format!("{hash:?}"),
                        expected: hex(&expected),
                        computed: hex(&computed),
                    },
                )
                .into());
            }
            if let Some(size) = block.check_compression(e.method)? {
                compressed_sizes.push(size);
            }
            blocks_verified += 1;
        }
        if e.method == 8 {
            crate::parse::appx::check_compressed_blocks(e, &compressed_sizes)?;
        }
        total += e.size;
    }
    Ok(AppxBlockMapReport {
        algorithm: format!("{hash:?}"),
        files_verified: expected.len(),
        blocks_verified,
        uncompressed_bytes: total,
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    fn fixture(name: &str) -> Vec<u8> {
        std::fs::read(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures")
                .join(name),
        )
        .unwrap()
    }
    #[test]
    fn payload_faults_preserve_signature_math_and_isolate_axpc() {
        for (good, bad) in [
            ("good.msix", "bad-appx-payload.msix"),
            (
                "appx-independent-jsign.msix",
                "bad-appx-independent-payload.msix",
            ),
        ] {
            let good_bytes = fixture(good);
            let bad_bytes = fixture(bad);
            let good = Appx::parse(&good_bytes).unwrap();
            let bad = Appx::parse(&bad_bytes).unwrap();
            assert_eq!(good.signature(), bad.signature());
            let signature = bad.signature().to_vec();
            let sd = crate::cms::SignedData::parse(&signature).unwrap();
            sd.verify(sd.signers[0], false).unwrap();
            let (hash, expected, _) = sd.appx_digest().unwrap();
            assert_eq!(digests(&good, hash).unwrap().0, expected);
            let computed = digests(&bad, hash).unwrap().0;
            assert_ne!(computed, expected);
            let error = mismatch(expected, &computed, hash);
            assert_eq!(error.code, ErrorCode::AppxDigestMismatch);
            assert_eq!(error.details["component"], "AXPC");
        }
    }
    #[test]
    fn signed_invalid_metadata_is_not_a_container_or_setup_failure() {
        for (name, code) in [
            ("bad-appx-block-hash.msix", ErrorCode::BlockHashMismatch),
            ("bad-appx-compressed-size.msix", ErrorCode::InvalidAppx),
        ] {
            let bytes = fixture(name);
            let package = Appx::parse(&bytes).unwrap();
            let signature = package.signature().to_vec();
            let sd = crate::cms::SignedData::parse(&signature).unwrap();
            sd.verify(sd.signers[0], false).unwrap();
            let (hash, expected, _) = sd.appx_digest().unwrap();
            assert_eq!(digests(&package, hash).unwrap().0, expected);
            let error = validate(&package, hash, digests(&package, hash).unwrap().1).unwrap_err();
            assert_eq!(
                error.downcast_ref::<VerificationError>().unwrap().code,
                code
            );
        }
        let bytes = fixture("bad-appx-publisher.msix");
        let package = Appx::parse(&bytes).unwrap();
        let signature = package.signature().to_vec();
        let sd = crate::cms::SignedData::parse(&signature).unwrap();
        let signer = sd.verify(sd.signers[0], false).unwrap();
        let (hash, expected, _) = sd.appx_digest().unwrap();
        assert_eq!(digests(&package, hash).unwrap().0, expected);
        let report = validate(&package, hash, digests(&package, hash).unwrap().1).unwrap();
        let error = publisher(&report, &signer.cert).unwrap_err();
        assert_eq!(
            error.downcast_ref::<VerificationError>().unwrap().code,
            ErrorCode::AppxPublisherMismatch
        );
    }
    #[test]
    fn independent_signtool_checks_zip64_components_and_every_payload_block() {
        let bytes = fixture("appx-independent-signtool.msix");
        let package = Appx::parse(&bytes).unwrap();
        let signature = package.signature().to_vec();
        let sd = crate::cms::SignedData::parse(&signature).unwrap();
        let signer = sd.verify(sd.signers[0], false).unwrap();
        let (hash, expected, _) = sd.appx_digest().unwrap();
        assert_eq!(digests(&package, hash).unwrap().0, expected);
        let report = validate(&package, hash, digests(&package, hash).unwrap().1).unwrap();
        publisher(&report, &signer.cert).unwrap();
        assert_eq!(report.block_map.files_verified, 5);
        assert_eq!(report.block_map.blocks_verified, 5);
        assert_eq!(
            report
                .components
                .iter()
                .map(|c| c.component.as_str())
                .collect::<Vec<_>>(),
            ["AXPC", "AXCD", "AXCT", "AXBM"]
        );
    }
    #[test]
    fn bundle_faults_retain_valid_outer_signature_and_digest_math() {
        for fault in [
            "offset",
            "size",
            "duplicate",
            "missing",
            "orphan",
            "orphan-other",
            "architecture",
            "version",
            "name",
            "namespace",
            "unknown",
            "empty",
            "compressed",
            "child-digest",
            "child-signature",
            "child-unsigned",
            "child-timestamp",
            "different-signer",
            "nested-bundle",
            "block-hash",
            "content-types",
            "stub",
            "flat",
            "resource-id",
            "resource-type",
            "architecture-default",
            "package-child",
            "package-ctype",
            "child-crc",
            "resource-boolean",
        ] {
            let bytes = fixture(&format!("bad-appxbundle-{fault}.msixbundle"));
            let appx = Appx::parse(&bytes).unwrap();
            assert!(appx.is_bundle());
            let signature = appx.signature().to_vec();
            let sd = crate::cms::SignedData::parse(&signature).unwrap();
            let (hash, expected, bundle) = sd.appx_digest().unwrap();
            assert!(bundle);
            sd.verify(sd.signers[0], false).unwrap();
            assert_eq!(digests(&appx, hash).unwrap().0, expected, "{fault}");
        }
    }
    #[test]
    fn independent_bundle_payload_fault_retains_the_original_signature() {
        let good_bytes = fixture("appxbundle-independent-jsign.msixbundle");
        let bad_bytes = fixture("bad-appxbundle-independent-payload.msixbundle");
        let good = Appx::parse(&good_bytes).unwrap();
        let bad = Appx::parse(&bad_bytes).unwrap();
        assert_eq!(good.signature(), bad.signature());
        let signature = bad.signature().to_vec();
        let sd = crate::cms::SignedData::parse(&signature).unwrap();
        sd.verify(sd.signers[0], false).unwrap();
        let (hash, expected, bundle) = sd.appx_digest().unwrap();
        assert!(bundle);
        let computed = digests(&bad, hash).unwrap().0;
        assert_ne!(computed, expected);
        assert_eq!(
            mismatch(expected, &computed, hash).details["component"],
            "AXPC"
        );
    }
    #[test]
    fn domain_fields_and_explicit_library_api_are_format_specific() {
        let mut roots = crate::TrustStore::default();
        roots.add_roots(&fixture("root.der")).unwrap();
        roots.add_crl(&fixture("good.crl")).unwrap();
        let options = crate::VerifyOptions {
            trust: Some(&roots),
            check_revocation: true,
            allow_sha1: false,
            now: 1_800_000_000,
        };
        let bytes = fixture("good.msix");
        for report in [
            crate::verify(&bytes, &options).unwrap(),
            crate::verify_appx(&bytes, &options).unwrap(),
        ] {
            let appx = report.appx.as_ref().unwrap();
            assert_eq!(appx.identity.publisher, "CN=rssig test publisher");
            assert_eq!(appx.block_map.files_verified, 2);
            assert_eq!(appx.block_map.blocks_verified, 2);
            assert!(report.rdp.is_none());
            for c in &appx.components {
                assert_eq!(c.digest.expected, c.digest.computed);
                assert_eq!(c.digest.expected.len(), 64);
            }
            let value = serde_json::to_value(report).unwrap();
            assert_eq!(value["format"], "appx_authenticode");
            assert!(value["signatures"][0].get("image_digest").is_none());
            let roundtrip: VerificationBundle = serde_json::from_value(value.clone()).unwrap();
            assert_eq!(serde_json::to_value(roundtrip).unwrap(), value);
            let mut legacy = value.clone();
            legacy["appx"].as_object_mut().unwrap().remove("kind");
            let legacy: VerificationBundle = serde_json::from_value(legacy).unwrap();
            assert_eq!(legacy.appx.unwrap().kind, AppxKind::Package);
        }
        let bytes = fixture("good-appx-catalog.msix");
        let report = crate::verify_appx(&bytes, &options).unwrap();
        assert!(
            !report
                .appx
                .unwrap()
                .code_integrity_catalog
                .unwrap()
                .signature_verified
        );
        let value = serde_json::to_value(crate::verify_appx(b"MZ", &options).unwrap_err()).unwrap();
        assert_eq!(value["code"], "invalid_appx");
        assert_eq!(value["stage"], "appx");
        assert!(has_extension(Path::new("P.MSIX")));
        assert!(has_extension(Path::new("P.APPX")));
        assert!(!has_extension(Path::new("P.zip")));
    }
}
