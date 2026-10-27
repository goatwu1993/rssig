//! Embedded single-package MSIX/AppX integrity. No extraction or installation.
mod zip;
use crate::{crypto::Hash, domain::*};
use anyhow::{Context, Result, ensure};
use base64ct::{Base64, Encoding};
use roxmltree::{Document, Node, ParsingOptions};
use std::{collections::BTreeMap, path::Path, str::FromStr};
use x509_cert::{Certificate, name::Name};
const SIG: &str = "AppxSignature.p7x";
const CT: &str = "[Content_Types].xml";
const BM: &str = "AppxBlockMap.xml";
const MANIFEST: &str = "AppxManifest.xml";
const CI: &str = "AppxMetadata/CodeIntegrity.cat";
const XML_LIMIT: usize = 8 * 1024 * 1024;
const BM_NS: &str = "http://schemas.microsoft.com/appx/2010/blockmap";
const CT_NS: &str = "http://schemas.openxmlformats.org/package/2006/content-types";
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
fn xml(bytes: &[u8]) -> Result<Document<'_>> {
    ensure!(bytes.len() <= XML_LIMIT, "package XML exceeds size limit");
    let text = std::str::from_utf8(bytes)?;
    Ok(Document::parse_with_options(
        text,
        ParsingOptions {
            allow_dtd: false,
            nodes_limit: 100_000,
            ..Default::default()
        },
    )?)
}
fn attrs(node: Node<'_, '_>, allowed: &[&str]) -> Result<()> {
    for a in node.attributes() {
        ensure!(
            a.namespace().is_none() && allowed.contains(&a.name()),
            "unsupported XML attribute: {}",
            a.name()
        );
    }
    ensure!(
        node.children()
            .filter(|n| n.is_text())
            .all(|n| n.text().unwrap_or("").trim().is_empty()),
        "unexpected XML text"
    );
    Ok(())
}
fn attr<'a, 'b>(node: Node<'a, 'b>, name: &str) -> Result<&'a str> {
    node.attribute(name)
        .with_context(|| format!("missing package XML attribute {name}"))
}
fn number(node: Node<'_, '_>, name: &str) -> Result<usize> {
    let text = attr(node, name)?;
    ensure!(
        !text.is_empty() && text.bytes().all(|c| c.is_ascii_digit()),
        "invalid package XML integer"
    );
    Ok(text.parse()?)
}
fn excluded(name: &str) -> bool {
    [SIG, CT, BM, CI].contains(&name)
}
pub(crate) struct Appx<'a> {
    bytes: &'a [u8],
    zip: zip::Zip<'a>,
    signature: Vec<u8>,
    components: Vec<AppxComponentReport>,
    pub report: Option<Box<AppxReport>>,
}
impl<'a> Appx<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self> {
        let zip = tagged(zip::Zip::parse(bytes), Stage::Appx)?;
        if zip.get("AppxMetadata/AppxBundleManifest.xml").is_some() {
            return Err(VerificationError::new(
                ErrorCode::UnsupportedAppx,
                Stage::Appx,
                "MSIX/AppX bundles are unsupported; supply a single package",
            )
            .into());
        }
        for name in [CT, BM, MANIFEST] {
            ensure!(
                zip.get(name).is_some(),
                "missing required MSIX/AppX part: {name}"
            );
        }
        let entry = zip.get(SIG).ok_or_else(|| {
            VerificationError::new(
                ErrorCode::Unsigned,
                Stage::Appx,
                "package has no AppxSignature.p7x",
            )
        })?;
        tagged(zip.unsigned_directory(), Stage::Appx)?;
        let blob = entry.read(4 * 1024 * 1024)?;
        ensure!(
            blob.starts_with(b"PKCX") && blob.len() > 4,
            "invalid PKCX signature header"
        );
        Ok(Self {
            bytes,
            zip,
            signature: blob[4..].to_vec(),
            components: Vec::new(),
            report: None,
        })
    }
    pub fn signature(&self) -> &[u8] {
        &self.signature
    }
    fn read(&self, name: &str) -> Result<Vec<u8>> {
        self.zip
            .get(name)
            .with_context(|| format!("missing package part {name}"))?
            .read(XML_LIMIT)
    }
    pub fn digests(&mut self, hash: Hash) -> Result<Vec<u8>> {
        let sig = self.zip.get(SIG).unwrap();
        let directory = self.zip.unsigned_directory()?;
        let ct = self.read(CT)?;
        let bm = self.read(BM)?;
        let mut values = vec![
            ("AXPC", hash.digest(&self.bytes[..sig.offset])),
            ("AXCD", hash.digest(&directory)),
            ("AXCT", hash.digest(&ct)),
            ("AXBM", hash.digest(&bm)),
        ];
        if let Some(ci) = self.zip.get(CI) {
            values.push(("AXCI", hash.digest(&ci.read(8 * 1024 * 1024)?)));
        }
        let mut bundle = b"APPX".to_vec();
        self.components.clear();
        for (tag, value) in values {
            bundle.extend(tag.as_bytes());
            bundle.extend(&value);
            self.components.push(AppxComponentReport {
                component: tag.into(),
                digest: DigestReport {
                    algorithm: format!("{hash:?}"),
                    expected: hex(&value),
                    computed: hex(&value),
                },
            });
        }
        Ok(bundle)
    }
    pub fn mismatch(&self, expected: &[u8], computed: &[u8], hash: Hash) -> VerificationError {
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
    pub fn validate(&mut self, hash: Hash) -> Result<()> {
        tagged(self.content_types(), Stage::Appx)?;
        let identity = tagged(self.identity(), Stage::Appx)?;
        let block_map = tagged(self.block_map(hash), Stage::BlockMap)?;
        let catalog = self
            .zip
            .get(CI)
            .map(|e| {
                e.read(8 * 1024 * 1024).map(|b| AppxCatalogReport {
                    sha256: hex(&Hash::Sha256.digest(&b)),
                    signature_verified: false,
                })
            })
            .transpose()?;
        self.report = Some(Box::new(AppxReport {
            identity,
            block_map,
            components: self.components.clone(),
            code_integrity_catalog: catalog,
        }));
        Ok(())
    }
    fn identity(&self) -> Result<AppxIdentity> {
        let bytes = self.read(MANIFEST)?;
        let doc = xml(&bytes)?;
        let root = doc.root_element();
        let ns = root
            .tag_name()
            .namespace()
            .context("missing manifest namespace")?;
        ensure!(
            root.tag_name().name() == "Package"
                && [
                    "http://schemas.microsoft.com/appx/manifest/foundation/windows10",
                    "http://schemas.microsoft.com/appx/2010/manifest"
                ]
                .contains(&ns),
            "unsupported package manifest root or namespace"
        );
        let identities: Vec<_> = root
            .children()
            .filter(|n| n.has_tag_name((ns, "Identity")))
            .collect();
        ensure!(
            identities.len() == 1,
            "manifest must contain exactly one package Identity"
        );
        let id = identities[0];
        let name = attr(id, "Name")?;
        let publisher = attr(id, "Publisher")?;
        let version = attr(id, "Version")?;
        ensure!(
            (3..=50).contains(&name.len())
                && name
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || c == b'.' || c == b'-'),
            "unsupported package identity name"
        );
        ensure!(!publisher.is_empty(), "empty package publisher");
        Name::from_str(publisher).context("unsupported manifest publisher DN")?;
        let parts: Vec<_> = version.split('.').collect();
        ensure!(
            parts.len() == 4
                && parts.iter().all(|v| !v.is_empty()
                    && v.bytes().all(|c| c.is_ascii_digit())
                    && v.parse::<u16>().is_ok()),
            "invalid package version"
        );
        let architecture = id.attribute("ProcessorArchitecture");
        ensure!(
            architecture.is_none_or(|a| ["neutral", "x86", "x64", "arm", "arm64"].contains(&a)),
            "unsupported package architecture"
        );
        Ok(AppxIdentity {
            name: name.into(),
            publisher: publisher.into(),
            version: version.into(),
            processor_architecture: architecture.map(str::to_owned),
        })
    }
    pub fn publisher(&self, cert: &Certificate) -> Result<()> {
        let publisher = &self
            .report
            .as_ref()
            .context("package metadata was not checked")?
            .identity
            .publisher;
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
                                a.value.unwrap_or_else(|| {
                                    format!("{}:{}", a.asn1_tag, a.raw_value_hex)
                                }),
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
    fn content_types(&self) -> Result<()> {
        let bytes = self.read(CT)?;
        let doc = xml(&bytes)?;
        let root = doc.root_element();
        ensure!(
            root.has_tag_name((CT_NS, "Types")),
            "invalid content-types root"
        );
        attrs(root, &[])?;
        let mut defaults = BTreeMap::new();
        let mut overrides = BTreeMap::new();
        for n in root.children().filter(|n| n.is_element()) {
            if n.has_tag_name((CT_NS, "Default")) {
                attrs(n, &["Extension", "ContentType"])?;
                let ext = attr(n, "Extension")?;
                ensure!(
                    !ext.is_empty() && ext.is_ascii() && !ext.contains(['.', '/', '\\']),
                    "invalid default content-type extension"
                );
                ensure!(
                    defaults
                        .insert(ext.to_ascii_lowercase(), attr(n, "ContentType")?)
                        .is_none(),
                    "duplicate default content type"
                );
            } else if n.has_tag_name((CT_NS, "Override")) {
                attrs(n, &["PartName", "ContentType"])?;
                let name = attr(n, "PartName")?
                    .strip_prefix('/')
                    .context("content-type override must be absolute package part")?;
                ensure!(
                    zip::safe_name(name)
                        && overrides
                            .insert(name.to_ascii_lowercase(), attr(n, "ContentType")?)
                            .is_none(),
                    "unsafe or duplicate content-type override"
                );
            } else {
                anyhow::bail!("unsupported content-types element");
            }
            ensure!(
                !n.children().any(|v| v.is_element()),
                "nested content-type element"
            );
        }
        for e in &self.zip.entries {
            if e.name == CT {
                continue;
            }
            let content = overrides
                .get(&e.name.to_ascii_lowercase())
                .copied()
                .or_else(|| {
                    e.name
                        .rsplit_once('.')
                        .and_then(|(_, ext)| defaults.get(&ext.to_ascii_lowercase()).copied())
                })
                .context("package part has no content type")?;
            ensure!(!content.is_empty(), "empty package content type");
            let required = match e.name.as_str() {
                SIG => Some("application/vnd.ms-appx.signature"),
                BM => Some("application/vnd.ms-appx.blockmap+xml"),
                MANIFEST => Some("application/vnd.ms-appx.manifest+xml"),
                CI => Some("application/vnd.ms-pkiseccat"),
                _ => None,
            };
            if let Some(required) = required {
                ensure!(
                    content == required,
                    "incorrect package footprint content type: {}",
                    e.name
                );
            }
        }
        Ok(())
    }
    fn block_map(&self, signature_hash: Hash) -> Result<AppxBlockMapReport> {
        let bytes = self.read(BM)?;
        let doc = xml(&bytes)?;
        let root = doc.root_element();
        ensure!(
            root.has_tag_name((BM_NS, "BlockMap")),
            "invalid block-map root or namespace"
        );
        attrs(root, &["HashMethod", "IgnorableNamespaces"])?;
        let hash = match attr(root, "HashMethod")? {
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
        let expected: Vec<_> = self
            .zip
            .entries
            .iter()
            .filter(|e| !excluded(&e.name))
            .collect();
        let files: Vec<_> = root.children().filter(|n| n.is_element()).collect();
        ensure!(
            files.len() == expected.len(),
            "block map must cover every payload part exactly once"
        );
        let mut blocks_verified = 0;
        let mut total = 0;
        for (file, e) in files.into_iter().zip(&expected) {
            ensure!(
                file.has_tag_name((BM_NS, "File")),
                "unsupported block-map element"
            );
            attrs(file, &["Name", "Size", "LfhSize"])?;
            let name = attr(file, "Name")?;
            ensure!(
                !name.contains('/') && name.replace('\\', "/") == e.name,
                "block-map path or order differs from ZIP entries"
            );
            ensure!(
                number(file, "Size")? == e.size && number(file, "LfhSize")? == e.lfh_size,
                "block-map file size or local-header size mismatch"
            );
            let blocks: Vec<_> = file.children().filter(|n| n.is_element()).collect();
            ensure!(
                blocks.len() == e.size.div_ceil(65536),
                "block-map block count mismatch"
            );
            let data = e.read(64 * 1024 * 1024)?;
            let mut compressed_sizes = Vec::new();
            for (index, (block, content)) in blocks.into_iter().zip(data.chunks(65536)).enumerate()
            {
                ensure!(
                    block.has_tag_name((BM_NS, "Block")),
                    "unsupported block-map child"
                );
                attrs(block, &["Hash", "Size"])?;
                ensure!(
                    !block.children().any(|n| n.is_element()),
                    "nested block-map Block"
                );
                let expected = Base64::decode_vec(attr(block, "Hash")?)
                    .map_err(|e| anyhow::anyhow!("invalid block hash base64: {e}"))?;
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
                if e.method == 0 {
                    ensure!(
                        block.attribute("Size").is_none(),
                        "stored block must omit compressed Size"
                    );
                } else {
                    let size = number(block, "Size")?;
                    ensure!(size > 0, "empty compressed block");
                    compressed_sizes.push(size);
                }
                blocks_verified += 1;
            }
            if e.method == 8 {
                compressed_blocks(e, &compressed_sizes)?;
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
}
fn compressed_blocks(e: &zip::Entry<'_>, sizes: &[usize]) -> Result<()> {
    use flate2::{Decompress, FlushDecompress, Status};
    let mut stream = Decompress::new(false);
    let mut offset = 0;
    let mut remaining = e.size;
    let mut status = Status::Ok;
    for size in sizes {
        let content = zip::slice(e.compressed, offset, *size)?;
        let count = remaining.min(65536);
        let mut out = vec![0; count + 1];
        let old_in = stream.total_in();
        let old_out = stream.total_out();
        status = stream.decompress(content, &mut out, FlushDecompress::None)?;
        ensure!(
            stream.total_in() - old_in == *size as u64
                && stream.total_out() - old_out == count as u64,
            "compressed block boundaries differ from block-map Size"
        );
        offset = offset
            .checked_add(*size)
            .context("block-map compressed size overflow")?;
        remaining -= count;
    }
    ensure!(remaining == 0, "unverified compressed payload bytes");
    ensure!(
        status != Status::StreamEnd,
        "compressed block Size must exclude the final stream terminator"
    );
    {
        let tail = e
            .compressed
            .get(offset..)
            .context("compressed block exceeds ZIP data")?;
        ensure!(
            tail.len() == 2,
            "compressed block Sizes must leave exactly the two-byte stream terminator"
        );
        let mut out = [0; 1];
        let old = stream.total_out();
        status = stream.decompress(tail, &mut out, FlushDecompress::Finish)?;
        ensure!(
            stream.total_out() == old,
            "compressed stream tail emitted unaccounted payload"
        );
    }
    ensure!(
        status == Status::StreamEnd && stream.total_in() == e.compressed.len() as u64,
        "invalid compressed block stream termination"
    );
    Ok(())
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
            let mut good = Appx::parse(&good_bytes).unwrap();
            let mut bad = Appx::parse(&bad_bytes).unwrap();
            assert_eq!(good.signature(), bad.signature());
            let signature = bad.signature().to_vec();
            let sd = crate::cms::SignedData::parse(&signature).unwrap();
            sd.verify(sd.signers[0], false).unwrap();
            let (hash, expected) = sd.appx_digest().unwrap();
            assert_eq!(good.digests(hash).unwrap(), expected);
            let computed = bad.digests(hash).unwrap();
            assert_ne!(computed, expected);
            let error = bad.mismatch(expected, &computed, hash);
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
            let mut package = Appx::parse(&bytes).unwrap();
            let signature = package.signature().to_vec();
            let sd = crate::cms::SignedData::parse(&signature).unwrap();
            sd.verify(sd.signers[0], false).unwrap();
            let (hash, expected) = sd.appx_digest().unwrap();
            assert_eq!(package.digests(hash).unwrap(), expected);
            let error = package.validate(hash).unwrap_err();
            assert_eq!(
                error.downcast_ref::<VerificationError>().unwrap().code,
                code
            );
        }
        let bytes = fixture("bad-appx-publisher.msix");
        let mut package = Appx::parse(&bytes).unwrap();
        let signature = package.signature().to_vec();
        let sd = crate::cms::SignedData::parse(&signature).unwrap();
        let signer = sd.verify(sd.signers[0], false).unwrap();
        let (hash, expected) = sd.appx_digest().unwrap();
        assert_eq!(package.digests(hash).unwrap(), expected);
        package.validate(hash).unwrap();
        let error = package.publisher(&signer.cert).unwrap_err();
        assert_eq!(
            error.downcast_ref::<VerificationError>().unwrap().code,
            ErrorCode::AppxPublisherMismatch
        );
    }
    #[test]
    fn independent_signtool_checks_zip64_components_and_every_payload_block() {
        let bytes = fixture("appx-independent-signtool.msix");
        let mut package = Appx::parse(&bytes).unwrap();
        let signature = package.signature().to_vec();
        let sd = crate::cms::SignedData::parse(&signature).unwrap();
        let signer = sd.verify(sd.signers[0], false).unwrap();
        let (hash, expected) = sd.appx_digest().unwrap();
        assert_eq!(package.digests(hash).unwrap(), expected);
        package.validate(hash).unwrap();
        package.publisher(&signer.cert).unwrap();
        let report = package.report.unwrap();
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
