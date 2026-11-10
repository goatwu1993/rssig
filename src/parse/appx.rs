//! Untrusted MSIX/AppX archive/XML adapter. Never extracts or installs files.
pub(crate) mod zip;
use super::{Error, ErrorKind};
use anyhow::{Context, Result, ensure};
use base64ct::{Base64, Encoding};
use roxmltree::{Document, Node, ParsingOptions};
use std::borrow::Cow;
use std::{collections::BTreeMap, str::FromStr};
use x509_cert::name::Name;
const SIG: &str = "AppxSignature.p7x";
const CT: &str = "[Content_Types].xml";
const BM: &str = "AppxBlockMap.xml";
const MANIFEST: &str = "AppxManifest.xml";
const BUNDLE_MANIFEST: &str = "AppxMetadata/AppxBundleManifest.xml";
const CI: &str = "AppxMetadata/CodeIntegrity.cat";
const XML_LIMIT: usize = 8 * 1024 * 1024;
const BM_NS: &str = "http://schemas.microsoft.com/appx/2010/blockmap";
const CT_NS: &str = "http://schemas.openxmlformats.org/package/2006/content-types";
const BUNDLE_NS: &str = "http://schemas.microsoft.com/appx/2013/bundle";
fn structural<T>(r: Result<T>) -> core::result::Result<T, Error> {
    r.map_err(|e| Error::new(ErrorKind::InvalidAppx, e))
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
fn validate_version(version: &str) -> Result<()> {
    let parts: Vec<_> = version.split('.').collect();
    ensure!(
        parts.len() == 4
            && parts.iter().all(|v| !v.is_empty()
                && v.bytes().all(|c| c.is_ascii_digit())
                && v.parse::<u16>().is_ok()),
        "invalid package version"
    );
    Ok(())
}
fn identity(
    name: &str,
    publisher: &str,
    version: &str,
    architecture: Option<&str>,
    resource_id: Option<&str>,
) -> Result<AppxIdentity> {
    ensure!(
        (3..=50).contains(&name.len())
            && name
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'.' || c == b'-'),
        "unsupported package identity name"
    );
    ensure!(!publisher.is_empty(), "empty package publisher");
    Name::from_str(publisher).context("unsupported manifest publisher DN")?;
    validate_version(version)?;
    ensure!(
        architecture.is_none_or(|a| ["neutral", "x86", "x64", "arm", "arm64"].contains(&a)),
        "unsupported package architecture"
    );
    Ok(AppxIdentity {
        name: name.into(),
        publisher: publisher.into(),
        version: version.into(),
        processor_architecture: architecture.map(str::to_owned),
        resource_id: resource_id.filter(|s| !s.is_empty()).map(str::to_owned),
    })
}
fn excluded(name: &str) -> bool {
    [SIG, CT, BM, CI].contains(&name)
}
fn is_package_name(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    name.ends_with(".appx") || name.ends_with(".msix")
}
fn bundle_metadata(node: Node<'_, '_>) -> Result<()> {
    for child in node.children().filter(|n| n.is_element()) {
        attrs(child, &[])?;
        if child.has_tag_name((BUNDLE_NS, "Resources")) {
            for resource in child.children().filter(|n| n.is_element()) {
                ensure!(
                    resource.has_tag_name((BUNDLE_NS, "Resource")),
                    "unsupported bundle resource element"
                );
                attrs(resource, &["Language", "Scale", "DXFeatureLevel"])?;
                ensure!(
                    !resource.children().any(|n| n.is_element()),
                    "nested bundle resource element"
                );
            }
        } else {
            let ns = child.tag_name().namespace().unwrap_or("");
            ensure!(
                [BUNDLE_NS, "http://schemas.microsoft.com/appx/2018/bundle"].contains(&ns)
                    && child.tag_name().name() == "Dependencies",
                "unsupported bundle package metadata"
            );
            for dependency in child.children().filter(|n| n.is_element()) {
                ensure!(
                    dependency.has_tag_name((ns, "TargetDeviceFamily")),
                    "unsupported bundle dependency"
                );
                attrs(dependency, &["Name", "MinVersion", "MaxVersionTested"])?;
                ensure!(
                    !attr(dependency, "Name")?.is_empty(),
                    "empty target device family"
                );
                validate_version(attr(dependency, "MinVersion")?)?;
                validate_version(attr(dependency, "MaxVersionTested")?)?;
                ensure!(
                    !dependency.children().any(|n| n.is_element()),
                    "nested bundle dependency"
                );
            }
        }
    }
    Ok(())
}
/// Untrusted package identity extracted from its manifest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AppxIdentity {
    pub name: String,
    pub publisher: String,
    pub version: String,
    pub processor_architecture: Option<String>,
    pub resource_id: Option<String>,
}

/// One canonical, unhashed AppX component. `AXPC` borrows the original ZIP;
/// the unsigned directory and decoded footprint parts are owned.
#[derive(Debug)]
pub struct AppxDigestInput<'a> {
    pub tag: &'static str,
    pub bytes: Cow<'a, [u8]>,
}

/// An untrusted signed package layout, available with the `appx` feature.
///
/// Initial parsing checks ZIP/PKCX framing only. XML and block-map structures
/// are decoded explicitly so later metadata errors cannot mask digest failures.
/// Methods never record verification state or authenticate a publisher.
pub struct Appx<'a> {
    bytes: &'a [u8],
    zip: zip::Zip<'a>,
    signature: Vec<u8>,
}

/// A bundle manifest entry and its exact, borrowed stored ZIP payload.
#[derive(Debug)]
pub struct BundlePackage<'a> {
    pub file_name: String,
    pub package_type: String,
    pub architecture: Option<String>,
    pub resource_id: Option<String>,
    pub version: String,
    pub offset: usize,
    pub size: usize,
    pub bytes: &'a [u8],
}
impl<'a> Appx<'a> {
    pub fn parse(bytes: &'a [u8]) -> core::result::Result<Self, Error> {
        structural(Self::parse_inner(bytes))
    }
    fn parse_inner(bytes: &'a [u8]) -> Result<Self> {
        let zip = zip::Zip::parse(bytes)?;
        let is_bundle = zip.get(BUNDLE_MANIFEST).is_some();
        ensure!(
            !(is_bundle && zip.get(MANIFEST).is_some()),
            "package contains both package and bundle manifests"
        );
        let manifest = if is_bundle { BUNDLE_MANIFEST } else { MANIFEST };
        for name in [CT, BM, manifest] {
            ensure!(
                zip.get(name).is_some(),
                "missing required MSIX/AppX part: {name}"
            );
        }
        let entry = zip.get(SIG).ok_or_else(|| {
            Error::new(
                ErrorKind::UnsignedAppx,
                anyhow::anyhow!("package has no AppxSignature.p7x"),
            )
        })?;
        zip.unsigned_directory()?;
        let blob = entry.read(4 * 1024 * 1024)?;
        ensure!(
            blob.starts_with(b"PKCX") && blob.len() > 4,
            "invalid PKCX signature header"
        );
        Ok(Self {
            bytes,
            zip,
            signature: blob[4..].to_vec(),
        })
    }
    pub fn is_bundle(&self) -> bool {
        self.zip.get(BUNDLE_MANIFEST).is_some()
    }
    /// Decode bundle identity and entries without checking embedded signatures.
    pub fn bundle_packages(&self) -> core::result::Result<Vec<BundlePackage<'a>>, Error> {
        structural(self.bundle_identity_inner().map(|(_, packages)| packages))
    }
    /// Original immutable package bytes.
    pub fn as_bytes(&self) -> &'a [u8] {
        self.bytes
    }
    /// ZIP records in canonical file order. Reads are bounded and check CRC/DEFLATE framing.
    pub fn parts(&self) -> impl Iterator<Item = AppxPart<'_>> {
        self.zip.entries.iter().map(|entry| AppxPart { entry })
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
    /// Canonical component inputs in signed digest-bundle order, without hashes.
    pub fn digest_inputs(&self) -> core::result::Result<Vec<AppxDigestInput<'a>>, Error> {
        structural((|| {
            let sig = self.zip.get(SIG).expect("signature checked during parsing");
            let directory = self.zip.unsigned_directory()?;
            let ct = self.read(CT)?;
            let bm = self.read(BM)?;
            let mut inputs = vec![
                AppxDigestInput {
                    tag: "AXPC",
                    bytes: Cow::Borrowed(&self.bytes[..sig.offset]),
                },
                AppxDigestInput {
                    tag: "AXCD",
                    bytes: Cow::Owned(directory),
                },
                AppxDigestInput {
                    tag: "AXCT",
                    bytes: Cow::Owned(ct),
                },
                AppxDigestInput {
                    tag: "AXBM",
                    bytes: Cow::Owned(bm),
                },
            ];
            if let Some(ci) = self.zip.get(CI) {
                inputs.push(AppxDigestInput {
                    tag: "AXCI",
                    bytes: Cow::Owned(ci.read(XML_LIMIT)?),
                });
            }
            Ok(inputs)
        })())
    }
    /// Read the untrusted block-map XML for explicit decoding with `BlockMap`.
    pub fn block_map_bytes(&self) -> core::result::Result<Vec<u8>, Error> {
        structural(self.read(BM))
    }
    /// Read a package-hashed catalog; this does not verify its signature.
    pub fn code_integrity_catalog(&self) -> core::result::Result<Option<Vec<u8>>, Error> {
        structural(self.zip.get(CI).map(|e| e.read(XML_LIMIT)).transpose())
    }
    /// Decode and validate a package or bundle identity without publisher binding.
    pub fn identity(&self) -> core::result::Result<AppxIdentity, Error> {
        structural(if self.is_bundle() {
            self.bundle_identity_inner().map(|(id, _)| id)
        } else {
            self.identity_inner()
        })
    }
    pub fn bundle_identity(
        &self,
    ) -> core::result::Result<(AppxIdentity, Vec<BundlePackage<'a>>), Error> {
        structural(self.bundle_identity_inner())
    }
    fn identity_inner(&self) -> Result<AppxIdentity> {
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
        let architecture = id.attribute("ProcessorArchitecture");
        identity(
            attr(id, "Name")?,
            attr(id, "Publisher")?,
            attr(id, "Version")?,
            architecture,
            id.attribute("ResourceId"),
        )
    }
    /// Decode the manifest's ResourcePackage boolean; no deployment claim is made.
    pub fn resource_package(&self) -> core::result::Result<bool, Error> {
        structural(self.resource_package_inner())
    }
    fn resource_package_inner(&self) -> Result<bool> {
        let bytes = self.read(MANIFEST)?;
        let doc = xml(&bytes)?;
        let root = doc.root_element();
        let ns = root
            .tag_name()
            .namespace()
            .context("missing manifest namespace")?;
        let properties: Vec<_> = root
            .children()
            .filter(|n| n.has_tag_name((ns, "Properties")))
            .collect();
        ensure!(properties.len() <= 1, "duplicate package Properties");
        let values: Vec<_> = properties
            .iter()
            .flat_map(|n| n.children())
            .filter(|n| n.has_tag_name((ns, "ResourcePackage")))
            .collect();
        ensure!(values.len() <= 1, "duplicate ResourcePackage property");
        let Some(node) = values.first() else {
            return Ok(false);
        };
        ensure!(
            node.attributes().len() == 0 && !node.children().any(|n| n.is_element()),
            "invalid ResourcePackage property"
        );
        let value: String = node
            .children()
            .filter(|n| n.is_text())
            .filter_map(|n| n.text())
            .collect();
        match value.trim() {
            "true" | "1" => Ok(true),
            "false" | "0" => Ok(false),
            _ => anyhow::bail!("invalid ResourcePackage boolean"),
        }
    }
    fn bundle_identity_inner(&self) -> Result<(AppxIdentity, Vec<BundlePackage<'a>>)> {
        let bytes = self.read(BUNDLE_MANIFEST)?;
        let doc = xml(&bytes)?;
        let root = doc.root_element();
        ensure!(
            root.has_tag_name((BUNDLE_NS, "Bundle")),
            "invalid bundle manifest root or namespace"
        );
        attrs(root, &["SchemaVersion", "IgnorableNamespaces"])?;
        ensure!(
            ["1.0", "2.0", "3.0", "4.0", "5.0"].contains(&attr(root, "SchemaVersion")?),
            "unsupported bundle manifest schema version"
        );
        ensure!(
            root.children().filter(|n| n.is_element()).all(|n| {
                n.has_tag_name((BUNDLE_NS, "Identity")) || n.has_tag_name((BUNDLE_NS, "Packages"))
            }),
            "unsupported bundle manifest element"
        );
        let identities: Vec<_> = root
            .children()
            .filter(|n| n.has_tag_name((BUNDLE_NS, "Identity")))
            .collect();
        let package_lists: Vec<_> = root
            .children()
            .filter(|n| n.has_tag_name((BUNDLE_NS, "Packages")))
            .collect();
        ensure!(
            identities.len() == 1 && package_lists.len() == 1,
            "bundle manifest must have one Identity and Packages element"
        );
        let identity_node = identities[0];
        attrs(
            identity_node,
            &["Name", "Publisher", "Version", "ResourceId"],
        )?;
        ensure!(
            !identity_node.children().any(|n| n.is_element()),
            "nested bundle Identity element"
        );
        let identity = identity(
            attr(identity_node, "Name")?,
            attr(identity_node, "Publisher")?,
            attr(identity_node, "Version")?,
            None,
            identity_node.attribute("ResourceId"),
        )?;
        let list = package_lists[0];
        attrs(list, &[])?;
        let package_nodes: Vec<_> = list.children().filter(|n| n.is_element()).collect();
        ensure!(!package_nodes.is_empty(), "bundle contains no packages");
        let mut seen = BTreeMap::new();
        let mut packages = Vec::with_capacity(package_nodes.len());
        for node in package_nodes {
            ensure!(
                node.has_tag_name((BUNDLE_NS, "Package")),
                "unsupported bundle Packages element"
            );
            attrs(
                node,
                &[
                    "Type",
                    "Version",
                    "Architecture",
                    "FileName",
                    "Offset",
                    "Size",
                    "ResourceId",
                    "IsStub",
                ],
            )?;
            ensure!(
                node.attribute("IsStub").is_none_or(|v| v == "false"),
                "stub bundle packages are unsupported"
            );
            let package_type = attr(node, "Type")?;
            ensure!(
                ["application", "resource"].contains(&package_type),
                "unsupported bundle package type"
            );
            let version = attr(node, "Version")?;
            validate_version(version)?;
            bundle_metadata(node)?;
            let architecture = Some(node.attribute("Architecture").unwrap_or("neutral"));
            ensure!(
                architecture
                    .is_none_or(|a| { ["neutral", "x86", "x64", "arm", "arm64"].contains(&a) }),
                "unsupported bundle package architecture"
            );
            let file_name = attr(node, "FileName")?;
            let zip_name = file_name.replace('\\', "/");
            ensure!(
                zip::safe_name(&zip_name)
                    && [".appx", ".msix"]
                        .iter()
                        .any(|ext| zip_name.to_ascii_lowercase().ends_with(ext)),
                "invalid bundle package filename"
            );
            ensure!(
                seen.insert(zip_name.to_ascii_lowercase(), ()).is_none(),
                "duplicate bundle package filename"
            );
            let entry = self
                .zip
                .get(&zip_name)
                .context("bundle manifest references a missing package")?;
            ensure!(
                entry.method == 0,
                "compressed bundle packages are unsupported"
            );
            ensure!(
                entry.compressed.len() == entry.size
                    && crc32fast::hash(entry.compressed) == entry.crc,
                "bundle package ZIP size or CRC mismatch"
            );
            let offset = number(node, "Offset")?;
            let size = number(node, "Size")?;
            ensure!(
                offset == entry.offset + entry.lfh_size && size == entry.size,
                "bundle package offset or size differs from its ZIP record"
            );
            packages.push(BundlePackage {
                file_name: zip_name,
                package_type: package_type.into(),
                architecture: architecture.map(str::to_owned),
                resource_id: node
                    .attribute("ResourceId")
                    .filter(|s| !s.is_empty())
                    .map(str::to_owned),
                version: version.into(),
                offset,
                size,
                bytes: entry.compressed,
            });
        }
        let zipped: Vec<_> = self
            .zip
            .entries
            .iter()
            .filter(|entry| {
                [".appx", ".msix"]
                    .iter()
                    .any(|ext| entry.name.to_ascii_lowercase().ends_with(ext))
            })
            .collect();
        ensure!(
            zipped.len() == packages.len()
                && zipped
                    .iter()
                    .all(|entry| seen.contains_key(&entry.name.to_ascii_lowercase())),
            "bundle manifest and embedded package entries differ"
        );
        ensure!(
            self.zip.entries.iter().all(|entry| {
                excluded(&entry.name)
                    || entry.name == BUNDLE_MANIFEST
                    || seen.contains_key(&entry.name.to_ascii_lowercase())
            }),
            "bundle contains an unlisted payload part"
        );
        Ok((identity, packages))
    }
    /// Validate content-type declarations and footprint bindings, without hashes.
    pub fn content_types(&self) -> core::result::Result<(), Error> {
        structural(self.content_types_inner())
    }
    fn content_types_inner(&self) -> Result<()> {
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
                BUNDLE_MANIFEST => Some("application/vnd.ms-appx.bundlemanifest+xml"),
                CI => Some("application/vnd.ms-pkiseccat"),
                _ if self.is_bundle() && is_package_name(&e.name) => {
                    Some("application/vnd.ms-appx")
                }
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

    #[cfg(feature = "verify")]
    pub(crate) fn payload_parts<'p>(
        &'p self,
        packages: &[BundlePackage<'_>],
    ) -> Vec<&'p zip::Entry<'a>> {
        self.zip
            .entries
            .iter()
            .filter(|e| !excluded(&e.name) && !packages.iter().any(|p| p.file_name == e.name))
            .collect()
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

/// A bounded, untrusted block-map XML document. Hash methods remain opaque.
/// Files and blocks are decoded on demand in document order; no hashes are checked.
pub struct BlockMap<'xml> {
    doc: Document<'xml>,
}
impl<'xml> BlockMap<'xml> {
    pub fn parse(bytes: &'xml [u8]) -> core::result::Result<Self, Error> {
        structural((|| {
            let doc = xml(bytes)?;
            let root = doc.root_element();
            ensure!(
                root.has_tag_name((BM_NS, "BlockMap")),
                "invalid block-map root or namespace"
            );
            attrs(root, &["HashMethod", "IgnorableNamespaces"])?;
            Ok(Self { doc })
        })())
    }
    pub fn hash_method(&self) -> core::result::Result<&str, Error> {
        structural(attr(self.doc.root_element(), "HashMethod"))
    }
    pub fn files(&self) -> Vec<BlockMapFile<'_, 'xml>> {
        self.doc
            .root_element()
            .children()
            .filter(|n| n.is_element())
            .map(|node| BlockMapFile { node })
            .collect()
    }
}

/// A file element whose attributes and child blocks are decoded explicitly.
#[derive(Clone, Copy)]
pub struct BlockMapFile<'doc, 'xml> {
    node: Node<'doc, 'xml>,
}
impl<'doc, 'xml> BlockMapFile<'doc, 'xml> {
    fn header(&self) -> Result<()> {
        ensure!(
            self.node.has_tag_name((BM_NS, "File")),
            "unsupported block-map element"
        );
        attrs(self.node, &["Name", "Size", "LfhSize"])
    }
    pub fn name(&self) -> core::result::Result<&'doc str, Error> {
        structural(self.header().and_then(|()| attr(self.node, "Name")))
    }
    pub fn size(&self) -> core::result::Result<usize, Error> {
        structural(self.header().and_then(|()| number(self.node, "Size")))
    }
    pub fn local_header_size(&self) -> core::result::Result<usize, Error> {
        structural(self.header().and_then(|()| number(self.node, "LfhSize")))
    }
    pub fn blocks(&self) -> core::result::Result<Vec<BlockMapBlock<'doc, 'xml>>, Error> {
        structural(self.header().map(|()| {
            self.node
                .children()
                .filter(|n| n.is_element())
                .map(|node| BlockMapBlock { node })
                .collect()
        }))
    }
    #[cfg(feature = "verify")]
    pub(crate) fn check_part(&self, e: &zip::Entry<'_>) -> Result<Vec<BlockMapBlock<'doc, 'xml>>> {
        self.header()?;
        let name = attr(self.node, "Name")?;
        ensure!(
            !name.contains('/') && name.replace('\\', "/") == e.name,
            "block-map path or order differs from ZIP entries"
        );
        ensure!(
            number(self.node, "Size")? == e.size && number(self.node, "LfhSize")? == e.lfh_size,
            "block-map file size or local-header size mismatch"
        );
        let blocks = self.blocks()?;
        ensure!(
            blocks.len() == e.size.div_ceil(65536),
            "block-map block count mismatch"
        );
        Ok(blocks)
    }
}

/// One untrusted block hash and optional compressed size.
#[derive(Clone, Copy)]
pub struct BlockMapBlock<'doc, 'xml> {
    node: Node<'doc, 'xml>,
}
impl BlockMapBlock<'_, '_> {
    /// Decode the stored digest without enforcing an algorithm or authenticating it.
    pub fn hash(&self) -> core::result::Result<Vec<u8>, Error> {
        structural((|| {
            ensure!(
                self.node.has_tag_name((BM_NS, "Block")),
                "unsupported block-map child"
            );
            attrs(self.node, &["Hash", "Size"])?;
            ensure!(
                !self.node.children().any(|n| n.is_element()),
                "nested block-map Block"
            );
            Base64::decode_vec(attr(self.node, "Hash")?)
                .map_err(|e| anyhow::anyhow!("invalid block hash base64: {e}"))
        })())
    }
    pub fn compressed_size(&self) -> core::result::Result<Option<usize>, Error> {
        structural((|| {
            ensure!(
                self.node.has_tag_name((BM_NS, "Block")),
                "unsupported block-map child"
            );
            attrs(self.node, &["Hash", "Size"])?;
            ensure!(
                !self.node.children().any(|n| n.is_element()),
                "nested block-map Block"
            );
            self.node
                .attribute("Size")
                .map(|_| number(self.node, "Size"))
                .transpose()
        })())
    }
    #[cfg(feature = "verify")]
    pub(crate) fn check_compression(&self, method: u16) -> Result<Option<usize>> {
        if method == 0 {
            ensure!(
                self.node.attribute("Size").is_none(),
                "stored block must omit compressed Size"
            );
            Ok(None)
        } else {
            let size = number(self.node, "Size")?;
            ensure!(size > 0, "empty compressed block");
            Ok(Some(size))
        }
    }
}

#[cfg(feature = "verify")]
pub(crate) fn check_compressed_blocks(e: &zip::Entry<'_>, sizes: &[usize]) -> Result<()> {
    compressed_blocks(e, sizes)
}

/// A borrowed ZIP record from a parsed package. Its CRC is structural evidence,
/// not an authenticated digest. No paths are extracted to disk.
#[derive(Clone, Copy)]
pub struct AppxPart<'a> {
    entry: &'a zip::Entry<'a>,
}
impl<'a> AppxPart<'a> {
    pub fn name(&self) -> &'a str {
        &self.entry.name
    }
    pub fn offset(&self) -> usize {
        self.entry.offset
    }
    pub fn local_header_size(&self) -> usize {
        self.entry.lfh_size
    }
    pub fn compressed_bytes(&self) -> &'a [u8] {
        self.entry.compressed
    }
    pub fn uncompressed_size(&self) -> usize {
        self.entry.size
    }
    /// ZIP compression method: stored (0) or DEFLATE (8).
    pub fn compression_method(&self) -> u16 {
        self.entry.method
    }
    pub fn crc32(&self) -> u32 {
        self.entry.crc
    }
    /// Decode with a caller-supplied size limit, checking CRC and exact termination.
    pub fn read(&self, limit: usize) -> core::result::Result<Vec<u8>, Error> {
        structural(self.entry.read(limit))
    }
    /// Check the block map's compressed boundaries without checking block hashes.
    pub fn check_compressed_blocks(&self, sizes: &[usize]) -> core::result::Result<(), Error> {
        structural((|| {
            ensure!(
                self.entry.method == 8,
                "compressed block boundaries require DEFLATE"
            );
            ensure!(
                sizes.len() == self.entry.size.div_ceil(65536),
                "block-map block count mismatch"
            );
            compressed_blocks(self.entry, sizes)
        })())
    }
}
