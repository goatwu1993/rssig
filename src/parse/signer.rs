//! Borrowed, untrusted CMS signer and attribute structures.
use super::{AlgorithmIdentifier, Error, ErrorKind, error::DecodeError};
use crate::der::{self, Node};
use ::der::{
    Decode,
    asn1::{ObjectIdentifier, UintRef},
};
use alloc::vec::Vec;
use anyhow::{Result, ensure};

/// An opaque encoded value. Constructed payloads are not recursively interpreted.
#[derive(Clone, Copy, Debug)]
pub struct Content<'a> {
    pub(crate) node: Node<'a>,
}
impl<'a> Content<'a> {
    pub fn tag(&self) -> u8 {
        self.node.tag
    }
    pub fn as_der(&self) -> &'a [u8] {
        self.node.full
    }
    /// Contents excluding the tag and length, retaining any inner wrappers.
    pub fn value(&self) -> &'a [u8] {
        self.node.body
    }
}

/// Untrusted signer identity; neither alternative establishes certificate trust.
#[derive(Clone, Copy, Debug)]
pub enum SignerIdentifier<'a> {
    IssuerAndSerialNumber {
        issuer_der: &'a [u8],
        serial_number_der: &'a [u8],
    },
    SubjectKeyIdentifier(&'a [u8]),
}

/// One CMS attribute, preserving unknown OIDs and opaque value encodings.
#[derive(Debug)]
pub struct Attribute<'a> {
    node: Node<'a>,
    oid: ObjectIdentifier,
    pub(crate) oid_bytes: &'a [u8],
    values: Vec<Content<'a>>,
}
impl<'a> Attribute<'a> {
    pub fn as_der(&self) -> &'a [u8] {
        self.node.full
    }
    pub fn oid(&self) -> ObjectIdentifier {
        self.oid
    }
    pub fn values(&self) -> &[Content<'a>] {
        &self.values
    }
}

/// An implicitly tagged signed or unsigned attribute set, with original bytes.
/// Signed sets require canonical attribute order; both reject duplicate OIDs
/// and empty value sets. Values remain opaque, including nested CMS/timestamps.
#[derive(Debug)]
pub struct Attributes<'a> {
    node: Node<'a>,
    attributes: Vec<Attribute<'a>>,
}
impl<'a> Attributes<'a> {
    pub fn parse(bytes: &'a [u8]) -> core::result::Result<Self, Error> {
        let result = (|| {
            let mut rest = bytes;
            let node = der::take(&mut rest)?;
            ensure!(rest.is_empty(), "trailing DER data");
            Self::from_node(node)
        })();
        result.map_err(|e| Error::new(ErrorKind::MalformedCms, e))
    }
    pub(crate) fn from_node(node: Node<'a>) -> Result<Self> {
        ensure!(
            matches!(node.tag, 0xa0 | 0xa1),
            "invalid CMS attribute set tag"
        );
        let children = node.children()?;
        if node.tag == 0xa0 {
            ensure!(
                children.windows(2).all(|w| w[0].full <= w[1].full),
                "noncanonical signed attribute order"
            );
        }
        let mut attributes: Vec<Attribute<'a>> = Vec::new();
        for attr in children {
            let f = der::fields(attr.expect(0x30)?, 2)?;
            f[0].expect(6)?;
            ensure!(
                !attributes.iter().any(|a| a.oid_bytes == f[0].body),
                "duplicate CMS attribute"
            );
            let values = f[1].expect(0x31)?.children()?;
            ensure!(!values.is_empty(), "empty CMS attribute");
            let oid = ObjectIdentifier::from_der(f[0].full).map_err(DecodeError)?;
            attributes.push(Attribute {
                node: attr,
                oid,
                oid_bytes: f[0].body,
                values: values.into_iter().map(|node| Content { node }).collect(),
            });
        }
        Ok(Self { node, attributes })
    }
    pub fn as_der(&self) -> &'a [u8] {
        self.node.full
    }
    pub fn attributes(&self) -> &[Attribute<'a>] {
        &self.attributes
    }
}

// Shared framing only: verifier policy checks and deferred attributes retain
// their existing order relative to digests, certificates, and signature checks.
pub(crate) fn signer_fields(node: Node<'_>) -> Result<Vec<Node<'_>>> {
    node.expect(0x30)?.children()
}

pub(crate) fn signer_field_count(si: &[Node<'_>], has_attributes: bool) -> Result<usize> {
    let count = if has_attributes { 6 } else { 5 };
    ensure!(
        si.len() == count || si.len() == count + 1,
        "invalid SignerInfo fields"
    );
    Ok(count)
}

/// Structurally decoded SignerInfo. Algorithms, identity, attributes, signature,
/// and content are untrusted; parsing never authenticates their assertions.
///
/// ```
/// use rssig::parse::{SignedData, SignerInfo};
/// # let bytes = include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/parse-signer-views.der"));
/// let cms = SignedData::parse(bytes)?;
/// for raw in cms.signer_infos() {
///     let signer = SignerInfo::parse(raw)?;
///     assert_eq!(signer.signature_algorithm().oid().to_string(), "1.2.3.5");
/// }
/// # Ok::<(), rssig::parse::Error>(())
/// ```
#[derive(Debug)]
pub struct SignerInfo<'a> {
    node: Node<'a>,
    version: &'a [u8],
    identifier_der: &'a [u8],
    identifier: SignerIdentifier<'a>,
    digest_algorithm: AlgorithmIdentifier<'a>,
    signature_algorithm: AlgorithmIdentifier<'a>,
    signature: &'a [u8],
    signed: Option<Attributes<'a>>,
    unsigned: Option<Attributes<'a>>,
}
impl<'a> SignerInfo<'a> {
    pub fn parse(bytes: &'a [u8]) -> core::result::Result<Self, Error> {
        Self::parse_inner(bytes).map_err(|e| Error::new(ErrorKind::MalformedCms, e))
    }
    fn parse_inner(bytes: &'a [u8]) -> Result<Self> {
        let node = der::one(bytes, 0x30)?;
        let si = signer_fields(node)?;
        let signed_present = si.get(3).is_some_and(|n| n.tag == 0xa0);
        let count = signer_field_count(&si, signed_present)?;
        UintRef::from_der(si[0].full).map_err(DecodeError)?;
        let identifier = if si[1].tag == 0x80 {
            SignerIdentifier::SubjectKeyIdentifier(si[1].body)
        } else {
            let sid = der::fields(si[1].expect(0x30)?, 2)?;
            sid[0].expect(0x30)?.children()?;
            UintRef::from_der(sid[1].full).map_err(DecodeError)?;
            SignerIdentifier::IssuerAndSerialNumber {
                issuer_der: sid[0].full,
                serial_number_der: sid[1].full,
            }
        };
        let index = if signed_present { 4 } else { 3 };
        Ok(Self {
            node,
            version: si[0].full,
            identifier,
            identifier_der: si[1].full,
            digest_algorithm: AlgorithmIdentifier::from_node(si[2])?,
            signature_algorithm: AlgorithmIdentifier::from_node(si[index])?,
            signature: si[index + 1].expect(4)?.body,
            signed: if signed_present {
                Some(Attributes::from_node(si[3])?)
            } else {
                None
            },
            unsigned: if si.len() > count {
                Some(Attributes::from_node(si[count].expect(0xa1)?)?)
            } else {
                None
            },
        })
    }
    pub fn as_der(&self) -> &'a [u8] {
        self.node.full
    }
    pub fn version_der(&self) -> &'a [u8] {
        self.version
    }
    pub fn identifier_der(&self) -> &'a [u8] {
        self.identifier_der
    }
    pub fn identifier(&self) -> SignerIdentifier<'a> {
        self.identifier
    }
    pub fn digest_algorithm(&self) -> &AlgorithmIdentifier<'a> {
        &self.digest_algorithm
    }
    pub fn signature_algorithm(&self) -> &AlgorithmIdentifier<'a> {
        &self.signature_algorithm
    }
    pub fn signature(&self) -> &'a [u8] {
        self.signature
    }
    pub fn signed_attributes(&self) -> Option<&Attributes<'a>> {
        self.signed.as_ref()
    }
    pub fn unsigned_attributes(&self) -> Option<&Attributes<'a>> {
        self.unsigned.as_ref()
    }
}
