use super::{Error, ErrorKind, error::DecodeError};
use crate::der::{self, Node};
use ::der::{Decode, asn1::ObjectIdentifier};
use alloc::vec::Vec;
use anyhow::{Context, Result, ensure};
use x509_cert::Certificate;

pub(crate) const SIGNED_DATA: &[u8] = &[42, 134, 72, 134, 247, 13, 1, 7, 2];

pub(crate) fn algorithm_fields<'a>(node: Node<'a>, diagnostic: &str) -> Result<Vec<Node<'a>>> {
    let fields = node.expect(0x30)?.children()?;
    ensure!((1..=2).contains(&fields.len()), "{diagnostic}");
    fields[0].expect(6)?;
    Ok(fields)
}

/// An algorithm identifier, including algorithms the verifier does not support.
#[derive(Debug)]
pub struct AlgorithmIdentifier<'a> {
    pub(crate) node: Node<'a>,
    oid: ObjectIdentifier,
    parameters: Option<&'a [u8]>,
}
impl<'a> AlgorithmIdentifier<'a> {
    /// Decode an algorithm without applying verification support/parameter policy.
    pub fn parse(bytes: &'a [u8]) -> core::result::Result<Self, Error> {
        der::one(bytes, 0x30)
            .and_then(Self::from_node)
            .map_err(|e| Error::new(ErrorKind::MalformedCms, e))
    }

    pub(crate) fn from_node(node: Node<'a>) -> Result<Self> {
        let fields = algorithm_fields(node, "invalid AlgorithmIdentifier")?;
        Ok(Self {
            node,
            oid: ObjectIdentifier::from_der(fields[0].full).map_err(DecodeError)?,
            parameters: fields.get(1).map(|n| n.full),
        })
    }
    pub fn oid(&self) -> ObjectIdentifier {
        self.oid
    }
    pub fn as_der(&self) -> &'a [u8] {
        self.node.full
    }
    /// Parameters as encoded, including a NULL if present.
    pub fn parameters_der(&self) -> Option<&'a [u8]> {
        self.parameters
    }
}

/// One untrusted CMS CertificateChoices entry (RFC 5652 section 10.2.2).
///
/// X.509 certificates are decoded structurally. Context-specific alternatives
/// `[0]` through `[3]` are opaque: only envelope shape and bounded DER framing are
/// checked. Their semantics and signatures are not validated. Only X.509
/// entries can become signer or chain candidates, never trust anchors.
#[derive(Debug)]
pub struct CertificateChoice<'a> {
    node: Node<'a>,
    x509: Option<Certificate>,
}
impl<'a> CertificateChoice<'a> {
    /// Original tag, including class and constructed bits (0x30 or 0xa0..=0xa3).
    pub fn tag(&self) -> u8 {
        self.node.tag
    }
    pub fn as_der(&self) -> &'a [u8] {
        self.node.full
    }
    #[cfg(feature = "verify-core")]
    pub(crate) fn into_x509(self) -> Option<Certificate> {
        self.x509
    }

    pub fn x509(&self) -> Option<&Certificate> {
        self.x509.as_ref()
    }
}

/// An unverified CMS/legacy PKCS#7 SignedData envelope borrowing its input.
///
/// Preserves attached content, algorithms, signer encodings, certificates, and
/// revocation choices. SignerInfo bodies can be decoded explicitly with
/// [`super::SignerInfo`]. Nested signatures, timestamps, and
/// content-specific structures are not recursively interpreted by `parse`; use
/// [`SignedData::inspect`] for bounded recursive inspection. Empty
/// signer sets are parseable; verification requires at least one signer.
#[derive(Debug)]
pub struct SignedData<'a> {
    der: &'a [u8],
    pub(crate) version: Node<'a>,
    content_type: ObjectIdentifier,
    #[cfg(feature = "verify-core")]
    pub(crate) content_type_bytes: &'a [u8],
    pub(crate) content: Option<Node<'a>>,
    algorithms: Vec<AlgorithmIdentifier<'a>>,
    certificates: Vec<CertificateChoice<'a>>,
    revocations: Vec<&'a [u8]>,
    signers: Vec<&'a [u8]>,
}
impl<'a> SignedData<'a> {
    #[cfg(feature = "verify-core")]
    pub(crate) fn into_certificate_choices(self) -> Vec<CertificateChoice<'a>> {
        self.certificates
    }

    pub fn parse(bytes: &'a [u8]) -> core::result::Result<Self, Error> {
        Self::parse_inner(bytes).map_err(|e| Error::new(ErrorKind::MalformedCms, e))
    }

    pub(crate) fn parse_inner(bytes: &'a [u8]) -> Result<Self> {
        let outer = der::fields(der::one(bytes, 0x30)?, 2)?;
        ensure!(der::oid(outer[0], SIGNED_DATA), "not PKCS#7 SignedData");
        let sd = der::one(outer[1].expect(0xa0)?.body, 0x30)?.children()?;
        ensure!((4..=6).contains(&sd.len()), "invalid SignedData");
        ::der::asn1::UintRef::from_der(sd[0].full).map_err(DecodeError)?;
        let algorithms = sd[1]
            .expect(0x31)?
            .children()?
            .into_iter()
            .map(AlgorithmIdentifier::from_node)
            .collect::<Result<_>>()?;
        let ci = sd[2].expect(0x30)?.children()?;
        ensure!(
            (1..=2).contains(&ci.len()),
            "invalid encapsulated content fields"
        );
        let content_type = ObjectIdentifier::from_der(ci[0].full).map_err(DecodeError)?;
        let content = if ci.len() == 2 {
            let mut remaining = ci[1].expect(0xa0)?.body;
            let content = der::take(&mut remaining)?;
            ensure!(remaining.is_empty(), "trailing DER data");
            Some(content)
        } else {
            None
        };
        let mut i = 3;
        let certificates = if sd[i].tag == 0xa0 {
            let certs = sd[i]
                .children()?
                .into_iter()
                .map(certificate_choice)
                .collect::<Result<_>>()?;
            i += 1;
            certs
        } else {
            Vec::new()
        };
        let revocations = if i < sd.len() && sd[i].tag == 0xa1 {
            let crls = sd[i].children()?.iter().map(|n| n.full).collect();
            i += 1;
            crls
        } else {
            Vec::new()
        };
        ensure!(i + 1 == sd.len(), "invalid SignedData fields");
        let signers = sd[i].expect(0x31)?.children()?;
        ensure!(signers.len() <= 64, "invalid signer count");
        for signer in &signers {
            signer.expect(0x30)?;
        }
        Ok(Self {
            der: bytes,
            version: sd[0],
            content_type,
            #[cfg(feature = "verify-core")]
            content_type_bytes: ci[0].body,
            content,
            algorithms,
            certificates,
            revocations,
            signers: signers.into_iter().map(|node| node.full).collect(),
        })
    }

    pub fn as_der(&self) -> &'a [u8] {
        self.der
    }
    pub fn version_der(&self) -> &'a [u8] {
        self.version.full
    }
    pub fn content_type(&self) -> ObjectIdentifier {
        self.content_type
    }
    /// Complete encoded inner value, retaining the CMS OCTET STRING or legacy ANY wrapper.
    pub fn content_der(&self) -> Option<&'a [u8]> {
        self.content.map(|n| n.full)
    }
    /// Borrow attached content without interpreting content-specific structures.
    pub fn content(&self) -> Option<super::Content<'a>> {
        self.content.map(|node| super::Content { node })
    }
    pub fn digest_algorithms(&self) -> &[AlgorithmIdentifier<'a>] {
        &self.algorithms
    }
    pub fn certificate_choices(&self) -> &[CertificateChoice<'a>] {
        &self.certificates
    }
    /// Raw, untrusted embedded revocation choices; never the configured CRL store.
    pub fn revocation_choices_der(&self) -> &[&'a [u8]] {
        &self.revocations
    }
    /// Borrow raw SignerInfo encodings without allocating on access.
    pub fn signer_infos(&self) -> &[&'a [u8]] {
        &self.signers
    }
}

fn certificate_choice(node: Node<'_>) -> Result<CertificateChoice<'_>> {
    if node.tag == 0x30 {
        return Ok(CertificateChoice {
            node,
            x509: Some(
                Certificate::from_der(node.full)
                    .map_err(DecodeError)
                    .context("invalid embedded certificate")?,
            ),
        });
    } else {
        ensure!(
            (0xa0..=0xa3).contains(&node.tag),
            "unsupported CertificateChoices tag"
        );
        let fields = node.children()?;
        if node.tag == 0xa3 {
            ensure!(fields.len() == 2, "invalid other certificate format");
            ::der::asn1::ObjectIdentifier::from_der(fields[0].full).map_err(DecodeError)?;
        } else {
            ensure!(fields.len() == 3, "invalid opaque certificate envelope");
            fields[0].expect(0x30)?;
            let alg = fields[1].expect(0x30)?.children()?;
            ensure!(
                (1..=2).contains(&alg.len()),
                "invalid certificate algorithm"
            );
            ::der::asn1::ObjectIdentifier::from_der(alg[0].full).map_err(DecodeError)?;
            ::der::asn1::BitStringRef::from_der(fields[2].full).map_err(DecodeError)?;
        }
        validate_opaque(node, 0, &mut 16384)?;
    }
    Ok(CertificateChoice { node, x509: None })
}

// Check framing of opaque constructed values without interpreting their policy.
fn validate_opaque(node: Node<'_>, depth: usize, remaining: &mut usize) -> Result<()> {
    ensure!(
        depth <= 32 && *remaining > 0,
        "opaque certificate DER limit exceeded"
    );
    *remaining -= 1;
    if node.tag & 0x20 != 0 {
        let mut rest = node.body;
        while !rest.is_empty() {
            validate_opaque(der::take(&mut rest)?, depth + 1, remaining)?;
        }
    }
    Ok(())
}
