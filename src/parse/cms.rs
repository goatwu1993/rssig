use crate::{
    der::{self, Node},
    domain::{ErrorCode, Stage, VerificationError},
};
use ::der::{Decode, asn1::ObjectIdentifier};
use anyhow::{Context, Result, ensure};
use x509_cert::Certificate;

pub(crate) const SIGNED_DATA: &[u8] = &[42, 134, 72, 134, 247, 13, 1, 7, 2];

/// An algorithm identifier, including algorithms the verifier does not support.
#[derive(Debug)]
pub struct AlgorithmIdentifier<'a> {
    pub(crate) node: Node<'a>,
    oid: ObjectIdentifier,
    parameters: Option<&'a [u8]>,
}
impl<'a> AlgorithmIdentifier<'a> {
    fn parse(node: Node<'a>) -> Result<Self> {
        let fields = node.expect(0x30)?.children()?;
        ensure!(
            (1..=2).contains(&fields.len()),
            "invalid AlgorithmIdentifier"
        );
        Ok(Self {
            node,
            oid: ObjectIdentifier::from_der(fields[0].full)?,
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
    pub fn x509(&self) -> Option<&Certificate> {
        self.x509.as_ref()
    }
}

/// An unverified CMS/legacy PKCS#7 SignedData envelope borrowing its input.
///
/// Preserves attached content, algorithms, signer encodings, certificates, and
/// revocation choices. SignerInfo bodies, nested signatures, timestamps, and
/// content-specific structures are not recursively interpreted here. Empty
/// signer sets are parseable; verification requires at least one signer.
#[derive(Debug)]
pub struct SignedData<'a> {
    der: &'a [u8],
    pub(crate) version: Node<'a>,
    content_type: ObjectIdentifier,
    pub(crate) content_type_bytes: &'a [u8],
    pub(crate) content: Option<Node<'a>>,
    algorithms: Vec<AlgorithmIdentifier<'a>>,
    certificates: Vec<CertificateChoice<'a>>,
    revocations: Vec<&'a [u8]>,
    pub(crate) signers: Vec<Node<'a>>,
}
impl<'a> SignedData<'a> {
    pub fn parse(bytes: &'a [u8]) -> std::result::Result<Self, VerificationError> {
        Self::parse_inner(bytes)
            .map_err(|e| VerificationError::from_internal(e, ErrorCode::MalformedCms, Stage::Cms))
    }

    pub(crate) fn parse_inner(bytes: &'a [u8]) -> Result<Self> {
        let outer = der::fields(der::one(bytes, 0x30)?, 2)?;
        ensure!(der::oid(outer[0], SIGNED_DATA), "not PKCS#7 SignedData");
        let sd = der::one(outer[1].expect(0xa0)?.body, 0x30)?.children()?;
        ensure!((4..=6).contains(&sd.len()), "invalid SignedData");
        ::der::asn1::UintRef::from_der(sd[0].full)?;
        let algorithms = sd[1]
            .expect(0x31)?
            .children()?
            .into_iter()
            .map(AlgorithmIdentifier::parse)
            .collect::<Result<_>>()?;
        let ci = sd[2].expect(0x30)?.children()?;
        ensure!(
            (1..=2).contains(&ci.len()),
            "invalid encapsulated content fields"
        );
        let content_type = ObjectIdentifier::from_der(ci[0].full)?;
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
            content_type_bytes: ci[0].body,
            content,
            algorithms,
            certificates,
            revocations,
            signers,
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
    pub fn signer_infos(&self) -> Vec<&'a [u8]> {
        self.signers.iter().map(|n| n.full).collect()
    }
}

fn certificate_choice(node: Node<'_>) -> Result<CertificateChoice<'_>> {
    if node.tag == 0x30 {
        return Ok(CertificateChoice {
            node,
            x509: Some(Certificate::from_der(node.full).context("invalid embedded certificate")?),
        });
    } else {
        ensure!(
            (0xa0..=0xa3).contains(&node.tag),
            "unsupported CertificateChoices tag"
        );
        let fields = node.children()?;
        if node.tag == 0xa3 {
            ensure!(fields.len() == 2, "invalid other certificate format");
            ::der::asn1::ObjectIdentifier::from_der(fields[0].full)?;
        } else {
            ensure!(fields.len() == 3, "invalid opaque certificate envelope");
            fields[0].expect(0x30)?;
            let alg = fields[1].expect(0x30)?.children()?;
            ensure!(
                (1..=2).contains(&alg.len()),
                "invalid certificate algorithm"
            );
            ::der::asn1::ObjectIdentifier::from_der(alg[0].full)?;
            ::der::asn1::BitStringRef::from_der(fields[2].full)?;
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
