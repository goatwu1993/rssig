use crate::domain::{ErrorCode, Stage, VerificationError};
use crate::{
    crypto::{self, Hash},
    der::{self, Node},
};
use ::der::{Decode, Encode};
use alloc::vec::Vec;
use anyhow::{Context, Result, ensure};
use x509_cert::Certificate;

pub(crate) const DATA: &[u8] = &[42, 134, 72, 134, 247, 13, 1, 7, 1];
#[cfg(all(test, feature = "verify"))]
pub(crate) use crate::parse::cms::SIGNED_DATA;
pub(crate) const INDIRECT: &[u8] = &[43, 6, 1, 4, 1, 130, 55, 2, 1, 4];
const PE_IMAGE: &[u8] = &[43, 6, 1, 4, 1, 130, 55, 2, 1, 15];
const CONTENT_TYPE: &[u8] = &[42, 134, 72, 134, 247, 13, 1, 9, 3];
const MESSAGE_DIGEST: &[u8] = &[42, 134, 72, 134, 247, 13, 1, 9, 4];
pub(crate) const NESTED: &[u8] = &[43, 6, 1, 4, 1, 130, 55, 2, 4, 1];
pub(crate) const RFC3161: &[u8] = &[43, 6, 1, 4, 1, 130, 55, 3, 3, 1];
pub(crate) const CMS_TIMESTAMP: &[u8] = &[42, 134, 72, 134, 247, 13, 1, 9, 16, 2, 14];
pub(crate) const COUNTERSIGN: &[u8] = &[42, 134, 72, 134, 247, 13, 1, 9, 6];
pub(crate) const TST_INFO: &[u8] = &[42, 134, 72, 134, 247, 13, 1, 9, 16, 1, 4];

pub(crate) struct SignedData<'a> {
    pub content: Node<'a>,
    pub content_type: &'a [u8],
    pub certs: Vec<Certificate>,
    pub unverified_certificate_choices: Vec<crate::domain::UnverifiedCertificateChoice>,
    pub signers: Vec<Node<'a>>,
    digest_algorithms: Vec<Hash>,
}
pub(crate) struct Signer<'a, 'c> {
    pub hash: Hash,
    pub cert: &'c Certificate,
    pub signature: &'a [u8],
    pub unsigned: Vec<(Vec<u8>, Vec<Node<'a>>)>,
    pub signed: Vec<(Vec<u8>, Vec<Node<'a>>)>,
}

pub(crate) fn algorithm(node: Node<'_>) -> Result<Hash> {
    let fields = crate::parse::cms::algorithm_fields(node, "invalid AlgorithmIdentifier")?;
    if fields.len() == 2 {
        ensure!(
            fields[1].tag == 5 && fields[1].body.is_empty(),
            "unsupported digest parameters"
        );
    }
    Hash::from_oid(fields[0].body)
}

impl<'a> SignedData<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self> {
        let parsed = crate::parse::SignedData::parse_inner(bytes)?;
        // Retain legacy PKCS#7 v1 envelopes, including existing timestamp and
        // opaque certificate-choice fixtures. CMS envelopes use the version
        // implied by their content and certificate/revocation choices.
        let cms_version = if parsed.certificate_choices().iter().any(|c| c.tag() == 0xa3)
            || parsed
                .revocation_choices_der()
                .iter()
                .any(|c| c.first() == Some(&0xa1))
        {
            5
        } else if parsed.certificate_choices().iter().any(|c| c.tag() == 0xa2) {
            4
        } else {
            3
        };
        ensure!(
            parsed.version.body == [1] || parsed.version.body == [cms_version],
            "unsupported attached SignedData version"
        );
        let digest_algorithms = parsed
            .digest_algorithms()
            .iter()
            .map(|a| algorithm(a.node))
            .collect::<Result<Vec<_>>>()?;
        let content_type = parsed.content_type_bytes;
        let mut content = parsed
            .content
            .context("missing attached SignedData content")?
            .expect(if content_type == TST_INFO { 4 } else { 0x30 })?;
        // RFC 5652 wraps TSTInfo in an OCTET STRING; legacy Authenticode uses ANY.
        if content.tag == 4 {
            content = der::one(content.body, 0x30)?;
        }
        ensure!(!parsed.signer_infos().is_empty(), "invalid signer count");
        let signers = parsed
            .signer_infos()
            .iter()
            .map(|bytes| der::one(bytes, 0x30))
            .collect::<Result<_>>()?;
        let (certs, unverified_certificate_choices) = certificate_candidates(parsed);
        Ok(Self {
            content,
            content_type,
            certs,
            unverified_certificate_choices,
            signers,
            digest_algorithms,
        })
    }

    pub fn verify(&self, signer: Node<'a>, allow_sha1: bool) -> Result<Signer<'a, '_>> {
        // Authenticode hashes the contents of the sequence, RFC 3161 hashes its full encoding.
        let content = if self.content_type == INDIRECT {
            self.content.body
        } else {
            self.content.full
        };
        self.verify_signer(signer, content, Some(self.content_type), allow_sha1)
    }

    pub fn verify_signer(
        &self,
        signer: Node<'a>,
        content: &[u8],
        content_type: Option<&[u8]>,
        allow_sha1: bool,
    ) -> Result<Signer<'a, '_>> {
        verify_signer_inner(
            &self.certs,
            &self.digest_algorithms,
            signer,
            content,
            content_type,
            allow_sha1,
            false,
        )
    }

    pub fn image_digest(&self) -> Result<(Hash, &'a [u8])> {
        ensure!(
            self.content_type == INDIRECT,
            "not an Authenticode signature"
        );
        let indirect = der::fields(self.content, 2)?;
        let data = indirect[0].expect(0x30)?.children()?;
        ensure!(
            !data.is_empty() && der::oid(data[0], PE_IMAGE),
            "not a PE image signature"
        );
        self.indirect_digest()
    }
    pub fn cab_digest(&self) -> Result<(Hash, &'a [u8])> {
        ensure!(
            self.content_type == INDIRECT,
            "not a CAB Authenticode signature"
        );
        let indirect = der::fields(self.content, 2)?;
        let data = indirect[0].expect(0x30)?.children()?;
        ensure!(
            (1..=2).contains(&data.len())
                && der::oid(data[0], &[43, 6, 1, 4, 1, 130, 55, 2, 1, 25]),
            "not a CAB signature"
        );
        self.indirect_digest()
    }
    fn indirect_digest(&self) -> Result<(Hash, &'a [u8])> {
        let indirect = der::fields(self.content, 2)?;
        let digest = der::fields(indirect[1].expect(0x30)?, 2)?;
        Ok((algorithm(digest[0])?, digest[1].expect(4)?.body))
    }

    pub fn script_digest(&self) -> Result<(Hash, &'a [u8])> {
        ensure!(
            self.content_type == INDIRECT,
            "not a PowerShell Authenticode signature"
        );
        let indirect = der::fields(self.content, 2)?;
        let data = der::fields(indirect[0].expect(0x30)?, 2)?;
        ensure!(
            der::oid(data[0], &[43, 6, 1, 4, 1, 130, 55, 2, 1, 30]),
            "invalid PowerShell SIP type"
        );
        let sip = der::fields(data[1].expect(0x30)?, 7)?;
        ensure!(
            sip[0].expect(2)?.body == [1, 0, 0],
            "unsupported PowerShell SIP version"
        );
        ensure!(
            sip[1].expect(4)?.body
                == [
                    0x1f, 0xcc, 0x3b, 0x60, 0x59, 0x4b, 0x08, 0x4e, 0xb7, 0x24, 0xd2, 0xc6, 0x29,
                    0x7e, 0xf3, 0x51
                ],
            "invalid PowerShell SIP UUID"
        );
        for reserved in &sip[2..] {
            ensure!(
                reserved.expect(2)?.body == [0],
                "invalid PowerShell SIP reserved field"
            );
        }
        self.indirect_digest()
    }

    pub fn navx_digest(&self) -> Result<(Hash, &'a [u8])> {
        ensure!(
            self.content_type == INDIRECT,
            "not a NAVX Authenticode signature"
        );
        let indirect = der::fields(self.content, 2)?;
        let data = der::fields(indirect[0].expect(0x30)?, 2)?;
        ensure!(
            der::oid(data[0], &[43, 6, 1, 4, 1, 130, 55, 2, 1, 30]),
            "invalid NAVX SIP type"
        );
        let sip = der::fields(data[1].expect(0x30)?, 7)?;
        ensure!(
            sip[0].expect(2)?.body == [1],
            "unsupported NAVX SIP version"
        );
        ensure!(
            sip[1].expect(4)?.body
                == [
                    0x12, 0x34, 0x12, 0x34, 0xf8, 0x04, 0, 0, 0x78, 0x1d, 0x12, 0x34, 0x12, 0x34,
                    0x12, 0x34
                ],
            "invalid NAVX SIP UUID"
        );
        for reserved in &sip[2..] {
            ensure!(
                reserved.expect(2)?.body == [0],
                "invalid NAVX SIP reserved field"
            );
        }
        self.indirect_digest()
    }

    pub fn wsh_digest(&self, kind: crate::wsh::Kind) -> Result<(Hash, &'a [u8])> {
        ensure!(
            self.content_type == INDIRECT,
            "not a WSH Authenticode signature"
        );
        let indirect = der::fields(self.content, 2)?;
        let data = der::fields(indirect[0].expect(0x30)?, 2)?;
        ensure!(
            der::oid(data[0], &[43, 6, 1, 4, 1, 130, 55, 2, 1, 30]),
            "invalid WSH SIP type"
        );
        let sip = der::fields(data[1].expect(0x30)?, 7)?;
        ensure!(sip[0].expect(2)?.body == [1], "unsupported WSH SIP version");
        ensure!(
            sip[1].expect(4)?.body == kind.uuid(),
            "invalid WSH SIP UUID"
        );
        for reserved in &sip[2..] {
            ensure!(
                reserved.expect(2)?.body == [0],
                "invalid WSH SIP reserved field"
            );
        }
        self.indirect_digest()
    }

    #[cfg(feature = "appx")]
    pub fn appx_digest(&self) -> Result<(Hash, &'a [u8], bool)> {
        ensure!(
            self.content_type == INDIRECT,
            "not an MSIX/AppX Authenticode signature"
        );
        let indirect = der::fields(self.content, 2)?;
        let data = der::fields(indirect[0].expect(0x30)?, 2)?;
        ensure!(
            der::oid(data[0], &[43, 6, 1, 4, 1, 130, 55, 2, 1, 30]),
            "invalid MSIX/AppX SIP type"
        );
        let sip = der::fields(data[1].expect(0x30)?, 7)?;
        ensure!(
            sip[0].expect(2)?.body == [1, 1, 0, 0],
            "unsupported MSIX/AppX SIP version"
        );
        let uuid = sip[1].expect(4)?.body;
        let is_bundle = if uuid
            == [
                0x4b, 0xdf, 0xc5, 0x0a, 7, 0xce, 0xe2, 0x4d, 0xb7, 0x6e, 0x23, 0xc8, 0x39, 0xa0,
                0x9f, 0xd1,
            ] {
            false
        } else {
            ensure!(
                uuid == [
                    0xb3, 0x58, 0x5f, 0x0f, 0xde, 0xaa, 0x9a, 0x4b, 0xa4, 0x34, 0x95, 0x74, 0x2d,
                    0x92, 0xec, 0xeb,
                ],
                "unsupported MSIX/AppX SIP UUID"
            );
            true
        };
        for value in &sip[2..] {
            ensure!(
                value.expect(2)?.body == [0],
                "invalid MSIX/AppX SIP reserved field"
            );
        }
        let (hash, digest) = self.indirect_digest()?;
        if hash == Hash::Sha1 {
            return Err(VerificationError::new(
                ErrorCode::UnsupportedAlgorithm,
                Stage::PackageDigest,
                "MSIX/AppX requires SHA-256, SHA-384, or SHA-512",
            )
            .into());
        }
        let width = hash.digest(b"").len() + 4;
        ensure!(
            digest.starts_with(b"APPX") && [4 + 4 * width, 4 + 5 * width].contains(&digest.len()),
            "invalid MSIX/AppX digest bundle size"
        );
        for (i, name) in [b"AXPC", b"AXCD", b"AXCT", b"AXBM", b"AXCI"]
            .iter()
            .take((digest.len() - 4) / width)
            .enumerate()
        {
            ensure!(
                &digest[4 + i * width..8 + i * width] == *name,
                "unknown, duplicate, or reordered MSIX/AppX digest component"
            );
        }
        Ok((hash, digest, is_bundle))
    }

    pub fn package_digest(&self) -> Result<(Hash, &'a [u8])> {
        ensure!(
            self.content_type == INDIRECT,
            "not an MSI Authenticode signature"
        );
        let indirect = der::fields(self.content, 2)?;
        let data = der::fields(indirect[0].expect(0x30)?, 2)?;
        ensure!(
            der::oid(data[0], &[43, 6, 1, 4, 1, 130, 55, 2, 1, 30]),
            "invalid MSI SIP type"
        );
        let sip = der::fields(data[1].expect(0x30)?, 7)?;
        ensure!(
            matches!(sip[0].expect(2)?.body, [1] | [2]),
            "unsupported MSI SIP version"
        );
        ensure!(
            sip[1].expect(4)?.body
                == [
                    0xf1, 0x10, 0x0c, 0, 0, 0, 0, 0, 0xc0, 0, 0, 0, 0, 0, 0, 0x46
                ],
            "invalid MSI SIP UUID"
        );
        for reserved in &sip[2..] {
            ensure!(
                reserved.expect(2)?.body == [0],
                "invalid MSI SIP reserved field"
            );
        }
        self.indirect_digest()
    }

    pub fn page_hashes(&self) -> Result<Option<(Hash, &'a [u8])>> {
        let indirect = der::fields(self.content, 2)?;
        let data = indirect[0].expect(0x30)?.children()?;
        ensure!(data.len() <= 2, "invalid SpcAttributePeImageData");
        if data.len() == 1 {
            return Ok(None);
        }
        let image = data[1].expect(0x30)?.children()?;
        ensure!(image.len() == 2, "invalid SpcPeImageData");
        image[0].expect(3)?;
        let link = der::one(image[1].expect(0xa0)?.body, 0xa1);
        // A file-name link [2] carries no page hashes.
        let mut bytes = image[1].body;
        let choice = der::take(&mut bytes)?;
        ensure!(bytes.is_empty(), "invalid SpcLink");
        if choice.tag == 0xa2 || choice.tag == 0x80 {
            return Ok(None);
        }
        let moniker = der::fields(link?, 2)?;
        const CLASS: &[u8] = &[
            0xa6, 0xb5, 0x86, 0xd5, 0xb4, 0xa1, 0x24, 0x66, 0xae, 5, 0xa2, 0x17, 0xda, 0x8e, 0x60,
            0xd6,
        ];
        ensure!(
            moniker[0].expect(4)?.body == CLASS,
            "unknown SpcSerializedObject class"
        );
        let set = der::fields(der::one(moniker[1].expect(4)?.body, 0x31)?, 1)?;
        let attr = der::fields(set[0].expect(0x30)?, 2)?;
        let hash = if der::oid(attr[0], &[43, 6, 1, 4, 1, 130, 55, 2, 3, 1]) {
            Hash::Sha1
        } else if der::oid(attr[0], &[43, 6, 1, 4, 1, 130, 55, 2, 3, 2]) {
            Hash::Sha256
        } else {
            anyhow::bail!("unknown page hash algorithm");
        };
        let values = der::fields(attr[1].expect(0x31)?, 1)?;
        Ok(Some((hash, values[0].expect(4)?.body)))
    }
}

pub(crate) type Attributes<'a> = Vec<(Vec<u8>, Vec<Node<'a>>)>;
fn attributes(node: Node<'_>) -> Result<Attributes<'_>> {
    let parsed = crate::parse::Attributes::from_node(node)?;
    Ok(parsed
        .attributes()
        .iter()
        .map(|attr| {
            (
                attr.oid_bytes.to_vec(),
                attr.values().iter().map(|v| v.node).collect(),
            )
        })
        .collect())
}
pub(crate) fn attribute<'a>(attrs: &Attributes<'a>, oid: &[u8]) -> Result<Option<Node<'a>>> {
    if let Some((_, values)) = attrs.iter().find(|(o, _)| o == oid) {
        ensure!(values.len() == 1, "expected single CMS attribute value");
        Ok(Some(values[0]))
    } else {
        Ok(None)
    }
}

fn verify_signer_inner<'a, 'c>(
    certificates: &'c [Certificate],
    digest_algorithms: &[Hash],
    signer: Node<'a>,
    content: &[u8],
    content_type: Option<&[u8]>,
    allow_sha1: bool,
    allow_bare: bool,
) -> Result<Signer<'a, 'c>> {
    let si = crate::parse::signer::signer_fields(signer)?;
    let has_attributes = si.get(3).is_some_and(|n| n.tag == 0xa0);
    ensure!(
        has_attributes || allow_bare,
        "SignerInfo must contain authenticated attributes"
    );
    let fields = crate::parse::signer::signer_field_count(&si, has_attributes)?;
    ensure!(
        si[0].expect(2)?.body == [1],
        "unsupported issuer-and-serial SignerInfo version"
    );
    let sid = der::fields(si[1].expect(0x30)?, 2)?;
    ::der::asn1::UintRef::from_der(sid[1].full).map_err(crate::compat_error)?;
    let hash = algorithm(si[2])?;
    if allow_bare && !allow_sha1 && hash == Hash::Sha1 {
        return Err(VerificationError::new(
            ErrorCode::WeakAlgorithm,
            Stage::Cms,
            "SHA-1 RDP CMS requires --allow-sha1",
        )
        .into());
    }
    ensure!(
        allow_sha1 || hash != Hash::Sha1,
        "SHA-1 requires --allow-sha1"
    );
    if content_type.is_some() {
        ensure!(
            digest_algorithms.contains(&hash),
            "signer digest absent from SignedData digestAlgorithms"
        );
    }
    // Identity matching is independent of signature validity and trust policy.
    // Identical decoded DER certificates are harmless duplicates; any distinct
    // matching certificate is ambiguous, including one carrying the same key.
    let mut selected: Option<&Certificate> = None;
    let mut matching_certificates = 0usize;
    let mut ambiguous = false;
    for candidate in certificates {
        if candidate
            .tbs_certificate
            .issuer
            .to_der()
            .map_err(crate::compat_error)?
            != sid[0].full
            || candidate
                .tbs_certificate
                .serial_number
                .to_der()
                .map_err(crate::compat_error)?
                != sid[1].full
        {
            continue;
        }
        matching_certificates += 1;
        if let Some(first) = selected {
            ambiguous |= candidate != first;
        } else {
            selected = Some(candidate);
        }
    }
    if ambiguous {
        return Err(VerificationError::new(
            ErrorCode::AmbiguousSignerCertificate,
            Stage::Cms,
            "distinct certificates match the signer issuer and serial",
        )
        .detail("matching_certificates", matching_certificates)
        .into());
    }
    let cert = selected.context("signer certificate missing")?;
    let signed = if has_attributes {
        attributes(si[3].expect(0xa0)?)?
    } else {
        Vec::new()
    };
    let mut attrs_der = Vec::new();
    if has_attributes {
        let md = attribute(&signed, MESSAGE_DIGEST)?.context("missing signed messageDigest")?;
        let computed = hash.digest(content);
        if md.tag != 4 || md.body != computed {
            return Err(VerificationError::new(
                ErrorCode::ContentDigestMismatch,
                Stage::Cms,
                "CMS content digest mismatch",
            )
            .detail("expected", crate::domain::hex(md.body))
            .detail("computed", crate::domain::hex(&computed))
            .into());
        }
        if let Some(content_type) = content_type {
            ensure!(
                attribute(&signed, CONTENT_TYPE)?.is_some_and(|n| der::oid(n, content_type)),
                "signed contentType mismatch"
            );
        } else {
            ensure!(
                attribute(&signed, CONTENT_TYPE)?.is_none(),
                "countersignature must omit contentType"
            );
        }
        attrs_der = si[3].full.to_vec();
        attrs_der[0] = 0x31;
    }
    let algorithm_index = if has_attributes { 4 } else { 3 };
    let alg =
        crate::parse::cms::algorithm_fields(si[algorithm_index], "invalid signature algorithm")?;
    if alg[0].body == [42, 134, 72, 206, 61, 4, 3, 2]
        || alg[0].body == [42, 134, 72, 206, 61, 4, 3, 3]
    {
        ensure!(alg.len() == 1, "ECDSA signature parameters must be absent");
    }
    if alg.len() == 2 {
        ensure!(
            alg[1].tag == 5 && alg[1].body.is_empty(),
            "unsupported signature parameters"
        );
    }
    let signature = si[algorithm_index + 1].expect(4)?.body;
    crypto::verify_spki(
        &cert
            .tbs_certificate
            .subject_public_key_info
            .to_der()
            .map_err(crate::compat_error)?,
        hash,
        alg[0].body,
        if has_attributes { &attrs_der } else { content },
        signature,
    )?;
    let unsigned = if si.len() == fields + 1 {
        attributes(si[fields].expect(0xa1)?)?
    } else {
        Vec::new()
    };
    Ok(Signer {
        hash,
        cert,
        signature,
        unsigned,
        signed,
    })
}

pub(crate) fn verify_countersigner<'a, 'c>(
    certificates: &'c [Certificate],
    signer: Node<'a>,
    content: &[u8],
    allow_sha1: bool,
) -> Result<Signer<'a, 'c>> {
    verify_signer_inner(certificates, &[], signer, content, None, allow_sha1, false)
}

/// Explicit detached id-data CMS entry point. Authenticode stays attached and
/// requires signed attributes through SignedData::parse/verify.
pub(crate) struct DetachedData<'a> {
    pub certs: Vec<Certificate>,
    pub unverified_certificate_choices: Vec<crate::domain::UnverifiedCertificateChoice>,
    pub signers: Vec<Node<'a>>,
    digest_algorithms: Vec<Hash>,
}
impl<'a> DetachedData<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self> {
        let parsed = crate::parse::SignedData::parse_inner(bytes)?;
        ensure!(
            parsed.version.body == [1],
            "invalid detached SignedData version or fields"
        );
        let digest_algorithms = parsed
            .digest_algorithms()
            .iter()
            .map(|a| algorithm(a.node))
            .collect::<Result<Vec<_>>>()?;
        ensure!(
            !digest_algorithms.is_empty(),
            "empty detached digestAlgorithms"
        );
        ensure!(
            parsed.content_type_bytes == DATA && parsed.content.is_none(),
            "detached RDP signature must use id-data without embedded content"
        );
        ensure!(
            !parsed.signer_infos().is_empty(),
            "invalid detached signer count"
        );
        let signers = parsed
            .signer_infos()
            .iter()
            .map(|bytes| der::one(bytes, 0x30))
            .collect::<Result<_>>()?;
        let (certs, unverified_certificate_choices) = certificate_candidates(parsed);
        Ok(Self {
            certs,
            unverified_certificate_choices,
            signers,
            digest_algorithms,
        })
    }

    pub fn verify(
        &self,
        signer: Node<'a>,
        content: &[u8],
        allow_sha1: bool,
    ) -> Result<Signer<'a, '_>> {
        verify_signer_inner(
            &self.certs,
            &self.digest_algorithms,
            signer,
            content,
            Some(DATA),
            allow_sha1,
            true,
        )
    }
}

fn certificate_candidates(
    parsed: crate::parse::SignedData<'_>,
) -> (
    Vec<Certificate>,
    Vec<crate::domain::UnverifiedCertificateChoice>,
) {
    let mut certs = Vec::new();
    let mut opaque = Vec::new();
    for choice in parsed.into_certificate_choices() {
        let tag = choice.tag();
        let der = choice.as_der();
        if let Some(cert) = choice.into_x509() {
            certs.push(cert);
        } else {
            opaque.push(crate::domain::UnverifiedCertificateChoice {
                tag,
                der: crate::domain::hex(der),
            });
        }
    }
    (certs, opaque)
}

#[cfg(test)]
mod borrowing_tests {
    use super::*;

    #[test]
    fn lib08_certificate_candidates_move_decoded_storage() {
        let pe =
            crate::parse::Pe::parse(include_bytes!("../tests/fixtures/good-pe64.exe")).unwrap();
        let mut rest = pe.signatures().unwrap()[0];
        let bytes = crate::der::take(&mut rest).unwrap().full;
        let parsed = crate::parse::SignedData::parse(bytes).unwrap();
        let before: Vec<_> = parsed
            .certificate_choices()
            .iter()
            .filter_map(|c| c.x509())
            .map(|c| c.tbs_certificate.subject.0.as_ptr())
            .collect();
        let (certs, _) = certificate_candidates(parsed);
        assert!(!certs.is_empty());
        assert_eq!(
            before,
            certs
                .iter()
                .map(|c| c.tbs_certificate.subject.0.as_ptr())
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn lib08_signer_borrows_selected_certificate() {
        let bytes = include_bytes!("../tests/fixtures/good-pe64.exe");
        let pe = crate::parse::Pe::parse(bytes).unwrap();
        let signatures = pe.signatures().unwrap();
        let mut rest = signatures[0];
        let cms = crate::der::take(&mut rest).unwrap().full;
        let sd = SignedData::parse(cms).unwrap();
        let signer = sd.verify(sd.signers[0], false).unwrap();
        assert!(sd.certs.iter().any(|cert| core::ptr::eq(cert, signer.cert)));
    }
}
