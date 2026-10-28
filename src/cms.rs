use crate::domain::{ErrorCode, Stage, VerificationError};
use crate::{
    crypto::{self, Hash},
    der::{self, Node},
};
use ::der::{Decode, Encode};
use anyhow::{Context, Result, ensure};
use x509_cert::Certificate;

pub(crate) const DATA: &[u8] = &[42, 134, 72, 134, 247, 13, 1, 7, 1];
pub(crate) const SIGNED_DATA: &[u8] = &[42, 134, 72, 134, 247, 13, 1, 7, 2];
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
    pub signers: Vec<Node<'a>>,
    digest_algorithms: Vec<Hash>,
}
pub(crate) struct Signer<'a> {
    pub hash: Hash,
    pub cert: Certificate,
    pub signature: &'a [u8],
    pub unsigned: Vec<(Vec<u8>, Vec<Node<'a>>)>,
    pub signed: Vec<(Vec<u8>, Vec<Node<'a>>)>,
}

pub(crate) fn algorithm(node: Node<'_>) -> Result<Hash> {
    let fields = node.expect(0x30)?.children()?;
    ensure!(
        !fields.is_empty() && fields.len() <= 2,
        "invalid AlgorithmIdentifier"
    );
    fields[0].expect(6)?;
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
        let outer = der::fields(der::one(bytes, 0x30)?, 2)?;
        ensure!(der::oid(outer[0], SIGNED_DATA), "not PKCS#7 SignedData");
        let sd = der::one(outer[1].expect(0xa0)?.body, 0x30)?.children()?;
        ensure!(sd.len() >= 4 && sd.len() <= 6, "invalid SignedData");
        sd[0].expect(2)?;
        let digest_algorithms = sd[1]
            .expect(0x31)?
            .children()?
            .into_iter()
            .map(algorithm)
            .collect::<Result<Vec<_>>>()?;
        let ci = der::fields(sd[2].expect(0x30)?, 2)?;
        ci[0].expect(6)?;
        let mut content = der::one(
            ci[1].expect(0xa0)?.body,
            if ci[0].body == TST_INFO { 4 } else { 0x30 },
        )?;
        // RFC 5652 wraps TSTInfo in an OCTET STRING; legacy Authenticode uses ANY.
        if content.tag == 4 {
            content = der::one(content.body, 0x30)?;
        }
        let mut certs = Vec::new();
        let mut i = 3;
        if sd[i].tag == 0xa0 {
            for cert in sd[i].children()? {
                certs.push(
                    Certificate::from_der(cert.full).context("invalid embedded certificate")?,
                );
            }
            i += 1;
        }
        if i < sd.len() && sd[i].tag == 0xa1 {
            i += 1;
        } // Embedded CRLs are untrusted until path validation.
        ensure!(i + 1 == sd.len(), "invalid SignedData fields");
        let signers = sd[i].expect(0x31)?.children()?;
        ensure!(
            !signers.is_empty() && signers.len() <= 64,
            "invalid signer count"
        );
        Ok(Self {
            content,
            content_type: ci[0].body,
            certs,
            signers,
            digest_algorithms,
        })
    }

    pub fn verify(&self, signer: Node<'a>, allow_sha1: bool) -> Result<Signer<'a>> {
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
    ) -> Result<Signer<'a>> {
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
    let mut result: Attributes<'_> = Vec::new();
    let children = node.children()?;
    if node.tag == 0xa0 {
        ensure!(
            children.windows(2).all(|w| w[0].full <= w[1].full),
            "noncanonical signed attribute order"
        );
    }
    for attr in children {
        let f = der::fields(attr.expect(0x30)?, 2)?;
        f[0].expect(6)?;
        ensure!(
            !result.iter().any(|(oid, _)| oid == f[0].body),
            "duplicate CMS attribute"
        );
        let values = f[1].expect(0x31)?.children()?;
        ensure!(!values.is_empty(), "empty CMS attribute");
        result.push((f[0].body.to_vec(), values));
    }
    Ok(result)
}
pub(crate) fn attribute<'a>(attrs: &Attributes<'a>, oid: &[u8]) -> Result<Option<Node<'a>>> {
    if let Some((_, values)) = attrs.iter().find(|(o, _)| o == oid) {
        ensure!(values.len() == 1, "expected single CMS attribute value");
        Ok(Some(values[0]))
    } else {
        Ok(None)
    }
}

fn verify_signer_inner<'a>(
    certificates: &[Certificate],
    digest_algorithms: &[Hash],
    signer: Node<'a>,
    content: &[u8],
    content_type: Option<&[u8]>,
    allow_sha1: bool,
    allow_bare: bool,
) -> Result<Signer<'a>> {
    let si = signer.expect(0x30)?.children()?;
    let has_attributes = si.get(3).is_some_and(|n| n.tag == 0xa0);
    ensure!(
        has_attributes || allow_bare,
        "SignerInfo must contain authenticated attributes"
    );
    let fields = if has_attributes { 6 } else { 5 };
    ensure!(
        si.len() == fields || si.len() == fields + 1,
        "invalid SignerInfo fields"
    );
    if allow_bare {
        ensure!(
            si[0].expect(2)?.body == [1],
            "unsupported detached signer version"
        );
    }
    si[0].expect(2)?;
    let sid = der::fields(si[1].expect(0x30)?, 2)?;
    sid[1].expect(2)?;
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
    let cert = certificates
        .iter()
        .find(|cert| {
            cert.tbs_certificate.issuer.to_der().ok().as_deref() == Some(sid[0].full)
                && cert.tbs_certificate.serial_number.to_der().ok().as_deref() == Some(sid[1].full)
        })
        .context("signer certificate missing")?
        .clone();
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
    let alg = si[algorithm_index].expect(0x30)?.children()?;
    ensure!(
        !alg.is_empty() && alg.len() <= 2,
        "invalid signature algorithm"
    );
    alg[0].expect(6)?;
    if alg.len() == 2 {
        ensure!(
            alg[1].tag == 5 && alg[1].body.is_empty(),
            "unsupported signature parameters"
        );
    }
    let signature = si[algorithm_index + 1].expect(4)?.body;
    crypto::verify_spki(
        &cert.tbs_certificate.subject_public_key_info.to_der()?,
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

pub(crate) fn verify_countersigner<'a>(
    certificates: &[Certificate],
    signer: Node<'a>,
    content: &[u8],
    allow_sha1: bool,
) -> Result<Signer<'a>> {
    verify_signer_inner(certificates, &[], signer, content, None, allow_sha1, false)
}

/// Explicit detached id-data CMS entry point. Authenticode stays attached and
/// requires signed attributes through SignedData::parse/verify.
pub(crate) struct DetachedData<'a> {
    pub certs: Vec<Certificate>,
    pub signers: Vec<Node<'a>>,
    digest_algorithms: Vec<Hash>,
}
impl<'a> DetachedData<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self> {
        let outer = der::fields(der::one(bytes, 0x30)?, 2)?;
        ensure!(der::oid(outer[0], SIGNED_DATA), "not PKCS#7 SignedData");
        let sd = der::one(outer[1].expect(0xa0)?.body, 0x30)?.children()?;
        ensure!(
            (4..=6).contains(&sd.len()) && sd[0].expect(2)?.body == [1],
            "invalid detached SignedData version or fields"
        );
        let digest_algorithms = sd[1]
            .expect(0x31)?
            .children()?
            .into_iter()
            .map(algorithm)
            .collect::<Result<Vec<_>>>()?;
        ensure!(
            !digest_algorithms.is_empty(),
            "empty detached digestAlgorithms"
        );
        let ci = der::fields(sd[2].expect(0x30)?, 1)?;
        ensure!(
            der::oid(ci[0], DATA),
            "detached RDP signature must use id-data without embedded content"
        );
        let mut i = 3;
        let mut certs = Vec::new();
        if sd[i].tag == 0xa0 {
            for node in sd[i].children()? {
                certs.push(
                    Certificate::from_der(node.full).context("invalid embedded certificate")?,
                );
            }
            i += 1;
        }
        // Local configured CRLs alone supply revocation validation.
        if i < sd.len() && sd[i].tag == 0xa1 {
            i += 1;
        }
        ensure!(i + 1 == sd.len(), "invalid detached SignedData fields");
        let signers = sd[i].expect(0x31)?.children()?;
        ensure!(
            !signers.is_empty() && signers.len() <= 64,
            "invalid detached signer count"
        );
        Ok(Self {
            certs,
            signers,
            digest_algorithms,
        })
    }
    pub fn verify(&self, signer: Node<'a>, content: &[u8], allow_sha1: bool) -> Result<Signer<'a>> {
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
