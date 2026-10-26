use crate::domain::{ErrorCode, Stage, VerificationError};
use crate::{
    crypto::{self, Hash},
    der::{self, Node},
};
use ::der::{Decode, Encode};
use anyhow::{Context, Result, ensure};
use x509_cert::Certificate;

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
        let si = signer.expect(0x30)?.children()?;
        ensure!(
            si.len() == 6 || si.len() == 7,
            "SignerInfo must contain authenticated attributes"
        );
        si[0].expect(2)?;
        let sid = der::fields(si[1].expect(0x30)?, 2)?;
        sid[1].expect(2)?;
        let hash = algorithm(si[2])?;
        ensure!(
            allow_sha1 || hash != Hash::Sha1,
            "SHA-1 requires --allow-sha1"
        );
        if content_type.is_some() {
            ensure!(
                self.digest_algorithms.contains(&hash),
                "signer digest absent from SignedData digestAlgorithms"
            );
        }
        let cert = self
            .certs
            .iter()
            .find(|cert| {
                cert.tbs_certificate.issuer.to_der().ok().as_deref() == Some(sid[0].full)
                    && cert.tbs_certificate.serial_number.to_der().ok().as_deref()
                        == Some(sid[1].full)
            })
            .context("signer certificate missing")?
            .clone();
        let signed = attributes(si[3].expect(0xa0)?)?;
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
        let alg = si[4].expect(0x30)?.children()?;
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
        let signature = si[5].expect(4)?.body;
        let mut attrs_der = si[3].full.to_vec();
        attrs_der[0] = 0x31; // Signature is over the DER SET OF, not its implicit [0] tag.
        crypto::verify_spki(
            &cert.tbs_certificate.subject_public_key_info.to_der()?,
            hash,
            alg[0].body,
            &attrs_der,
            signature,
        )?;
        let unsigned = if si.len() == 7 {
            attributes(si[6].expect(0xa1)?)?
        } else {
            Vec::new()
        };
        Ok(Signer {
            cert,
            signature,
            unsigned,
            signed,
        })
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
    fn indirect_digest(&self) -> Result<(Hash, &'a [u8])> {
        let indirect = der::fields(self.content, 2)?;
        let digest = der::fields(indirect[1].expect(0x30)?, 2)?;
        Ok((algorithm(digest[0])?, digest[1].expect(4)?.body))
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
