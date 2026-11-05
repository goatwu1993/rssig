//! Bounded structural inspection. Every assertion here remains unauthenticated.
use super::{AlgorithmIdentifier, Error, ErrorKind, SignedData, SignerInfo, error::DecodeError};
use crate::der::{self, Node};
use ::der::{
    Decode,
    asn1::{ObjectIdentifier, UintRef},
};
use alloc::{string::ToString, vec, vec::Vec};
use anyhow::{Result, ensure};

const NESTED: &[u8] = &[43, 6, 1, 4, 1, 130, 55, 2, 4, 1];
const RFC3161: &[u8] = &[43, 6, 1, 4, 1, 130, 55, 3, 3, 1];
const CMS_TIMESTAMP: &[u8] = &[42, 134, 72, 134, 247, 13, 1, 9, 16, 2, 14];
const COUNTERSIGN: &[u8] = &[42, 134, 72, 134, 247, 13, 1, 9, 6];
const SIGNING_TIME: &[u8] = &[42, 134, 72, 134, 247, 13, 1, 9, 5];
const TST_INFO: &str = "1.2.840.113549.1.9.16.1.4";

/// Shared limits across nested CMS, timestamp tokens, countersigners, and siblings.
#[derive(Clone, Copy, Debug)]
pub struct InspectionLimits {
    /// Root depth is zero. Values above eight are clamped to eight.
    pub max_depth: usize,
    pub max_objects: usize,
    /// Cumulative input bytes, including repeated inspection of nested encodings.
    pub max_bytes: usize,
    /// Cumulative DER nodes visited during framing preflight.
    pub max_der_nodes: usize,
}
impl Default for InspectionLimits {
    fn default() -> Self {
        Self {
            max_depth: 8,
            max_objects: 64,
            max_bytes: 16 * 1024 * 1024,
            max_der_nodes: 65536,
        }
    }
}

/// Consumable work budget. Reuse across top-level signatures to bound total work.
/// Failed calls retain their charges; a depleted budget never resets itself.
#[derive(Debug, Default)]
pub struct InspectionBudget {
    limits: InspectionLimits,
    objects: usize,
    bytes: usize,
    nodes: usize,
}
impl InspectionBudget {
    pub fn new(limits: InspectionLimits) -> Self {
        Self {
            limits,
            objects: 0,
            bytes: 0,
            nodes: 0,
        }
    }
    fn charge(&mut self, bytes: &[u8], depth: usize) -> Result<()> {
        limit(depth <= self.limits.max_depth.min(8))?;
        limit(self.objects < self.limits.max_objects)?;
        self.objects += 1;
        limit(bytes.len() <= self.limits.max_bytes.saturating_sub(self.bytes))?;
        self.bytes += bytes.len();
        self.scan(der::take(&mut &*bytes)?, 0)
    }
    fn scan(&mut self, node: Node<'_>, depth: usize) -> Result<()> {
        limit(depth <= 96 && self.nodes < self.limits.max_der_nodes)?;
        self.nodes += 1;
        if node.tag & 0x20 != 0 {
            let mut rest = node.body;
            while !rest.is_empty() {
                self.scan(der::take(&mut rest)?, depth + 1)?;
            }
        }
        Ok(())
    }
}
fn limit(ok: bool) -> Result<()> {
    if !ok {
        return Err(Error::new(
            ErrorKind::InspectionLimit,
            anyhow::anyhow!("CMS inspection work/depth limit exceeded"),
        )
        .into());
    }
    Ok(())
}

/// A decoded time assertion, never a verified signing time.
#[derive(Debug)]
pub struct ParsedTime<'a> {
    node: Node<'a>,
    seconds: u64,
    fraction: Option<&'a str>,
}
impl<'a> ParsedTime<'a> {
    pub fn parse(bytes: &'a [u8]) -> core::result::Result<Self, Error> {
        let result = (|| {
            let mut rest = bytes;
            let node = der::take(&mut rest)?;
            ensure!(rest.is_empty(), "trailing time DER");
            Self::from_node(node)
        })();
        result.map_err(|e| Error::new(ErrorKind::MalformedCms, e))
    }
    fn from_node(node: Node<'a>) -> Result<Self> {
        let mut fraction = None;
        let seconds = match node.tag {
            0x17 => ::der::asn1::UtcTime::from_der(node.full)
                .map_err(DecodeError)?
                .to_unix_duration()
                .as_secs(),
            0x18 if node.body.len() > 15 => {
                let b = node.body;
                ensure!(
                    b.len() <= 80 && b[14] == b'.' && b.last() == Some(&b'Z'),
                    "noncanonical fractional GeneralizedTime"
                );
                let f = &b[15..b.len() - 1];
                ensure!(
                    !f.is_empty() && f.iter().all(u8::is_ascii_digit) && f.last() != Some(&b'0'),
                    "noncanonical fractional GeneralizedTime"
                );
                fraction = Some(core::str::from_utf8(f)?);
                let mut whole = vec![0x18, 15];
                whole.extend_from_slice(&b[..14]);
                whole.push(b'Z');
                ::der::asn1::GeneralizedTime::from_der(&whole)
                    .map_err(DecodeError)?
                    .to_unix_duration()
                    .as_secs()
            }
            0x18 => ::der::asn1::GeneralizedTime::from_der(node.full)
                .map_err(DecodeError)?
                .to_unix_duration()
                .as_secs(),
            _ => anyhow::bail!("invalid timestamp time encoding"),
        };
        Ok(Self {
            node,
            seconds,
            fraction,
        })
    }
    pub fn as_der(&self) -> &'a [u8] {
        self.node.full
    }
    pub fn unix_seconds(&self) -> u64 {
        self.seconds
    }
    pub fn fractional_seconds(&self) -> Option<&'a str> {
        self.fraction
    }
}

/// RFC3161 TSTInfo fields. Unknown policy/algorithms are preserved without policy checks.
#[derive(Debug)]
pub struct TstInfo<'a> {
    der: &'a [u8],
    pub version_der: &'a [u8],
    pub policy: ObjectIdentifier,
    pub imprint_algorithm: AlgorithmIdentifier<'a>,
    pub imprint: &'a [u8],
    pub serial_number_der: &'a [u8],
    pub parsed_time: ParsedTime<'a>,
    /// Optional fields retained as DER; their semantics are not interpreted.
    pub optional_fields: Vec<&'a [u8]>,
}
impl<'a> TstInfo<'a> {
    pub fn parse(bytes: &'a [u8]) -> core::result::Result<Self, Error> {
        Self::inner(bytes).map_err(|e| Error::new(ErrorKind::MalformedCms, e))
    }
    fn inner(bytes: &'a [u8]) -> Result<Self> {
        let f = der::one(bytes, 0x30)?.children()?;
        ensure!(f.len() >= 5, "truncated TSTInfo");
        UintRef::from_der(f[0].full).map_err(DecodeError)?;
        let policy = ObjectIdentifier::from_der(f[1].full).map_err(DecodeError)?;
        let imprint = der::fields(f[2].expect(0x30)?, 2)?;
        UintRef::from_der(f[3].full).map_err(DecodeError)?;
        f[4].expect(0x18)?;
        // Optional RFC3161 fields must retain their prescribed order and unique tags.
        let mut last = 0;
        for n in &f[5..] {
            let rank = match n.tag {
                0x30 => 1,
                1 => 2,
                2 => 3,
                0xa0 => 4,
                0xa1 => 5,
                _ => anyhow::bail!("invalid TSTInfo optional field"),
            };
            ensure!(rank > last, "invalid TSTInfo optional field order");
            last = rank;
            match n.tag {
                1 => {
                    ensure!(n.body == [255], "noncanonical TSTInfo ordering");
                }
                2 => {
                    UintRef::from_der(n.full).map_err(DecodeError)?;
                }
                _ => {
                    n.children()?;
                }
            }
        }
        Ok(Self {
            der: bytes,
            version_der: f[0].full,
            policy,
            imprint_algorithm: AlgorithmIdentifier::from_node(imprint[0])?,
            imprint: imprint[1].expect(4)?.body,
            serial_number_der: f[3].full,
            parsed_time: ParsedTime::from_node(f[4])?,
            optional_fields: f[5..].iter().map(|n| n.full).collect(),
        })
    }
    pub fn as_der(&self) -> &'a [u8] {
        self.der
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InspectionKind {
    Nested,
    Rfc3161,
    Pkcs9Countersignature,
}

/// A recognized unsigned attribute value, retaining the original encoding.
#[derive(Debug)]
pub struct InspectedChild<'a> {
    pub kind: InspectionKind,
    pub value_der: &'a [u8],
    pub cms: Option<InspectedCms<'a>>,
    pub countersigner: Option<InspectedSigner<'a>>,
    pub parsed_time: Option<ParsedTime<'a>>,
}
#[derive(Debug)]
pub struct InspectedSigner<'a> {
    pub signer: SignerInfo<'a>,
    pub children: Vec<InspectedChild<'a>>,
}
#[derive(Debug)]
pub struct InspectedCms<'a> {
    pub signed_data: SignedData<'a>,
    pub signers: Vec<InspectedSigner<'a>>,
    pub tst_info: Option<TstInfo<'a>>,
}

impl<'a> SignedData<'a> {
    /// Recursively inspect known unsigned attributes with one consumable budget.
    /// Unknown attributes remain opaque in the signer views. No hashes, signatures,
    /// imprint bindings, certificates, time policy, or trust are verified.
    pub fn inspect(
        bytes: &'a [u8],
        budget: &mut InspectionBudget,
    ) -> core::result::Result<InspectedCms<'a>, Error> {
        inspect_cms(bytes, budget, 0).map_err(|e| Error::new(ErrorKind::MalformedCms, e))
    }
}
fn inspect_cms<'a>(
    bytes: &'a [u8],
    budget: &mut InspectionBudget,
    depth: usize,
) -> Result<InspectedCms<'a>> {
    budget.charge(bytes, depth)?;
    let signed_data = SignedData::parse(bytes)?;
    let tst_info = if signed_data.content_type().to_string() == TST_INFO {
        let content = signed_data
            .content()
            .ok_or_else(|| anyhow::anyhow!("detached TSTInfo"))?;
        ensure!(content.tag() == 4, "invalid TSTInfo content wrapper");
        budget.charge(content.value(), depth)?;
        Some(TstInfo::parse(content.value())?)
    } else {
        None
    };
    let mut signers = Vec::new();
    for raw in signed_data.signer_infos() {
        signers.push(inspect_signer(raw, budget, depth)?);
    }
    Ok(InspectedCms {
        signed_data,
        signers,
        tst_info,
    })
}
fn inspect_signer<'a>(
    bytes: &'a [u8],
    budget: &mut InspectionBudget,
    depth: usize,
) -> Result<InspectedSigner<'a>> {
    budget.charge(bytes, depth)?;
    let signer = SignerInfo::parse(bytes)?;
    let mut children = Vec::new();
    if let Some(attrs) = signer.unsigned_attributes() {
        for attr in attrs.attributes() {
            let kind = match attr.oid_bytes() {
                NESTED => InspectionKind::Nested,
                RFC3161 | CMS_TIMESTAMP => InspectionKind::Rfc3161,
                COUNTERSIGN => InspectionKind::Pkcs9Countersignature,
                _ => continue,
            };
            for value in attr.values() {
                let (cms, countersigner, parsed_time) = if kind
                    == InspectionKind::Pkcs9Countersignature
                {
                    let counter = inspect_signer(value.as_der(), budget, depth + 1)?;
                    let mut time = None;
                    if let Some(attrs) = counter.signer.signed_attributes() {
                        for attr in attrs.attributes() {
                            if attr.oid_bytes() == SIGNING_TIME {
                                ensure!(attr.values().len() == 1, "multiple signingTime values");
                                time = Some(ParsedTime::parse(attr.values()[0].as_der())?);
                            }
                        }
                    }
                    (None, Some(counter), time)
                } else {
                    let cms = inspect_cms(value.as_der(), budget, depth + 1)?;
                    let time = if kind == InspectionKind::Rfc3161 {
                        let info = cms
                            .tst_info
                            .as_ref()
                            .ok_or_else(|| anyhow::anyhow!("timestamp token lacks TSTInfo"))?;
                        Some(ParsedTime::parse(info.parsed_time.as_der())?)
                    } else {
                        None
                    };
                    (Some(cms), None, time)
                };
                children.push(InspectedChild {
                    kind,
                    value_der: value.as_der(),
                    cms,
                    countersigner,
                    parsed_time,
                });
            }
        }
    }
    Ok(InspectedSigner { signer, children })
}
