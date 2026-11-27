//! Convert decoded certificate/CRL metadata into the public JSON domain.
use crate::{crypto::Hash, domain::*};
use ::der::{Decode, Encode, Tagged};
use alloc::{
    borrow::ToOwned,
    format,
    string::{String, ToString},
    vec,
    vec::Vec,
};
use x509_cert::{Certificate, crl::CertificateList, name::Name};

impl DistinguishedName {
    pub(crate) fn parse(name: &Name) -> Self {
        let mut result = Self {
            display: name.to_string(),
            common_names: vec![],
            organizations: vec![],
            organizational_units: vec![],
            countries: vec![],
            rdns: vec![],
        };
        for rdn in &name.0 {
            let mut attributes = Vec::new();
            for atv in rdn.0.iter() {
                let oid = atv.oid.to_string();
                let raw = atv.value.value();
                let tag = atv.value.tag();
                let value = match tag {
                    ::der::Tag::Utf8String
                    | ::der::Tag::PrintableString
                    | ::der::Tag::Ia5String
                    | ::der::Tag::VisibleString
                    | ::der::Tag::NumericString => {
                        core::str::from_utf8(raw).ok().map(str::to_owned)
                    }
                    ::der::Tag::BmpString if raw.len() % 2 == 0 => String::from_utf16(
                        &raw.as_chunks::<2>()
                            .0
                            .iter()
                            .map(|b| u16::from_be_bytes(*b))
                            .collect::<Vec<_>>(),
                    )
                    .ok(),
                    _ => None, // Preserve unfamiliar encodings instead of guessing or losing bytes.
                };
                if let Some(value) = &value {
                    match oid.as_str() {
                        "2.5.4.3" => result.common_names.push(value.clone()),
                        "2.5.4.10" => result.organizations.push(value.clone()),
                        "2.5.4.11" => result.organizational_units.push(value.clone()),
                        "2.5.4.6" => result.countries.push(value.clone()),
                        _ => {}
                    }
                }
                let short = match oid.as_str() {
                    "2.5.4.3" => Some("CN"),
                    "2.5.4.10" => Some("O"),
                    "2.5.4.11" => Some("OU"),
                    "2.5.4.6" => Some("C"),
                    "2.5.4.7" => Some("L"),
                    "2.5.4.8" => Some("ST"),
                    "1.2.840.113549.1.9.1" => Some("emailAddress"),
                    _ => None,
                };
                attributes.push(NameAttribute {
                    oid,
                    name: short.map(str::to_owned),
                    value,
                    asn1_tag: format!("{tag:?}"),
                    raw_value_hex: hex(raw),
                });
            }
            result.rdns.push(attributes);
        }
        result
    }
}

impl OidReport {
    pub(crate) fn new(oid: impl ToString) -> Self {
        let oid = oid.to_string();
        let name = match oid.as_str() {
            "1.3.6.1.5.5.7.3.1" => Some("server_auth"),
            "1.3.6.1.5.5.7.3.2" => Some("client_auth"),
            "1.3.6.1.5.5.7.3.3" => Some("code_signing"),
            "1.3.6.1.5.5.7.3.8" => Some("time_stamping"),
            "2.5.29.37.0" => Some("any_extended_key_usage"),
            "1.2.840.113549.1.1.1" => Some("rsa_encryption"),
            "1.2.840.113549.1.1.11" => Some("sha256_with_rsa"),
            "1.2.840.113549.1.1.12" => Some("sha384_with_rsa"),
            "1.2.840.113549.1.1.13" => Some("sha512_with_rsa"),
            "1.2.840.10045.2.1" => Some("ec_public_key"),
            "1.2.840.10045.4.3.2" => Some("ecdsa_sha256"),
            "1.2.840.10045.4.3.3" => Some("ecdsa_sha384"),
            _ => None,
        }
        .map(str::to_owned);
        Self { oid, name }
    }
}
/// The extension `T` of `tbs` for the report: its criticality and value, or
/// `None` when it is absent or cannot be decoded, which `undecoded` then
/// records. A repeat is recorded as one whatever its values, as PATH-014
/// names it first.
fn decoded<T>(
    tbs: &x509_cert::TbsCertificate,
    undecoded: &mut Vec<UndecodedExtension>,
) -> Option<(bool, T)>
where
    T: for<'a> Decode<'a> + ::der::oid::AssociatedOid,
{
    let mut instances = tbs
        .extensions
        .iter()
        .flatten()
        .filter(|e| e.extn_id == T::OID);
    let first = instances.next()?;
    let reason = if instances.next().is_some() {
        UndecodedReason::RepeatedExtension
    } else {
        match T::from_der(first.extn_value.as_bytes()) {
            Ok(value) => return Some((first.critical, value)),
            Err(_) => UndecodedReason::MalformedExtension,
        }
    };
    undecoded.push(UndecodedExtension {
        oid: T::OID.to_string(),
        reason,
    });
    None
}

impl CertificateReport {
    /// The report of `cert`. It reports and does not judge, as OpenSSL
    /// decodes a certificate's extensions only when it validates a path
    /// (PATH-013): an extension it cannot decode is listed in
    /// `undecoded_extensions`, never an error.
    pub(crate) fn parse(cert: &Certificate) -> anyhow::Result<Self> {
        use x509_cert::ext::pkix::{BasicConstraints, ExtendedKeyUsage, KeyUsage};
        let tbs = &cert.tbs_certificate;
        let der = cert.to_der().map_err(crate::compat_error)?;
        let mut undecoded_extensions = Vec::new();
        let basic_constraints =
            decoded::<BasicConstraints>(tbs, &mut undecoded_extensions).map(|(critical, bc)| {
                BasicConstraintsReport {
                    critical,
                    ca: bc.ca,
                    path_length: bc.path_len_constraint,
                }
            });
        let key_usage =
            decoded::<KeyUsage>(tbs, &mut undecoded_extensions).map(|(critical, ku)| {
                let values = [
                    ("digital_signature", ku.digital_signature()),
                    ("content_commitment", ku.non_repudiation()),
                    ("key_encipherment", ku.key_encipherment()),
                    ("data_encipherment", ku.data_encipherment()),
                    ("key_agreement", ku.key_agreement()),
                    ("key_cert_sign", ku.key_cert_sign()),
                    ("crl_sign", ku.crl_sign()),
                    ("encipher_only", ku.encipher_only()),
                    ("decipher_only", ku.decipher_only()),
                ];
                KeyUsageReport {
                    critical,
                    usages: values
                        .into_iter()
                        .filter(|(_, enabled)| *enabled)
                        .map(|(name, _)| name.to_owned())
                        .collect(),
                }
            });
        let extended_key_usage =
            decoded::<ExtendedKeyUsage>(tbs, &mut undecoded_extensions).map(|(critical, eku)| {
                EkuReport {
                    critical,
                    usages: eku.0.iter().map(OidReport::new).collect(),
                }
            });
        Ok(Self {
            sha256: hex(&Hash::Sha256.digest(&der)),
            der_hex: hex(&der),
            serial_number: hex(tbs.serial_number.as_bytes()),
            version: tbs.version as u8 + 1,
            subject: DistinguishedName::parse(&tbs.subject),
            issuer: DistinguishedName::parse(&tbs.issuer),
            not_before: tbs.validity.not_before.to_unix_duration().as_secs(),
            not_after: tbs.validity.not_after.to_unix_duration().as_secs(),
            public_key_algorithm: OidReport::new(tbs.subject_public_key_info.algorithm.oid),
            signature_algorithm: OidReport::new(cert.signature_algorithm.oid),
            extended_key_usage,
            key_usage,
            basic_constraints,
            undecoded_extensions,
            extensions: extensions(tbs.extensions.as_deref().unwrap_or_default()),
        })
    }
}
fn extensions(ext: &[x509_cert::ext::Extension]) -> Vec<ExtensionReport> {
    ext.iter()
        .map(|e| ExtensionReport {
            oid: e.extn_id.to_string(),
            critical: e.critical,
            value_der_hex: hex(e.extn_value.as_bytes()),
        })
        .collect()
}

impl CrlReport {
    pub(crate) fn parse(bytes: &[u8]) -> anyhow::Result<Self> {
        let crl = CertificateList::from_der(bytes).map_err(crate::compat_error)?;
        let tbs = crl.tbs_cert_list;
        Ok(Self {
            sha256: hex(&Hash::Sha256.digest(bytes)),
            der_hex: hex(bytes),
            issuer: DistinguishedName::parse(&tbs.issuer),
            this_update: tbs.this_update.to_unix_duration().as_secs(),
            next_update: tbs.next_update.map(|t| t.to_unix_duration().as_secs()),
            signature_algorithm: OidReport::new(crl.signature_algorithm.oid),
            role: "supplied".into(),
            revoked_certificates: tbs
                .revoked_certificates
                .unwrap_or_default()
                .iter()
                .map(|r| RevokedCertificateReport {
                    serial_number: hex(r.serial_number.as_bytes()),
                    revocation_time: r.revocation_date.to_unix_duration().as_secs(),
                    extensions: extensions(r.crl_entry_extensions.as_deref().unwrap_or_default()),
                })
                .collect(),
            extensions: extensions(tbs.crl_extensions.as_deref().unwrap_or_default()),
        })
    }
}
