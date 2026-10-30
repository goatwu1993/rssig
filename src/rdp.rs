//! RDP signs selected settings, not the whole text file. No client is launched.
use crate::{
    cms::{self, DetachedData},
    crypto::Hash,
    domain::*,
    verify::{VerifyOptions, verify_timestamp},
};
use anyhow::{Context, Result, ensure};
use base64ct::{Base64, Encoding};
use std::{collections::BTreeSet, path::Path};

const MAX_FILE: usize = 16 * 1024 * 1024;
const MAX_SETTINGS: usize = 4096;

pub(crate) struct Rdp {
    pub signature: Vec<u8>,
    pub canonical: Vec<u8>,
    pub coverage: RdpCoverage,
}

pub(crate) fn has_extension(path: &Path) -> bool {
    path.extension()
        .and_then(|v| v.to_str())
        .is_some_and(|v| v.eq_ignore_ascii_case("rdp"))
}
pub(crate) fn looks_like(bytes: &[u8]) -> bool {
    ["signscope:s:", "signature:s:"].iter().any(|marker| {
        let le: Vec<_> = marker.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let be: Vec<_> = marker.encode_utf16().flat_map(u16::to_be_bytes).collect();
        [marker.as_bytes(), &le, &be]
            .iter()
            .any(|s| bytes.windows(s.len()).any(|w| w == *s))
    })
}
fn decode(bytes: &[u8]) -> Result<String> {
    ensure!(bytes.len() <= MAX_FILE, "RDP file exceeds 16 MiB limit");
    let text = if bytes.starts_with(&[255, 254]) || bytes.starts_with(&[254, 255]) {
        ensure!(bytes.len().is_multiple_of(2), "odd-length UTF-16 RDP file");
        let units: Vec<_> = bytes
            .as_chunks::<2>()
            .0
            .iter()
            .map(|b| {
                if bytes[0] == 255 {
                    u16::from_le_bytes(*b)
                } else {
                    u16::from_be_bytes(*b)
                }
            })
            .collect();
        String::from_utf16(&units)?
    } else {
        std::str::from_utf8(bytes)?.to_owned()
    };
    let text = text.strip_prefix('\u{feff}').unwrap_or(&text);
    ensure!(!text.contains('\0'), "NUL or unsupported RDP encoding");
    Ok(text.to_owned())
}
impl Rdp {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let text = decode(bytes)?;
        let normalized = text.replace("\r\n", "\n");
        ensure!(!normalized.contains('\r'), "lone CR in RDP text");
        let mut keys = BTreeSet::new();
        let mut settings = Vec::new();
        let mut scope = None;
        let mut signature = None;
        for line in normalized
            .strip_suffix('\n')
            .unwrap_or(&normalized)
            .split('\n')
        {
            ensure!(
                !line.is_empty() && line.trim() == line,
                "blank or padded RDP line"
            );
            let mut parts = line.splitn(3, ':');
            let name = parts.next().unwrap();
            let kind = parts.next().context("missing RDP value type")?;
            let value = parts.next().context("missing RDP setting value")?;
            ensure!(
                !name.is_empty()
                    && name.trim() == name
                    && name.bytes().all(|c| c.is_ascii_alphanumeric() || c == b' '),
                "invalid RDP setting name"
            );
            let key = name.to_ascii_lowercase();
            ensure!(keys.insert(key.clone()), "duplicate RDP setting: {name}");
            ensure!(keys.len() <= MAX_SETTINGS, "too many RDP settings");
            ensure!(name == key, "noncanonical RDP setting name casing");
            ensure!(
                !value.chars().any(char::is_control),
                "control character in RDP setting"
            );
            let value_type = match kind {
                "s" => RdpValueType::String,
                "i" => {
                    value.parse::<i32>().context("invalid RDP integer")?;
                    RdpValueType::Integer
                }
                "b" => {
                    ensure!(
                        value.len().is_multiple_of(2)
                            && value.bytes().all(|c| c.is_ascii_hexdigit()),
                        "invalid binary RDP setting"
                    );
                    RdpValueType::Binary
                }
                _ => anyhow::bail!("unsupported RDP value type"),
            };
            if key == "signscope" || key == "signature" {
                ensure!(kind == "s", "RDP signature metadata must have string type");
                if key == "signscope" {
                    scope = Some(value);
                } else {
                    signature = Some(value);
                }
            } else {
                settings.push((
                    RdpSetting {
                        name: key,
                        value_type,
                        value: value.into(),
                    },
                    line,
                ));
            }
        }
        let Some(encoded) = signature else {
            ensure!(scope.is_none(), "RDP scope without signature");
            return Err(VerificationError::new(
                ErrorCode::Unsigned,
                Stage::Rdp,
                "RDP file has no signature",
            )
            .into());
        };
        let scope = scope.context("RDP signature without signscope")?;
        ensure!(!scope.is_empty(), "empty RDP signature scope");
        let mut used = BTreeSet::new();
        let mut names = Vec::new();
        let mut signed_settings = Vec::new();
        let mut canonical = String::new();
        for name in scope.split(',') {
            ensure!(used.insert(name.to_owned()), "duplicate RDP scope entry");
            let (_, key, kind) = SCOPES.iter().find(|(n, _, _)| *n == name).ok_or_else(|| {
                VerificationError::new(
                    ErrorCode::UnsupportedRdpScope,
                    Stage::Rdp,
                    "unsupported RDP signature scope entry",
                )
                .detail("scope", name)
            })?;
            let (setting, line) = settings
                .iter()
                .find(|(s, _)| s.name == *key)
                .with_context(|| format!("missing RDP scoped setting: {name}"))?;
            let actual = match setting.value_type {
                RdpValueType::String => "s",
                RdpValueType::Integer => "i",
                RdpValueType::Binary => "b",
            };
            ensure!(
                actual == *kind,
                "RDP scoped setting has incorrect type: {name}"
            );
            names.push(name.to_owned());
            signed_settings.push(setting.clone());
            canonical.push_str(line);
            canonical.push_str("\r\n");
        }
        ensure!(
            signed_settings
                .iter()
                .any(|s| s.name == "full address" && !s.value.is_empty()),
            "RDP scope must include a nonempty Full Address"
        );
        canonical.push_str("signscope:s:");
        canonical.push_str(scope);
        canonical.push_str("\r\n\0");
        let canonical: Vec<_> = canonical
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        let unsigned_settings = settings
            .into_iter()
            .filter(|(s, _)| !signed_settings.iter().any(|v| v.name == s.name))
            .map(|(s, _)| s)
            .collect();
        let blob = Base64::decode_vec(encoded)
            .map_err(|e| anyhow::anyhow!("invalid RDP signature base64: {e}"))?;
        ensure!(blob.len() >= 12, "truncated RDP signature header");
        ensure!(
            blob[..8] == [1, 0, 1, 0, 1, 0, 0, 0],
            "unsupported RDP signature header"
        );
        let len = u32::from_le_bytes(blob[8..12].try_into()?) as usize;
        ensure!(
            len > 0 && len == blob.len() - 12,
            "RDP signature length mismatch or trailing data"
        );
        let signature = blob[12..].to_vec();
        let coverage = RdpCoverage {
            full_file_signed: false,
            signscope: names,
            signed_settings,
            unsigned_settings,
            canonical_sha256: hex(&Hash::Sha256.digest(&canonical)),
        };
        Ok(Self {
            signature,
            canonical,
            coverage,
        })
    }
}
fn at<T>(result: Result<T>, code: ErrorCode, stage: Stage) -> Result<T> {
    result.map_err(|e| VerificationError::from_internal(e, code, stage).into())
}
pub(crate) fn verify(bytes: &[u8], options: &VerifyOptions<'_>) -> Result<VerificationBundle> {
    let rdp = at(Rdp::parse(bytes), ErrorCode::InvalidRdp, Stage::Rdp)?;
    let sd = at(
        DetachedData::parse(&rdp.signature),
        ErrorCode::MalformedCms,
        Stage::Cms,
    )?;
    let mut signatures = Vec::new();
    for si in &sd.signers {
        let signer = at(
            sd.verify(*si, &rdp.canonical, options.allow_sha1),
            ErrorCode::InvalidSignature,
            Stage::Cms,
        )?;
        if signer.unsigned.iter().any(|(id, _)| id == cms::NESTED) {
            return Err(VerificationError::new(
                ErrorCode::MalformedCms,
                Stage::Cms,
                "nested RDP signatures are unsupported",
            )
            .into());
        }
        let timestamp_verification = at(
            verify_timestamp(&sd.certs, &signer, options),
            ErrorCode::InvalidTimestamp,
            Stage::Timestamp,
        )?;
        let timestamp = timestamp_verification.as_ref().map(|t| t.signing_time);
        let trust = if let Some(store) = options.trust {
            Some(at(
                verify_trust(
                    store,
                    &signer.cert,
                    &sd.certs,
                    timestamp.unwrap_or(options.now),
                    options,
                ),
                ErrorCode::CertificateChainInvalid,
                Stage::CertificateChain,
            )?)
        } else {
            None
        };
        let certificate = CertificateReport::parse(&signer.cert)?;
        if let Some(timestamp) = &timestamp_verification {
            crate::verify::check_fractional_validity(
                trust.as_ref(),
                timestamp.signing_time,
                timestamp.fractional_seconds.as_deref(),
            )?;
        }
        signatures.push(SignatureReport {
            unverified_certificate_choices: sd.unverified_certificate_choices.clone(),
            subject: certificate.subject.display.clone(),
            digest_algorithm: format!("{:?}", signer.hash),
            certificate_sha256: certificate.sha256.clone(),
            timestamp,
            chain_trusted: options.trust.is_some(),
            revocation_checked: options.trust.is_some() && options.check_revocation,
            nested_depth: 0,
            certificate,
            embedded_certificates: sd
                .certs
                .iter()
                .map(CertificateReport::parse)
                .collect::<Result<_>>()?,
            image_digest: None,
            package_digest: None,
            script_digest: None,
            extended_digest: None,
            page_hashes: None,
            trust,
            timestamp_verification,
        });
    }
    Ok(VerificationBundle {
        format: "rdp_signed_settings".into(),
        validation_time: options.now,
        file_sha256: hex(&Hash::Sha256.digest(bytes)),
        signatures,
        rdp: Some(rdp.coverage),
        appx: None,
    })
}
fn verify_trust(
    store: &crate::TrustStore,
    leaf: &x509_cert::Certificate,
    certificates: &[x509_cert::Certificate],
    at: u64,
    options: &VerifyOptions<'_>,
) -> Result<TrustReport> {
    use x509_cert::ext::pkix::ExtendedKeyUsage;
    const USAGES: &[&[u8]] = &[
        crate::trust::CODE_SIGNING,
        &[43, 6, 1, 5, 5, 7, 3, 1],
        &[43, 6, 1, 4, 1, 130, 55, 54, 1, 2],
    ];
    let usage = leaf.tbs_certificate.get::<ExtendedKeyUsage>()?;
    let mut failure = None;
    for eku in USAGES {
        if usage
            .as_ref()
            .is_some_and(|(_, u)| u.0.iter().any(|v| v.as_bytes() == *eku))
        {
            match store.verify(
                leaf,
                certificates,
                eku,
                at,
                options.now,
                options.check_revocation,
            ) {
                Ok(report) => return Ok(report),
                Err(e) => {
                    if failure.is_none() {
                        failure = Some(e)
                    }
                }
            }
        }
    }
    Err(failure.unwrap_or_else(|| {
        VerificationError::new(
            ErrorCode::InvalidEku,
            Stage::Certificate,
            "RDP signer requires codeSigning, serverAuth, or Remote Desktop Authentication EKU",
        )
        .detail("certificate", CertificateReport::parse(leaf).ok())
        .into()
    }))
}

// Display-name -> setting key/type, pinned to the independent nfedera signer.
const SCOPES: &[(&str, &str, &str)] = &[
    ("Full Address", "full address", "s"),
    ("Alternate Full Address", "alternate full address", "s"),
    ("PCB", "pcb", "s"),
    (
        "Use Redirection Server Name",
        "use redirection server name",
        "i",
    ),
    ("Server Port", "server port", "i"),
    ("Negotiate Security Layer", "negotiate security layer", "i"),
    ("EnableCredSspSupport", "enablecredsspsupport", "i"),
    ("DisableConnectionSharing", "disableconnectionsharing", "i"),
    ("AutoReconnection Enabled", "autoreconnection enabled", "i"),
    ("GatewayHostname", "gatewayhostname", "s"),
    ("GatewayUsageMethod", "gatewayusagemethod", "i"),
    (
        "GatewayProfileUsageMethod",
        "gatewayprofileusagemethod",
        "i",
    ),
    ("GatewayCredentialsSource", "gatewaycredentialssource", "i"),
    ("Support URL", "support url", "s"),
    ("PromptCredentialOnce", "promptcredentialonce", "i"),
    (
        "Require pre-authentication",
        "require pre-authentication",
        "i",
    ),
    (
        "Pre-authentication server address",
        "pre-authentication server address",
        "s",
    ),
    ("Alternate Shell", "alternate shell", "s"),
    ("Shell Working Directory", "shell working directory", "s"),
    ("RemoteApplicationProgram", "remoteapplicationprogram", "s"),
    (
        "RemoteApplicationExpandWorkingdir",
        "remoteapplicationexpandworkingdir",
        "s",
    ),
    ("RemoteApplicationMode", "remoteapplicationmode", "i"),
    ("RemoteApplicationGuid", "remoteapplicationguid", "s"),
    ("RemoteApplicationName", "remoteapplicationname", "s"),
    ("RemoteApplicationIcon", "remoteapplicationicon", "s"),
    ("RemoteApplicationFile", "remoteapplicationfile", "s"),
    (
        "RemoteApplicationFileExtensions",
        "remoteapplicationfileextensions",
        "s",
    ),
    ("RemoteApplicationCmdLine", "remoteapplicationcmdline", "s"),
    (
        "RemoteApplicationExpandCmdLine",
        "remoteapplicationexpandcmdline",
        "s",
    ),
    ("Prompt For Credentials", "prompt for credentials", "i"),
    ("Authentication Level", "authentication level", "i"),
    ("AudioMode", "audiomode", "i"),
    ("RedirectDrives", "redirectdrives", "i"),
    ("RedirectPrinters", "redirectprinters", "i"),
    ("RedirectCOMPorts", "redirectcomports", "i"),
    ("RedirectSmartCards", "redirectsmartcards", "i"),
    ("RedirectPOSDevices", "redirectposdevices", "i"),
    ("RedirectClipboard", "redirectclipboard", "i"),
    ("DevicesToRedirect", "devicestoredirect", "s"),
    ("DrivesToRedirect", "drivestoredirect", "s"),
    ("LoadBalanceInfo", "loadbalanceinfo", "s"),
    ("RedirectDirectX", "redirectdirectx", "i"),
    ("RDGIsKDCProxy", "rdgiskdcproxy", "i"),
    ("KDCProxyName", "kdcproxyname", "s"),
    ("EventLogUploadAddress", "eventloguploadaddress", "s"),
];

#[cfg(test)]
mod tests {
    use super::*;
    use ::der::Encode;
    fn fixture(name: &str) -> Vec<u8> {
        std::fs::read(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures")
                .join(name),
        )
        .unwrap()
    }
    #[test]
    fn signed_and_unsigned_mutations_have_distinct_cryptographic_effects() {
        for (good, bad, unsigned) in [
            (
                "good.rdp",
                "bad-rdp-setting.rdp",
                "good-rdp-unsigned-change.rdp",
            ),
            (
                "rdp-independent-nfedera.rdp",
                "bad-rdp-independent-setting.rdp",
                "good-rdp-independent-unsigned-change.rdp",
            ),
        ] {
            let good = Rdp::parse(&fixture(good)).unwrap();
            let bad = Rdp::parse(&fixture(bad)).unwrap();
            let unsigned = Rdp::parse(&fixture(unsigned)).unwrap();
            assert_eq!(good.signature, bad.signature);
            assert_eq!(good.signature, unsigned.signature);
            assert_ne!(good.canonical, bad.canonical);
            assert_eq!(good.canonical, unsigned.canonical);
            let sd = DetachedData::parse(&bad.signature).unwrap();
            sd.verify(sd.signers[0], &good.canonical, false).unwrap();
            assert!(sd.verify(sd.signers[0], &bad.canonical, false).is_err());
            assert!(!good.coverage.full_file_signed);
            assert_eq!(unsigned.coverage.unsigned_settings[0].value, "2048");
        }
        let good = Rdp::parse(&fixture("good-rdp-attributes.rdp")).unwrap();
        let bad = Rdp::parse(&fixture("bad-rdp-attributes-setting.rdp")).unwrap();
        assert_eq!(good.signature, bad.signature);
        let sd = DetachedData::parse(&bad.signature).unwrap();
        sd.verify(sd.signers[0], &good.canonical, false).unwrap();
        let error = sd
            .verify(sd.signers[0], &bad.canonical, false)
            .err()
            .unwrap();
        assert_eq!(
            error.downcast_ref::<VerificationError>().unwrap().code,
            ErrorCode::ContentDigestMismatch
        );
    }
    #[test]
    fn direct_signatures_do_not_relax_authenticode_or_countersignature_policy() {
        let pe_bytes = fixture("bad-rdp-pe-no-attributes.exe");
        let pe = crate::pe::Pe::parse(&pe_bytes).unwrap();
        let cms = pe.certificates().unwrap()[0];
        let sd = cms::SignedData::parse(cms).unwrap();
        let (hash, expected) = sd.image_digest().unwrap();
        assert_eq!(pe.digest(hash).unwrap(), expected);
        let si = sd.signers[0].children().unwrap();
        assert_eq!(si.len(), 5);
        let signer = sd
            .certs
            .iter()
            .find(|cert| {
                cert.tbs_certificate.serial_number.to_der().unwrap()
                    == si[1].children().unwrap()[1].full
            })
            .unwrap();
        crate::crypto::verify_spki(
            &signer
                .tbs_certificate
                .subject_public_key_info
                .to_der()
                .unwrap(),
            hash,
            si[3].children().unwrap()[0].body,
            sd.content.body,
            si[4].body,
        )
        .unwrap();
        assert!(sd.verify(sd.signers[0], false).is_err());
        let rdp = Rdp::parse(&fixture("good.rdp")).unwrap();
        assert!(cms::SignedData::parse(&rdp.signature).is_err());
        let detached = DetachedData::parse(&rdp.signature).unwrap();
        assert!(
            cms::verify_countersigner(&detached.certs, detached.signers[0], &rdp.canonical, false)
                .is_err()
        );
    }
    #[test]
    fn truncation_and_parser_budgets_fail_closed() {
        for (name, newline_bytes) in [
            ("good.rdp", 2),
            ("good-rdp-utf16le.rdp", 4),
            ("good-rdp-utf16be.rdp", 4),
        ] {
            let bytes = fixture(name);
            for end in 0..bytes.len() {
                if end == bytes.len() - newline_bytes {
                    assert!(Rdp::parse(&bytes[..end]).is_ok());
                } else {
                    assert!(
                        Rdp::parse(&bytes[..end]).is_err(),
                        "accepted {name} prefix {end}"
                    );
                }
            }
        }
        assert!(
            Rdp::parse(&vec![b'a'; MAX_FILE + 1])
                .err()
                .unwrap()
                .to_string()
                .contains("limit")
        );
        let many: String = (0..MAX_SETTINGS + 1)
            .map(|i| format!("setting{i}:s:x\n"))
            .collect();
        assert!(
            Rdp::parse(many.as_bytes())
                .err()
                .unwrap()
                .to_string()
                .contains("too many")
        );
        let good = String::from_utf8(fixture("good.rdp")).unwrap();
        for prefix in [
            "x:b:0\n",
            "x:b:zz\n",
            "x:z:a\n",
            "x:i:2147483648\n",
            "x:s:a\0b\n",
            "x:s:\u{7}\n",
        ] {
            assert!(Rdp::parse(format!("{prefix}{good}").as_bytes()).is_err());
        }
        let mut utf16 = fixture("good-rdp-utf16le.rdp");
        utf16[2..4].copy_from_slice(&0xd800u16.to_le_bytes());
        assert!(Rdp::parse(&utf16).is_err());
        let text = "full address:s:example.invalid\r\n";
        let no_bom: Vec<_> = text.encode_utf16().flat_map(u16::to_le_bytes).collect();
        assert!(Rdp::parse(&no_bom).is_err());
        let with_binary = format!("password 51:b:0011aaff\r\n{good}");
        let parsed = Rdp::parse(with_binary.as_bytes()).unwrap();
        assert!(matches!(
            parsed.coverage.unsigned_settings[0].value_type,
            RdpValueType::Binary
        ));
        assert!(has_extension(Path::new("connection.RDP")));
        assert!(!has_extension(Path::new("connection")));
        assert!(!has_extension(Path::new("connection.exe")));
    }
    #[test]
    fn trust_selection_and_serialized_coverage_are_explicit() {
        let mut trust = crate::TrustStore::default();
        trust.add_roots(&fixture("root.der")).unwrap();
        trust.add_crl(&fixture("good.crl")).unwrap();
        let options = VerifyOptions {
            trust: Some(&trust),
            check_revocation: true,
            allow_sha1: false,
            now: 1_800_000_000,
        };
        for (name, usage) in [
            ("good.rdp", "1.3.6.1.5.5.7.3.3"),
            ("good-rdp-server-auth.rdp", "1.3.6.1.5.5.7.3.1"),
            ("good-rdp-remote-auth.rdp", "1.3.6.1.4.1.311.54.1.2"),
        ] {
            let bytes = fixture(name);
            for report in [
                crate::verify(&bytes, &options).unwrap(),
                crate::verify_rdp(&bytes, &options).unwrap(),
            ] {
                let rdp = report.rdp.as_ref().unwrap();
                assert!(!rdp.full_file_signed);
                assert_eq!(
                    rdp.signscope,
                    ["Full Address", "Server Port", "RedirectClipboard"]
                );
                assert_eq!(rdp.signed_settings[0].name, "full address");
                assert_eq!(rdp.unsigned_settings[0].name, "desktopwidth");
                let json = serde_json::to_value(report).unwrap();
                assert_eq!(json["rdp"]["signed_settings"][1]["value_type"], "i");
                assert_eq!(json["signatures"][0]["trust"]["required_eku"]["oid"], usage);
                let roundtrip: VerificationBundle = serde_json::from_value(json.clone()).unwrap();
                assert_eq!(serde_json::to_value(roundtrip).unwrap(), json);
            }
        }
        let err = crate::verify_rdp(&fixture("unsigned.rdp"), &options).unwrap_err();
        let json = serde_json::to_value(err).unwrap();
        assert_eq!(json["code"], "unsigned");
        assert_eq!(json["stage"], "rdp");
    }
}
