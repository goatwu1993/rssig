//! Untrusted RDP setting framing, scope coverage, and canonical detached CMS input.
use super::{Error, ErrorKind, TextEncoding};
use alloc::{borrow::ToOwned, collections::BTreeSet, format, string::String, vec::Vec};
use anyhow::{Context, Result, ensure};
use base64ct::{Base64, Encoding};
pub(crate) const MAX_FILE: usize = 16 * 1024 * 1024;
pub(crate) const MAX_SETTINGS: usize = 4096;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RdpValueType {
    String,
    Integer,
    Binary,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RdpSetting {
    pub name: String,
    pub value_type: RdpValueType,
    pub value: String,
}
/// Untrusted scoped RDP settings and canonical detached CMS input.
/// Membership in `signed_settings` is a stored scope assertion, not a verified claim.
#[derive(Debug)]
pub struct Rdp<'a> {
    bytes: &'a [u8],
    text: String,
    signature: Vec<u8>,
    canonical: Vec<u8>,
    signscope: Vec<String>,
    signed_settings: Vec<RdpSetting>,
    unsigned_settings: Vec<RdpSetting>,
}
// Kept typed so the verifier can preserve the unsupported-scope detail.
#[derive(Debug)]
pub(crate) struct UnsupportedScope {
    pub(crate) entry: String,
}
impl core::fmt::Display for UnsupportedScope {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("unsupported RDP signature scope entry")
    }
}
impl core::error::Error for UnsupportedScope {}
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
        core::str::from_utf8(bytes)?.to_owned()
    };
    let text = text.strip_prefix('\u{feff}').unwrap_or(&text);
    ensure!(!text.contains('\0'), "NUL or unsupported RDP encoding");
    Ok(text.to_owned())
}
impl<'a> Rdp<'a> {
    pub fn parse(bytes: &'a [u8]) -> core::result::Result<Self, Error> {
        Self::parse_inner(bytes).map_err(|e| Error::new(ErrorKind::InvalidRdp, e))
    }
    fn parse_inner(bytes: &'a [u8]) -> Result<Self> {
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
            return Err(Error::new(
                ErrorKind::UnsignedRdp,
                anyhow::anyhow!("RDP file has no signature"),
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
                Error::new(
                    ErrorKind::UnsupportedRdpScope,
                    UnsupportedScope {
                        entry: name.to_owned(),
                    }
                    .into(),
                )
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
        Ok(Self {
            bytes,
            text,
            signature,
            canonical,
            signscope: names,
            signed_settings,
            unsigned_settings,
        })
    }
    pub fn as_bytes(&self) -> &'a [u8] {
        self.bytes
    }
    pub fn encoding(&self) -> TextEncoding {
        TextEncoding::detect(self.bytes)
    }
    /// Decoded text without the encoding BOM, preserving stored line endings.
    pub fn decoded_text(&self) -> &str {
        &self.text
    }
    pub fn signature(&self) -> &[u8] {
        &self.signature
    }
    /// UTF-16LE scoped lines and signscope, ending in CRLF and a NUL code unit.
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical
    }
    /// Scope membership is an unauthenticated assertion until verification succeeds.
    pub fn signscope(&self) -> &[String] {
        &self.signscope
    }
    pub fn signed_settings(&self) -> &[RdpSetting] {
        &self.signed_settings
    }
    pub fn unsigned_settings(&self) -> &[RdpSetting] {
        &self.unsigned_settings
    }
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
