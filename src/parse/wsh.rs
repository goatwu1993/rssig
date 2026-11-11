//! Windows Script Host text containers; stored scripts are never executed or decoded as code.
use super::{Error, ErrorKind, TextEncoding};
use alloc::{borrow::ToOwned, format, string::String, vec::Vec};
use anyhow::{Context, Result, ensure};
use base64ct::{Base64, Encoding};

/// Comment style / SIP identity; encoded VBE/JSE bodies remain opaque stored text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    VbScript,
    JScript,
    Wsf,
}
impl Kind {
    pub(crate) fn markers(self) -> (&'static str, &'static str, &'static str) {
        match self {
            Self::VbScript => (
                "'' SIG '' Begin signature block",
                "'' SIG '' End signature block",
                "'' SIG '' ",
            ),
            Self::JScript => (
                "// SIG // Begin signature block",
                "// SIG // End signature block",
                "// SIG // ",
            ),
            Self::Wsf => ("<signature>", "</signature>", "** SIG ** "),
        }
    }
    #[cfg(feature = "verify-core")]
    pub(crate) fn format(self) -> &'static str {
        match self {
            Self::VbScript => "vbscript_authenticode",
            Self::JScript => "jscript_authenticode",
            Self::Wsf => "wsf_authenticode",
        }
    }
    #[cfg(feature = "verify-core")]
    pub(crate) fn uuid(self) -> [u8; 16] {
        match self {
            Self::VbScript => [
                0x4e, 0xf0, 0x29, 0x16, 0x99, 0x27, 0xb5, 0x4d, 0x8f, 0xe5, 0xac, 0xe1, 0x0f, 0x17,
                0xeb, 0xab,
            ],
            Self::JScript => [
                0x10, 0xe0, 0xc9, 0x06, 0xce, 0x38, 0xd4, 0x11, 0xa2, 0xa3, 0, 0x10, 0x4b, 0xd3,
                0x50, 0x90,
            ],
            Self::Wsf => [
                0x70, 0x05, 0x61, 0x1a, 0xce, 0x38, 0xd4, 0x11, 0xa2, 0xa3, 0, 0x10, 0x4b, 0xd3,
                0x50, 0x90,
            ],
        }
    }
}
const KINDS: [Kind; 3] = [Kind::VbScript, Kind::JScript, Kind::Wsf];
pub(crate) fn detect(bytes: &[u8]) -> core::result::Result<Kind, Error> {
    detect_inner(bytes).map_err(|e| Error::new(ErrorKind::InvalidWsh, e))
}
fn contains(bytes: &[u8], marker: &str) -> bool {
    let le: Vec<_> = marker.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let be: Vec<_> = marker.encode_utf16().flat_map(u16::to_be_bytes).collect();
    [marker.as_bytes(), &le, &be]
        .iter()
        .any(|needle| bytes.windows(needle.len()).any(|w| w == *needle))
}
fn detect_inner(bytes: &[u8]) -> Result<Kind> {
    let found: Vec<_> = KINDS
        .into_iter()
        .filter(|k| contains(bytes, k.markers().2.trim_end()))
        .collect();
    if found.is_empty() {
        return Err(Error::new(
            ErrorKind::UnsignedWsh,
            anyhow::anyhow!("WSH script has no signature block"),
        )
        .into());
    }
    ensure!(found.len() == 1, "mixed WSH signature styles");
    Ok(found[0])
}
fn decode(bytes: &[u8], kind: Kind) -> Result<String> {
    ensure!(bytes.len() <= 64 * 1024 * 1024, "WSH input exceeds 64 MiB");
    let text = if bytes.starts_with(&[0xff, 0xfe]) || bytes.starts_with(&[0xfe, 0xff]) {
        ensure!(bytes.len().is_multiple_of(2), "odd-length UTF-16 WSH input");
        let units: Vec<_> = bytes[2..]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|b| {
                if bytes[0] == 0xff {
                    u16::from_le_bytes(*b)
                } else {
                    u16::from_be_bytes(*b)
                }
            })
            .collect();
        String::from_utf16(&units)?
    } else if let Some(body) = bytes.strip_prefix(&[0xef, 0xbb, 0xbf]) {
        core::str::from_utf8(body)?.to_owned()
    } else {
        ensure!(
            kind == Kind::Wsf || bytes.is_ascii(),
            "BOM-less VBScript/JScript must be ASCII; Unicode requires a BOM"
        );
        core::str::from_utf8(bytes)?.to_owned()
    };
    ensure!(!text.contains('\0'), "NUL or unsupported WSH encoding");
    Ok(text)
}
/// Untrusted WSH container. WSF additionally requires the `xml` feature.
/// The decoded body excludes the BOM and stored signature block.
#[derive(Debug)]
pub struct Wsh<'a> {
    bytes: &'a [u8],
    pub(crate) kind: Kind,
    body: String,
    position: u32,
    signature: Vec<u8>,
}
impl<'a> Wsh<'a> {
    /// Parse explicit comment style, rejecting mixed styles and malformed framing.
    pub fn parse(bytes: &'a [u8], kind: Kind) -> core::result::Result<Self, Error> {
        Self::parse_inner(bytes, kind).map_err(|e| Error::new(ErrorKind::InvalidWsh, e))
    }
    fn parse_inner(bytes: &'a [u8], kind: Kind) -> Result<Self> {
        let text = decode(bytes, kind)?;
        for other in KINDS.into_iter().filter(|k| *k != kind) {
            ensure!(
                !text.contains(other.markers().2.trim_end()),
                "mixed or mismatched WSH signature styles"
            );
        }
        ensure!(
            !text.contains("# SIG #") && !text.contains("<!-- SIG #"),
            "mixed script signature styles"
        );
        let (begin, end, prefix) = kind.markers();
        if !text.contains(prefix.trim_end()) && !text.contains(begin) && !text.contains(end) {
            return Err(Error::new(
                ErrorKind::UnsignedWsh,
                anyhow::anyhow!("WSH script has no signature block"),
            )
            .into());
        }
        ensure!(
            text.matches(begin).count() == 1 && text.matches(end).count() == 1,
            "missing or duplicate WSH signature markers"
        );
        let start = text
            .find(&format!("\r\n{begin}\r\n"))
            .context("WSH signature requires preceding CRLF and CRLF marker lines")?;
        let payload_start = start + 2 + begin.len() + 2;
        let end_start = text.find(end).context("missing signature end")?;
        ensure!(payload_start <= end_start, "reversed signature markers");
        let after = end_start + end.len() + 2;
        ensure!(
            text.get(end_start + end.len()..after) == Some("\r\n"),
            "WSH end marker requires CRLF"
        );
        let encoded = &text[payload_start..end_start];
        ensure!(
            !encoded.is_empty() && encoded.len() <= 16 * 1024 * 1024,
            "empty or oversized WSH signature"
        );
        let lines = encoded
            .strip_suffix("\r\n")
            .context("WSH payload requires CRLF lines")?;
        let mut base64 = String::with_capacity(lines.len());
        for line in lines.split("\r\n") {
            let value = line
                .strip_prefix(prefix)
                .context("invalid WSH signature line prefix")?;
            ensure!(
                !value.is_empty() && value.len() <= 64 && value.len().is_multiple_of(4),
                "invalid WSH base64 line length"
            );
            base64.push_str(value);
        }
        let signature =
            Base64::decode_vec(&base64).map_err(|e| anyhow::anyhow!("invalid WSH base64: {e}"))?;
        ensure!(!signature.is_empty(), "empty WSH signature");
        if kind == Kind::Wsf {
            validate_wsf(&text, start, after)?;
        } else {
            ensure!(after == text.len(), "WSH signature must terminate the file");
        }
        let position = u32::try_from(text[..start].encode_utf16().count())?;
        let mut body = text[..start].to_owned();
        body.push_str(&text[after..]);
        if kind == Kind::Wsf {
            ensure!(
                body.rfind("</job>") == Some(start),
                "ambiguous WSF insertion position"
            );
        }
        Ok(Self {
            bytes,
            kind,
            body,
            position,
            signature,
        })
    }
    pub fn as_bytes(&self) -> &'a [u8] {
        self.bytes
    }
    pub fn encoding(&self) -> TextEncoding {
        TextEncoding::detect(self.bytes)
    }
    /// Decoded body excluding the signature block; BOM treatment is format-specific.
    pub fn body(&self) -> &str {
        &self.body
    }
    pub fn signature(&self) -> &[u8] {
        &self.signature
    }
    pub fn kind(&self) -> Kind {
        self.kind
    }
    pub fn detect(bytes: &[u8]) -> core::result::Result<Kind, Error> {
        detect(bytes)
    }
    pub fn insertion_position(&self) -> u32 {
        self.position
    }
    /// Canonical hash input includes the UTF-16 code-unit insertion position.
    pub fn authenticode_bytes(&self) -> Vec<u8> {
        let mut bytes: Vec<_> = self
            .body
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        bytes.extend(self.position.to_le_bytes());
        bytes
    }
    pub fn update_digest(&self, digest: &mut impl digest::Update) {
        for unit in self.body.encode_utf16() {
            digest.update(&unit.to_le_bytes());
        }
        digest.update(&self.position.to_le_bytes());
    }
}
#[cfg(feature = "xml")]
fn validate_wsf(text: &str, start: usize, after: usize) -> Result<()> {
    super::wsf_xml::validate(text, start, after)
}
#[cfg(not(feature = "xml"))]
fn validate_wsf(_text: &str, _start: usize, _after: usize) -> Result<()> {
    Err(Error::new(
        ErrorKind::UnsupportedWsfXml,
        anyhow::anyhow!("WSF parsing requires the xml feature"),
    )
    .into())
}
