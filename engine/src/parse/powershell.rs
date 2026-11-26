//! Hash-comment and XML-comment PowerShell Authenticode signatures; scripts are never executed.
use super::{Error, ErrorKind, TextEncoding};
use alloc::{borrow::ToOwned, string::String, vec::Vec};
use anyhow::{Result, ensure};
use base64ct::{Base64, Encoding};

const BEGIN: &str = "# SIG # Begin signature block";
const END: &str = "# SIG # End signature block";
pub(crate) const PREFIX: &str = "\r\n# SIG # Begin signature block\r\n";
pub(crate) const SUFFIX: &str = "# SIG # End signature block\r\n";
pub(crate) const MAX_SIGNATURE_TEXT: usize = 16 * 1024 * 1024;

/// Untrusted hash-comment or XML-comment script, borrowing the exact stored bytes.
/// Decoding, block framing, and canonical bytes do not authenticate the script.
#[derive(Debug)]
pub struct Powershell<'a> {
    bytes: &'a [u8],
    body: String,
    signature: Vec<u8>,
}

fn decode(bytes: &[u8]) -> Result<String> {
    let text = if bytes.starts_with(&[0xff, 0xfe]) || bytes.starts_with(&[0xfe, 0xff]) {
        ensure!(
            bytes.len().is_multiple_of(2),
            "odd-length UTF-16 PowerShell script"
        );
        let little = bytes[0] == 0xff;
        let units: Vec<_> = bytes
            .as_chunks::<2>()
            .0
            .iter()
            .map(|b| {
                let pair = [b[0], b[1]];
                if little {
                    u16::from_le_bytes(pair)
                } else {
                    u16::from_be_bytes(pair)
                }
            })
            .collect();
        String::from_utf16(&units)?
    } else {
        core::str::from_utf8(bytes)?.to_owned()
    };
    ensure!(
        !text.contains('\0'),
        "NUL or unsupported script encoding (UTF-16 requires a BOM)"
    );
    Ok(text)
}

impl<'a> Powershell<'a> {
    /// Parse a hash-comment block, without interpreting the script or CMS.
    pub fn parse(bytes: &'a [u8]) -> core::result::Result<Self, Error> {
        Self::parse_style(bytes, false).map_err(|e| Error::new(ErrorKind::InvalidPowershell, e))
    }
    /// Parse XML-comment framing; this is not XMLDSig or XML validation.
    pub fn parse_xml(bytes: &'a [u8]) -> core::result::Result<Self, Error> {
        Self::parse_style(bytes, true).map_err(|e| Error::new(ErrorKind::InvalidPowershell, e))
    }
    fn parse_style(bytes: &'a [u8], xml: bool) -> Result<Self> {
        if xml
            && !bytes.starts_with(&[0xef, 0xbb, 0xbf])
            && !bytes.starts_with(&[0xff, 0xfe])
            && !bytes.starts_with(&[0xfe, 0xff])
        {
            ensure!(
                bytes.is_ascii(),
                "BOM-less PowerShell XML must be ASCII; Unicode requires a BOM"
            );
        }
        let (begin, end, prefix, suffix, comment_start, comment_end, hint) = if xml {
            (
                "<!-- SIG # Begin signature block -->",
                "<!-- SIG # End signature block -->",
                "\r\n<!-- SIG # Begin signature block -->\r\n",
                "<!-- SIG # End signature block -->\r\n",
                "<!-- ",
                " -->",
                "SIG #",
            )
        } else {
            (BEGIN, END, PREFIX, SUFFIX, "# ", "", "# SIG #")
        };
        let mut text = decode(bytes)?;
        if !text.contains(hint) {
            return Err(Error::new(
                ErrorKind::UnsignedPowershell,
                anyhow::anyhow!("PowerShell script has no signature block"),
            )
            .into());
        }
        if xml {
            ensure!(
                !text.contains("# SIG #"),
                "mixed hash/XML signature styles are unsupported"
            );
        }
        ensure!(
            text.matches(begin).count() == 1 && text.matches(end).count() == 1,
            "missing or duplicate PowerShell signature markers"
        );
        let start = text.find(prefix).ok_or_else(|| {
            anyhow::anyhow!(
                "PowerShell signature block requires a preceding CRLF and CRLF marker lines"
            )
        })?;
        let encoded_start = start + prefix.len();
        let before_end = text.strip_suffix(suffix).ok_or_else(|| {
            anyhow::anyhow!("PowerShell signature end marker must terminate the file with CRLF")
        })?;
        ensure!(
            encoded_start <= before_end.len(),
            "reversed PowerShell signature markers"
        );
        let encoded = &before_end[encoded_start..];
        ensure!(
            !encoded.is_empty() && encoded.len() <= MAX_SIGNATURE_TEXT,
            "empty or oversized PowerShell signature block"
        );
        let lines = encoded
            .strip_suffix("\r\n")
            .ok_or_else(|| anyhow::anyhow!("PowerShell signature payload requires CRLF lines"))?;
        let mut base64 = String::with_capacity(lines.len());
        for line in lines.split("\r\n") {
            let value = line
                .strip_prefix(comment_start)
                .and_then(|v| v.strip_suffix(comment_end))
                .ok_or_else(|| {
                    anyhow::anyhow!("PowerShell signature line has invalid comment delimiters")
                })?;
            ensure!(
                !value.is_empty() && value.len() <= 64 && value.len().is_multiple_of(4),
                "invalid PowerShell base64 line length"
            );
            base64.push_str(value);
        }
        let signature = Base64::decode_vec(&base64)
            .map_err(|e| anyhow::anyhow!("invalid PowerShell signature base64: {e}"))?;
        ensure!(!signature.is_empty(), "empty PowerShell CMS signature");
        text.truncate(start);
        Ok(Self {
            bytes,
            body: text,
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
    /// Canonical hash input: decoded body in UTF-16LE, including a stored BOM.
    pub fn authenticode_bytes(&self) -> Vec<u8> {
        self.body
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect()
    }
    pub fn update_digest(&self, digest: &mut impl digest::Update) {
        for unit in self.body.encode_utf16() {
            digest.update(&unit.to_le_bytes());
        }
    }
}
