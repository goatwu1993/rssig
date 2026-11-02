//! Input classification shared by the CLI and byte-oriented verification API.
//! Binary magic outranks filename hints; text hints outrank signature markers.
use crate::{
    domain::{ErrorCode, Stage, VerificationError},
    wsh::{self, Kind},
};
use std::path::Path;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Format {
    Pe,
    Msi,
    Cab,
    Navx,
    Powershell,
    PowershellXml,
    Wsh(Kind),
    Appx,
    Rdp,
}

impl Format {
    pub(crate) fn report_name(self) -> &'static str {
        match self {
            Self::Pe => "pe_authenticode",
            Self::Msi => "msi_authenticode",
            Self::Cab => "cab_authenticode",
            Self::Navx => "navx_authenticode",
            Self::Powershell => "powershell_authenticode",
            Self::PowershellXml => "powershell_xml_authenticode",
            Self::Wsh(kind) => kind.format(),
            Self::Appx => "appx_authenticode",
            Self::Rdp => "rdp_signed_settings",
        }
    }
}

fn binary(bytes: &[u8]) -> Option<Format> {
    if bytes.starts_with(crate::msi::MAGIC) {
        Some(Format::Msi)
    } else if bytes.starts_with(crate::navx::MAGIC) {
        Some(Format::Navx)
    } else if bytes.starts_with(crate::cab::MAGIC) {
        Some(Format::Cab)
    } else if bytes.starts_with(b"PK\x03\x04") {
        Some(Format::Appx)
    } else if bytes.starts_with(b"MZ") {
        Some(Format::Pe)
    } else {
        None
    }
}

#[cfg(test)]
pub(crate) fn is_binary(bytes: &[u8]) -> bool {
    binary(bytes).is_some()
}

pub(crate) fn detect(bytes: &[u8], path: Option<&Path>) -> Result<Format, VerificationError> {
    if let Some(format) = binary(bytes) {
        return Ok(format);
    }
    if let Some(path) = path {
        if crate::appx::has_extension(path) {
            return Ok(Format::Appx);
        }
        if crate::powershell::has_xml_extension(path) {
            return Ok(Format::PowershellXml);
        }
        if crate::rdp::has_extension(path) {
            return Ok(Format::Rdp);
        }
        if crate::powershell::has_extension(path) {
            return Ok(Format::Powershell);
        }
        if let Some(kind) = wsh::extension(path) {
            return Ok(Format::Wsh(kind));
        }
    }
    if wsh::looks_like(bytes) {
        wsh::detect(bytes)
            .map(Format::Wsh)
            .map_err(|e| VerificationError::from_internal(e, ErrorCode::InvalidWsh, Stage::Wsh))
    } else if crate::powershell::looks_like(bytes) {
        Ok(Format::Powershell)
    } else if crate::powershell::looks_like_xml(bytes) {
        Ok(Format::PowershellXml)
    } else if crate::rdp::looks_like(bytes) {
        Ok(Format::Rdp)
    } else {
        // Preserve the verifier's historical fallback and invalid_pe diagnostic.
        Ok(Format::Pe)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binary_magic_outranks_every_text_and_package_filename_hint() {
        for (bytes, expected) in [
            (b"MZ".as_slice(), Format::Pe),
            (crate::msi::MAGIC, Format::Msi),
            (crate::cab::MAGIC, Format::Cab),
            (crate::navx::MAGIC, Format::Navx),
            (b"PK\x03\x04".as_slice(), Format::Appx),
        ] {
            for name in ["x.ps1", "x.ps1xml", "x.vbs", "x.rdp", "x.msix", "x.exe"] {
                assert_eq!(detect(bytes, Some(Path::new(name))).unwrap(), expected);
            }
        }
    }

    #[test]
    fn text_hints_outrank_markers_and_unknown_bytes_retain_pe_fallback() {
        let ps = include_bytes!("../tests/fixtures/good-powershell.ps1");
        assert_eq!(detect(ps, None).unwrap(), Format::Powershell);
        assert_eq!(detect(ps, Some(Path::new("x.RDP"))).unwrap(), Format::Rdp);
        assert_eq!(
            detect(ps, Some(Path::new("x.PS1XML"))).unwrap(),
            Format::PowershellXml
        );
        assert_eq!(
            detect(ps, Some(Path::new("x.VBS"))).unwrap(),
            Format::Wsh(Kind::VbScript)
        );
        assert_eq!(detect(ps, Some(Path::new("x.MSIX"))).unwrap(), Format::Appx);
        assert_eq!(detect(b"unknown", None).unwrap(), Format::Pe);
        assert_eq!(
            detect(b"unknown", Some(Path::new("x.bin"))).unwrap(),
            Format::Pe
        );
    }
}
