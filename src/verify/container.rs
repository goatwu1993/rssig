//! Supported Authenticode containers and their embedded CMS framing rules.
use super::tagged;
use crate::{
    appx::Appx, cab::Cab, der, domain::*, format::Format, msi::Msi, navx::Navx, pe::Pe,
    powershell::Powershell, wsh::Wsh,
};
use anyhow::Result;

pub(super) enum Container<'a> {
    Pe(Pe<'a>),
    Appx(Box<Appx<'a>>),
    Cab(Cab<'a>),
    Navx(Navx<'a>),
    Powershell(Powershell<'a>),
    Wsh(Wsh<'a>),
    Msi(Box<Msi<'a>>),
}

impl Container<'_> {
    pub(super) fn signatures(&self) -> Result<Vec<Vec<u8>>> {
        Ok(match self {
            Container::Pe(pe) => tagged(
                pe.certificates(),
                ErrorCode::InvalidCertificateTable,
                Stage::CertificateTable,
            )?
            .iter()
            .map(|c| c.to_vec())
            .collect(),
            Container::Msi(msi) => vec![msi.signature().to_vec()],
            Container::Appx(appx) => vec![appx.signature().to_vec()],
            Container::Navx(navx) => vec![navx.signature().to_vec()],
            Container::Cab(cab) => vec![cab.signature().to_vec()],
            Container::Powershell(script) => vec![script.signature().to_vec()],
            Container::Wsh(script) => vec![script.signature().to_vec()],
        })
    }
}

/// Validate each CMS frame immediately before verifying it, so later malformed
/// entries cannot mask an earlier signature failure.
pub(super) fn cms_der(certificate: &[u8], format: Format) -> Result<&[u8]> {
    // Some signers count zero padding inside dwLength. Only permit zeroes
    // after one complete DER object, never arbitrary unsigned payloads.
    let mut rest = certificate;
    let node = tagged(der::take(&mut rest), ErrorCode::MalformedCms, Stage::Cms)?;
    if matches!(
        format,
        Format::Powershell | Format::PowershellXml | Format::Wsh(_) | Format::Appx | Format::Navx
    ) && !rest.is_empty()
    {
        return Err(VerificationError::new(
            ErrorCode::MalformedCms,
            Stage::Cms,
            "trailing data in embedded CMS signature",
        )
        .into());
    }
    if matches!(format, Format::Msi) && !rest.is_empty() {
        return Err(VerificationError::new(
            ErrorCode::MalformedCms,
            Stage::Cms,
            "trailing data in MSI signature stream",
        )
        .into());
    }
    if matches!(format, Format::Cab) && (rest.len() > 7 || !rest.iter().all(|b| *b == 0)) {
        return Err(VerificationError::new(
            ErrorCode::MalformedCms,
            Stage::Cms,
            "invalid trailing data in CAB signature",
        )
        .into());
    }
    if !rest.iter().all(|b| *b == 0) {
        return Err(VerificationError::new(
            ErrorCode::InvalidCertificateTable,
            Stage::CertificateTable,
            "nonzero trailing data in WIN_CERTIFICATE",
        )
        .detail("trailing_bytes", rest.len())
        .into());
    }
    Ok(node.full)
}
