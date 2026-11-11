//! Supported Authenticode containers and their embedded CMS framing rules.
use super::tagged;
use crate::{
    appx::Appx, cab::Cab, der, domain::*, format::Format, msi::Msi, navx::Navx, pe::Pe,
    powershell::Powershell, wsh::Wsh,
};
use anyhow::Result;
use std::borrow::Cow;

pub(super) enum Container<'a, 'p> {
    Pe(Pe<'a>),
    Appx(&'p Appx<'a>),
    Cab(Cab<'a>),
    Navx(Navx<'a>),
    Powershell(Powershell<'a>),
    Wsh(Wsh<'a>),
    Msi(&'p mut Msi<'a>),
}

impl<'a, 'p> Container<'a, 'p>
where
    'a: 'p,
{
    pub(super) fn signatures(&self) -> Result<Vec<Cow<'p, [u8]>>> {
        Ok(match self {
            Container::Pe(pe) => tagged(
                pe.certificates(),
                ErrorCode::InvalidCertificateTable,
                Stage::CertificateTable,
            )?
            .into_iter()
            .map(Cow::Borrowed)
            .collect(),
            Container::Msi(msi) => vec![Cow::Owned(msi.signature().to_vec())],
            Container::Appx(appx) => vec![Cow::Borrowed(appx.signature())],
            Container::Navx(navx) => vec![Cow::Borrowed(navx.signature())],
            Container::Cab(cab) => vec![Cow::Borrowed(cab.signature())],
            Container::Powershell(script) => vec![Cow::Owned(script.signature().to_vec())],
            Container::Wsh(script) => vec![Cow::Owned(script.signature().to_vec())],
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

#[cfg(test)]
mod borrowing_tests {
    use super::*;

    #[test]
    fn lib08_signature_copy_measurements() {
        let pe = Pe::parse(include_bytes!("../../tests/fixtures/good-pe64.exe")).unwrap();
        let cab = Cab::parse(include_bytes!("../../tests/fixtures/good.cab")).unwrap();
        let navx = Navx::parse(include_bytes!("../../tests/fixtures/good.navx")).unwrap();
        let appx = Appx::parse(include_bytes!("../../tests/fixtures/good.msix")).unwrap();
        let cab_pointer = cab.signature().as_ptr();
        let navx_pointer = navx.signature().as_ptr();
        let pe_pointer = pe.certificates().unwrap()[0].as_ptr();
        for (name, container, expected) in [
            ("pe", Container::Pe(pe), Some(pe_pointer)),
            ("cab", Container::Cab(cab), Some(cab_pointer)),
            ("navx", Container::Navx(navx), Some(navx_pointer)),
            (
                "appx",
                Container::Appx(&appx),
                Some(appx.signature().as_ptr()),
            ),
        ] {
            let signatures = container.signatures().unwrap();
            let previous_copied: usize = signatures.iter().map(|s| s.len()).sum();
            let copied: usize = signatures
                .iter()
                .filter(|s| matches!(s, Cow::Owned(_)))
                .map(|s| s.len())
                .sum();
            assert_eq!(copied, 0);
            if let Some(expected) = expected {
                assert_eq!(signatures[0].as_ptr(), expected);
            }
            println!("{name}: signature payload bytes copied {previous_copied} -> {copied}");
        }
    }
}
