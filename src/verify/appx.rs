//! Verify every embedded bundle package and bind its identity and signer.
use super::{VerifyOptions, tagged, verify_inner};
use crate::{appx::Appx, domain::*, format::Format};
use anyhow::{Context, Result};

pub(super) fn verify_bundle(
    appx: &Appx<'_>,
    verification: &mut VerificationBundle,
    options: &VerifyOptions<'_>,
) -> Result<()> {
    let bundle_signer = verification
        .signatures
        .first()
        .context("bundle has no verified signing certificate")?
        .certificate_sha256
        .clone();
    let mut package_reports = Vec::with_capacity(appx.bundle_packages().len());
    for package in appx.bundle_packages() {
        let nested = tagged(
            Appx::parse(package.bytes),
            ErrorCode::InvalidAppx,
            Stage::Appx,
        )?;
        if nested.is_bundle() {
            return Err(VerificationError::new(
                ErrorCode::UnsupportedAppx,
                Stage::Appx,
                "nested MSIX/AppX bundles are unsupported",
            )
            .detail("file_name", &package.file_name)
            .into());
        }
        let package_verification =
            verify_inner(package.bytes, options, Format::Appx).map_err(|error| {
                VerificationError::from_internal(error, ErrorCode::InvalidAppx, Stage::Appx)
                    .detail("bundle_package", &package.file_name)
            })?;
        let package_report = package_verification
            .appx
            .as_ref()
            .context("verified bundle package has no AppX report")?;
        if !(package_report.kind == AppxKind::Package
            && package_report.identity.name == appx.report.as_ref().unwrap().identity.name
            && package_report.identity.version == package.version
            && package_report.identity.resource_id == package.resource_id
            && (package.package_type == "resource")
                == tagged(
                    nested.resource_package(),
                    ErrorCode::InvalidAppx,
                    Stage::Appx,
                )?
            && package.architecture.as_ref().is_none_or(|architecture| {
                package_report
                    .identity
                    .processor_architecture
                    .as_deref()
                    .unwrap_or("neutral")
                    == architecture
            }))
        {
            return Err(VerificationError::new(
                ErrorCode::InvalidAppx,
                Stage::Appx,
                "bundle package identity differs from its manifest entry",
            )
            .detail("bundle_package", &package.file_name)
            .into());
        }
        let package_signer = package_verification
            .signatures
            .first()
            .context("bundle package has no verified signing certificate")?;
        if package_signer.certificate_sha256 != bundle_signer {
            return Err(VerificationError::new(
                ErrorCode::AppxPublisherMismatch,
                Stage::Appx,
                "bundle package and bundle use different signing certificates",
            )
            .detail("file_name", &package.file_name)
            .detail("bundle_certificate_sha256", &bundle_signer)
            .detail(
                "package_certificate_sha256",
                &package_signer.certificate_sha256,
            )
            .into());
        }
        package_reports.push(AppxBundlePackageReport {
            file_name: package.file_name.clone(),
            package_type: package.package_type.clone(),
            architecture: package.architecture.clone(),
            resource_id: package.resource_id.clone(),
            version: package.version.clone(),
            offset: package.offset,
            size: package.size,
            verification: Box::new(package_verification),
        });
    }
    verification
        .appx
        .as_mut()
        .context("verified bundle has no AppX report")?
        .bundle_packages = Some(package_reports);
    Ok(())
}
