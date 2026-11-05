//! Project untrusted parser values into owned inspection reports.
//! No verifier, trust store, clock, or filesystem access belongs in this module.
use crate::{
    domain::*,
    parse::{InspectedCms, InspectedSigner, InspectionBudget, ParsedTime, Pe, SignedData},
};

pub(crate) fn pe(bytes: &[u8]) -> Result<ParseReport, VerificationError> {
    let pe = Pe::parse(bytes)?;
    let mut budget = InspectionBudget::default();
    Ok(ParseReport {
        format: "pe".into(),
        verification_performed: false,
        signatures: pe
            .signatures()?
            .into_iter()
            .map(|bytes| signed_data(bytes, &mut budget))
            .collect::<Result<_, _>>()?,
    })
}

pub(crate) fn cms(bytes: &[u8]) -> Result<ParseReport, VerificationError> {
    Ok(ParseReport {
        format: "cms".into(),
        verification_performed: false,
        signatures: vec![signed_data(bytes, &mut InspectionBudget::default())?],
    })
}

fn signed_data(
    bytes: &[u8],
    budget: &mut InspectionBudget,
) -> Result<ParsedCmsReport, VerificationError> {
    inspected(SignedData::inspect(bytes, budget)?)
}

fn project(
    parsed: &SignedData<'_>,
    inspection: ParsedCmsInspection,
) -> Result<ParsedCmsReport, VerificationError> {
    let certificate_choices = parsed
        .certificate_choices()
        .iter()
        .map(|choice| {
            Ok(ParsedCertificateChoice {
                tag: choice.tag(),
                der: hex(choice.as_der()),
                certificate: choice
                    .x509()
                    .map(CertificateReport::parse)
                    .transpose()
                    .map_err(|error| {
                        VerificationError::from_internal(
                            error,
                            ErrorCode::InvalidCertificate,
                            Stage::Certificate,
                        )
                    })?,
            })
        })
        .collect::<Result<_, VerificationError>>()?;
    Ok(ParsedCmsReport {
        version_der: hex(parsed.version_der()),
        content_type: parsed.content_type().to_string(),
        content_der: parsed.content_der().map(hex),
        digest_algorithms: parsed
            .digest_algorithms()
            .iter()
            .map(|algorithm| ParsedAlgorithmReport {
                oid: algorithm.oid().to_string(),
                der: hex(algorithm.as_der()),
                parameters_der: algorithm.parameters_der().map(hex),
            })
            .collect(),
        certificate_choices,
        revocation_choices_der: parsed
            .revocation_choices_der()
            .iter()
            .map(|der| hex(der))
            .collect(),
        signer_infos_der: parsed.signer_infos().iter().copied().map(hex).collect(),
        inspection,
    })
}

fn parsed_time(time: &ParsedTime<'_>) -> ParsedTimeReport {
    ParsedTimeReport {
        der: hex(time.as_der()),
        unix_seconds: time.unix_seconds(),
        fractional_seconds: time.fractional_seconds().map(Into::into),
    }
}
fn inspected(cms: InspectedCms<'_>) -> Result<ParsedCmsReport, VerificationError> {
    let inspection = ParsedCmsInspection {
        signers: cms
            .signers
            .into_iter()
            .map(inspected_signer)
            .collect::<Result<_, _>>()?,
        tst_info: cms.tst_info.map(|info| ParsedTstInfo {
            der: hex(info.as_der()),
            policy: info.policy.to_string(),
            imprint_algorithm: ParsedAlgorithmReport {
                oid: info.imprint_algorithm.oid().to_string(),
                der: hex(info.imprint_algorithm.as_der()),
                parameters_der: info.imprint_algorithm.parameters_der().map(hex),
            },
            imprint: hex(info.imprint),
            serial_number_der: hex(info.serial_number_der),
            parsed_time: parsed_time(&info.parsed_time),
            optional_fields_der: info.optional_fields.into_iter().map(hex).collect(),
        }),
    };
    project(&cms.signed_data, inspection)
}
fn inspected_signer(
    signer: InspectedSigner<'_>,
) -> Result<ParsedSignerInspection, VerificationError> {
    Ok(ParsedSignerInspection {
        der: hex(signer.signer.as_der()),
        children: signer
            .children
            .into_iter()
            .map(|child| {
                Ok(ParsedChildInspection {
                    kind: match child.kind {
                        crate::parse::InspectionKind::Nested => "nested",
                        crate::parse::InspectionKind::Rfc3161 => "rfc3161",
                        crate::parse::InspectionKind::Pkcs9Countersignature => {
                            "pkcs9_countersignature"
                        }
                    }
                    .into(),
                    value_der: hex(child.value_der),
                    cms: child.cms.map(inspected).transpose()?.map(Box::new),
                    countersigner: child.countersigner.map(inspected_signer).transpose()?,
                    parsed_time: child.parsed_time.as_ref().map(parsed_time),
                })
            })
            .collect::<Result<_, VerificationError>>()?,
    })
}
