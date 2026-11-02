//! Project untrusted parser values into owned inspection reports.
//! No verifier, trust store, clock, or filesystem access belongs in this module.
use crate::{
    domain::*,
    parse::{Pe, SignedData},
};

pub(crate) fn pe(bytes: &[u8]) -> Result<ParseReport, VerificationError> {
    let pe = Pe::parse(bytes)?;
    Ok(ParseReport {
        format: "pe".into(),
        verification_performed: false,
        signatures: pe
            .signatures()?
            .into_iter()
            .map(signed_data)
            .collect::<Result<_, _>>()?,
    })
}

pub(crate) fn cms(bytes: &[u8]) -> Result<ParseReport, VerificationError> {
    Ok(ParseReport {
        format: "cms".into(),
        verification_performed: false,
        signatures: vec![signed_data(bytes)?],
    })
}

fn signed_data(bytes: &[u8]) -> Result<ParsedCmsReport, VerificationError> {
    let parsed = SignedData::parse(bytes)?;
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
        signer_infos_der: parsed.signer_infos().into_iter().map(hex).collect(),
    })
}
