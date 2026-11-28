//! PATH-T001: exact selected chains and typed path-check failures, with offline CRLs.
use super::support::*;
use rssig_engine::domain::{ErrorCode, Stage};
use sha2::{Digest, Sha256};

fn run(input: &str, roots: &str) -> Output {
    run_fixture(
        input,
        &[
            "verify",
            "--no-system-roots",
            "--roots",
            roots,
            "--time",
            "1800000000",
            "--crl",
            "fixtures/path-root.crl",
            "--crl",
            "fixtures/path-issuer.crl",
            "--crl",
            "fixtures/path-upper.crl",
            "--crl",
            "fixtures/path-other-root.crl",
        ],
    )
}
fn selected(input: &str, roots: &str, certificates: &[&str]) {
    let output = run(input, roots);
    assert_eq!(output.exit_code, 0, "{}", output.json);
    expect_success(&output);
    let sig = &output.json["results"][0]["signatures"][0];
    assert_eq!(sig["chain_trusted"], true);
    assert_eq!(sig["revocation_checked"], true);
    assert_eq!(sig["trust"]["revocation"]["status"], "good");
    assert_eq!(sig["trust"]["revocation"]["method"], "crl");
    assert_eq!(sig["trust"]["validation_time"], 1_800_000_000u64);
    let chain = sig["trust"]["chain"].as_array().unwrap();
    assert_eq!(chain.len(), certificates.len());
    assert_eq!(sig["certificate"], chain[0]);
    for (actual, name) in chain.iter().zip(certificates) {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(format!("path-{name}.der"));
        let bytes = std::fs::read(path).unwrap();
        let digest = format!("{:x}", Sha256::digest(&bytes));
        assert_eq!(actual["sha256"], digest, "selected certificate {name}");
        let der: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(actual["der_hex"], der);
    }
    // The typed domain result must carry the same complete chain.
    assert_eq!(
        output.success().signatures[0]
            .trust
            .as_ref()
            .unwrap()
            .chain
            .len(),
        certificates.len()
    );
}
fn rejected(input: &str, roots: &str, code: ErrorCode, stage: Stage, diagnostic: &str) {
    let output = run(input, roots);
    assert_eq!(output.exit_code, 1, "{}", output.json);
    let error = &output.json["results"][0]["error"];
    assert_eq!(
        error["code"],
        serde_json::to_value(code).unwrap(),
        "{error}"
    );
    assert_eq!(
        error["stage"],
        serde_json::to_value(stage).unwrap(),
        "{error}"
    );
    assert!(
        error["message"].as_str().unwrap().contains(diagnostic),
        "{error}"
    );
    assert!(output.json["results"][0].get("signatures").is_none());
}

#[test]
fn good_path_basic() {
    selected(
        "good-path-basic.exe",
        "fixtures/path-root.der",
        &["leaf", "issuer", "root"],
    );
}

#[test]
fn bad_path_ca_false() {
    rejected(
        "bad-path-ca-false.exe",
        "fixtures/path-root.der",
        ErrorCode::CertificateChainInvalid,
        Stage::CertificateChain,
        "EndEntityUsedAsCa",
    );
}

#[test]
fn bad_path_ca_missing_bc() {
    rejected(
        "bad-path-ca-missing-bc.exe",
        "fixtures/path-root.der",
        ErrorCode::CertificateChainInvalid,
        Stage::CertificateChain,
        "EndEntityUsedAsCa",
    );
}

#[test]
fn bad_path_leaf_ca() {
    rejected(
        "bad-path-leaf-ca.exe",
        "fixtures/path-root.der",
        ErrorCode::CertificateChainInvalid,
        Stage::CertificateChain,
        "CaUsedAsEndEntity",
    );
}

#[test]
fn bad_path_ca_critical() {
    rejected(
        "bad-path-ca-critical.exe",
        "fixtures/path-root.der",
        ErrorCode::CertificateChainInvalid,
        Stage::CertificateChain,
        "UnsupportedCriticalExtension",
    );
}

#[test]
fn bad_path_leaf_critical() {
    rejected(
        "bad-path-leaf-critical.exe",
        "fixtures/path-root.der",
        ErrorCode::CertificateChainInvalid,
        Stage::CertificateChain,
        "UnsupportedCriticalExtension",
    );
}

/// PATH-013: each extension rssig or webpki decodes, given a value that does
/// not decode as it, on the signing leaf (`leaf`) or the intermediate (`ca`).
const MALFORMED_EXTENSIONS: [(&str, &str); 8] = [
    ("bc", "2.5.29.19"),
    ("ku", "2.5.29.15"),
    ("eku", "2.5.29.37"),
    ("san", "2.5.29.17"),
    ("nc", "2.5.29.30"),
    ("crldp", "2.5.29.31"),
    ("ski", "2.5.29.14"),
    ("aki", "2.5.29.35"),
];

fn malformed_extension_fails_the_path(certificate: &str) {
    let mut certificates = Vec::new();
    for (label, oid) in MALFORMED_EXTENSIONS {
        let output = run(
            &format!("bad-path-{certificate}-malformed-{label}.exe"),
            "fixtures/path-root.der",
        );
        assert_eq!(output.exit_code, 1, "{label}: {}", output.json);
        assert!(output.json["results"][0].get("signatures").is_none());
        let error = &output.json["results"][0]["error"];
        assert_eq!(
            error["code"], "certificate_chain_invalid",
            "{label}: {error}"
        );
        assert_eq!(error["stage"], "certificate_chain", "{label}: {error}");
        let details = &error["details"];
        // webpki itself rejects an intermediate whose basicConstraints,
        // extKeyUsage or nameConstraints does not decode while it builds the
        // path, before rssig's path callback can name the extension.
        if certificate == "ca" && ["bc", "eku", "nc"].contains(&label) {
            assert!(details.get("reason").is_none(), "{label}: {error}");
            assert!(
                error["message"].as_str().unwrap().contains("BadDer"),
                "{label}: {error}"
            );
            continue;
        }
        assert_eq!(details["reason"], "malformed_extension", "{label}: {error}");
        assert_eq!(details["extension"], oid, "{label}: {error}");
        let sha256 = details["certificate_sha256"].as_str().unwrap();
        assert_eq!(sha256.len(), 64, "{label}: {error}");
        // details.certificate is the signer, as in every chain error. Its
        // report marks an extension the report decodes and could not.
        let signer = &details["certificate"];
        assert!(signer.is_object(), "{error}");
        assert_eq!(signer["sha256"] == sha256, certificate == "leaf", "{label}");
        let undecoded = if certificate == "leaf" && ["bc", "ku", "eku"].contains(&label) {
            serde_json::json!([{"oid": oid, "reason": "malformed_extension"}])
        } else {
            serde_json::Value::Null
        };
        assert_eq!(signer["undecoded_extensions"], undecoded, "{label}");
        certificates.push(sha256.to_owned());
    }
    // Each fixture changes one certificate, so each names its own.
    let named = certificates.len();
    certificates.sort();
    certificates.dedup();
    assert_eq!(certificates.len(), named);
    assert_eq!(
        named,
        MALFORMED_EXTENSIONS.len() - if certificate == "ca" { 3 } else { 0 }
    );
}

#[test]
fn intermediate_san_that_is_no_sequence_fails_in_webpki() {
    rejected(
        "bad-path-ca-san-not-a-sequence.exe",
        "fixtures/path-root.der",
        ErrorCode::CertificateChainInvalid,
        Stage::CertificateChain,
        "BadDer",
    );
}

#[test]
fn malformed_extension_in_the_leaf_fails_the_path() {
    malformed_extension_fails_the_path("leaf");
}

#[test]
fn malformed_extension_in_an_intermediate_fails_the_path() {
    malformed_extension_fails_the_path("ca");
}

#[test]
fn malformed_intermediate_is_passed_over_for_a_valid_issuer() {
    selected(
        "good-path-ca-malformed-first.exe",
        "fixtures/path-root.der",
        &["leaf", "issuer", "root"],
    );
}

#[test]
fn repeated_extension_fails_the_path() {
    // PATH-014: any extension, in the leaf or an intermediate.
    let mut certificates = Vec::new();
    for (who, label, oid) in [
        ("leaf", "ski", "2.5.29.14"),
        ("leaf", "eku", "2.5.29.37"),
        ("leaf", "unfamiliar", "1.2.3.4.5"),
        ("ca", "ski", "2.5.29.14"),
    ] {
        let output = run(
            &format!("bad-path-{who}-repeated-{label}.exe"),
            "fixtures/path-root.der",
        );
        assert_eq!(output.exit_code, 1, "{who} {label}: {}", output.json);
        assert!(output.json["results"][0].get("signatures").is_none());
        let error = &output.json["results"][0]["error"];
        assert_eq!(error["code"], "certificate_chain_invalid", "{error}");
        assert_eq!(error["stage"], "certificate_chain", "{error}");
        let details = &error["details"];
        assert_eq!(details["reason"], "repeated_extension", "{error}");
        assert_eq!(details["extension"], oid, "{error}");
        let sha256 = details["certificate_sha256"].as_str().unwrap();
        // details.certificate is the signer, as in every chain error. Its
        // report marks a repeat of an extension the report decodes.
        let signer = &details["certificate"];
        assert!(signer.is_object(), "{error}");
        assert_eq!(
            signer["sha256"] == sha256,
            who == "leaf",
            "{who} {label}: {error}"
        );
        let undecoded = if (who, label) == ("leaf", "eku") {
            serde_json::json!([{"oid": oid, "reason": "repeated_extension"}])
        } else {
            serde_json::Value::Null
        };
        assert_eq!(signer["undecoded_extensions"], undecoded, "{who} {label}");
        // The signer is judged before any usage; an intermediate with it.
        assert_eq!(
            details.get("required_eku").is_some(),
            who == "ca",
            "{error}"
        );
        certificates.push(sha256.to_owned());
    }
    certificates.sort();
    certificates.dedup();
    assert_eq!(certificates.len(), 4);
}

#[test]
fn intermediate_repeating_an_extension_webpki_keeps_fails_in_webpki() {
    rejected(
        "bad-path-ca-repeated-bc.exe",
        "fixtures/path-root.der",
        ErrorCode::CertificateChainInvalid,
        Stage::CertificateChain,
        "ExtensionValueInvalid",
    );
}

#[test]
fn repeating_intermediate_is_passed_over_for_a_valid_issuer() {
    selected(
        "good-path-ca-repeated-first.exe",
        "fixtures/path-root.der",
        &["leaf", "issuer", "root"],
    );
}

#[test]
fn repeat_is_reported_before_an_earlier_malformed_value() {
    // PATH-014 with PATH-013: the subjectKeyIdentifier that does not decode
    // comes first, the repeated authorityKeyIdentifier is reported.
    for who in ["leaf", "ca"] {
        let output = run(
            &format!("bad-path-{who}-repeated-and-malformed.exe"),
            "fixtures/path-root.der",
        );
        assert_eq!(output.exit_code, 1, "{who}: {}", output.json);
        let error = &output.json["results"][0]["error"];
        assert_eq!(error["code"], "certificate_chain_invalid", "{error}");
        assert_eq!(error["stage"], "certificate_chain", "{error}");
        assert_eq!(error["details"]["reason"], "repeated_extension", "{error}");
        assert_eq!(error["details"]["extension"], "2.5.29.35", "{error}");
    }
}

/// PATH-014: a candidate that repeats an extension webpki keeps fails in
/// webpki, with its message and no `details.reason`.
fn fails_in_webpki(input: &str, roots: &str) {
    let output = run(input, roots);
    assert_eq!(output.exit_code, 1, "{}", output.json);
    assert!(output.json["results"][0].get("signatures").is_none());
    let error = &output.json["results"][0]["error"];
    assert_eq!(error["code"], "certificate_chain_invalid", "{error}");
    assert_eq!(error["stage"], "certificate_chain", "{error}");
    let message = error["message"].as_str().unwrap();
    assert!(message.contains("ExtensionValueInvalid"), "{error}");
    assert!(error["details"].get("reason").is_none(), "{error}");
}

#[test]
fn intermediate_repeating_its_san_fails_in_webpki() {
    fails_in_webpki("bad-path-ca-repeated-san.exe", "fixtures/path-root.der");
}

#[test]
fn intermediate_webpki_rejects_is_passed_over_for_a_valid_issuer() {
    selected(
        "good-path-ca-repeated-san-first.exe",
        "fixtures/path-root.der",
        &["leaf", "issuer", "root"],
    );
}

#[test]
fn candidate_webpki_rejects_is_reported_when_no_path_is_found() {
    // webpki 0.103.16 parses each embedded candidate before it compares its
    // subject, and ranks the parse failure above the unknown issuer: under a
    // root that issued neither candidate, and for a CA on no path, the result
    // is not untrusted_root (PATH-T019).
    fails_in_webpki(
        "good-path-ca-repeated-san-first.exe",
        "fixtures/path-other-root.der",
    );
    fails_in_webpki(
        "bad-path-unrelated-repeated-issuer.exe",
        "fixtures/path-root.der",
    );
}

#[test]
fn non_ascii_ia5_string_in_the_leaf_san_fails_the_path() {
    let output = run("bad-path-leaf-san-non-ascii.exe", "fixtures/path-root.der");
    assert_eq!(output.exit_code, 1, "{}", output.json);
    let error = &output.json["results"][0]["error"];
    assert_eq!(error["code"], "certificate_chain_invalid", "{error}");
    assert_eq!(error["details"]["reason"], "malformed_extension", "{error}");
    assert_eq!(error["details"]["extension"], "2.5.29.17", "{error}");
}

#[test]
fn intermediate_with_malformed_basic_constraints_is_passed_over_and_reported() {
    // PATH-013: the candidate the path goes around is still reported.
    let input = "good-path-ca-malformed-bc-first.exe";
    selected(input, "fixtures/path-root.der", &["leaf", "issuer", "root"]);
    let output = run(input, "fixtures/path-root.der");
    let signature = &output.json["results"][0]["signatures"][0];
    let embedded = signature["embedded_certificates"].as_array().unwrap();
    let marked: Vec<_> = embedded
        .iter()
        .filter(|c| c.get("undecoded_extensions").is_some())
        .collect();
    assert_eq!(marked.len(), 1, "{signature}");
    undecoded(
        marked[0],
        "basic_constraints",
        "2.5.29.19",
        "malformed_extension",
    );
    for certificate in signature["trust"]["chain"].as_array().unwrap() {
        assert!(certificate.get("undecoded_extensions").is_none());
        assert_ne!(certificate["sha256"], marked[0]["sha256"]);
    }
}

/// `report` marks the extension `oid` as one it could not decode: the typed
/// `field` is null, the reason is given, and the value stays in `extensions`.
fn undecoded(report: &serde_json::Value, field: &str, oid: &str, reason: &str) {
    assert_eq!(
        report["undecoded_extensions"],
        serde_json::json!([{"oid": oid, "reason": reason}]),
        "{report}"
    );
    assert!(report[field].is_null(), "{report}");
    let raw = report["extensions"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["oid"] == oid)
        .count();
    let expected = if reason == "repeated_extension" { 2 } else { 1 };
    assert_eq!(raw, expected, "{report}");
}

const REPORTED_EXTENSIONS: [(&str, &str, &str); 3] = [
    ("bc", "basic_constraints", "2.5.29.19"),
    ("ku", "key_usage", "2.5.29.15"),
    ("eku", "extended_key_usage", "2.5.29.37"),
];

fn integrity_only(input: &str) -> Output {
    let output = run_fixture(
        input,
        &["verify", "--integrity-only", "--time", "1800000000"],
    );
    assert_eq!(output.exit_code, 0, "{input}: {}", output.json);
    output
}

#[test]
fn integrity_only_reports_a_signer_extension_it_cannot_decode() {
    for (label, field, oid) in REPORTED_EXTENSIONS {
        let output = integrity_only(&format!("bad-path-leaf-malformed-{label}.exe"));
        let signature = &output.json["results"][0]["signatures"][0];
        assert_eq!(signature["chain_trusted"], false);
        undecoded(&signature["certificate"], field, oid, "malformed_extension");
        // The two fields the defect does not touch are still decoded.
        for (_, other, _) in REPORTED_EXTENSIONS {
            assert_eq!(
                signature["certificate"][other].is_null(),
                other == field,
                "{label} {other}"
            );
        }
    }
    let output = integrity_only("bad-path-leaf-repeated-eku.exe");
    let signer = &output.json["results"][0]["signatures"][0]["certificate"];
    undecoded(
        signer,
        "extended_key_usage",
        "2.5.29.37",
        "repeated_extension",
    );
}

#[test]
fn integrity_only_reports_an_embedded_certificate_extension_it_cannot_decode() {
    let mut inputs: Vec<_> = REPORTED_EXTENSIONS
        .iter()
        .map(|(label, field, oid)| {
            let input = format!("bad-path-ca-malformed-{label}.exe");
            (input, *field, *oid, "malformed_extension")
        })
        .collect();
    inputs.push((
        "bad-path-ca-repeated-bc.exe".into(),
        "basic_constraints",
        "2.5.29.19",
        "repeated_extension",
    ));
    for (input, field, oid, reason) in inputs {
        let output = integrity_only(&input);
        let signature = &output.json["results"][0]["signatures"][0];
        assert!(
            signature["certificate"]
                .get("undecoded_extensions")
                .is_none()
        );
        let embedded = signature["embedded_certificates"].as_array().unwrap();
        assert_eq!(embedded.len(), 2, "{input}");
        undecoded(&embedded[1], field, oid, reason);
    }
}

#[test]
fn well_formed_certificate_report_has_no_undecoded_extensions_field() {
    let output = integrity_only("good-path-basic.exe");
    let signature = &output.json["results"][0]["signatures"][0];
    assert!(
        signature["certificate"]
            .get("undecoded_extensions")
            .is_none()
    );
    assert!(signature["certificate"]["basic_constraints"].is_object());
}

#[test]
fn malformed_duplicate_is_not_blamed_for_an_untrusted_root() {
    let output = run(
        "good-path-ca-malformed-first.exe",
        "fixtures/path-other-root.der",
    );
    assert_eq!(output.exit_code, 1, "{}", output.json);
    let error = &output.json["results"][0]["error"];
    assert_eq!(error["code"], "untrusted_root", "{error}");
    assert_eq!(error["stage"], "certificate_chain", "{error}");
    assert!(error["details"].get("reason").is_none(), "{error}");
}

#[test]
fn integrity_only_builds_no_path_so_a_malformed_signer_extension_verifies() {
    // PATH-013 judges path certificates; integrity-only builds no path, as
    // OpenSSL checks no extension without path verification.
    let output = run_fixture(
        "bad-path-leaf-malformed-ski.exe",
        &["verify", "--integrity-only", "--time", "1800000000"],
    );
    assert_eq!(output.exit_code, 0, "{}", output.json);
    let signature = &output.json["results"][0]["signatures"][0];
    assert_eq!(signature["chain_trusted"], false);
}

#[test]
fn malformed_intermediate_is_reported_before_its_revocation() {
    // As OpenSSL's verify_chain runs check_extensions before
    // check_revocation; crl-path-root-revoked-issuer.crl revokes the CA's
    // serial, which the malformed CA shares.
    let output = run_fixture(
        "bad-path-ca-malformed-ski.exe",
        &[
            "verify",
            "--no-system-roots",
            "--roots",
            "fixtures/path-root.der",
            "--time",
            "1800000000",
            "--crl",
            "fixtures/path-issuer.crl",
            "--crl",
            "fixtures/crl-path-root-revoked-issuer.crl",
        ],
    );
    assert_eq!(output.exit_code, 1, "{}", output.json);
    let error = &output.json["results"][0]["error"];
    assert_eq!(error["code"], "certificate_chain_invalid", "{error}");
    assert_eq!(error["details"]["reason"], "malformed_extension", "{error}");
}

#[test]
fn malformed_ca_is_not_blamed_for_an_untrusted_root() {
    let output = run(
        "bad-path-ca-malformed-ski.exe",
        "fixtures/path-other-root.der",
    );
    assert_eq!(output.exit_code, 1, "{}", output.json);
    let error = &output.json["results"][0]["error"];
    assert_eq!(error["code"], "untrusted_root", "{error}");
    assert!(error["details"].get("reason").is_none(), "{error}");
}

#[test]
fn malformed_candidate_outranks_a_missing_key_cert_sign() {
    let output = run("bad-path-ca-ku-and-malformed.exe", "fixtures/path-root.der");
    assert_eq!(output.exit_code, 1, "{}", output.json);
    let error = &output.json["results"][0]["error"];
    assert_eq!(error["code"], "certificate_chain_invalid", "{error}");
    assert_eq!(error["details"]["reason"], "malformed_extension", "{error}");
    assert_eq!(error["details"]["extension"], "2.5.29.14", "{error}");
}

#[test]
fn malformed_ca_of_an_unrelated_chain_is_not_blamed() {
    let output = run(
        "bad-path-unrelated-malformed-issuer.exe",
        "fixtures/path-root.der",
    );
    assert_eq!(output.exit_code, 1, "{}", output.json);
    let error = &output.json["results"][0]["error"];
    assert_eq!(error["code"], "untrusted_root", "{error}");
    assert!(error["details"].get("reason").is_none(), "{error}");
}

fn extension_of_another_format_fails_the_path(input: &str, reason: &str, extension: &str) {
    let output = run_fixture(
        input,
        &[
            "verify",
            "--no-system-roots",
            "--roots",
            "fixtures/root.der",
            "--crl",
            "fixtures/good.crl",
            "--time",
            "1800000000",
        ],
    );
    assert_eq!(output.exit_code, 1, "{}", output.json);
    let error = &output.json["results"][0]["error"];
    assert_eq!(error["code"], "certificate_chain_invalid", "{error}");
    assert_eq!(error["stage"], "certificate_chain", "{error}");
    assert_eq!(error["details"]["reason"], reason, "{error}");
    assert_eq!(error["details"]["extension"], extension, "{error}");
}

#[test]
fn malformed_extension_in_an_rdp_signer_fails_the_path() {
    extension_of_another_format_fails_the_path(
        "bad-rdp-malformed-eku.rdp",
        "malformed_extension",
        "2.5.29.37",
    );
}

#[test]
fn malformed_extension_in_a_tsa_certificate_fails_the_path() {
    extension_of_another_format_fails_the_path(
        "tsa-malformed-ski.exe",
        "malformed_extension",
        "2.5.29.14",
    );
}

#[test]
fn repeated_extension_in_an_rdp_signer_fails_the_path() {
    extension_of_another_format_fails_the_path(
        "bad-rdp-repeated-eku.rdp",
        "repeated_extension",
        "2.5.29.37",
    );
}

/// RDP-T005: with no configured root, an RDP signer reports `untrusted_root`
/// before its EKU is read, as every other format does (PATH-013, PATH-014,
/// PATH-001), whatever its extKeyUsage holds.
#[test]
fn rdp_signer_eku_without_a_configured_root_is_untrusted() {
    for input in [
        "bad-rdp-malformed-eku.rdp",
        "bad-rdp-repeated-eku.rdp",
        "bad-rdp-no-eku.rdp",
        "bad-rdp-eku.rdp",
    ] {
        let output = run_fixture(
            input,
            &[
                "verify",
                "--no-system-roots",
                "--no-revocation",
                "--time",
                "1800000000",
            ],
        );
        assert_eq!(output.exit_code, 1, "{input}: {}", output.json);
        let error = &output.json["results"][0]["error"];
        assert_eq!(error["code"], "untrusted_root", "{input}: {error}");
        assert_eq!(error["stage"], "certificate_chain", "{input}: {error}");
        assert!(error["details"].get("reason").is_none(), "{input}: {error}");
    }
}

#[test]
fn repeated_extension_in_a_tsa_certificate_fails_the_path() {
    extension_of_another_format_fails_the_path(
        "tsa-repeated-ski.exe",
        "repeated_extension",
        "2.5.29.14",
    );
}

#[test]
fn bad_path_pathlen() {
    rejected(
        "bad-path-pathlen.exe",
        "fixtures/path-root.der",
        ErrorCode::CertificateChainInvalid,
        Stage::CertificateChain,
        "PathLenConstraintViolated",
    );
}

#[test]
fn bad_path_name_outside() {
    rejected(
        "bad-path-name-outside.exe",
        "fixtures/path-root.der",
        ErrorCode::CertificateChainInvalid,
        Stage::CertificateChain,
        "NameConstraintViolation",
    );
}

#[test]
fn bad_path_name_excluded() {
    rejected(
        "bad-path-name-excluded.exe",
        "fixtures/path-root.der",
        ErrorCode::CertificateChainInvalid,
        Stage::CertificateChain,
        "NameConstraintViolation",
    );
}

#[test]
fn bad_path_wrong_key() {
    rejected(
        "bad-path-wrong-key.exe",
        "fixtures/path-root.der",
        ErrorCode::CertificateChainInvalid,
        Stage::CertificateChain,
        "InvalidSignatureForPublicKey",
    );
}

#[test]
fn good_path_leaf_no_bc() {
    selected(
        "good-path-leaf-no-bc.exe",
        "fixtures/path-root.der",
        &["leaf-no-bc", "issuer", "root"],
    );
}

#[test]
fn good_path_leaf_no_ku() {
    selected(
        "good-path-leaf-no-ku.exe",
        "fixtures/path-root.der",
        &["leaf-no-ku", "issuer", "root"],
    );
}

#[test]
fn good_path_leaf_noncritical() {
    selected(
        "good-path-leaf-noncritical.exe",
        "fixtures/path-root.der",
        &["leaf-noncritical", "issuer", "root"],
    );
}

#[test]
fn good_path_ca_noncritical() {
    selected(
        "good-path-ca-noncritical.exe",
        "fixtures/path-root.der",
        &["leaf", "ca-noncritical", "root"],
    );
}

#[test]
fn good_path_ca_no_ku() {
    selected(
        "good-path-ca-no-ku.exe",
        "fixtures/path-root.der",
        &["leaf", "ca-no-ku", "root"],
    );
}

#[test]
fn good_path_ca_good_eku() {
    selected(
        "good-path-ca-good-eku.exe",
        "fixtures/path-root.der",
        &["leaf", "ca-good-eku", "root"],
    );
}

#[test]
fn bad_path_ca_eku() {
    rejected(
        "bad-path-ca-eku.exe",
        "fixtures/path-root.der",
        ErrorCode::InvalidEku,
        Stage::CertificateChain,
        "RequiredEkuNotFoundContext",
    );
}

#[test]
fn bad_path_leaf_no_eku() {
    rejected(
        "bad-path-leaf-no-eku.exe",
        "fixtures/path-root.der",
        ErrorCode::InvalidEku,
        Stage::Certificate,
        "lacks required EKU",
    );
}

#[test]
fn bad_path_ca_ku() {
    rejected(
        "bad-path-ca-ku.exe",
        "fixtures/path-root.der",
        ErrorCode::InvalidKeyUsage,
        Stage::CertificateChain,
        "lacks keyCertSign",
    );
}

#[test]
fn good_path_pathlen() {
    selected(
        "good-path-pathlen.exe",
        "fixtures/path-root.der",
        &["leaf", "lower", "upper", "root"],
    );
}

#[test]
fn good_path_name_good() {
    selected(
        "good-path-name-good.exe",
        "fixtures/path-root.der",
        &["dns-good", "constrained", "root"],
    );
}

#[test]
fn good_path_wrong_key_first() {
    selected(
        "good-path-wrong-key-first.exe",
        "fixtures/path-root.der",
        &["leaf", "issuer", "root"],
    );
}

#[test]
fn good_path_wrong_key_last() {
    selected(
        "good-path-wrong-key-last.exe",
        "fixtures/path-root.der",
        &["leaf", "issuer", "root"],
    );
}

#[test]
fn good_path_cross_first() {
    selected(
        "good-path-cross-first.exe",
        "fixtures/path-root.der",
        &["leaf", "issuer", "root"],
    );
}

#[test]
fn good_path_cross_last() {
    selected(
        "good-path-cross-last.exe",
        "fixtures/path-root.der",
        &["leaf", "issuer", "root"],
    );
}

#[test]
fn good_path_cycle_escape() {
    selected(
        "good-path-cycle-escape.exe",
        "fixtures/path-root.der",
        &["leaf", "issuer", "root"],
    );
}

#[test]
fn good_path_cycle_escape_reversed() {
    selected(
        "good-path-cycle-escape-reversed.exe",
        "fixtures/path-root.der",
        &["leaf", "issuer", "root"],
    );
}

#[test]
fn good_path_ca_ku_first() {
    selected(
        "good-path-ca-ku-first.exe",
        "fixtures/path-root.der",
        &["leaf", "issuer", "root"],
    );
}

#[test]
fn good_path_ca_ku_last() {
    selected(
        "good-path-ca-ku-last.exe",
        "fixtures/path-root.der",
        &["leaf", "issuer", "root"],
    );
}

#[test]
fn bad_path_cross_untrusted() {
    rejected(
        "bad-path-cross-untrusted.exe",
        "fixtures/path-root.der",
        ErrorCode::UntrustedRoot,
        Stage::CertificateChain,
        "UnknownIssuer",
    );
}

#[test]
fn bad_path_cycle() {
    rejected(
        "bad-path-cycle.exe",
        "fixtures/path-root.der",
        ErrorCode::UntrustedRoot,
        Stage::CertificateChain,
        "UnknownIssuer",
    );
}

#[test]
fn bad_path_cycle_reversed() {
    rejected(
        "bad-path-cycle-reversed.exe",
        "fixtures/path-root.der",
        ErrorCode::UntrustedRoot,
        Stage::CertificateChain,
        "UnknownIssuer",
    );
}

#[test]
fn good_path_cross_other_root() {
    selected(
        "good-path-cross-first.exe",
        "fixtures/path-other-root.der",
        &["leaf", "cross", "other-root"],
    );
}

#[test]
fn good_path_root_expired() {
    selected(
        "good-path-basic.exe",
        "fixtures/path-root-expired.der",
        &["leaf", "issuer", "root-expired"],
    );
}

#[test]
fn good_path_root_profile() {
    selected(
        "good-path-basic.exe",
        "fixtures/path-root-profile.der",
        &["leaf", "issuer", "root-profile"],
    );
}

#[test]
fn good_path_root_name() {
    selected(
        "good-path-root-name.exe",
        "fixtures/path-root-constrained.der",
        &["dns-good", "issuer", "root-constrained"],
    );
}

#[test]
fn bad_path_root_name() {
    rejected(
        "good-path-root-name.exe",
        "fixtures/path-root-denied.der",
        ErrorCode::CertificateChainInvalid,
        Stage::CertificateChain,
        "NameConstraintViolation",
    );
}

#[test]
fn good_path_root_selection() {
    selected(
        "good-path-root-name.exe",
        "fixtures/path-roots-alternative.pem",
        &["dns-good", "issuer", "root-constrained"],
    );
}
