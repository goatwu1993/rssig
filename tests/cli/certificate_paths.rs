//! PATH-T00001: exact selected chains and typed path-check failures, with offline CRLs.
use super::support::*;
use rssig::domain::{ErrorCode, Stage};
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
