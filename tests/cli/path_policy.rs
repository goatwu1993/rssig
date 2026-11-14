//! SEC-06: exact selected chains and typed policy failures, with offline CRLs.
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
            "fixtures/sec06-root.crl",
            "--crl",
            "fixtures/sec06-issuer.crl",
            "--crl",
            "fixtures/sec06-upper.crl",
            "--crl",
            "fixtures/sec06-other-root.crl",
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
            .join(format!("sec06-{name}.der"));
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
fn good_sec06_basic() {
    selected(
        "good-sec06-basic.exe",
        "fixtures/sec06-root.der",
        &["leaf", "issuer", "root"],
    );
}

#[test]
fn bad_sec06_ca_false() {
    rejected(
        "bad-sec06-ca-false.exe",
        "fixtures/sec06-root.der",
        ErrorCode::CertificateChainInvalid,
        Stage::CertificateChain,
        "EndEntityUsedAsCa",
    );
}

#[test]
fn bad_sec06_ca_missing_bc() {
    rejected(
        "bad-sec06-ca-missing-bc.exe",
        "fixtures/sec06-root.der",
        ErrorCode::CertificateChainInvalid,
        Stage::CertificateChain,
        "EndEntityUsedAsCa",
    );
}

#[test]
fn bad_sec06_leaf_ca() {
    rejected(
        "bad-sec06-leaf-ca.exe",
        "fixtures/sec06-root.der",
        ErrorCode::CertificateChainInvalid,
        Stage::CertificateChain,
        "CaUsedAsEndEntity",
    );
}

#[test]
fn bad_sec06_ca_critical() {
    rejected(
        "bad-sec06-ca-critical.exe",
        "fixtures/sec06-root.der",
        ErrorCode::CertificateChainInvalid,
        Stage::CertificateChain,
        "UnsupportedCriticalExtension",
    );
}

#[test]
fn bad_sec06_leaf_critical() {
    rejected(
        "bad-sec06-leaf-critical.exe",
        "fixtures/sec06-root.der",
        ErrorCode::CertificateChainInvalid,
        Stage::CertificateChain,
        "UnsupportedCriticalExtension",
    );
}

#[test]
fn bad_sec06_pathlen() {
    rejected(
        "bad-sec06-pathlen.exe",
        "fixtures/sec06-root.der",
        ErrorCode::CertificateChainInvalid,
        Stage::CertificateChain,
        "PathLenConstraintViolated",
    );
}

#[test]
fn bad_sec06_name_outside() {
    rejected(
        "bad-sec06-name-outside.exe",
        "fixtures/sec06-root.der",
        ErrorCode::CertificateChainInvalid,
        Stage::CertificateChain,
        "NameConstraintViolation",
    );
}

#[test]
fn bad_sec06_name_excluded() {
    rejected(
        "bad-sec06-name-excluded.exe",
        "fixtures/sec06-root.der",
        ErrorCode::CertificateChainInvalid,
        Stage::CertificateChain,
        "NameConstraintViolation",
    );
}

#[test]
fn bad_sec06_wrong_key() {
    rejected(
        "bad-sec06-wrong-key.exe",
        "fixtures/sec06-root.der",
        ErrorCode::CertificateChainInvalid,
        Stage::CertificateChain,
        "InvalidSignatureForPublicKey",
    );
}

#[test]
fn good_sec06_leaf_no_bc() {
    selected(
        "good-sec06-leaf-no-bc.exe",
        "fixtures/sec06-root.der",
        &["leaf-no-bc", "issuer", "root"],
    );
}

#[test]
fn good_sec06_leaf_no_ku() {
    selected(
        "good-sec06-leaf-no-ku.exe",
        "fixtures/sec06-root.der",
        &["leaf-no-ku", "issuer", "root"],
    );
}

#[test]
fn good_sec06_leaf_noncritical() {
    selected(
        "good-sec06-leaf-noncritical.exe",
        "fixtures/sec06-root.der",
        &["leaf-noncritical", "issuer", "root"],
    );
}

#[test]
fn good_sec06_ca_noncritical() {
    selected(
        "good-sec06-ca-noncritical.exe",
        "fixtures/sec06-root.der",
        &["leaf", "ca-noncritical", "root"],
    );
}

#[test]
fn good_sec06_ca_no_ku() {
    selected(
        "good-sec06-ca-no-ku.exe",
        "fixtures/sec06-root.der",
        &["leaf", "ca-no-ku", "root"],
    );
}

#[test]
fn good_sec06_ca_good_eku() {
    selected(
        "good-sec06-ca-good-eku.exe",
        "fixtures/sec06-root.der",
        &["leaf", "ca-good-eku", "root"],
    );
}

#[test]
fn bad_sec06_ca_eku() {
    rejected(
        "bad-sec06-ca-eku.exe",
        "fixtures/sec06-root.der",
        ErrorCode::InvalidEku,
        Stage::CertificateChain,
        "RequiredEkuNotFoundContext",
    );
}

#[test]
fn bad_sec06_leaf_no_eku() {
    rejected(
        "bad-sec06-leaf-no-eku.exe",
        "fixtures/sec06-root.der",
        ErrorCode::InvalidEku,
        Stage::Certificate,
        "lacks required EKU",
    );
}

#[test]
fn bad_sec06_ca_ku() {
    rejected(
        "bad-sec06-ca-ku.exe",
        "fixtures/sec06-root.der",
        ErrorCode::InvalidKeyUsage,
        Stage::CertificateChain,
        "lacks keyCertSign",
    );
}

#[test]
fn good_sec06_pathlen() {
    selected(
        "good-sec06-pathlen.exe",
        "fixtures/sec06-root.der",
        &["leaf", "lower", "upper", "root"],
    );
}

#[test]
fn good_sec06_name_good() {
    selected(
        "good-sec06-name-good.exe",
        "fixtures/sec06-root.der",
        &["dns-good", "constrained", "root"],
    );
}

#[test]
fn good_sec06_wrong_key_first() {
    selected(
        "good-sec06-wrong-key-first.exe",
        "fixtures/sec06-root.der",
        &["leaf", "issuer", "root"],
    );
}

#[test]
fn good_sec06_wrong_key_last() {
    selected(
        "good-sec06-wrong-key-last.exe",
        "fixtures/sec06-root.der",
        &["leaf", "issuer", "root"],
    );
}

#[test]
fn good_sec06_cross_first() {
    selected(
        "good-sec06-cross-first.exe",
        "fixtures/sec06-root.der",
        &["leaf", "issuer", "root"],
    );
}

#[test]
fn good_sec06_cross_last() {
    selected(
        "good-sec06-cross-last.exe",
        "fixtures/sec06-root.der",
        &["leaf", "issuer", "root"],
    );
}

#[test]
fn good_sec06_cycle_escape() {
    selected(
        "good-sec06-cycle-escape.exe",
        "fixtures/sec06-root.der",
        &["leaf", "issuer", "root"],
    );
}

#[test]
fn good_sec06_cycle_escape_reversed() {
    selected(
        "good-sec06-cycle-escape-reversed.exe",
        "fixtures/sec06-root.der",
        &["leaf", "issuer", "root"],
    );
}

#[test]
fn good_sec06_ca_ku_first() {
    selected(
        "good-sec06-ca-ku-first.exe",
        "fixtures/sec06-root.der",
        &["leaf", "issuer", "root"],
    );
}

#[test]
fn good_sec06_ca_ku_last() {
    selected(
        "good-sec06-ca-ku-last.exe",
        "fixtures/sec06-root.der",
        &["leaf", "issuer", "root"],
    );
}

#[test]
fn bad_sec06_cross_untrusted() {
    rejected(
        "bad-sec06-cross-untrusted.exe",
        "fixtures/sec06-root.der",
        ErrorCode::UntrustedRoot,
        Stage::CertificateChain,
        "UnknownIssuer",
    );
}

#[test]
fn bad_sec06_cycle() {
    rejected(
        "bad-sec06-cycle.exe",
        "fixtures/sec06-root.der",
        ErrorCode::UntrustedRoot,
        Stage::CertificateChain,
        "UnknownIssuer",
    );
}

#[test]
fn bad_sec06_cycle_reversed() {
    rejected(
        "bad-sec06-cycle-reversed.exe",
        "fixtures/sec06-root.der",
        ErrorCode::UntrustedRoot,
        Stage::CertificateChain,
        "UnknownIssuer",
    );
}

#[test]
fn good_sec06_cross_other_root() {
    selected(
        "good-sec06-cross-first.exe",
        "fixtures/sec06-other-root.der",
        &["leaf", "cross", "other-root"],
    );
}

#[test]
fn good_sec06_root_expired() {
    selected(
        "good-sec06-basic.exe",
        "fixtures/sec06-root-expired.der",
        &["leaf", "issuer", "root-expired"],
    );
}

#[test]
fn good_sec06_root_profile() {
    selected(
        "good-sec06-basic.exe",
        "fixtures/sec06-root-profile.der",
        &["leaf", "issuer", "root-profile"],
    );
}

#[test]
fn good_sec06_root_name() {
    selected(
        "good-sec06-root-name.exe",
        "fixtures/sec06-root-constrained.der",
        &["dns-good", "issuer", "root-constrained"],
    );
}

#[test]
fn bad_sec06_root_name() {
    rejected(
        "good-sec06-root-name.exe",
        "fixtures/sec06-root-denied.der",
        ErrorCode::CertificateChainInvalid,
        Stage::CertificateChain,
        "NameConstraintViolation",
    );
}

#[test]
fn good_sec06_root_selection() {
    selected(
        "good-sec06-root-name.exe",
        "fixtures/sec06-roots-alternative.pem",
        &["dns-good", "issuer", "root-constrained"],
    );
}
