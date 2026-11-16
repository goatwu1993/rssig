//! SEC-07 loading failures are configuration errors, not verification verdicts.
use super::support::*;
use der::Decode;

fn rejected(file: &str, flag: &str, fragment: &str) {
    let path = |name: &str| format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let code = rssig::cli::run_with_writers(
        [
            "rssig",
            "verify",
            "--no-system-roots",
            "--time",
            "1800000000",
            "--roots",
            &path("root.der"),
            "--crl",
            &path("good.crl"),
            flag,
            &path(file),
            &path("good-pe64.exe"),
        ],
        &mut stdout,
        &mut stderr,
    )
    .unwrap();
    assert_eq!(code, 2, "{file}: {}", String::from_utf8_lossy(&stdout));
    assert!(stdout.is_empty());
    let stderr = String::from_utf8(stderr).unwrap();
    assert!(stderr.starts_with("error:"), "{stderr}");
    assert!(stderr.contains(file), "{stderr}");
    assert!(stderr.contains(fragment), "{stderr}");
}

#[test]
fn sec07_unsupported_anchor_is_not_silently_excluded() {
    let bytes = include_bytes!("../fixtures/sec07-root-unsupported.der");
    // Isolate anchor conversion, not malformed X.509 input.
    x509_cert::Certificate::from_der(bytes).unwrap();
    assert!(
        webpki::anchor_from_trusted_cert(&rustls_pki_types::CertificateDer::from(bytes.as_slice()))
            .is_err()
    );
    rejected(
        "sec07-root-unsupported.der",
        "--roots",
        "unsupported trust anchor",
    );
    rejected("sec07-roots-unsupported.pem", "--roots", "entry 2");
}

#[test]
fn sec07_mixed_and_trailing_root_input_is_rejected() {
    for (file, entry) in [
        ("sec07-roots-invalid.pem", "entry 2"),
        ("sec07-roots-invalid-first.pem", "entry 1"),
        ("sec07-roots-trailing.pem", "entry 2"),
        ("sec07-roots-truncated.pem", "entry 2"),
    ] {
        rejected(file, "--roots", entry);
    }
}

#[test]
fn sec07_mixed_and_trailing_crl_input_is_rejected() {
    for (file, entry) in [
        ("sec07-crls-invalid.pem", "entry 2"),
        ("sec07-crls-invalid-first.pem", "entry 1"),
        ("sec07-crls-trailing.pem", "entry 2"),
    ] {
        rejected(file, "--crl", entry);
    }
}

#[test]
fn sec07_empty_and_wrong_label_inputs_are_rejected() {
    for flag in ["--roots", "--crl"] {
        rejected("sec07-empty.pem", flag, "empty trust input");
    }
    rejected(
        "sec07-crls-good.pem",
        "--roots",
        "expected CERTIFICATE PEM label",
    );
    rejected(
        "sec07-roots-good.pem",
        "--crl",
        "expected X509 CRL PEM label",
    );
}

fn loaded(root: &str, crl: &str) -> Output {
    run_fixture(
        "good-pe64.exe",
        &[
            "verify",
            "--no-system-roots",
            "--time",
            "1800000000",
            "--roots",
            root,
            "--crl",
            crl,
        ],
    )
}

#[test]
fn sec07_valid_pem_and_duplicates_preserve_exact_reports() {
    let baseline = loaded("fixtures/root.der", "fixtures/good.crl");
    expect_success(&baseline);
    for (root, crl) in [
        (
            "fixtures/sec07-roots-good.pem",
            "fixtures/sec07-crls-good.pem",
        ),
        (
            "fixtures/sec07-roots-duplicate.pem",
            "fixtures/sec07-crls-duplicate.pem",
        ),
        ("fixtures/sec07-roots-whitespace.pem", "fixtures/good.crl"),
    ] {
        let out = loaded(root, crl);
        expect_success(&out);
        assert_eq!(out.json, baseline.json);
        let sig = &out.json["results"][0]["signatures"][0];
        assert_eq!(sig["chain_trusted"], true);
        assert_eq!(sig["revocation_checked"], true);
        let crls = sig["trust"]["revocation"]["crls"].as_array().unwrap();
        assert_eq!(crls.len(), 1);
        assert_eq!(crls[0]["role"], "supplied");
        assert!(crls[0].get("signature_verified").is_none());
        assert_eq!(
            out.success().signatures[0]
                .trust
                .as_ref()
                .unwrap()
                .revocation
                .crls
                .len(),
            1
        );
    }
}

#[test]
fn sec07_crl_loading_does_not_authenticate_it() {
    let out = loaded("fixtures/root.der", "fixtures/sec07-crls-forged.pem");
    assert_eq!(out.exit_code, 1);
    assert_eq!(
        out.json["results"][0]["error"]["code"],
        "invalid_crl_signature"
    );
    assert_eq!(out.json["results"][0]["error"]["stage"], "revocation");
}

#[test]
fn sec07_empty_store_remains_untrusted() {
    let out = run_fixture(
        "good-pe64.exe",
        &[
            "verify",
            "--no-system-roots",
            "--time",
            "1800000000",
            "--crl",
            "fixtures/good.crl",
        ],
    );
    assert_eq!(out.exit_code, 1);
    assert_eq!(out.json["results"][0]["error"]["code"], "untrusted_root");
    assert_eq!(
        out.json["results"][0]["error"]["stage"],
        "certificate_chain"
    );
}
