//! TRUST-T001 loading failures are configuration errors, not verification verdicts.
use super::support::*;
use x509_cert::der::Decode;

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
    // Each cause is printed once, not repeated through the error's source chain.
    assert_eq!(stderr.matches(fragment).count(), 1, "{stderr}");
}

#[test]
fn unsupported_anchor_is_not_silently_excluded() {
    let bytes = include_bytes!("../fixtures/root-unsupported.der");
    // Isolate anchor conversion, not malformed X.509 input.
    x509_cert::Certificate::from_der(bytes).unwrap();
    assert!(
        webpki::anchor_from_trusted_cert(&rustls_pki_types::CertificateDer::from(bytes.as_slice()))
            .is_err()
    );
    rejected(
        "root-unsupported.der",
        "--roots",
        "unsupported trust anchor",
    );
    rejected("root-bundle-unsupported.pem", "--roots", "entry 2");
}

#[test]
fn mixed_and_trailing_root_input_is_rejected() {
    for (file, entry) in [
        ("root-bundle-invalid.pem", "entry 2"),
        ("root-bundle-invalid-first.pem", "entry 1"),
        ("root-bundle-trailing.pem", "entry 2"),
        ("root-bundle-truncated.pem", "entry 2"),
    ] {
        rejected(file, "--roots", entry);
    }
}

#[test]
fn mixed_and_trailing_crl_input_is_rejected() {
    for (file, entry) in [
        ("crl-bundle-invalid.pem", "entry 2"),
        ("crl-bundle-invalid-first.pem", "entry 1"),
        ("crl-bundle-trailing.pem", "entry 2"),
    ] {
        rejected(file, "--crl", entry);
    }
}

#[test]
fn empty_and_wrong_label_inputs_are_rejected() {
    for flag in ["--roots", "--crl"] {
        rejected("trust-empty.pem", flag, "empty trust input");
    }
    rejected(
        "crl-bundle-good.pem",
        "--roots",
        "expected CERTIFICATE PEM label",
    );
    rejected(
        "root-bundle-good.pem",
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
fn valid_pem_and_duplicates_preserve_exact_reports() {
    let baseline = loaded("fixtures/root.der", "fixtures/good.crl");
    expect_success(&baseline);
    for (root, crl) in [
        (
            "fixtures/root-bundle-good.pem",
            "fixtures/crl-bundle-good.pem",
        ),
        (
            "fixtures/root-bundle-duplicate.pem",
            "fixtures/crl-bundle-duplicate.pem",
        ),
        ("fixtures/root-bundle-whitespace.pem", "fixtures/good.crl"),
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
fn crl_loading_does_not_authenticate_it() {
    let out = loaded("fixtures/root.der", "fixtures/crl-bundle-forged.pem");
    assert_eq!(out.exit_code, 1);
    assert_eq!(
        out.json["results"][0]["error"]["code"],
        "invalid_crl_signature"
    );
    assert_eq!(out.json["results"][0]["error"]["stage"], "revocation");
}

#[test]
fn empty_store_remains_untrusted() {
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
