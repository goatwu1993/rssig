use super::support::*;
#[test]
fn cms_structure_and_binding() {
    let args = [
        "verify",
        "--no-system-roots",
        "--roots",
        "fixtures/root.der",
        "--crl",
        "fixtures/good.crl",
        "--time",
        "1800000000",
    ];
    let good = run_fixture("good-cms-structure.exe", &args);
    assert_eq!(good.exit_code, 0);
    for (file, code) in [
        ("bad-cms-signeddata-version.exe", "malformed_cms"),
        ("bad-cms-signer-version.exe", "invalid_signature"),
        ("bad-cms-value-order.exe", "invalid_signature"),
        ("bad-cms-ecdsa-parameters.exe", "invalid_signature"),
    ] {
        let out = run_fixture(file, &args);
        assert_eq!(out.exit_code, 1, "{file}");
        assert_eq!(out.json["results"][0]["error"]["code"], code);
        assert_eq!(out.json["results"][0]["error"]["stage"], "cms");
    }
}

#[test]
fn cms_attribute_multiplicity() {
    let args = [
        "verify",
        "--no-system-roots",
        "--roots",
        "fixtures/root.der",
        "--crl",
        "fixtures/good.crl",
        "--time",
        "1800000000",
    ];
    for file in [
        "good-cms-duplicate-unknown-signed.exe",
        "good-cms-duplicate-unknown-unsigned.exe",
    ] {
        let out = run_fixture(file, &args);
        assert_eq!(out.exit_code, 0, "{file}: {}", out.json);
    }
    for file in [
        "bad-cms-duplicate-content-type.exe",
        "bad-cms-duplicate-message-digest.exe",
        "bad-cms-duplicate-signing-time.exe",
        "bad-cms-duplicate-nested.exe",
    ] {
        let out = run_fixture(file, &args);
        assert_eq!(out.exit_code, 1, "{file}");
        let error = &out.json["results"][0]["error"];
        assert_eq!(error["code"], "invalid_signature", "{file}: {error}");
        assert_eq!(error["stage"], "cms", "{file}");
    }
    // A signer with two timestamps is rejected by TSA-004, not by the CMS layer.
    for file in ["tsa-duplicate-rfc.exe", "tsa-duplicate-counter.exe"] {
        let out = run_fixture(file, &args);
        assert_eq!(out.exit_code, 1, "{file}");
        let error = &out.json["results"][0]["error"];
        assert_eq!(error["code"], "invalid_timestamp", "{file}: {error}");
        assert_eq!(error["stage"], "timestamp", "{file}");
    }
}
