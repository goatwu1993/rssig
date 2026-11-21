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
