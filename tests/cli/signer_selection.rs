use super::support::*;
#[test]
fn sec05_signer_selection_is_independent_of_certificate_order() {
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
    let mut selected = None;
    for name in ["good-sec05-duplicate.exe", "good-sec05-reordered.exe"] {
        let out = run_fixture(name, &args);
        assert_eq!(out.exit_code, 0);
        let signature = &out.json["results"][0]["signatures"][0];
        let current = (signature["certificate"].clone(), signature["trust"].clone());
        if let Some(previous) = &selected {
            assert_eq!(previous, &current);
        }
        selected = Some(current);
        assert_eq!(
            out.json["results"][0]["signatures"][0]["revocation_checked"],
            true
        );
    }
    for name in [
        "bad-sec05-key-last.exe",
        "bad-sec05-key-first.exe",
        "bad-sec05-policy-first.exe",
        "bad-sec05-policy-last.exe",
    ] {
        let out = run_fixture(name, &args);
        assert_eq!(out.exit_code, 1, "{name}");
        let e = &out.json["results"][0]["error"];
        assert_eq!(e["code"], "ambiguous_signer_certificate", "{name}: {e}");
        assert_eq!(e["stage"], "cms");
        assert_eq!(e["details"]["matching_certificates"], 2);
    }
    let missing = run_fixture("bad-sec05-missing.exe", &args);
    assert_eq!(missing.exit_code, 1);
    assert_eq!(
        missing.json["results"][0]["error"]["code"],
        "invalid_signature"
    );
}
