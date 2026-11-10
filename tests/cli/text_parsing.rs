//! Public text parsers and CLI verification share the committed specification.
use super::support::*;

#[test]
fn lib04_powershell_independent_jsign() {
    let output = run_fixture(
        "powershell-independent-jsign.ps1",
        &["verify", "--integrity-only", "--time", "1800000000"],
    );
    assert_eq!(output.exit_code, 0);
    expect_success(&output);
    assert_eq!(
        output.json["results"][0]["format"],
        "powershell_authenticode"
    );
}

#[test]
fn lib04_powershell_independent_tampered() {
    let output = run_fixture(
        "bad-powershell-independent-digest.ps1",
        &["verify", "--integrity-only", "--time", "1800000000"],
    );
    assert_eq!(output.exit_code, 1);
    assert_eq!(
        output.json["results"][0]["error"]["code"],
        "script_digest_mismatch"
    );
    assert_eq!(output.json["results"][0]["error"]["stage"], "script_digest");
}

#[test]
fn lib04_wsh_wsh_independent_jsign_vbs() {
    let output = run_fixture(
        "wsh-independent-jsign.vbs",
        &["verify", "--integrity-only", "--time", "1800000000"],
    );
    assert_eq!(output.exit_code, 0);
    expect_success(&output);
    assert_eq!(output.json["results"][0]["format"], "vbscript_authenticode");
}

#[test]
fn lib04_rdp_independent_nfedera() {
    let output = run_fixture(
        "rdp-independent-nfedera.rdp",
        &["verify", "--integrity-only", "--time", "1800000000"],
    );
    assert_eq!(output.exit_code, 0);
    expect_success(&output);
    assert_eq!(output.json["results"][0]["format"], "rdp_signed_settings");
}

#[test]
fn lib04_bad_rdp_independent_setting() {
    let output = run_fixture(
        "bad-rdp-independent-setting.rdp",
        &["verify", "--integrity-only", "--time", "1800000000"],
    );
    assert_eq!(output.exit_code, 1);
    assert_eq!(
        output.json["results"][0]["error"]["code"],
        "invalid_signature"
    );
    assert_eq!(output.json["results"][0]["error"]["stage"], "cms");
}

#[test]
fn lib04_psxml_independent_ascii() {
    let output = run_fixture(
        "psxml-independent-jsign-ascii.ps1xml",
        &["verify", "--integrity-only", "--time", "1800000000"],
    );
    assert_eq!(output.exit_code, 0);
    expect_success(&output);
    assert_eq!(
        output.json["results"][0]["format"],
        "powershell_xml_authenticode"
    );
}
