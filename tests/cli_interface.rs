use rssig::cli;
use serde_json::Value;

#[test]
fn invalid_arguments_are_captured_without_exiting_the_test_process() {
    let mut output = Vec::new();
    let exit = cli::run(["rssig", "verify"], &mut output).unwrap();
    let json: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(exit, 2);
    assert_eq!(json["error"]["code"], "invalid_arguments");
}

#[test]
fn help_is_json_written_to_the_supplied_writer() {
    let mut output = Vec::new();
    let exit = cli::run(["rssig", "--help"], &mut output).unwrap();
    let json: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(exit, 0);
    assert_eq!(json["command"], "help");
    assert!(json["text"].as_str().unwrap().contains("verify"));
}

fn fixture(name: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

fn invoke(arguments: &[std::ffi::OsString]) -> (u8, Value) {
    let mut output = Vec::new();
    let code = cli::run(arguments, &mut output).unwrap();
    (code, serde_json::from_slice(&output).unwrap())
}

#[test]
fn multiple_inputs_preserve_successes_and_each_problem_in_input_order() {
    let args = vec![
        "rssig".into(),
        "verify".into(),
        "--integrity-only".into(),
        "--time".into(),
        "1800000000".into(),
        fixture("good-pe64.exe").into_os_string(),
        fixture("bad-image-digest.exe").into_os_string(),
        fixture("not-pe.bin").into_os_string(),
    ];
    let (code, json) = invoke(&args);
    assert_eq!(code, 1);
    assert_eq!(json["results"].as_array().unwrap().len(), 3);
    assert_eq!(json["results"][0]["ok"], true);
    assert_eq!(json["results"][1]["error"]["code"], "image_digest_mismatch");
    assert_eq!(json["results"][2]["error"]["code"], "invalid_pe");
    assert_eq!(json["type"], json["results"][1]["error"]["type"]);
}

#[test]
fn version_is_a_serialized_information_report() {
    let (code, json) = invoke(&["rssig".into(), "--version".into()]);
    let info: rssig::domain::InformationReport = serde_json::from_value(json).unwrap();
    assert_eq!(code, 0);
    assert!(info.ok);
    assert_eq!(info.command, "version");
    assert!(info.text.contains(env!("CARGO_PKG_VERSION")));
}

#[test]
fn unknown_subcommands_are_argument_problems() {
    let (code, json) = invoke(&["rssig".into(), "does-not-exist".into()]);
    assert_eq!(code, 2);
    assert_eq!(json["error"]["code"], "invalid_arguments");
}

#[test]
fn old_test_runner_is_no_longer_a_product_command() {
    let (code, json) = invoke(&["rssig".into(), "test".into()]);
    assert_eq!(code, 2);
    assert_eq!(json["error"]["code"], "invalid_arguments");
}

#[test]
fn integrity_only_conflicts_with_trust_policy_flags() {
    let (code, json) = invoke(&[
        "rssig".into(),
        "verify".into(),
        "--integrity-only".into(),
        "--no-system-roots".into(),
        fixture("good-pe64.exe").into_os_string(),
    ]);
    assert_eq!(code, 2);
    assert_eq!(json["error"]["code"], "invalid_arguments");
}

fn configuration_problem(flag: &str, file: &str) {
    let mut args: Vec<std::ffi::OsString> = [
        "rssig",
        "verify",
        "--no-system-roots",
        "--no-revocation",
        "--time",
        "1800000000",
    ]
    .into_iter()
    .map(Into::into)
    .collect();
    args.extend([
        flag.into(),
        fixture(file).into_os_string(),
        fixture("good-pe64.exe").into_os_string(),
    ]);
    let (code, json) = invoke(&args);
    assert_eq!(code, 2);
    assert_eq!(json["error"]["code"], "configuration");
    assert_eq!(json["error"]["stage"], "configuration");
    assert_eq!(json["detail"], json["error"]["detail"]);
}

#[test]
fn missing_roots_are_configuration_problems() {
    configuration_problem("--roots", "missing-root.der");
}
#[test]
fn malformed_roots_are_configuration_problems() {
    configuration_problem("--roots", "not-pe.bin");
}
#[test]
fn missing_crls_are_configuration_problems() {
    configuration_problem("--crl", "missing.crl");
}
#[test]
fn malformed_crls_are_configuration_problems() {
    configuration_problem("--crl", "not-pe.bin");
}

#[test]
fn verification_without_time_uses_the_clock_without_affecting_unsigned_errors() {
    // Unsigned input makes this assertion independent of the wall clock.
    let (code, json) = invoke(&[
        "rssig".into(),
        "verify".into(),
        "--integrity-only".into(),
        fixture("unsigned.exe").into_os_string(),
    ]);
    assert_eq!(code, 1);
    assert_eq!(json["results"][0]["error"]["code"], "unsigned");
}

#[test]
fn writer_failures_are_returned_without_panicking() {
    struct Closed;
    impl std::io::Write for Closed {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "sink closed",
            ))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let error = cli::run(["rssig", "--help"], Closed).unwrap_err();
    assert!(error.to_string().contains("sink closed"));
}
